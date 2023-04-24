use std::collections::HashMap;
use std::net::IpAddr;

use crate::svc_http;
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

mod chrono_json_format {
  use std::str::FromStr;

  use chrono::{DateTime, Local};
  use serde::{self, Deserialize, Deserializer, Serializer};

  pub fn serialize<S>(date: &DateTime<Local>, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    let s = date.to_rfc3339();
    serializer.serialize_str(&s)
  }

  pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Local>, D::Error>
  where
    D: Deserializer<'de>,
  {
    let s = String::deserialize(deserializer)?;
    DateTime::<Local>::from_str(s.as_str()).map_err(serde::de::Error::custom)
  }
}

mod chrono_json_format_option {
  use std::str::FromStr;

  use chrono::{DateTime, Local};
  use serde::{self, Deserialize, Deserializer, Serializer};

  pub fn serialize<S>(date: &Option<DateTime<Local>>, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    return match date {
      Some(dt) => {
        let s = dt.to_rfc3339();
        serializer.serialize_str(&s)
      }
      None => serializer.serialize_none(),
    };
  }

  pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DateTime<Local>>, D::Error>
  where
    D: Deserializer<'de>,
  {
    match Option::<String>::deserialize(deserializer)? {
      Some(s) => Ok(Some(
        DateTime::<Local>::from_str(s.as_str()).map_err(serde::de::Error::custom)?,
      )),
      None => Ok(None),
    }
  }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Command {
  /// from machine name
  #[serde(default)]
  pub(crate) name: String,

  /// publish timestamp
  #[serde(with = "chrono_json_format")]
  pub(crate) timestamp: DateTime<Local>,

  /// custom labels
  #[serde(default = "HashMap::default")]
  pub(crate) labels: HashMap<String, String>,

  /// publish payload
  #[serde(default = "Payload::default")]
  #[serde(flatten)]
  pub(crate) payload: Payload,
}

impl Default for Command {
  fn default() -> Self {
    Self {
      name: Default::default(),
      timestamp: Local::now(),
      labels: Default::default(),
      payload: Payload::default(),
    }
  }
}

impl Command {
  pub fn new(
    name: String,
    timestamp: Option<DateTime<Local>>,
    labels: Option<HashMap<String, String>>,
    payload: Option<Payload>,
  ) -> Self {
    Self {
      name,
      timestamp: timestamp.unwrap_or(Local::now()),
      labels: labels.unwrap_or_default(),
      payload: payload.unwrap_or_default(),
    }
  }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SvcInfo {
  pub(crate) name: String,
  #[serde(skip_serializing_if = "Option::<IpAddr>::is_none", default)]
  pub(crate) ip_addr: Option<IpAddr>,
  #[serde(
    with = "chrono_json_format_option",
    skip_serializing_if = "Option::<DateTime::<Local>>::is_none",
    default
  )]
  pub(crate) latest_timestamp: Option<DateTime<Local>>,
  pub(crate) hostname: String,
  pub(crate) endpoint: svc_http::Uri,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ClipPayload {
  pub(crate) hash: String,
  pub(crate) timestamp_nano: i64,
  #[serde(skip)]
  #[allow(unused)]
  pub(crate) content: Option<clipboard::Content>,
}

impl From<clipboard::Content> for ClipPayload {
  fn from(content: clipboard::Content) -> Self {
    Self {
      hash: content.md5_sum(),
      timestamp_nano: Local::now().timestamp_nanos(),
      content: Some(content),
    }
  }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "kind", content = "payload")]
pub enum Payload {
  None,
  Info(SvcInfo),
  Clipboard(ClipPayload),
}

impl Default for Payload {
  fn default() -> Self {
    Self::None
  }
}
