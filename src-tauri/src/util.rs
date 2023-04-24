use crate::result::{Error, Result};
use log::LevelFilter;
use serde::de::Error as SerError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::net::IpAddr;
use std::path::PathBuf;

#[macro_export]
macro_rules! pow {
  ($a:expr, $b:literal) => {{
    let mut r = 1;
    for _ in 0..$b {
      r = r * $a;
    }
    r
  }};
}

pub fn config_logger(level: Option<LevelFilter>, file: Option<PathBuf>) {
  let lvl_filter = level.unwrap_or(
    #[cfg(debug_assertions)]
    LevelFilter::Debug,
    #[cfg(not(debug_assertions))]
    LevelFilter::Info,
  );
  let mut log_target = env_logger::Target::Stderr;
  if let Some(file_name) = file {
    let f = file_rotate::FileRotate::new(
      file_name,
      file_rotate::suffix::AppendCount::new(5),
      file_rotate::ContentLimit::Bytes(pow!(1024, 2) * 10), // 10 MB
      file_rotate::compression::Compression::None,
      #[cfg(unix)]
      Some(0o644),
    );
    log_target = env_logger::Target::Pipe(Box::new(f));
  }
  env_logger::Builder::new()
    .target(log_target)
    .format_timestamp_millis()
    .format_level(true)
    .filter_level(lvl_filter)
    .parse_env("SHARE_ANYWHERE_LOG")
    .init();
}

pub fn hostname() -> String {
  hostname::get()
    .expect("cannot get hostname")
    .into_string()
    .ok()
    .unwrap_or("".into())
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct NetworkDevice {
  name: String,
  desc: Option<String>,
  addresses: Vec<IpAddr>,
}

impl NetworkDevice {
  pub(crate) fn list() -> Result<Vec<NetworkDevice>> {
    Ok(
      pcap::Device::list()
        .map_err(|e| Error::from(e.to_string()))?
        .into_iter()
        .map(|item| item.into())
        .collect(),
    )
  }
}

impl From<pcap::Device> for NetworkDevice {
  fn from(value: pcap::Device) -> Self {
    Self {
      name: value.name,
      desc: value.desc,
      addresses: value
        .addresses
        .into_iter()
        .filter(|item| item.addr.is_ipv4())
        .map(|item| item.addr)
        .collect(),
    }
  }
}

#[derive(Clone, Debug, Default)]
pub struct B64Data(pub Vec<u8>);

impl AsRef<[u8]> for B64Data {
  fn as_ref(&self) -> &[u8] {
    self.0.as_ref()
  }
}

impl serde::Serialize for B64Data {
  fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    let s = base64::encode(self.0.as_slice());
    serializer.serialize_str(s.as_str())
  }
}

impl<'de> serde::Deserialize<'de> for B64Data {
  fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    let s = String::deserialize(deserializer)?;
    let data = base64::decode(s).map_err(|e| SerError::custom(e.to_string()))?;
    Ok(Self(data))
  }
}
