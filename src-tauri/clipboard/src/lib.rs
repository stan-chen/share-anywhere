#[macro_use]
#[cfg(target_os = "macos")]
extern crate objc;

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use linux::{read_clipboard_any, set_clipboard_any};
#[cfg(target_os = "macos")]
use macos::{read_clipboard_any, set_clipboard_any};

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Content {
  String(String),
  Image(String, Vec<u8>),
  Files(Vec<PathBuf>),
}

impl Content {
  pub fn md5_sum(&self) -> String {
    let mut state = md5::Context::new();
    match self {
      Self::String(s) => {
        state.write("String".as_bytes()).unwrap_or(0);
        state.write(s.as_bytes()).unwrap_or(0);
      }
      Self::Image(_, data) => {
        state.write("Image".as_bytes()).unwrap_or(0);
        state.write(data.as_ref()).unwrap_or(0);
      }
      Self::Files(files) => {
        state.write("Files".as_bytes()).unwrap_or(0);
        for x in files {
          state
            .write(x.to_str().unwrap_or("").as_bytes())
            .unwrap_or(0);
        }
      }
    }
    state.flush().unwrap();
    format!("{:x}", state.compute())
  }
}

pub fn get() -> Result<Content> {
  read_clipboard_any()
}

pub fn set(content: Content) -> Result<()> {
  set_clipboard_any(&content)
}

#[derive(Debug, PartialEq)]
pub enum Error {
  NoContent,
  NoFiles,
  SystemError(String),
}

impl From<String> for Error {
  fn from(value: String) -> Self {
    Self::SystemError(value)
  }
}

impl ToString for Error {
  fn to_string(&self) -> String {
    format!("{self:?}")
  }
}

pub type Result<T> = std::result::Result<T, Error>;
