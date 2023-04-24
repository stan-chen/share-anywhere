use std::fmt::{Debug, Display, Formatter};

#[derive(Debug)]
pub enum Error {
  IOErr(std::io::Error),
  JSONErr(serde_json::Error),
  HTTPErr(hyper::Error),
  #[allow(unused)]
  Other(String),
  CryptoErr(String),
}

impl Display for Error {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    Debug::fmt(&self, f)
  }
}

impl std::error::Error for Error {}

impl From<String> for Error {
  fn from(err: String) -> Self {
    Self::Other(err)
  }
}

impl From<std::io::Error> for Error {
  fn from(err: std::io::Error) -> Self {
    Self::IOErr(err)
  }
}

impl From<serde_json::Error> for Error {
  fn from(err: serde_json::Error) -> Self {
    Self::JSONErr(err)
  }
}

impl From<&str> for Error {
  fn from(err: &str) -> Self {
    Self::Other(err.into())
  }
}

impl From<hyper::Error> for Error {
  fn from(err: hyper::Error) -> Self {
    Self::HTTPErr(err)
  }
}

pub type Result<T> = std::result::Result<T, Error>;
