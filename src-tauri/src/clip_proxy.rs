use log::trace;
use std::sync::Arc;
use tauri::api::process::{Command, CommandEvent};

use clipboard::Content;

use crate::result::{Error, Result};

pub fn get_clipboard() -> Result<Content> {
  let output = Command::new_sidecar("clip-cli")
    .map_err(|e| Error::from(e.to_string()))?
    .args(["get"])
    .output()
    .map_err(|e| Error::from(e.to_string()))?;
  return if !output.status.success() {
    Err(Error::from(format!(
      "failed get clipboard: {}",
      output.stderr
    )))
  } else {
    serde_json::from_str(output.stdout.as_str()).map_err(|e| Error::from(e.to_string()))
  };
}

pub async fn set_clipboard(content: Content) -> Result<()> {
  let data = serde_json::to_vec(&content).map_err(|e| Error::from(e.to_string()))?;
  trace!("write data: {}", String::from_utf8(data.clone()).unwrap());
  let (mut rz, mut child) = Command::new_sidecar("clip-cli")
    .map_err(|e| Error::from(e.to_string()))?
    .args(["set", "-c"])
    .spawn()
    .map_err(|e| Error::from(e.to_string()))?;
  let barr = Arc::new(tokio::sync::Barrier::new(2));
  let inner_barr = barr.clone();
  let receive_task = tokio::task::spawn(async move {
    let mut stderr = None;
    inner_barr.wait().await;
    if let Some(ev) = rz.recv().await {
      match ev {
        CommandEvent::Terminated(term_payload) => {
          if term_payload.code == Some(0) {
            return Ok(());
          }
          return Err(Error::from(format!(
            "failed set clipboard with code ({:?}): stderr: {:?}",
            term_payload.code, stderr
          )));
        }
        #[allow(unused)]
        CommandEvent::Stderr(err) => {
          trace!("set clipboard command return stderr: {}", err);
          stderr = Some(err);
        }
        ev => {
          return Err(Error::from(format!(
            "failed set clipboard because event: {ev:?}"
          )));
        }
      }
    }
    Err(Error::from("failed set clipboard with no any events"))
  });
  barr.wait().await;
  child
    .write(data.as_slice())
    .map_err(|e| Error::from(e.to_string()))?;

  receive_task.await.map_err(|e| Error::from(e.to_string()))?
}
