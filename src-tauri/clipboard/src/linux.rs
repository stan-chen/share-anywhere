use std::path::PathBuf;

use gtk::gdk::Display;
use gtk::gdk_pixbuf;
use gtk::prelude::PixbufLoaderExt;
use gtk::Clipboard;

use crate::{Content, Error, Result};

fn uri_to(uri: &str) -> Option<PathBuf> {
  urlencoding::decode(uri)
    .ok()?
    .strip_prefix("file://")
    .map(PathBuf::from)
}

fn get_clipboard_object() -> Result<Clipboard> {
  gtk::init().map_err(|err| Error::SystemError(err.to_string()))?;
  let display = Display::open(std::env::var("DISPLAY").unwrap_or(":1".into()).as_str());
  if display.is_none() {
    return Err(Error::SystemError("cannot init display".into()));
  }
  Clipboard::default(&display.unwrap()).ok_or(Error::SystemError("cannot init clipboard".into()))
}

pub(crate) fn read_clipboard_any() -> Result<Content> {
  let cb = get_clipboard_object()?;
  let uris = cb.wait_for_uris();
  if !uris.is_empty() {
    return Ok(Content::Files(
      uris
        .into_iter()
        .filter_map(|item| uri_to(item.as_str()))
        .collect(),
    ));
  }

  match cb.wait_for_text() {
    Some(ss) => {
      return Ok(Content::String(ss.to_string()));
    }
    _ => {}
  }

  match cb.wait_for_image() {
    Some(img) => {
      let png = img
        .save_to_bufferv("png", &[])
        .map_err(|e| Error::SystemError(e.to_string()))?;
      let dy_img = image::load_from_memory_with_format(png.as_slice(), image::ImageFormat::Png)
        .map_err(|e| Error::SystemError(e.to_string()))?;
      let mut buf = std::io::Cursor::new(Vec::new());
      dy_img
        .write_to(&mut buf, image::ImageFormat::Png)
        .map_err(|e| Error::SystemError(e.to_string()))?;
      return Ok(Content::Image("PNG".into(), buf.get_ref().clone()));
    }
    _ => {}
  }

  Err(Error::NoContent)
}

pub(crate) fn set_clipboard_any(content: &Content) -> Result<()> {
  let cb = get_clipboard_object()?;
  return match content {
    Content::String(s) => {
      cb.set_text(s.as_str());
      cb.store();
      read_clipboard_any().map(|_| ())
    }
    Content::Image(_, data) => {
      let loader = gdk_pixbuf::PixbufLoader::with_type("png").unwrap();
      loader.write(data.as_slice()).unwrap();
      loader.close().unwrap();
      let buf = loader.pixbuf().unwrap();
      cb.set_image(&buf);
      cb.store();
      read_clipboard_any().map(|_| ())
    }
    Content::Files(_) => Err(Error::SystemError(
      "clipboard type Files is not supported".into(),
    )),
  };
}
