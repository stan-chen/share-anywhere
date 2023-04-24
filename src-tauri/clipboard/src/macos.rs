use std::mem::transmute;
use std::path::PathBuf;

use objc::runtime::{Class, Object};
use objc_foundation::{object_struct, INSArray, INSData, INSObject, INSString};
use objc_foundation::{NSArray, NSData, NSDictionary, NSObject, NSString};
use objc_id::{Id, Owned};

use crate::{Content, Error, Result};

object_struct!(NSImage);
object_struct!(NSBitmapImageRep);

impl NSImage {
  fn tiff_bytes(&self) -> Option<Vec<u8>> {
    let tiff_data: Id<NSData> = unsafe {
      let data: *mut NSData = msg_send![self, TIFFRepresentation];
      Id::from_ptr(data)
    };
    tiff_data.bytes().to_owned().into()
  }

  pub fn png_bytes(&self) -> Result<Vec<u8>> {
    let tiff_data = self.tiff_bytes().ok_or(Error::NoContent)?;
    let tiff_image =
      image::load_from_memory_with_format(tiff_data.as_slice(), image::ImageFormat::Tiff)
        .map_err(|e| Error::SystemError(e.to_string()))?;
    let mut buf = std::io::Cursor::new(Vec::new());
    tiff_image
      .write_to(&mut buf, image::ImageFormat::Png)
      .map_err(|e| Error::SystemError(e.to_string()))?;
    Ok(buf.get_ref().clone())
  }

  pub fn from_png(data: &Vec<u8>) -> Result<Id<Self>> {
    let img = image::load_from_memory_with_format(data.as_slice(), image::ImageFormat::Png)
      .map_err(|e| Error::SystemError(e.to_string()))?;
    let mut buf = std::io::Cursor::new(Vec::new());
    img
      .write_to(&mut buf, image::ImageFormat::Tiff)
      .map_err(|e| Error::SystemError(e.to_string()))?;

    let tiff_data = NSData::from_vec(buf.get_ref().clone());

    let cls = Self::class();
    let ns_image: Id<Self> = unsafe {
      let obj: *mut Self = msg_send![cls, alloc];
      let obj: *mut Self = msg_send![obj, initWithData: tiff_data];
      Id::from_retained_ptr(obj)
    };
    Ok(ns_image)
  }
}

pub struct Clipboard {
  pasteboard: Id<Object>,
}

// required to bring NSPasteboard into the path of the class-resolver
#[link(name = "AppKit", kind = "framework")]
extern "C" {
  // NSString
  static NSPasteboardURLReadingFileURLsOnlyKey: &'static Object;
}

impl Clipboard {
  pub fn new() -> Result<Clipboard> {
    let ns_pasteboard = class!(NSPasteboard);
    let pasteboard: *mut Object = unsafe { msg_send![ns_pasteboard, generalPasteboard] };
    if pasteboard.is_null() {
      return Err(Error::SystemError(
        "NSPasteboard#generalPasteboard returned null".into(),
      ));
    }
    let pasteboard: Id<Object> = unsafe { Id::from_ptr(pasteboard) };
    Ok(Clipboard { pasteboard })
  }

  pub fn read_image(&self) -> Result<Vec<u8>> {
    let image_class: Id<NSObject> = {
      let cls: Id<Class> = unsafe { Id::from_ptr(class("NSImage")) };
      unsafe { transmute(cls) }
    };
    let classes: Id<NSArray<NSObject, Owned>> = NSArray::from_vec(vec![image_class]);
    let options: Id<NSDictionary<NSObject, NSObject>> = NSDictionary::new();
    let image_array: Id<NSArray<NSImage>> = unsafe {
      let obj: *mut NSArray<NSImage> =
        msg_send![self.pasteboard, readObjectsForClasses:&*classes options:&*options];
      if obj.is_null() {
        return Err(Error::SystemError(
          "pasteboard#readObjectsForClasses:options: returned null".into(),
        ));
      }
      Id::from_ptr(obj)
    };
    if image_array.count() == 0 {
      Err(Error::SystemError(
        "pasteboard#readObjectsForClasses:options: returned empty".into(),
      ))
    } else {
      image_array[0].png_bytes()
    }
  }

  pub fn read_string(&self) -> Result<String> {
    let string_class: Id<NSObject> = {
      let cls: Id<Class> = unsafe { Id::from_ptr(class("NSString")) };
      unsafe { transmute(cls) }
    };
    let classes: Id<NSArray<NSObject, Owned>> = NSArray::from_vec(vec![string_class]);
    let options: Id<NSDictionary<NSObject, NSObject>> = NSDictionary::new();
    let string_array: Id<NSArray<NSString>> = unsafe {
      let obj: *mut NSArray<NSString> =
        msg_send![self.pasteboard, readObjectsForClasses:&*classes options:&*options];
      if obj.is_null() {
        return Err(Error::SystemError(
          "pasteboard#readObjectsForClasses:options: returned null".into(),
        ));
      }
      Id::from_ptr(obj)
    };
    if string_array.count() == 0 {
      Err(Error::SystemError(
        "pasteboard#readObjectsForClasses:options: returned empty".into(),
      ))
    } else {
      Ok(string_array[0].as_str().to_owned())
    }
  }

  pub fn read_files(&self) -> Result<Vec<String>> {
    let ns_dict = class!(NSDictionary);
    let ns_number = class!(NSNumber);
    let options: Id<NSDictionary<NSObject, NSObject>> = unsafe {
      let obj: Id<NSObject> =
        Id::from_ptr(msg_send![ns_number, numberWithBool: objc::runtime::YES]);
      Id::from_ptr(
        msg_send![ns_dict, dictionaryWithObject: &*obj forKey: NSPasteboardURLReadingFileURLsOnlyKey],
      )
    };

    let nsurl_class: Id<NSObject> = {
      let cls: Id<Class> = unsafe { Id::from_ptr(class("NSURL")) };
      unsafe { transmute(cls) }
    };

    let classes: Id<NSArray<NSObject, Owned>> = NSArray::from_vec(vec![nsurl_class]);
    let nsurl_array: Id<NSArray<NSObject>> = unsafe {
      let obj: *mut NSArray<NSObject> =
        msg_send![self.pasteboard, readObjectsForClasses:&*classes options:&*options];
      if obj.is_null() {
        return Err(Error::NoFiles);
      }
      Id::from_ptr(obj)
    };

    let results: Vec<_> = nsurl_array
      .to_vec()
      .into_iter()
      .filter_map(|obj| {
        let s: &NSString = unsafe {
          let is_file: bool = msg_send![obj, isFileURL];
          if !is_file {
            return None;
          }
          let ret = msg_send![obj, path];
          ret
        };
        Some(s.as_str().to_owned())
      })
      .collect();
    if results.is_empty() {
      Err(Error::NoFiles)
    } else {
      Ok(results)
    }
  }

  pub fn set_string(&self, data: &str) -> Result<()> {
    let string_array = NSArray::from_vec(vec![NSString::from_str(&data)]);
    let _: usize = unsafe { msg_send![self.pasteboard, clearContents] };
    let success: bool = unsafe { msg_send![self.pasteboard, writeObjects: string_array] };
    return if success {
      Ok(())
    } else {
      Err(Error::SystemError(
        "NSPasteboard#writeObjects: returned false".into(),
      ))
    };
  }

  pub fn set_image(&self, data: &Vec<u8>) -> Result<()> {
    let image_array = NSArray::from_vec(vec![NSImage::from_png(data).unwrap()]);
    let _: usize = unsafe { msg_send![self.pasteboard, clearContents] };
    let success: bool = unsafe { msg_send![self.pasteboard, writeObjects: image_array] };
    return if success {
      Ok(())
    } else {
      Err(Error::SystemError(
        "NSPasteboard#writeObjects: returned false".into(),
      ))
    };
  }
}

// this is a convenience function that both cocoa-rs and
// glutin define, which seems to depend on the fact that
// Option::None has the same representation as a null pointer
#[inline]
fn class(name: &str) -> *mut Class {
  unsafe { transmute(Class::get(name)) }
}

pub(crate) fn read_clipboard_any() -> Result<Content> {
  let clipboard = Clipboard::new()?;
  if let Ok(files) = clipboard.read_files() {
    return Ok(Content::Files(
      files.into_iter().map(PathBuf::from).collect(),
    ));
  }

  if let Ok(s) = clipboard.read_string() {
    return Ok(Content::String(s));
  }

  if let Ok(img) = clipboard.read_image() {
    return Ok(Content::Image("".into(), img));
  }

  return Err(Error::NoContent);
}

pub(crate) fn set_clipboard_any(content: &Content) -> Result<()> {
  let clipboard = Clipboard::new()?;
  match content {
    Content::String(s) => {
      return clipboard.set_string(s.as_str());
    }
    Content::Image(_, data) => {
      return clipboard.set_image(data);
    }
    _ => {}
  }
  Err(Error::NoContent)
}
