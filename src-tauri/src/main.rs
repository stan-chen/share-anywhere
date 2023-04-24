#![cfg_attr(
  all(not(debug_assertions), target_os = "windows"),
  windows_subsystem = "windows"
)]

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::Arc;

use clap::{arg, command, Args, Parser};
use log::{error, info};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, CustomMenuItem, Manager, SystemTray, SystemTrayEvent, SystemTrayMenu};
use tauri_plugin_positioner::{Position, WindowExt};

use crate::svc_command::SvcInfo;
use crate::svc_manager::SvcManagerBuilder;
use crate::util::B64Data;
use svc_manager::SvcManager;

mod cert_gen;
mod clip_proxy;
mod result;
mod svc_command;
mod svc_crypto;
mod svc_http;
mod svc_manager;
mod svc_transport;
mod util;

mod log_level_serialize {
  use log::LevelFilter;
  use serde::de::Error;
  use serde::{Deserialize, Deserializer, Serializer};

  pub fn serialize<S>(lvl: &Option<LevelFilter>, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    match lvl {
      None => serializer.serialize_none(),
      Some(l) => serializer.serialize_str(l.as_str()),
    }
  }

  pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<LevelFilter>, D::Error>
  where
    D: Deserializer<'de>,
  {
    let s = Option::<String>::deserialize(deserializer)?;
    return match s {
      Some(ss) => ss
        .parse()
        .map(|item| Some(item))
        .map_err(|e| D::Error::custom(e)),
      None => Ok(None),
    };
  }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct AppTlsOptions {
  /// tls ca file
  #[serde(skip_serializing_if = "Option::<B64Data>::is_none", default)]
  ca: Option<B64Data>,
  /// tls server cert file
  #[serde(skip_serializing_if = "Option::<B64Data>::is_none", default)]
  server_cert: Option<B64Data>,
  /// tls server key file
  #[serde(skip_serializing_if = "Option::<B64Data>::is_none", default)]
  server_key: Option<B64Data>,
  /// tls client cert file
  #[serde(skip_serializing_if = "Option::<B64Data>::is_none", default)]
  client_cert: Option<B64Data>,
  /// tls client key file
  #[serde(skip_serializing_if = "Option::<B64Data>::is_none", default)]
  client_key: Option<B64Data>,
}

impl AppTlsOptions {
  pub fn valid(&self) -> bool {
    return self.ca.is_some()
      && self.client_cert.is_some()
      && self.client_key.is_some()
      && self.server_cert.is_some()
      && self.server_key.is_some();
  }
}

#[derive(Args, Debug, Clone, Serialize, Deserialize, Default)]
#[group(required = false, multiple = false)]
struct AppLogOptions {
  /// tracing log level
  #[arg(long = "log-level")]
  #[serde(
    with = "log_level_serialize",
    default,
    skip_serializing_if = "Option::<log::LevelFilter>::is_none"
  )]
  log_level: Option<log::LevelFilter>,
  /// tracing log file
  #[arg(long = "log-file")]
  #[serde(default, skip_serializing_if = "Option::<PathBuf>::is_none")]
  log_file: Option<PathBuf>,
}

#[derive(Parser, Debug, Clone, Serialize, Deserialize)]
#[command(author, version, about, long_about = None)]
struct AppOptions {
  /// YAML config file path
  #[serde(skip)]
  #[arg(long = "config", short = 'c')]
  config: Option<PathBuf>,
  /// advertisement name
  #[arg(long = "name")]
  #[serde(default = "AppOptions::default_name")]
  name: Option<String>,
  /// multicast address
  #[arg(long = "multicast-addr")]
  #[serde(default = "AppOptions::default_multicast_addr")]
  multicast_address: Option<SocketAddrV4>,
  /// http listen port
  #[arg(long = "http-listen-port")]
  #[serde(default = "AppOptions::default_http_listen_port")]
  http_listen_port: Option<u16>,
  /// multicast binding ip address
  #[arg(long = "interface")]
  #[serde(default = "AppOptions::default_interface")]
  interface: Option<Ipv4Addr>,
  /// broadcaster cipher
  #[arg(skip)]
  #[serde(default, skip_serializing_if = "Option::<String>::is_none")]
  broadcast_cipher: Option<String>,
  /// log options
  #[command(flatten)]
  #[serde(default)]
  log: AppLogOptions,
  /// tls options
  #[arg(skip)]
  #[serde(default)]
  tls: AppTlsOptions,
}

impl Default for AppOptions {
  fn default() -> Self {
    Self {
      config: None,
      name: Self::default_name(),
      multicast_address: Self::default_multicast_addr(),
      http_listen_port: Self::default_http_listen_port(),
      interface: Self::default_interface(),
      broadcast_cipher: None,
      log: Default::default(),
      tls: Default::default(),
    }
  }
}

impl AppOptions {
  pub fn config_filename(tauri_config: tauri::Config) -> PathBuf {
    let default_cfg_file = {
      let cfg_dir =
        tauri::api::path::app_config_dir(&tauri_config).expect("cannot find app config file");
      std::fs::create_dir_all(cfg_dir.as_path()).expect("cannot create dir");
      cfg_dir.join("config.yaml")
    };
    Self::parse()
      .config
      .map(|p| Some(p))
      .unwrap_or(
        std::env::var("SHARE_ANYWHERE_CONFIG")
          .ok()
          .map(|s| s.into()),
      )
      .unwrap_or(default_cfg_file)
  }

  pub fn default_name() -> Option<String> {
    Some(util::hostname())
  }

  pub fn default_multicast_addr() -> Option<SocketAddrV4> {
    Some(SocketAddrV4::new([239, 255, 255, 250].into(), 60000))
  }

  pub fn default_interface() -> Option<Ipv4Addr> {
    Some(Ipv4Addr::UNSPECIFIED)
  }

  pub fn default_http_listen_port() -> Option<u16> {
    Some(60001)
  }
}

impl AppOptions {
  pub fn load_from_config(tauri_config: tauri::Config) -> Self {
    let cfg_file = Self::config_filename(tauri_config);
    println!("loading config file {cfg_file:?}");
    let mut cfg_opts: AppOptions = std::fs::read(cfg_file.clone())
      .map(|data| serde_yaml::from_slice(data.as_slice()).expect("parse config file failed"))
      .unwrap_or(Self::default());
    cfg_opts.update_from(std::env::args().into_iter());
    cfg_opts.config = Some(cfg_file);
    cfg_opts
  }

  pub fn save_to_config(&self) -> Result<(), io::Error> {
    let cfg_file = self.config.clone().ok_or(io::Error::new(
      io::ErrorKind::Other,
      "cannot get config filename",
    ))?;
    info!("save config to {cfg_file:?}");
    let f = std::fs::OpenOptions::new()
      .write(true)
      .truncate(true)
      .create(true)
      .open(cfg_file)?;
    serde_yaml::to_writer(f, self).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
  }

  pub fn new_manager_builder(self) -> SvcManagerBuilder {
    let mut manager_builder = SvcManagerBuilder::new(
      self.name.unwrap_or(util::hostname()),
      self.interface.unwrap(),
      self.multicast_address.unwrap(),
      self.http_listen_port.unwrap(),
    );
    if self.tls.valid() {
      let tls = self.tls.clone();
      manager_builder = manager_builder
        .with_tls_client_config(
          tls.ca.clone().unwrap(),
          tls.client_cert.unwrap(),
          tls.client_key.unwrap(),
        )
        .with_tls_server_config(
          tls.ca.unwrap(),
          tls.server_cert.unwrap(),
          tls.server_key.unwrap(),
        );
    }
    if let Some(cipher) = self.broadcast_cipher {
      manager_builder = manager_builder.with_cipher(cipher);
    }
    manager_builder
  }
}

trait SetupApp {
  fn setup_system_tray_app(self) -> Self;
  fn setup_commands(self) -> Self;
}

impl<R: tauri::Runtime> SetupApp for tauri::Builder<R> {
  fn setup_system_tray_app(self) -> Self {
    let system_tray_menu;
    #[cfg(target_os = "macos")]
    {
      let quit = CustomMenuItem::new("quit".to_string(), "退出").accelerator("Cmd+Q");
      system_tray_menu = SystemTrayMenu::new().add_item(quit);
    }
    #[cfg(target_os = "linux")]
    {
      let open = CustomMenuItem::new("open".to_string(), "打开");
      let quit = CustomMenuItem::new("quit".to_string(), "退出").accelerator("Alt+Q");
      system_tray_menu = SystemTrayMenu::new().add_item(open).add_item(quit);
    }

    let trigger_window_show = |app: &AppHandle<R>| {
      let window = app.get_window("main").unwrap();
      // use TrayCenter as initial window position
      #[cfg(target_os = "macos")]
      let _ = window.move_window(Position::TrayCenter);
      #[cfg(target_os = "linux")]
      let _ = window.move_window(Position::TopRight);
      if window.is_visible().unwrap() {
        window.hide().unwrap();
      } else {
        window.show().unwrap();
        window.set_focus().unwrap();
      }
    };

    self
      .system_tray(SystemTray::new().with_menu(system_tray_menu))
      .on_system_tray_event(move |app, event| {
        tauri_plugin_positioner::on_tray_event(app, &event);
        match event {
          SystemTrayEvent::LeftClick {
            position: _,
            size: _,
            ..
          } => trigger_window_show(app),
          SystemTrayEvent::MenuItemClick { id, .. } => match id.as_str() {
            "quit" => {
              std::process::exit(0);
            }
            "open" => trigger_window_show(app),
            _ => {}
          },
          _ => {}
        }
      })
  }

  fn setup_commands(self) -> Self {
    self.invoke_handler(tauri::generate_handler![
      list_devices_command,
      update_inhibition,
      get_app_config,
      list_network_devices,
      create_selfsigned_chains,
      save_config,
    ])
  }
}

#[tauri::command]
async fn get_app_config(state: tauri::State<'_, Arc<AppOptions>>) -> Result<AppOptions, String> {
  let opts = state.as_ref().clone();
  Ok(opts)
}

#[tauri::command]
async fn list_devices_command(state: tauri::State<'_, SvcManager>) -> Result<Vec<SvcInfo>, String> {
  Ok(state.get_all_devices().await)
}

#[tauri::command]
async fn update_inhibition(
  state: tauri::State<'_, SvcManager>,
  inhibition: bool,
) -> Result<(), String> {
  state.update_inhibition(inhibition);
  Ok(())
}

#[tauri::command]
async fn list_network_devices() -> Result<Vec<util::NetworkDevice>, String> {
  util::NetworkDevice::list().map_err(|e| e.to_string())
}

#[tauri::command]
async fn create_selfsigned_chains() -> Result<AppTlsOptions, String> {
  let chains = cert_gen::generate_cert_chain().map_err(|e| e.to_string())?;
  Ok(AppTlsOptions {
    ca: Some(B64Data(chains.ca_cert_bytes.into())),
    server_cert: Some(B64Data(chains.server_cert_bytes.into())),
    server_key: Some(B64Data(chains.server_key_bytes.into())),
    client_cert: Some(B64Data(chains.client_cert_bytes.into())),
    client_key: Some(B64Data(chains.client_key_bytes.into())),
  })
}

#[tauri::command]
async fn save_config(
  mut options: AppOptions,
  state: tauri::State<'_, Arc<AppOptions>>,
) -> Result<(), String> {
  let orig_options = state.as_ref().clone();
  options.config = orig_options.config;
  options.save_to_config().map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() {
  let tauri_context = tauri::generate_context!();
  let args = AppOptions::load_from_config(tauri_context.config().clone());
  let log_opts = args.log.clone();
  util::config_logger(log_opts.log_level, log_opts.log_file);

  tauri::Builder::default()
    .plugin(tauri_plugin_positioner::init())
    .setup_system_tray_app()
    .setup_commands()
    .manage(Arc::new(args.clone()))
    .on_window_event(|event| match event.event() {
      tauri::WindowEvent::Focused(is_focused) => {
        // detect click outside of the focused window and hide the app
        if !is_focused {
          event.window().hide().unwrap();
        }
      }
      _ => {}
    })
    .setup(move |app| {
      let handle = app.app_handle();
      tauri::async_runtime::spawn(async move {
        let manager = args
          .new_manager_builder()
          .build()
          .await
          .map_err(|e| {
            eprintln!("failed create service manager: {e:?}");
            error!("failed create service manager: {e:?}");
            std::process::exit(1);
          })
          .expect("cannot create service manager");
        manager.spawn();
        handle.manage(manager);
      });
      Ok(())
    })
    .run(tauri_context)
    .expect("error while running tauri application");
}
