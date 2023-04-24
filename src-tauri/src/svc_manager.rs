use std::collections::HashMap;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper::server::conn::AddrStream;
use hyper::service::make_service_fn;
use hyper::{Body, Request, Response};
use log::{debug, error, info};
use tokio::sync::{Mutex, RwLock};
use tokio_rustls::rustls::{ClientConfig, ServerConfig};

use crate::result::{Error, Result};
use crate::svc_command::{ClipPayload, Command, Payload, SvcInfo};
use crate::svc_crypto::AesGcmOpts;
use crate::svc_http::{
  create_http_client, create_http_server_builder, create_https_server_builder, HTTPClient,
  TlsConfigBuilder,
};
use crate::{clip_proxy, svc_http, svc_transport};

#[derive(Clone)]
pub struct SvcManagerBuilder {
  name: String,
  interface: Ipv4Addr,
  multicast_addr: SocketAddrV4,
  http_listen_port: u16,
  cipher: Option<String>,
  tls_client_config: Option<ClientConfig>,
  tls_server_config: Option<ServerConfig>,
}

impl SvcManagerBuilder {
  pub fn new(
    name: String,
    interface: Ipv4Addr,
    multicast_addr: SocketAddrV4,
    http_listen_port: u16,
  ) -> Self {
    Self {
      name,
      interface,
      multicast_addr,
      http_listen_port,
      cipher: None,
      tls_server_config: None,
      tls_client_config: None,
    }
  }

  pub fn with_tls_client_config<D: AsRef<[u8]>>(mut self, ca: D, cert: D, key: D) -> Self {
    self.tls_client_config = Some(
      TlsConfigBuilder::new(ca, cert, key)
        .build_client()
        .expect("cannot build tls client config"),
    );
    self
  }

  pub fn with_tls_server_config<D: AsRef<[u8]>>(mut self, ca: D, cert: D, key: D) -> Self {
    self.tls_server_config = Some(
      TlsConfigBuilder::new(ca, cert, key)
        .build_server()
        .expect("cannot build tls client config"),
    );
    self
  }

  pub fn with_cipher(mut self, cipher: String) -> Self {
    self.cipher = Some(cipher);
    self
  }

  pub async fn build(self) -> Result<SvcManager> {
    return match SvcManager::new(
      self.name,
      self.interface,
      self.multicast_addr,
      self.http_listen_port,
      self.tls_client_config,
      self.tls_server_config,
    )
    .await
    {
      Ok(manager) => {
        if let Some(cipher) = self.cipher {
          manager.update_cipher(cipher).await?;
        }
        Ok(manager)
      }
      Err(e) => Err(e),
    };
  }
}

#[derive(Clone)]
#[allow(unused)]
pub struct SvcManager {
  /// self name default hostname
  name: String,
  /// udp multi cast broadcaster
  broadcaster: Arc<svc_transport::UDPBroadcastV4>,
  /// crypt AES-GCM-256
  cryptos: Arc<RwLock<Option<AesGcmOpts>>>,
  /// self api endpoint
  endpoint: SocketAddrV4,
  /// networking all machines
  machines: Arc<Mutex<HashMap<std::net::IpAddr, SvcInfo>>>,
  /// my applied clipboard
  current_clip_content: Arc<Mutex<ClipPayload>>,
  /// api client
  http_client: Arc<Box<dyn HTTPClient<hyper::Body> + Sync + Send + 'static>>,
  /// tls server config
  tls_server_config: Arc<Option<ServerConfig>>,
  /// inhibition all auto copy
  inhibition: Arc<AtomicBool>,
}

impl SvcManager {
  async fn new(
    name: String,
    interface: Ipv4Addr,
    multicast_addr: SocketAddrV4,
    http_listen_port: u16,
    tls_client_config: Option<ClientConfig>,
    tls_server_config: Option<ServerConfig>,
  ) -> Result<Self> {
    let http_addr = SocketAddrV4::new(interface, http_listen_port);
    let broadcaster = svc_transport::UDPBroadcastV4::new(multicast_addr, Some(interface)).await?;
    let http_client = create_http_client(tls_client_config);
    Ok(Self {
      name,
      broadcaster: Arc::new(broadcaster),
      cryptos: Default::default(),
      endpoint: http_addr,
      machines: Default::default(),
      current_clip_content: Default::default(),
      http_client: Arc::new(http_client),
      tls_server_config: Arc::new(tls_server_config),
      inhibition: Arc::new(Default::default()),
    })
  }
}

impl SvcManager {
  async fn get_clipboard(&self) -> Result<clipboard::Content> {
    clip_proxy::get_clipboard()
  }

  async fn set_clipboard(&self, content: clipboard::Content) -> Result<()> {
    info!("set clipboard data by hash: {:?}", content.md5_sum());
    clip_proxy::set_clipboard(content).await
  }

  pub async fn update_cipher(&self, key: String) -> Result<()> {
    info!("update broadcaster AES cipher, packet will crypt by AES-GCM-256");
    let opts = AesGcmOpts::new(key.as_bytes())?;
    let mut guard = self.cryptos.write().await;
    *guard = Some(opts);
    Ok(())
  }

  pub fn is_inhibition(&self) -> bool {
    self.inhibition.load(std::sync::atomic::Ordering::SeqCst)
  }

  pub fn update_inhibition(&self, t: bool) {
    self
      .inhibition
      .store(t, std::sync::atomic::Ordering::SeqCst)
  }

  async fn receive_packet(&self) -> Result<(Vec<u8>, SocketAddr)> {
    let (data, addr) = self.broadcaster.receive_packet().await?;
    let dec_data = match self.cryptos.read().await.as_ref() {
      Some(opts) => opts.decrypt(data.as_slice())?,
      None => data,
    };
    Ok((dec_data, addr))
  }

  async fn send_packet(&self, input: &[u8]) -> Result<usize> {
    return match self.cryptos.read().await.as_ref() {
      Some(opts) => {
        self
          .broadcaster
          .send_packet(opts.encrypt(input).as_slice())
          .await
      }
      None => self.broadcaster.send_packet(input).await,
    };
  }

  async fn get_from_machine(
    &self,
    addr: std::net::IpAddr,
    uri_path: String,
  ) -> Result<Response<Body>> {
    let c = self.http_client.clone();
    if let Some(m) = self.machines.lock().await.get(&addr) {
      if let Ok(uri) = m.endpoint.with_path_and_query(uri_path) {
        return c.get(uri.into()).await.map_err(|e| Error::from(e));
      }
    }
    Err(format!("cannot get response from {}", addr).into())
  }

  async fn receive_commands(&self, cmds: &Vec<Command>, from_addr: SocketAddr) {
    if self.is_inhibition() {
      return;
    }
    let mut current_clip = self.current_clip_content.lock().await;
    for cmd in cmds.into_iter() {
      match &cmd.payload {
        Payload::Info(info) => {
          let mut store = info.clone();
          if let Ok(new_uri) = store.endpoint.with_host(from_addr.clone().ip().to_string()) {
            store.endpoint = new_uri;
          }
          store.ip_addr = Some(from_addr.ip());
          store.latest_timestamp = Some(chrono::Local::now());
          let key = from_addr.ip().clone();
          let mut guard = self.machines.lock().await;
          if let None = guard.insert(key.clone(), store) {
            info!("update server info {} successful", key);
          }
        }
        Payload::Clipboard(clip_info) => {
          if current_clip.timestamp_nano < clip_info.timestamp_nano {
            debug!("updating networking clipboard content for: {clip_info:?}");
            match self
              .get_from_machine(from_addr.ip().clone(), "/clipboard".into())
              .await
            {
              Ok(mut response) => {
                if !response.status().is_success() {
                  error!(
                    "get clipboard from remote failed with status: {}",
                    response.status()
                  );
                  continue;
                }
                match hyper::body::to_bytes(response.body_mut()).await {
                  Ok(data) => match serde_json::from_slice::<clipboard::Content>(data.as_ref()) {
                    Ok(clip_data) => match clip_data {
                      clipboard::Content::String(_) | clipboard::Content::Image(_, _) => {
                        if let Err(e) = self.set_clipboard(clip_data.clone()).await {
                          error!("failed set clipboard content: {e:?}");
                        } else {
                          let mut new_content = clip_info.clone();
                          new_content.hash = clip_data.md5_sum();
                          new_content.content = Some(clip_data);
                          (*current_clip) = new_content;
                        }
                      }
                      clipboard::Content::Files(_) => {
                        // ignore Files content
                        //debug!("ignore Content::Files update");
                      }
                    },
                    Err(e) => error!("failed to parse json str: {e:?}"),
                  },
                  _ => {}
                }
              }
              Err(e) => error!(
                "cannot get clipboard data from remote: {}, {e:?}",
                cmd.name.clone()
              ),
            }
          }
        }
        _ => {}
      }
    }
  }

  pub async fn scan_loop(&self) -> Result<()> {
    loop {
      match self.receive_packet().await {
        Ok((data, from_addr)) => match serde_json::from_slice::<Vec<Command>>(data.as_slice()) {
          Ok(cmds) => {
            self.receive_commands(&cmds, from_addr).await;
          }
          _ => {}
        },
        Err(err) => {
          error!("receive broadcaster packet failed: {err:?}");
        }
      }
    }
  }

  fn collect_self_info(&self) -> SvcInfo {
    let h = hostname::get()
      .unwrap_or_default()
      .into_string()
      .unwrap_or("".into());
    let self_ep = format!(
      "{}://{}/",
      if self.tls_server_config.is_none() {
        "http"
      } else {
        "https"
      },
      self.endpoint.to_string()
    )
    .parse()
    .unwrap();

    SvcInfo {
      name: self.name.clone(),
      ip_addr: None,
      latest_timestamp: Default::default(),
      hostname: h,
      endpoint: self_ep,
    }
  }

  async fn update_self_clipboard(&mut self) -> Result<Command> {
    let mut guard = self.current_clip_content.lock().await;
    let payload = match self.get_clipboard().await {
      Ok(c) => ClipPayload::from(c),
      Err(e) => {
        guard.timestamp_nano = 0;
        return Err(e);
      }
    };
    if guard.hash != payload.hash {
      debug!(
        "update self clipboard because mem({}) and clip({})",
        guard.hash, payload.hash
      );
      (*guard) = payload;
    }
    return Ok(Command::new(
      self.name.clone(),
      None,
      None,
      Some(Payload::Clipboard(guard.clone())),
    ));
  }

  pub async fn advertise_loop(&mut self, interval: std::time::Duration) -> Result<()> {
    loop {
      let mut advertises = vec![Command::new(
        self.name.clone(),
        None,
        None,
        Some(Payload::Info(self.collect_self_info())),
      )];
      if !self.is_inhibition() {
        match self.update_self_clipboard().await {
          Ok(cmd) => advertises.push(cmd),
          Err(e) => error!("failed update self clipboard: {e:?}"),
        }
      }
      if let Ok(data) = serde_json::to_string(&advertises) {
        self.send_packet(data.as_bytes()).await.unwrap_or(0);
      }

      tokio::time::sleep(interval).await;
    }
  }

  pub async fn start_http_server(&self) -> Result<()> {
    let bind_addr = SocketAddr::V4(self.endpoint.clone());
    info!(
      "start http api at endpoint: {}://{}",
      {
        if self.tls_server_config.is_none() {
          "http"
        } else {
          "https"
        }
      },
      bind_addr
    );
    // And a MakeService to handle each connection...
    let make_https_svc = make_service_fn(move |_: &svc_http::TlsStream| {
      let m = self.clone();
      async move { Ok::<_, hyper::Error>(m) }
    });

    let make_http_svc = make_service_fn(move |_: &AddrStream| {
      let m = self.clone();
      async move { Ok::<_, hyper::Error>(m) }
    });

    match self.tls_server_config.as_ref().clone() {
      None => create_http_server_builder(&bind_addr)
        .map_err(|e| Error::from(e.to_string()))?
        .serve(make_http_svc)
        .await
        .map_err(|e| Error::from(e)),
      Some(tls_cfg) => create_https_server_builder(&bind_addr, tls_cfg)
        .map_err(|e| Error::from(e.to_string()))?
        .serve(make_https_svc)
        .await
        .map_err(|e| Error::from(e)),
    }
  }

  pub async fn get_all_devices(&self) -> Vec<SvcInfo> {
    self
      .machines
      .lock()
      .await
      .clone()
      .into_values()
      .map(|item| item)
      .collect()
  }

  pub fn spawn(&self) {
    let manager_for_scan = self.clone();
    tokio::spawn(async move { manager_for_scan.scan_loop().await.unwrap() });
    let manager_for_api = self.clone();
    tokio::spawn(async move { manager_for_api.start_http_server().await.unwrap() });
    let mut manager_for_advertise = self.clone();
    tokio::spawn(async move {
      manager_for_advertise
        .advertise_loop(std::time::Duration::new(3, 0))
        .await
        .unwrap()
    });
  }
}

impl SvcManager {
  async fn serve_clipboard_data(&mut self) -> Result<Response<Body>> {
    if let Some(clip_cmd) = self.current_clip_content.lock().await.content.clone() {
      if let Ok(data) = serde_json::to_vec(&clip_cmd) {
        return Response::builder()
          .status(200)
          .body(data.into())
          .map_err(|e| e.to_string().into());
      }
    }
    Response::builder()
      .status(500)
      .body("internal server error".into())
      .map_err(|e| e.to_string().into())
  }
}

impl hyper::service::Service<Request<Body>> for SvcManager {
  type Response = Response<Body>;
  type Error = Error;
  type Future = Pin<Box<dyn Future<Output = Result<Self::Response>> + Send>>;

  fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<()>> {
    Poll::Ready(Ok(()))
  }

  fn call(&mut self, req: Request<Body>) -> Self::Future {
    let uri_path = req.uri().path();
    return match uri_path {
      "/clipboard" => {
        let mut manager = self.clone();
        Box::pin(async move { manager.serve_clipboard_data().await })
      }
      _ => Box::pin(async {
        Response::builder()
          .status(404)
          .body(Body::from("not found"))
          .map_err(|e| e.to_string().into())
      }),
    };
  }
}
