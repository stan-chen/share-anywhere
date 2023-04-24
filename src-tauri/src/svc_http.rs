use hyper::client::{HttpConnector, ResponseFuture};
use hyper::server::accept::Accept;
use hyper::server::conn::{AddrIncoming, AddrStream};
use hyper::server::Builder;
use hyper::{Request, Server};
use log::trace;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::SystemTime;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::rustls;
use tokio_rustls::rustls::client::{ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::server::AllowAnyAuthenticatedClient;
use tokio_rustls::rustls::{Certificate, ClientConfig, Error, ServerConfig, ServerName};

enum State {
  Handshaking(tokio_rustls::Accept<AddrStream>),
  Streaming(tokio_rustls::server::TlsStream<AddrStream>),
}

// tokio_rustls::server::TlsStream doesn't expose constructor methods,
// so we have to TlsAcceptor::accept and handshake to have access to it
// TlsStream implements AsyncRead/AsyncWrite handshaking tokio_rustls::Accept first
pub struct TlsStream {
  state: State,
}

impl TlsStream {
  fn new(stream: AddrStream, config: Arc<ServerConfig>) -> TlsStream {
    let accept = tokio_rustls::TlsAcceptor::from(config).accept(stream);
    TlsStream {
      state: State::Handshaking(accept),
    }
  }
}

impl AsyncRead for TlsStream {
  fn poll_read(self: Pin<&mut Self>, cx: &mut Context, buf: &mut ReadBuf) -> Poll<io::Result<()>> {
    let pin = self.get_mut();
    match pin.state {
      State::Handshaking(ref mut accept) => match ready!(Pin::new(accept).poll(cx)) {
        Ok(mut stream) => {
          let result = Pin::new(&mut stream).poll_read(cx, buf);
          pin.state = State::Streaming(stream);
          result
        }
        Err(err) => Poll::Ready(Err(err)),
      },
      State::Streaming(ref mut stream) => Pin::new(stream).poll_read(cx, buf),
    }
  }
}

impl AsyncWrite for TlsStream {
  fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
    let pin = self.get_mut();
    match pin.state {
      State::Handshaking(ref mut accept) => match ready!(Pin::new(accept).poll(cx)) {
        Ok(mut stream) => {
          let result = Pin::new(&mut stream).poll_write(cx, buf);
          pin.state = State::Streaming(stream);
          result
        }
        Err(err) => Poll::Ready(Err(err)),
      },
      State::Streaming(ref mut stream) => Pin::new(stream).poll_write(cx, buf),
    }
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    match self.state {
      State::Handshaking(_) => Poll::Ready(Ok(())),
      State::Streaming(ref mut stream) => Pin::new(stream).poll_flush(cx),
    }
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    match self.state {
      State::Handshaking(_) => Poll::Ready(Ok(())),
      State::Streaming(ref mut stream) => Pin::new(stream).poll_shutdown(cx),
    }
  }
}

pub struct TlsAcceptor {
  config: Arc<ServerConfig>,
  incoming: AddrIncoming,
}

impl TlsAcceptor {
  pub fn new(config: Arc<ServerConfig>, incoming: AddrIncoming) -> TlsAcceptor {
    TlsAcceptor { config, incoming }
  }
}

impl Accept for TlsAcceptor {
  type Conn = TlsStream;
  type Error = io::Error;

  fn poll_accept(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
    let pin = self.get_mut();
    match ready!(Pin::new(&mut pin.incoming).poll_accept(cx)) {
      Some(Ok(sock)) => Poll::Ready(Some(Ok(TlsStream::new(sock, pin.config.clone())))),
      Some(Err(e)) => Poll::Ready(Some(Err(e))),
      None => Poll::Ready(None),
    }
  }
}

fn load_certs(cert_bytes: &[u8]) -> Result<Vec<Certificate>, io::Error> {
  let mut reader = io::BufReader::new(cert_bytes);
  // Load and return certificate.
  let certs =
    rustls_pemfile::certs(&mut reader).map_err(|_| error("failed to load certificate".into()))?;
  Ok(certs.into_iter().map(Certificate).collect())
}

fn load_private_key(key_bytes: &[u8]) -> Result<rustls::PrivateKey, io::Error> {
  let mut reader = io::BufReader::new(key_bytes);
  // Load and return a single private key.
  let key_bytes = match rustls_pemfile::read_one(&mut reader)? {
    Some(rustls_pemfile::Item::ECKey(data)) => data,
    Some(rustls_pemfile::Item::PKCS8Key(data)) => data,
    Some(rustls_pemfile::Item::RSAKey(data)) => data,
    _ => {
      return Err(io::Error::new(
        io::ErrorKind::Other,
        format!("key bytes is not a valid key"),
      ));
    }
  };
  Ok(rustls::PrivateKey(key_bytes))
}

fn error(e: String) -> io::Error {
  io::Error::new(io::ErrorKind::Other, e)
}

pub struct SelfCAVerifier {
  roots: Vec<Certificate>,
}

type CertChainAndRoots<'a, 'b> = (
  webpki::EndEntityCert<'a>,
  Vec<&'a [u8]>,
  Vec<webpki::TrustAnchor<'b>>,
);

fn pki_error(error: webpki::Error) -> Error {
  use webpki::Error::*;
  match error {
    BadDer | BadDerTime => Error::InvalidCertificateEncoding,
    InvalidSignatureForPublicKey => Error::InvalidCertificateSignature,
    UnsupportedSignatureAlgorithm | UnsupportedSignatureAlgorithmForPublicKey => {
      Error::InvalidCertificateSignatureType
    }
    e => Error::InvalidCertificateData(format!("invalid peer certificate: {}", e)),
  }
}

fn prepare<'a, 'b>(
  end_entity: &'a Certificate,
  intermediates: &'a [Certificate],
  roots: &'b Vec<Certificate>,
) -> Result<CertChainAndRoots<'a, 'b>, Error> {
  // EE cert must appear first.
  let cert = webpki::EndEntityCert::try_from(end_entity.0.as_ref()).map_err(pki_error)?;

  let intermediates: Vec<&'a [u8]> = intermediates.iter().map(|cert| cert.0.as_ref()).collect();

  let trustroots: Vec<webpki::TrustAnchor> = roots
    .iter()
    .filter_map(|item| webpki::TrustAnchor::try_from_cert_der(item.as_ref()).ok())
    .collect();

  Ok((cert, intermediates, trustroots))
}

static SUPPORTED_SIG_ALGS: &[&webpki::SignatureAlgorithm] = &[
  &webpki::ECDSA_P256_SHA256,
  &webpki::ECDSA_P256_SHA384,
  &webpki::ECDSA_P384_SHA256,
  &webpki::ECDSA_P384_SHA384,
  &webpki::ED25519,
  &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
  &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
  &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
  &webpki::RSA_PKCS1_2048_8192_SHA256,
  &webpki::RSA_PKCS1_2048_8192_SHA384,
  &webpki::RSA_PKCS1_2048_8192_SHA512,
  &webpki::RSA_PKCS1_3072_8192_SHA384,
];

impl ServerCertVerifier for SelfCAVerifier {
  fn verify_server_cert(
    &self,
    end_entity: &Certificate,
    intermediates: &[Certificate],
    _server_name: &ServerName,
    _scts: &mut dyn Iterator<Item = &[u8]>,
    ocsp_response: &[u8],
    now: SystemTime,
  ) -> Result<ServerCertVerified, Error> {
    let (cert, chain, trustroots) = prepare(end_entity, intermediates, &self.roots)?;
    let webpki_now = webpki::Time::try_from(now).map_err(|_| Error::FailedToGetCurrentTime)?;
    cert
      .verify_is_valid_tls_server_cert(
        SUPPORTED_SIG_ALGS,
        &webpki::TlsServerTrustAnchors(&trustroots),
        &chain,
        webpki_now,
      )
      .map_err(pki_error)
      .map(|_| cert)?;

    if !ocsp_response.is_empty() {
      trace!("Unvalidated OCSP response: {:?}", ocsp_response.to_vec());
    }

    Ok(ServerCertVerified::assertion())
  }
}

struct SkipVerifyServerCert {}

impl ServerCertVerifier for SkipVerifyServerCert {
  fn verify_server_cert(
    &self,
    _end_entity: &Certificate,
    _intermediates: &[Certificate],
    _server_name: &ServerName,
    _scts: &mut dyn Iterator<Item = &[u8]>,
    _ocsp_response: &[u8],
    _now: SystemTime,
  ) -> Result<ServerCertVerified, Error> {
    Ok(ServerCertVerified::assertion())
  }
}

pub struct TlsConfigBuilder {
  ca: Vec<u8>,
  cert: Vec<u8>,
  key: Vec<u8>,
}

impl TlsConfigBuilder {
  pub fn new<D: AsRef<[u8]>>(ca: D, cert: D, key: D) -> Self {
    Self {
      ca: ca.as_ref().into(),
      cert: cert.as_ref().into(),
      key: key.as_ref().into(),
    }
  }
}

impl TlsConfigBuilder {
  pub fn build_client(&self) -> Result<ClientConfig, io::Error> {
    // Load root CA
    let ca_certs = load_certs(self.ca.as_slice())?;
    // Load public certificate.
    let certs = load_certs(self.cert.as_slice())?;
    // Load private key.
    let key = load_private_key(self.key.as_slice())?;
    // Do not use client certificate authentication.
    let cfg = ClientConfig::builder()
      .with_safe_defaults()
      .with_custom_certificate_verifier(Arc::new(SelfCAVerifier { roots: ca_certs }))
      .with_single_cert(certs, key)
      .map_err(|e| error(format!("{}", e)))?;
    Ok(cfg)
  }

  pub fn build_server(&self) -> Result<ServerConfig, io::Error> {
    // Load root CA
    let mut ca_store = rustls::RootCertStore::empty();
    let ca_certs = load_certs(self.ca.as_slice())?;
    for x in ca_certs.into_iter() {
      ca_store.add(&x).map_err(|e| error(e.to_string()))?;
    }
    let verifier = AllowAnyAuthenticatedClient::new(ca_store);
    // Load public certificate.
    let certs = load_certs(self.cert.as_slice())?;
    // Load private key.
    let key = load_private_key(self.key.as_slice())?;
    // Do not use client certificate authentication.
    let mut cfg = ServerConfig::builder()
      .with_safe_defaults()
      .with_client_cert_verifier(verifier)
      .with_single_cert(certs, key)
      .map_err(|e| error(format!("{}", e)))?;
    // Configure ALPN to accept HTTP/2, HTTP/1.1, and HTTP/1.0 in that order.
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    Ok(cfg)
  }
}

pub trait HTTPClient<B> {
  fn get(&self, uri: hyper::Uri) -> ResponseFuture;
  fn request(&self, req: Request<B>) -> ResponseFuture;
}

impl<C, B> HTTPClient<B> for hyper::Client<C, B>
where
  C: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
  B: hyper::body::HttpBody + Send + 'static + Default,
  B::Data: Send,
  B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
  fn get(&self, uri: hyper::Uri) -> ResponseFuture {
    hyper::Client::<C, B>::get(self, uri)
  }

  fn request(&self, req: Request<B>) -> ResponseFuture {
    hyper::Client::<C, B>::request(self, req)
  }
}

pub fn create_http_client(
  tls_opts: Option<ClientConfig>,
) -> Box<dyn HTTPClient<hyper::Body> + Sync + Send + 'static> {
  match tls_opts {
    None => {
      Box::new(hyper::Client::builder().build::<HttpConnector, hyper::Body>(HttpConnector::new()))
    }
    Some(tls_cfg) => {
      let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_cfg)
        .https_only()
        .enable_http1()
        .enable_http2()
        .build();
      Box::new(
        hyper::Client::builder()
          .build::<hyper_rustls::HttpsConnector<HttpConnector>, hyper::Body>(connector),
      )
    }
  }
}

pub fn create_https_server_builder(
  addr: &SocketAddr,
  tls_cfg: ServerConfig,
) -> hyper::Result<Builder<TlsAcceptor>> {
  let incoming = AddrIncoming::bind(&addr)?;
  // Build TLS configuration.
  // Create a TCP listener via tokio.
  Ok(Server::builder(TlsAcceptor::new(
    Arc::new(tls_cfg),
    incoming,
  )))
}

pub fn create_http_server_builder(addr: &SocketAddr) -> hyper::Result<Builder<AddrIncoming>> {
  let incoming = AddrIncoming::bind(&addr)?;
  Ok(Server::builder(incoming))
}

#[derive(Clone, Debug)]
pub struct Uri {
  scheme: hyper::http::uri::Scheme,
  authority: hyper::http::uri::Authority,
  path_and_query: hyper::http::uri::PathAndQuery,
}

impl Default for Uri {
  fn default() -> Self {
    let parts = hyper::Uri::default().into_parts();
    Self {
      scheme: parts.scheme.unwrap(),
      authority: parts.authority.unwrap(),
      path_and_query: parts.path_and_query.unwrap(),
    }
  }
}

impl From<hyper::Uri> for Uri {
  fn from(u: hyper::Uri) -> Self {
    Self {
      scheme: u.scheme().unwrap().clone(),
      authority: u.authority().unwrap().clone(),
      path_and_query: u.path_and_query().unwrap().clone(),
    }
  }
}

impl std::str::FromStr for Uri {
  type Err = hyper::http::uri::InvalidUri;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    let parts = hyper::Uri::from_str(s)?.into_parts();
    Ok(Self {
      scheme: parts.scheme.unwrap(),
      authority: parts.authority.unwrap(),
      path_and_query: parts.path_and_query.unwrap(),
    })
  }
}

impl Into<hyper::Uri> for Uri {
  fn into(self) -> hyper::Uri {
    hyper::Uri::builder()
      .scheme(self.scheme.clone())
      .authority(self.authority.clone())
      .path_and_query(self.path_and_query.clone())
      .build()
      .unwrap()
  }
}

impl Uri {
  #[allow(unused)]
  pub fn with_scheme<T>(&self, scheme: T) -> Result<Self, hyper::http::Error>
  where
    hyper::http::uri::Scheme: TryFrom<T>,
    <hyper::http::uri::Scheme as TryFrom<T>>::Error: Into<hyper::http::Error>,
  {
    let sch = scheme
      .try_into()
      .map_err(Into::<hyper::http::Error>::into)?;
    Ok(Self {
      scheme: sch,
      authority: self.authority.clone(),
      path_and_query: self.path_and_query.clone(),
    })
  }

  #[allow(unused)]
  pub fn with_port(&self, port: u16) -> Result<Self, hyper::http::Error> {
    let self_authority = self.authority.clone();
    let authority = format!("{}:{}", self_authority.host(), port).parse()?;
    Ok(Self {
      scheme: self.scheme.clone(),
      authority,
      path_and_query: self.path_and_query.clone(),
    })
  }

  pub fn with_host<S: AsRef<str>>(&self, host: S) -> Result<Self, hyper::http::Error> {
    let port = self.authority.clone().port_u16().unwrap_or(80);
    let authority = format!("{}:{}", host.as_ref(), port).parse()?;
    Ok(Self {
      scheme: self.scheme.clone(),
      authority,
      path_and_query: self.path_and_query.clone(),
    })
  }

  #[allow(unused)]
  pub fn with_authority<T>(&self, authority: T) -> Result<Self, hyper::http::Error>
  where
    hyper::http::uri::Authority: TryFrom<T>,
    <hyper::http::uri::Authority as TryFrom<T>>::Error: Into<hyper::http::Error>,
  {
    let authority = authority
      .try_into()
      .map_err(Into::<hyper::http::Error>::into)?;
    Ok(Self {
      scheme: self.scheme.clone(),
      authority,
      path_and_query: self.path_and_query.clone(),
    })
  }

  #[allow(unused)]
  pub fn with_path_and_query<T>(&self, p_and_q: T) -> Result<Self, hyper::http::Error>
  where
    hyper::http::uri::PathAndQuery: TryFrom<T>,
    <hyper::http::uri::PathAndQuery as TryFrom<T>>::Error: Into<hyper::http::Error>,
  {
    let path_and_query = p_and_q
      .try_into()
      .map_err(Into::<hyper::http::Error>::into)?;
    Ok(Self {
      scheme: self.scheme.clone(),
      authority: self.authority.clone(),
      path_and_query,
    })
  }
}

impl Serialize for Uri {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    let u: hyper::Uri = self.clone().into();
    serializer.serialize_str(u.to_string().as_str())
  }
}

impl<'de> Deserialize<'de> for Uri {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    String::deserialize(deserializer)?
      .parse()
      .map_err(|e: hyper::http::uri::InvalidUri| serde::de::Error::custom(e.to_string()))
      .map(|item: hyper::Uri| item.into())
  }
}

#[cfg(test)]
mod tests {
  use crate::svc_http::create_http_client;
  use hyper::Body;
  use tauri::http::Uri;

  #[tokio::test]
  async fn test_client_get() {
    let c = create_http_client(None);
    let response = c
      .get("http://www.baidu.com/".parse().unwrap())
      .await
      .unwrap();
    println!("response: {response:?}");
  }
  #[tokio::test]
  async fn test_client_request() {
    let c = create_http_client(None);
    let request = hyper::Request::builder()
      .method("GET")
      .uri(Uri::from_static("http://www.baidu.com/"))
      .body(Body::empty())
      .unwrap();
    let response = c.request(request).await.unwrap();
    println!("response: {response:?}");
  }
}
