use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use log::debug;
use tokio::net::UdpSocket;

use crate::result::{Error, Result};

pub(crate) struct UDPBroadcastV4 {
  sock: UdpSocket,
  multicast_addr: SocketAddrV4,
  multicast_interface: Ipv4Addr,
}

impl UDPBroadcastV4 {
  pub async fn new<A: Into<SocketAddrV4>>(
    multicast_addr: A,
    interface: Option<Ipv4Addr>,
  ) -> Result<Self> {
    let multicast_addr = multicast_addr.into();
    let multicast_ip = multicast_addr.ip().clone();
    let multicast_interface = interface.unwrap_or([0, 0, 0, 0].into());
    debug!(
      "bind udp socket to {}, join multicast of Addr({}), interface({})",
      multicast_addr, multicast_ip, multicast_interface
    );
    let sock = UdpSocket::bind(multicast_addr).await?;
    sock
      .join_multicast_v4(multicast_ip, multicast_interface)
      .map_err(|e| Error::from(e))?;
    Ok(Self {
      sock,
      multicast_addr,
      multicast_interface,
    })
  }

  #[allow(unused)]
  fn local_addr(&self) -> Result<SocketAddr> {
    self.sock.local_addr().map_err(|e| Error::from(e))
  }
}

impl UDPBroadcastV4 {
  #[allow(unused)]
  pub async fn send_packet(&self, data: &[u8]) -> Result<usize> {
    Self::send(
      data,
      self.multicast_addr,
      Some(SocketAddrV4::new(self.multicast_interface, 0)),
    )
    .await
  }

  pub async fn send<T: Into<SocketAddrV4>>(
    data: &[u8],
    remote: T,
    local: Option<T>,
  ) -> Result<usize> {
    let target = remote.into();
    let bind_addr = local
      .map(|item| item.into())
      .unwrap_or(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
    let sock = UdpSocket::bind(bind_addr)
      .await
      .map_err(|e| Error::from(e))?;
    sock.set_multicast_loop_v4(false)?;
    sock.send_to(data, target).await.map_err(|e| Error::from(e))
  }

  pub async fn receive_packet(&self) -> Result<(Vec<u8>, SocketAddr)> {
    let mut buf = [0; 4096];
    let (sz, addr) = self
      .sock
      .recv_from(&mut buf)
      .await
      .map_err(|e| Error::from(e))?;
    Ok((Vec::from(&buf[..sz]), addr))
  }
}

impl Drop for UDPBroadcastV4 {
  fn drop(&mut self) {
    self
      .sock
      .leave_multicast_v4(self.multicast_addr.ip().clone(), self.multicast_interface)
      .unwrap_or(());
  }
}
