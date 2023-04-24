use std::io;
use std::path::PathBuf;
use std::process::Command;

fn error(s: String) -> io::Error {
  io::Error::new(io::ErrorKind::Other, s)
}

fn generate_cert(
  ca_path: PathBuf,
  ca_key_path: PathBuf,
  cert_path: PathBuf,
  key_path: PathBuf,
  csr_conf_path: PathBuf,
  ext_conf_path: PathBuf,
) -> Result<(), io::Error> {
  let (ca_path, ca_key_path, cert_path, key_path, csr_conf_path, ext_conf_path) = (
    ca_path.to_str().ok_or(error("ca path invalid".into()))?,
    ca_key_path
      .to_str()
      .ok_or(error("ca key path invalid".into()))?,
    cert_path
      .to_str()
      .ok_or(error("cert path invalid".into()))?,
    key_path.to_str().ok_or(error("key path invalid".into()))?,
    csr_conf_path
      .to_str()
      .ok_or(error("conf path invalid".into()))?,
    ext_conf_path
      .to_str()
      .ok_or(error("conf path invalid".into()))?,
  );
  let csr_path = String::from(cert_path) + ".csr";
  // generate csr
  let r = Command::new("openssl")
    .args([
      "req",
      "-new",
      "-nodes",
      "-newkey",
      "ec",
      "-pkeyopt",
      "ec_paramgen_curve:P-256",
      "-keyout",
      key_path,
      "-out",
      csr_path.as_str(),
      "-config",
      csr_conf_path,
    ])
    .output()
    .map_err(|e| error(e.to_string()))?;

  if !r.status.success() {
    return Err(error(format!(
      "generate cert failed: {}",
      String::from_utf8(r.stderr).unwrap_or("".into())
    )));
  }
  // openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 3650 -sha256 -extfile cert.conf

  let r = Command::new("openssl")
    .args([
      "x509",
      "-req",
      "-in",
      csr_path.as_str(),
      "-CA",
      ca_path,
      "-CAkey",
      ca_key_path,
      "-CAcreateserial",
      "-out",
      cert_path,
      "-days",
      "3650",
      "-sha256",
      "-extfile",
      ext_conf_path,
    ])
    .output()
    .map_err(|e| error(e.to_string()))?;

  if !r.status.success() {
    return Err(error(format!(
      "generate cert failed: {}",
      String::from_utf8(r.stderr).unwrap_or("".into())
    )));
  }
  Ok(())
}

fn generate_cert_chain_in_place(tmp_dir: PathBuf) -> Result<CertChains, io::Error> {
  let ca_path = tmp_dir.join("ca.crt");
  let ca_key_path = tmp_dir.join("ca.key");
  // generate ca
  let r = Command::new("openssl")
    .args([
      "req",
      "-x509",
      "-sha256",
      "-days",
      "3650",
      "-nodes",
      "-newkey",
      "ec",
      "-pkeyopt",
      "ec_paramgen_curve:P-256",
      "-subj",
      "/CN=ShareAnywhereCA/C=CN/ST=SC/O=Share Anywhere/OU=Share Anywhere",
      "-out",
      ca_path.to_str().ok_or(error("path is not valid".into()))?,
      "-keyout",
      ca_key_path
        .to_str()
        .ok_or(error("path is not valid".into()))?,
    ])
    .output()?;
  if !r.status.success() {
    return Err(error(format!(
      "generate ca failed: {}",
      String::from_utf8(r.stderr).unwrap_or("".into())
    )));
  }
  // generate server.crt
  let server_cert_path = tmp_dir.join("server.crt");
  let server_key_path = tmp_dir.join("server.key");
  let client_cert_path = tmp_dir.join("client.crt");
  let client_key_path = tmp_dir.join("client.key");
  let csr_conf_path = tmp_dir.join("csr.conf");
  let ext_conf_path = tmp_dir.join("cert.conf");

  std::fs::write(csr_conf_path.clone(), include_bytes!("csr.conf"))?;
  std::fs::write(ext_conf_path.clone(), include_bytes!("cert.conf"))?;
  generate_cert(
    ca_path.clone(),
    ca_key_path.clone(),
    server_cert_path.clone(),
    server_key_path.clone(),
    csr_conf_path.clone(),
    ext_conf_path.clone(),
  )?;
  generate_cert(
    ca_path.clone(),
    ca_key_path.clone(),
    client_cert_path.clone(),
    client_key_path.clone(),
    csr_conf_path.clone(),
    ext_conf_path.clone(),
  )?;
  Ok(CertChains {
    ca_cert_bytes: std::fs::read(ca_path)?,
    ca_key_bytes: std::fs::read(ca_key_path)?,
    server_cert_bytes: std::fs::read(server_cert_path)?,
    server_key_bytes: std::fs::read(server_key_path)?,
    client_cert_bytes: std::fs::read(client_cert_path)?,
    client_key_bytes: std::fs::read(client_key_path)?,
  })
}

pub struct CertChains {
  pub ca_cert_bytes: Vec<u8>,
  pub ca_key_bytes: Vec<u8>,
  pub server_cert_bytes: Vec<u8>,
  pub server_key_bytes: Vec<u8>,
  pub client_cert_bytes: Vec<u8>,
  pub client_key_bytes: Vec<u8>,
}

pub fn generate_cert_chain() -> Result<CertChains, io::Error> {
  // mkdir tmpdir
  let tmp_dir = std::env::temp_dir().join(format!(
    "share-anywhere-tls-{}",
    std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap()
      .as_secs()
  ));
  std::fs::create_dir_all(tmp_dir.clone())?;

  return match generate_cert_chain_in_place(tmp_dir.clone()) {
    Ok(chains) => {
      std::fs::remove_dir_all(tmp_dir).unwrap_or(());
      Ok(chains)
    }
    Err(e) => {
      std::fs::remove_dir_all(tmp_dir).unwrap_or(());
      Err(e)
    }
  };
}

#[cfg(test)]
mod tests {
  use crate::cert_gen::generate_cert_chain;

  #[test]
  fn test_generate_cert() {
    generate_cert_chain().expect("generate failed");
  }
}
