use anyhow::Result;
use rustls::pki_types::{CertificateDer, ServerName};
use serde::Serialize;
use std::{
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpStream},
    sync::Arc,
    time::Duration,
};
use x509_parser::prelude::*;

#[derive(Debug, Clone, Serialize)]
pub struct CertificateIssuerInfo {
    organization: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<String>,
}

impl CertificateIssuerInfo {
    pub fn organization(&self) -> &str {
        &self.organization
    }
    pub fn country(&self) -> Option<&str> {
        self.country.as_deref()
    }

    fn parse_country(issuer: &X509Name) -> Option<String> {
        issuer
            .iter_country()
            .filter_map(|v| v.attr_value().as_any_str().ok())
            .collect::<Vec<_>>()
            .pop()
            .map(|s| s.to_string())
    }

    fn parse_organization(issuer: &X509Name) -> Result<String> {
        issuer
            .iter_organization()
            .filter_map(|v| v.attr_value().as_any_str().ok())
            .collect::<Vec<_>>()
            .pop()
            .ok_or_else(|| anyhow::anyhow!("No organization found"))
    }

    fn get_root_cert<'a>(certs: &'a [CertificateDer<'a>]) -> Result<&'a CertificateDer<'a>> {
        certs
            .last()
            .ok_or_else(|| anyhow::anyhow!("No root certificate found"))
    }

    pub fn from_der(certs: &[CertificateDer<'_>]) -> Result<Self> {
        // get the last cert (i.e. The root cert)
        let root_cert = Self::get_root_cert(certs)?;

        match X509Certificate::from_der(root_cert) {
            Ok((_rem, cert_info)) => {
                let issuer = cert_info.issuer();
                let organization = Self::parse_organization(issuer)?;
                let country = Self::parse_country(issuer);
                Ok(CertificateIssuerInfo {
                    organization,
                    country,
                })
            }
            Err(e) => Err(anyhow::anyhow!(
                "Failed to parse the root certificate: {}",
                e
            )),
        }
    }
}

fn generate_request(host: &str) -> Vec<u8> {
    concat!(
        "GET / HTTP/1.1\r\n",
        "Host: {}\r\n",
        "User-Agent: rustls-client\r\n",
        "Connection: close\r\n",
        "Accept: */*\r\n",
        "\r\n"
    )
    .replace("{}", host)
    .as_bytes()
    .to_vec()
}

fn get_socket_addrs(dns_ips: &[IpAddr]) -> SocketAddr {
    for ip in dns_ips {
        if ip.is_ipv4() {
            return SocketAddr::new(*ip, 443);
        }
    }
    // Fallback to the first IP if no IPv4 is found
    SocketAddr::new(dns_ips[0], 443)
}

fn config_tls() -> Arc<rustls::ClientConfig> {
    // let root_store = rustls::RootCertStore {
    //     roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    // };
    let mut root_store = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs") {
        root_store.add(cert).unwrap();
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Arc::new(config)
}

fn get_server_certs<'a, S: Write + Read>(
    stream: &'a mut rustls::Stream<'a, rustls::ClientConnection, S>,
) -> Result<&'a [CertificateDer<'a>]> {
    let certs = stream
        .conn
        .peer_certificates()
        .ok_or_else(|| anyhow::anyhow!("Failed to get peer certificates"))?;
    Ok(certs)
}

pub fn retrive_cert_info(
    domain_name: &str,
    ip: Option<&Vec<IpAddr>>,
) -> Result<CertificateIssuerInfo> {
    let tls_config = config_tls();
    // parse domain name
    let domain = ServerName::try_from(domain_name.to_string())
        .map_err(|e| anyhow::anyhow!("Invalid URL: {}", e))?;

    // setup TLS connection
    let mut conn = rustls::ClientConnection::new(tls_config, domain)
        .map_err(|e| anyhow::anyhow!("Failed to create connection: {}", e))?;

    let sockaddr = get_socket_addrs(
        &ip.ok_or_else(|| anyhow::anyhow!("No IP addresses provided for TLS connection"))?,
    );
    // TCP Connect to the server and perform the handshake
    let mut stream = TcpStream::connect_timeout(&sockaddr, Duration::from_millis(1000))
        .map_err(|e| anyhow::anyhow!("Failed to connect: {}", e))?;
    stream
        .set_read_timeout(Some(Duration::new(30, 0)))
        .map_err(|e| anyhow::anyhow!("Failed to set read timeout on the TCP stream: {}", e))?;
    // Establish TLS session
    let mut tls = rustls::Stream::new(&mut conn, &mut stream);

    // Send Https Get Request
    tls.write_all(generate_request(domain_name).as_slice())
        .map_err(|e| anyhow::anyhow!("Failed to write request: {}", e))?;

    // Get the TLS certificates
    let certs = get_server_certs(&mut tls)?;

    // Extract the root CA from the CA list and collect the organization and country
    CertificateIssuerInfo::from_der(certs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;

    #[test]
    fn test_retrive_cert_info() {
        let domain = "www.google.com";
        let google_ip = IpAddr::V4(Ipv4Addr::new(216, 58, 214, 67));
        let cert_info = retrive_cert_info(domain, Some(&vec![google_ip]));
        assert!(cert_info.is_ok());
        let cert_info = cert_info.unwrap();
        print!("{:?}", cert_info);
        assert_eq!(cert_info.organization(), "GlobalSign nv-sa");
        assert_eq!(cert_info.country(), Some("BE"));
    }

    // #[test]
    // fn test_retrive_cert_info_invalid_domain() {
    //     let domain = "opco.uniformation.fr";
    //     let cert_info = retrive_cert_info(domain);
    //     assert!(cert_info.is_err());
    //     //let cert_info = cert_info.unwrap();
    //     //print!("{:?}", cert_info);
    // }
}
