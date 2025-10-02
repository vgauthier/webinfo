use super::{asn, asn::Asn, dns, tls};
use anyhow::Result;
use hickory_resolver::{Resolver, name_server::ConnectionProvider};
use ip2asn::IpAsnMap;
use publicsuffix2::{List, MatchOpts, TypeFilter};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, sync::Arc};
use tracing::{Level, event};
use url::Url;

#[derive(Deserialize, Serialize, Debug, Clone)]
#[allow(dead_code)]
pub struct OriginRecord {
    pub origin: String,
    pub popularity: u32,
    pub date: String,
    pub country: String,
}

#[derive(Serialize, Debug, Default)]
pub struct IpInfoRecord {
    pub hostname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cname: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ns: Option<dns::NameServer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<Vec<IpAddr>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<Vec<Asn>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<tls::CertificateIssuerInfo>,
}

#[derive(Serialize, Debug)]
pub struct IpInfo {
    pub origin: OriginRecord,
    pub records: IpInfoRecord,
}

// Implement a method to create IpInfo from OriginRecord
impl IpInfo {
    pub async fn from_record<T: ConnectionProvider>(
        target: OriginRecord,
        resolver: Resolver<T>,
        ip2asn_map: Arc<IpAsnMap>,
    ) -> Result<IpInfo> {
        // Parse Hostname
        let hostname = extract_hostname(&target.origin)
            .map_err(|_| anyhow::anyhow!("Invalid hostname: {}", target.origin))?;
        // extract TLD
        let domain = extract_domain(&hostname);
        if domain.is_none() {
            return Err(anyhow::anyhow!(
                "Could not extract domain from hostname: {}",
                hostname
            ));
        }
        // Perform DNS lookups with timeouts
        let ip = dns::query_ipv4_ipv6(&hostname, &resolver);
        // CNAME lookup with timeout
        let cname = dns::query_cname(&hostname, &resolver);
        let (ip, cname) = tokio::join!(ip, cname);
        // NS lookup with timeout if domain is available
        let ns = match &domain {
            Some(domain) => dns::query_ns(domain, &resolver, &ip2asn_map).await,
            None => None,
        };

        // ASN lookup
        let asn = if let Some(ips) = &ip {
            asn::lookup_ip(ips, &ip2asn_map)
        } else {
            None
        };

        // Retrieve TLS certificate info if the URL scheme is HTTPS
        let tls = if target.origin.contains("https://") {
            match tls::retrive_cert_info(&hostname, ip.as_ref()) {
                Ok(tls_info) => Some(tls_info),
                Err(e) => {
                    event!(
                        Level::ERROR,
                        "Failed to retrieve TLS info for {}: {}",
                        hostname,
                        e
                    );
                    None
                }
            }
        } else {
            event!(
                Level::INFO,
                "Skipping TLS retrieval for non-HTTPS URL: {}",
                target.origin
            );
            None
        };
        Ok(IpInfo {
            origin: target.clone(),
            records: IpInfoRecord {
                hostname,
                domain,
                cname,
                ns,
                ip,
                asn,
                tls, //tls
            },
        })
    }
}

fn extract_hostname(url: &str) -> Result<String> {
    let match_opt = MatchOpts {
        strict: true,
        ..Default::default()
    };
    let list = List::default();
    let tld = list.tld(url, match_opt);
    if tld.is_none() {
        return Err(anyhow::anyhow!("Invalid TLD in URL: {}", url));
    }
    let parsed_url = Url::parse(url).ok();
    match parsed_url {
        Some(parsed_url) => Ok(parsed_url.host_str().unwrap_or("").to_string()),
        None => Err(anyhow::anyhow!("Failed to parse URL: {}", url)),
    }
}

fn extract_domain(hostname: &str) -> Option<String> {
    // You can filter to only use ICANN section rules.
    let opts_icann_only = MatchOpts {
        types: TypeFilter::Icann,
        ..Default::default()
    };
    let list = List::default();
    let parts = list.split(hostname, opts_icann_only);
    if let Some(parts) = parts {
        match parts.sll.as_deref() {
            None => {
                eprintln!(
                    "Warning: Could not parse domain from hostname: {}",
                    hostname
                );
                None
            }
            Some(_) => parts.sld.as_deref().map(|s| s.to_string()),
        }
    } else {
        eprintln!(
            "Warning: Could not parse domain from hostname: {}",
            hostname
        );
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::open_asn_db;

    #[test]
    fn test_extract_hostname() {
        let url = "https://www.example.com";
        let hostname = extract_hostname(url);
        assert!(hostname.is_ok());
        assert_eq!(hostname.unwrap(), "www.example.com".to_string());
    }

    #[test]
    fn test_extract_hostname_invalid() {
        let url = "https://www.example.toto";
        let hostname = extract_hostname(url);
        assert!(hostname.is_err());
    }

    #[test]
    fn test_extract_domain() {
        let url = "www.example.co.uk";
        let domain = extract_domain(url);
        assert_eq!(domain, Some("example.co.uk".to_string()));

        let url = "carrd.co";
        let domain = extract_domain(url);
        assert_eq!(domain, Some("carrd.co".to_string()));

        let url = "phpmyadmin.hosting.ovh.net";
        let domain = extract_domain(url);
        assert_eq!(domain, Some("ovh.net".to_string()));

        let url = "s3.amazonaws.com";
        let domain = extract_domain(url);
        assert_eq!(domain, Some("amazonaws.com".to_string()));

        let url = "senpai-stream.cam";
        let domain = extract_domain(url);
        assert_eq!(domain, Some("senpai-stream.cam".to_string()));
    }

    #[test]
    fn test_extract_domain_invalid() {
        let url = "invalid_domain";
        let domain = extract_domain(url);
        assert!(domain.is_none());

        let url = "https://www.example.toto";
        let domain = extract_domain(url);
        assert!(domain.is_none());
    }

    #[tokio::test]
    async fn test_from_record() {
        let origin = OriginRecord {
            origin: "https://www.example.com".to_string(),
            popularity: 100,
            date: "2023-10-01".to_string(),
            country: "US".to_string(),
        };
        // Use the host OS'es `/etc/resolv.conf`
        let resolver = Resolver::builder_tokio().unwrap().build();
        let ip2asn_map = open_asn_db().await.unwrap();
        let ip2asn_map = Arc::new(ip2asn_map);
        let ip_info = IpInfo::from_record(origin, resolver, ip2asn_map.clone()).await;
        assert!(ip_info.is_ok());
        let ip_info = ip_info.unwrap();
        assert_eq!(ip_info.records.hostname, "www.example.com");
        assert_eq!(ip_info.records.domain, "example.com".to_string().into());
    }

    #[tokio::test]
    async fn test_from_record_with_bad_hostname() {
        let origin = OriginRecord {
            origin: "https://www.example.toto".to_string(),
            popularity: 100,
            date: "2023-10-01".to_string(),
            country: "US".to_string(),
        };
        // Use the host OS'es `/etc/resolv.conf`
        let resolver = Resolver::builder_tokio().unwrap().build();
        let ip2asn_map = open_asn_db().await.unwrap();
        let ip2asn_map = Arc::new(ip2asn_map);
        let ip_info = IpInfo::from_record(origin, resolver, ip2asn_map.clone()).await;
        assert!(ip_info.is_err());
    }

    // #[tokio::test]
    // async fn test_from_record_error() {
    //     let origin = OriginRecord {
    //         origin: "https://opco.uniformation.fr".to_string(),
    //         popularity: 100,
    //         date: "2023-10-01".to_string(),
    //         country: "US".to_string(),
    //     };
    //     // Use the host OS'es `/etc/resolv.conf`
    //     let resolver = Resolver::builder_tokio().unwrap().build();
    //     let ip2asn_map = open_asn_db().await.unwrap();
    //     let ip2asn_map = Arc::new(ip2asn_map);
    //     let ip_info = IpInfo::from_record(origin, resolver, ip2asn_map.clone()).await;
    //     assert!(ip_info.is_ok());
    //     let ip_info = ip_info.unwrap();
    //     assert_eq!(ip_info.records.hostname, "opco.uniformation.fr");
    //     assert_eq!(ip_info.records.domain, "uniformation.fr".to_string().into());
    // }
}
