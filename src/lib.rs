mod asn;

pub mod dns;
pub mod model;
pub mod tls;
pub mod utils;

use anyhow::Result;
use hickory_resolver::{Resolver, name_server::ConnectionProvider};
use ip2asn::IpAsnMap;
pub use model::*;
use url::Url;

fn extract_hostname(url: &str) -> Option<String> {
    let parsed_url = Url::parse(url).ok();
    match parsed_url {
        Some(parsed_url) => Some(parsed_url.host_str()?.to_string()),
        None => None,
    }
}

fn extract_domain(url: &str) -> Result<String> {
    let domain = psl::domain_str(url)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse domain from URL: {}", url))?;
    Ok(domain.to_owned())
}

pub async fn query<T: ConnectionProvider>(
    target: OriginRecord,
    resolver: Resolver<T>,
    ip2asn_map: std::sync::Arc<IpAsnMap>,
) -> Result<IpInfo> {
    // Parse Hostname
    let hostname = extract_hostname(&target.origin)
        .ok_or_else(|| anyhow::anyhow!("Invalid hostname: {}", target.origin))?;
    // extract TLD
    let domain = extract_domain(&target.origin).map_err(|e| anyhow::anyhow!("{}", e))?;
    let ip = dns::query_ipv4_ipv6(&hostname, &resolver);
    let cname = dns::query_cname(&hostname, &resolver);
    let ns = dns::query_ns(&domain, &resolver, &ip2asn_map);
    let (ip, cname, ns) = tokio::join!(ip, cname, ns);
    let asn = if let Some(ips) = &ip {
        asn::lookup_ip(ips, &ip2asn_map)
    } else {
        None
    };
    let tls = tls::retrive_cert_info(&hostname).ok();
    Ok(IpInfo {
        origin: target.clone(),
        records: IpInfoRecord {
            hostname,
            domain: domain.to_string(),
            cname,
            ns,
            ip,
            asn,
            tls,
        },
    })
}
