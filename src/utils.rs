use anyhow::Result;
use hickory_proto::rr::domain::Name;
use hickory_proto::xfer::Protocol;
use hickory_resolver::{
    Resolver, config::NameServerConfig, config::ResolverConfig,
    name_server::TokioConnectionProvider,
};
use ip2asn::{Builder, IpAsnMap};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::{env, fs::File, io, path::Path};

fn is_tmp_file_exists(filename: &str) -> bool {
    let dir = env::temp_dir();
    Path::new(dir.join(filename).as_os_str()).exists()
}

async fn fetch_and_save_asn_db(url: &str, path: &Path) -> Result<()> {
    let response = reqwest::get(url).await?.bytes().await?;
    let mut dest = File::create(path)?;
    io::copy(&mut response.as_ref(), &mut dest)
        .map_err(|e| anyhow::anyhow!("Failed to save ASN database: {}", e))?;
    println!("Downloaded ASN database to {}", path.display());
    Ok(())
}

pub async fn open_asn_db() -> Result<IpAsnMap> {
    let filename = "ip2asn-combined.tsv.gz";
    let url = "https://iptoasn.com/data/ip2asn-combined.tsv.gz";
    let dir = env::temp_dir();
    let path = dir.join(filename);

    if !is_tmp_file_exists(filename) {
        fetch_and_save_asn_db(url, &path).await.map_err(|e| {
            anyhow::anyhow!(
                "Failed to fetch ASN database from {}: {}",
                url,
                e.to_string()
            )
        })?;
        println!("ASN database fetched successfully.");
    }
    println!("Loading ASN database from {}", path.display());
    // Build the IpAsnMap lookup table
    let ipasn = Builder::new().from_path(path)?.build()?;
    Ok(ipasn)
}

pub fn parse_ip_list(ip_list: &str) -> Vec<IpAddr> {
    ip_list
        .split(',')
        .filter_map(|s| s.trim().parse::<IpAddr>().ok())
        .collect()
}

pub fn get_dns_config_from_ips(dns_ips: &[IpAddr]) -> Vec<NameServerConfig> {
    dns_ips
        .iter()
        .map(|&ip| {
            let socket_addr = SocketAddr::new(ip, 53);
            NameServerConfig::new(socket_addr, Protocol::Udp)
        })
        .collect()
}

pub fn get_default_dns_config() -> Result<Resolver<TokioConnectionProvider>> {
    let ip: IpAddr = "1.1.1.1".parse()?;
    let socket_addr = SocketAddr::new(ip, 53);
    let name_server_config = NameServerConfig::new(socket_addr, Protocol::Udp);
    let name = Name::from_str("luxbulb.org.")?;
    let resolver_config = ResolverConfig::from_parts(Some(name), vec![], vec![name_server_config]);
    Ok(Resolver::builder_with_config(resolver_config, TokioConnectionProvider::default()).build())
}

/// Create a DNS resolver using Cloudflare's DNS server by default
/// or a custom DNS server if arguments is provided.
pub fn get_resolver(custom_dns: Option<String>) -> Result<Resolver<TokioConnectionProvider>> {
    if custom_dns.is_some() {
        let dns_ips = parse_ip_list(&custom_dns.unwrap());
        if !dns_ips.is_empty() {
            eprintln!("Resolution using custom DNS servers: {:?}", dns_ips);
            let dns_config = get_dns_config_from_ips(&dns_ips);
            let name = Name::from_str("luxbulb.org.")?;
            let resolver_config = ResolverConfig::from_parts(Some(name), vec![], dns_config);
            return Ok(Resolver::builder_with_config(
                resolver_config,
                TokioConnectionProvider::default(),
            )
            .build());
        } else {
            // If parsing failed or no valid IPs, fallback to default
            eprintln!("Resolution using default DNS servers: 1.1.1.1");
            return get_default_dns_config();
        }
    } else {
        // Use default Cloudflare DNS configuration
        eprintln!("Resolution using default DNS servers: 1.1.1.1");
        get_default_dns_config()
    }
}

/// Break an iterator into chunks of a specified size
/// https://users.rust-lang.org/t/how-to-breakup-an-iterator-into-chunks/87915/5
/// This function returns an iterator that yields vectors of items, each of size `chunk_size`.
/// The last chunk may be smaller if there are not enough items left.
pub fn chunked<I>(
    a: impl IntoIterator<Item = I>,
    chunk_size: usize,
) -> impl Iterator<Item = Vec<I>> {
    let mut a = a.into_iter();
    std::iter::from_fn(move || {
        Some(a.by_ref().take(chunk_size).collect()).filter(|chunk: &Vec<_>| !chunk.is_empty())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;
    #[test]
    fn test_chunked() {
        let data = vec![1, 2, 3, 4, 5, 6, 7];
        let chunk_size = 3;
        let chunks: Vec<Vec<i32>> = chunked(data, chunk_size).collect();
        assert_eq!(chunks, vec![vec![1, 2, 3], vec![4, 5, 6], vec![7]]);
    }

    #[tokio::test]
    async fn test_open_asn_db() {
        let result_fetch = open_asn_db().await;
        assert!(result_fetch.is_ok());
        // test if the temp file exists
        let result_tmp = open_asn_db().await;
        assert!(result_tmp.is_ok());
    }

    #[tokio::test]
    async fn test_fetch_and_save_asn_db() {
        let filename = "test_ip2asn-combined.tsv.gz";
        let url = "https://iptoasn.com/data/ip2asn-combined.tsv.gz";
        let dir = env::temp_dir();
        let path = dir.join(filename);
        // Remove the file if it exists
        if is_tmp_file_exists(filename) {
            std::fs::remove_file(&path).unwrap();
        }
        let result = fetch_and_save_asn_db(url, &path).await;
        assert!(result.is_ok());
        assert!(is_tmp_file_exists(filename));
        // Clean up
        std::fs::remove_file(&path).unwrap();
    }

    #[tokio::test]
    async fn test_get_resolver() {
        let resolver = get_resolver(None).unwrap();
        // Default should be Cloudflare
        assert_eq!(
            resolver.config().name_servers()[0].socket_addr,
            SocketAddr::from(([1, 1, 1, 1], 53))
        );
        let response = resolver.lookup_ip("example.com").await;
        assert!(response.is_ok());
    }

    #[test]
    fn test_parse_ip_list() {
        let ip_list = "1.1.1.1, 8.8.8.8, 8.8.4.4";
        let parsed_ips = parse_ip_list(ip_list);
        assert_eq!(parsed_ips.len(), 3);
        assert_eq!(parsed_ips[0], Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(parsed_ips[1], Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(parsed_ips[2], Ipv4Addr::new(8, 8, 4, 4));
    }

    #[test]
    fn test_parse_ip_list_with_error() {
        let ip_list = "1.1.";
        let parsed_ips = parse_ip_list(ip_list);
        assert_eq!(parsed_ips.len(), 0);
    }
}
