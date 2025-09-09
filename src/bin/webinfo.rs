use anyhow::Result;
use clap::Parser;
use futures::future::try_join_all;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::spawn;
use webinfo::{
    OriginRecord, query,
    utils::{get_resolver, open_asn_db},
};

#[derive(Parser)]
#[command(version, about, long_about = None, author = "Vincent Gauthier <vg@luxbulb.org>")]
struct Cli {
    /// Input CSV file path
    #[arg(short, long)]
    csv: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let csv_path = cli.csv;
    let map_ip_asn = open_asn_db()?;
    // Wrap the ASN map in an Arc for shared ownership
    let ip2asn_map = Arc::new(map_ip_asn);

    let resolver = get_resolver();
    let file =
        File::open(csv_path).map_err(|e| anyhow::anyhow!("Failed to open CSV file: {}", e))?;
    let mut rdr = csv::Reader::from_reader(file);
    let (tx, mut rx) = mpsc::channel::<Result<webinfo::IpInfo>>(2);

    // Spawn a task to handle results
    tokio::spawn(async move {
        let mut i = 0;
        while let Some(result) = rx.recv().await {
            match result {
                Ok(info) => println!("{} - {}", i, serde_json::to_string_pretty(&info).unwrap()),
                Err(e) => eprintln!("Error processing record: {}", e),
            }
            i += 1;
        }
    });

    // store all task handles
    let mut handles = vec![];
    // Process each record concurrently
    for result in rdr.deserialize() {
        let record: OriginRecord = result?;
        let r = resolver.clone();
        let s = tx.clone();
        let ip2asn_map_clone = ip2asn_map.clone();
        let handle = spawn(async move {
            let ip_info = query(record, r, ip2asn_map_clone).await;
            let _ = s.send(ip_info).await;
        });
        handles.push(handle);
    }
    // Wait for all tasks to complete
    try_join_all(handles).await?;
    Ok(())
}
