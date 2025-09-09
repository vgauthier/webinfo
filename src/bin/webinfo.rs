use anyhow::Result;
use clap::Parser;
use futures::future::try_join_all;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Semaphore, mpsc};
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

fn handle_result(mut rx: mpsc::Receiver<Result<webinfo::IpInfo>>) {
    // Handle results received from the channel
    tokio::spawn(async move {
        while let Some(result) = rx.recv().await {
            match result {
                Ok(info) => println!("{}", serde_json::to_string_pretty(&info).unwrap()),
                Err(e) => eprintln!("Error processing record: {}", e),
            }
        }
    });
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let csv_path = cli.csv;
    let map_ip_asn = open_asn_db()?;
    // Wrap the ASN map in an Arc for shared ownership
    let ip2asn_map = Arc::new(map_ip_asn);
    // limiter the number of concurrent tasks
    let permits = Arc::new(Semaphore::new(1000));
    let resolver = get_resolver();
    let file =
        File::open(csv_path).map_err(|e| anyhow::anyhow!("Failed to open CSV file: {}", e))?;
    let mut rdr = csv::Reader::from_reader(file);

    // create a channel to communicate results
    let (tx, rx) = mpsc::channel::<Result<webinfo::IpInfo>>(1000);

    // spawn a task to handle results
    handle_result(rx);

    // store all task handles
    let mut handles = vec![];

    // Process each record concurrently
    for result in rdr.deserialize() {
        let record: OriginRecord = result?;
        let r = resolver.clone();
        let s = tx.clone();
        let ip2asn_map_clone = ip2asn_map.clone();
        let permits = permits.clone();
        let handle = spawn(async move {
            // Acquire a permit before starting the task
            let _permit = permits.acquire().await;
            // Perform the query
            let ip_info = query(record, r, ip2asn_map_clone).await;
            // Send the result through the channel
            let _ = s.send(ip_info).await;
        });
        handles.push(handle);
    }
    // Wait for all tasks to complete
    try_join_all(handles).await?;
    Ok(())
}
