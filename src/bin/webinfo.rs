use anyhow::Result;
use clap::Parser;
use futures::future::try_join_all;
use itertools::izip;
use std::{fs::File, iter::repeat_with, path::PathBuf, sync::Arc};
use tokio::{sync::mpsc, task::spawn};
use webinfo::utils::chunked;

// Look at best pratices
// 1. https://youtu.be/XCrZleaIUO4?si=hDRLbn3wgZ2TqRuW
// 2. https://youtu.be/LRfDAZfo00o?si=tpwDBbNIh7Q59IvO
// 3. https://youtu.be/93SS3VGsKx4?si=hFAIx02eNzx_Qm7D
use webinfo::{
    IpInfo,
    ipinfo::OriginRecord,
    utils::{get_resolver, open_asn_db},
};

#[derive(Parser)]
#[command(version, about, long_about = None, author = "Vincent Gauthier <vg@luxbulb.org>")]
struct Cli {
    /// Input CSV file path
    #[arg(short, long)]
    csv: PathBuf,
    /// Number of concurrent tasks to run
    #[arg(short = 's', long = "size", default_value_t = 5)]
    chunk_size: usize,
}

async fn run(
    mut rdr: csv::Reader<File>,
    tx: mpsc::Sender<Result<webinfo::IpInfo>>,
    chunk_size: usize,
) -> Result<()> {
    // Initialize dns resolver
    let resolver = get_resolver();
    // Wrap the ASN map in an Arc for shared ownership
    let ip2asn_map = open_asn_db()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open ASN database: {}", e))?;
    let ip2asn_map = Arc::new(ip2asn_map);
    // Implement chunking to limit the number of concurrent tasks
    for chunk in chunked(rdr.deserialize::<OriginRecord>(), chunk_size) {
        // store all task handles
        let mut handles = Vec::new();
        // Create iterators that repeat the resolver, ip2asn_map, and tx for each record in the chunk
        let resolver_iter = repeat_with(|| resolver.clone()).take(chunk.len());
        let ip2asn_iter = repeat_with(|| ip2asn_map.clone()).take(chunk.len());
        let tx_iter = repeat_with(|| tx.clone()).take(chunk.len());
        // Process each record in the chunk
        for (record, r, ip2asn, sender) in izip!(chunk, resolver_iter, ip2asn_iter, tx_iter) {
            let record = match record {
                Ok(record) => record,
                Err(e) => {
                    eprintln!("Error processing record: {}", e);
                    continue;
                }
            };
            // Spawn a task
            let handle = spawn(async move {
                // Perform the query
                let ip_info = IpInfo::from_record(record, r, ip2asn).await;
                // Send the result through the channel
                let _ = sender.send(ip_info).await;
            });
            handles.push(handle);
        }

        // Wait for the current batch of tasks to complete
        let _ = try_join_all(handles).await?;
    }
    Ok(())
}

fn handle_result(mut rx: mpsc::Receiver<Result<webinfo::IpInfo>>) {
    // Handle results received from the channel
    tokio::spawn(async move {
        while let Some(result) = rx.recv().await {
            match result {
                Ok(info) => {
                    print!("{}", serde_json::to_string_pretty(&info).unwrap());
                    println!(",")
                }
                Err(e) => eprintln!("Error when processing record: {}", e),
            }
        }
    });
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let csv_path = cli.csv;
    // open the CSV file
    let rdr = csv::Reader::from_path(&csv_path)
        .map_err(|e| anyhow::anyhow!("Failed to open CSV file: {}", e))?;

    // create a channel to communicate results
    let (tx, rx) = mpsc::channel::<Result<webinfo::IpInfo>>(cli.chunk_size);

    // spawn a task to handle results
    handle_result(rx);

    // process chunk_size records concurrently
    run(rdr, tx, cli.chunk_size).await?;
    Ok(())
}
