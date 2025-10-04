use anyhow::Result;
use clap::Parser;
use futures::future::try_join_all;
use hickory_resolver::{Resolver, name_server::TokioConnectionProvider};
use indicatif::{HumanCount, ProgressBar, ProgressStyle};
use ip2asn::IpAsnMap;
use itertools::izip;
use std::{fs::File, iter::repeat_with, path::PathBuf, sync::Arc, time::SystemTime};
use tokio::{sync::mpsc, task::spawn};
use tracing::{Level, event};

// Look at best pratices
// 1. https://youtu.be/XCrZleaIUO4?si=hDRLbn3wgZ2TqRuW
// 2. https://youtu.be/LRfDAZfo00o?si=tpwDBbNIh7Q59IvO
// 3. https://youtu.be/93SS3VGsKx4?si=hFAIx02eNzx_Qm7D
use webinfo::{
    IpInfo,
    ipinfo::OriginRecord,
    utils::{chunked, count_lines, get_resolver, open_asn_db},
};

fn process_batch_of_records(
    chunk: Vec<Result<OriginRecord, csv::Error>>,
    resolver: &Resolver<TokioConnectionProvider>,
    ip2asn_map: &Arc<IpAsnMap>,
    tx: &mpsc::Sender<Result<IpInfo>>,
) -> Vec<tokio::task::JoinHandle<()>> {
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
                event!(Level::ERROR, "{}", e);
                continue;
            }
        };
        // Spawn a task
        let handle = spawn(async move {
            // Perform the query
            let ip_info = IpInfo::runner(record)
                .with_resolver(r)
                .with_ip2asn_map(ip2asn)
                .run()
                .await;
            let _ = sender.send(ip_info).await;
        });
        handles.push(handle);
    }
    handles
}

#[derive(Parser)]
#[command(version, about, long_about = None, author = "Vincent Gauthier <vg@luxbulb.org>")]
struct Cli {
    /// Input CSV file path
    #[arg(short, long)]
    csv: PathBuf,
    /// Number of concurrent tasks to run
    #[arg(short = 's', long = "size", default_value_t = 5)]
    chunk_size: usize,
    /// Custom DNS server IP addresses (comma-separated)
    #[arg(short = 'd', long = "dns")]
    dns: Option<String>,
    /// Log file path
    #[arg(short = 'l', long = "logfile", default_value = "./webinfo.log")]
    logfile: PathBuf,
}

async fn process_all_records(
    mut rdr: csv::Reader<File>,
    chunk_size: usize,
    total_lines: usize,
    custom_dns: Option<String>,
) -> Result<()> {
    // create a channel to communicate results
    let (tx, rx) = mpsc::channel::<Result<webinfo::IpInfo>>(chunk_size);

    // spawn a task to handle results
    handle_result(rx);

    // Initialize dns resolver
    let resolver = get_resolver(custom_dns)
        .map_err(|_| anyhow::anyhow!("Failed to create DNS resolver with default configuration"))?;
    // Wrap the ASN map in an Arc for shared ownership
    let ip2asn_map = open_asn_db()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open ASN database: {}", e))?;
    let ip2asn_map = Arc::new(ip2asn_map);

    // Create a progress bar
    let bar = ProgressBar::new(total_lines as u64);
    bar.set_style(ProgressStyle::with_template("[{bar:50.cyan/blue}] {msg}")?.progress_chars("= "));
    let mut progress = 0;

    // Implement chunking to limit the number of concurrent tasks
    for chunk in chunked(rdr.deserialize::<OriginRecord>(), chunk_size) {
        // Process each record in the chunk
        let now = SystemTime::now();
        // process the current batch of records and get their task handles
        let handles = process_batch_of_records(chunk, &resolver, &ip2asn_map, &tx);
        // Wait for the current batch of tasks to complete
        let _ = try_join_all(handles).await?;
        // Update progress bar
        bar.inc(chunk_size as u64);
        progress += chunk_size;
        bar.set_message(format!(
            "{}/{}, {} records processed in {:.2} seconds",
            HumanCount(progress.try_into()?),
            HumanCount(total_lines.try_into()?),
            chunk_size,
            now.elapsed().unwrap().as_secs_f64()
        ));
    }
    bar.finish();
    Ok(())
}

///
/// Handle results received from the channel and print json to stdout
/// @param rx Receiver channel
///
fn handle_result(mut rx: mpsc::Receiver<Result<webinfo::IpInfo>>) {
    // Handle results received from the channel
    tokio::spawn(async move {
        while let Some(result) = rx.recv().await {
            match result {
                Ok(info) => {
                    print!("{}", serde_json::to_string_pretty(&info).unwrap());
                    println!(",")
                }
                Err(e) => event!(Level::ERROR, "{}", e),
            }
        }
    });
}
//******************************************************************************
//
// Main function
//
//******************************************************************************
#[tokio::main]
async fn main() -> Result<()> {
    let timer = tracing_subscriber::fmt::time::SystemTime;
    let cli = Cli::parse();

    // Initialize logging
    let file_appender = tracing_appender::rolling::daily(
        cli.logfile.parent().unwrap(),
        cli.logfile.file_name().unwrap(),
    );
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .compact()
        .with_timer(timer)
        .with_writer(non_blocking)
        .with_ansi(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|_| anyhow::anyhow!("Failed to set global default subscriber"))?;

    let csv_path = cli.csv;
    let csv_path_str = csv_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Failed to convert CSV path to string"))?;
    let line_count = count_lines(csv_path_str)?;

    event!(
        Level::INFO,
        "Starting processing file: {:?} with {} lines",
        csv_path,
        line_count
    );

    // open the CSV file
    let rdr = csv::Reader::from_path(&csv_path)?;

    // process chunk_size records concurrently
    process_all_records(rdr, cli.chunk_size, line_count, cli.dns).await?;
    Ok(())
}

//******************************************************************************
//
// Tests
//
//******************************************************************************
#[cfg(test)]
mod tests {
    use super::*;
    use assert_fs::prelude::*; // Filesystem assertions

    #[tokio::test]
    async fn test_process_batch_of_records() {
        // Initialize dns resolver using the host OS'es `/etc/resolv.conf`
        let resolver = Resolver::builder_tokio().unwrap().build();
        // Wrap the ASN map in an Arc for shared ownership
        let ip2asn_map = open_asn_db().await.unwrap();
        let ip2asn_map = Arc::new(ip2asn_map);

        let file = assert_fs::NamedTempFile::new("sample.txt").unwrap();
        file.write_str(
            "origin,popularity,date,country\nhttps://www.google.fr,1000,2025-08-28,FR\n",
        )
        .unwrap();
        let mut rdr = csv::Reader::from_path(file.path()).unwrap();
        let records = rdr.deserialize::<OriginRecord>().collect::<Vec<_>>();
        let handles =
            process_batch_of_records(records, &resolver, &ip2asn_map, &mpsc::channel(1).0);
        assert_eq!(handles.len(), 1);
    }
}
