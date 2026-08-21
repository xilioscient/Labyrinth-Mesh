use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;

use labyrinth_core::management_plane::ManagementServer;
use labyrinth_core::metrics::dashboard_metrics;
use labyrinth_core::phase4::MultiPathController;

#[derive(Parser)]
#[command(
    name = "labyrinth-server",
    about = "Labyrinth-Mesh standalone management server",
    version
)]
struct Cli {
    /// Bind address for the HTTP API
    #[arg(long, env = "LABYRINTH_BIND", default_value = "0.0.0.0:9090")]
    bind: SocketAddr,

    /// Number of virtual paths to pre-allocate in metrics
    #[arg(long, default_value_t = 1)]
    paths: usize,
}

#[tokio::main]
async fn main() {
    labyrinth_core::log_capture::init_with_capture();
    let cli = Cli::parse();

    let metrics = dashboard_metrics(cli.paths);
    let ctrl = Arc::new(Mutex::new(
        MultiPathController::new(vec![]).expect("controller"),
    ));
    let server = ManagementServer::new(metrics, cli.bind, ctrl);

    eprintln!("[labyrinth-server] management plane on http://{}", cli.bind);
    eprintln!("[labyrinth-server] endpoints: /health  /metrics  /metrics/stream  /logs");

    match server.start().await {
        Ok(()) => {}
        Err(e) => {
            eprintln!("[labyrinth-server] fatal: {e}");
            std::process::exit(1);
        }
    }

    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}
