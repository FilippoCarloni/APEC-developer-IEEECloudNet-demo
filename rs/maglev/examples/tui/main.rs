use std::net::Ipv4Addr;

use clap::Parser;

mod dashboard;
mod layout;

use dashboard::Dashboard;

#[derive(Parser)]
#[command(about = "Live dashboard: XDP-extracted 5-tuple vs software re-parse (maglev_tui.c twin)")]
struct Cli {
    /// Interface to receive on
    #[arg(short, long, default_value = "veth-host")]
    iface: String,

    /// Comma-separated backend IPv4 addresses (names hashed into the Maglev table)
    #[arg(
        long,
        value_delimiter = ',',
        default_values_t = [Ipv4Addr::new(10, 0, 2, 1), Ipv4Addr::new(10, 0, 2, 2), Ipv4Addr::new(10, 0, 2, 3)]
    )]
    backends: Vec<Ipv4Addr>,
}

fn main() -> anyhow::Result<()> {
    Dashboard::new(Cli::parse()).run()
}
