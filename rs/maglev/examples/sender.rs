use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use anyhow::Context;
use clap::Parser;

#[derive(Parser)]
#[command(about = "UDP traffic generator")]
struct Cli {
    #[arg(long, default_value = "10.0.1.100")]
    dest: Ipv4Addr,

    #[arg(long, default_value_t = 9000)]
    port_base: u16,

    #[arg(long, default_value = "32")]
    flows: NonZeroUsize,

    #[arg(long, default_value_t = 100_000)]
    count: u64,

    #[arg(long, default_value_t = 64)]
    payload: usize,

    #[arg(long, default_value_t = 0)]
    pps: u64,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let sock = UdpSocket::bind("0.0.0.0:0").context("binding UDP socket")?;
    let payload = vec![0xABu8; cli.payload];
    let addrs: Vec<SocketAddr> = (0..cli.flows.get())
        .map(|i| SocketAddr::V4(SocketAddrV4::new(cli.dest, cli.port_base.wrapping_add(i as u16))))
        .collect();

    let start = Instant::now();
    for i in 0..cli.count {
        sock.send_to(&payload, addrs[(i % addrs.len() as u64) as usize])
            .context("sending packet")?;
        if cli.pps > 0 && i % 64 == 0 {
            let target = Duration::from_secs_f64(i as f64 / cli.pps as f64);
            let el = start.elapsed();
            if el < target {
                std::thread::sleep(target - el);
            }
        }
    }
    let el = start.elapsed().as_secs_f64();
    println!(
        "sender: {} packets in {:.3}s = {:.0} pps, {} flows to {}:{}-{}",
        cli.count,
        el,
        cli.count as f64 / el,
        cli.flows,
        cli.dest,
        cli.port_base,
        cli.port_base as usize + cli.flows.get() - 1
    );
    Ok(())
}
