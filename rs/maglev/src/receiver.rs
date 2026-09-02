use std::io::ErrorKind;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use maglev::backend::Backend;
use maglev::checksum;
use maglev::five_tuple::FiveTuple;
use maglev::flow_meta::FlowMeta;
use maglev::maglev_table::MaglevTable;
use pnet_datalink::{self as datalink, Channel};
use zerocopy::FromBytes;

use crate::Cli;

const VERBOSE_PACKETS: u64 = 5;

static RUNNING: AtomicBool = AtomicBool::new(true);

pub struct Receiver {
    iface: String,
    table: MaglevTable,
}

impl Receiver {
    pub fn new(cli: Cli) -> Self {
        let backends = cli
            .backends
            .iter()
            .map(|ip| Backend::new(&ip.to_string(), ip.octets()))
            .collect();
        Self { iface: cli.iface, table: MaglevTable::build(backends) }
    }

    pub fn run(self) -> anyhow::Result<()> {
        ctrlc::set_handler(|| RUNNING.store(false, Ordering::SeqCst))?;

        let iface = datalink::interfaces()
            .into_iter()
            .find(|i| i.name == self.iface)
            .with_context(|| format!("no such interface: {}", self.iface))?;
        let config = datalink::Config {
            read_timeout: Some(Duration::from_millis(250)),
            ..Default::default()
        };
        let mut rx = match datalink::channel(&iface, config)
            .with_context(|| {
                format!("opening AF_PACKET channel on {} (need root / CAP_NET_RAW)", self.iface)
            })? {
            Channel::Ethernet(_tx, rx) => rx,
            _ => bail!("unexpected channel type"),
        };
        let names: Vec<&str> = self.table.backends.iter().map(|b| b.name.as_str()).collect();
        eprintln!("maglev: listening on {}, backends {:?}", self.iface, names);

        let mut buf = Vec::with_capacity(2048);
        let (mut total, mut no_meta, mut verified, mut mismatch, mut unparsed, mut rewrite_fail) =
            (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
        let mut per_backend = vec![0u64; self.table.backends.len()];
        let start = Instant::now();
        let (mut last_t, mut last_n) = (Instant::now(), 0u64);

        while RUNNING.load(Ordering::Relaxed) {
            if total > 0 && last_t.elapsed() >= Duration::from_secs(1) {
                println!(
                    "[{:6.1}s] {total} pkts ({:.0} pps) meta={} verified={verified} mismatch={mismatch} no_meta={no_meta}",
                    start.elapsed().as_secs_f64(),
                    (total - last_n) as f64 / last_t.elapsed().as_secs_f64(),
                    total - no_meta
                );
                (last_t, last_n) = (Instant::now(), total);
            }

            let frame = match rx.next() {
                Ok(f) => f,
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(e) => Err(e).context("receiving frame")?,
            };
            total += 1;

            let (meta, rest) = match FlowMeta::ref_from_prefix(frame) {
                Ok((m, rest)) if m.is_valid() => (m, rest),
                _ => {
                    no_meta += 1;
                    continue;
                }
            };
            let hw = meta.five_tuple();
            let bi = self.table.lookup_index(hw.hash());
            per_backend[bi] += 1;

            match FiveTuple::from_frame(rest) {
                Some(sw) if sw == hw => verified += 1,
                Some(sw) => {
                    verified += 1;
                    mismatch += 1;
                    if mismatch <= VERBOSE_PACKETS {
                        println!("  MISMATCH xdp {hw} vs software {sw}");
                    }
                }
                None => unparsed += 1,
            }

            buf.clear();
            buf.extend_from_slice(rest);
            if !checksum::rewrite_daddr(&mut buf, 14, hw.proto, self.table.backends[bi].ip) {
                rewrite_fail += 1;
            }

            if total - no_meta <= VERBOSE_PACKETS {
                println!("  {hw} => {}", self.table.backends[bi].name);
            }
        }

        let el = start.elapsed().as_secs_f64();
        println!("\n=== summary ===");
        println!(
            "{total} packets in {el:.2}s ({:.0} pps): {} with metadata, {no_meta} without",
            total as f64 / el,
            total - no_meta
        );
        println!(
            "cross-check: {verified} verified, {mismatch} mismatch, {unparsed} not parseable in software; rewrite failures {rewrite_fail}"
        );
        let meta_pkts = total - no_meta;
        for (b, n) in self.table.backends.iter().zip(&per_backend) {
            println!(
                "  {:<15} {:>9} pkts  {:5.1}%",
                b.name,
                n,
                if meta_pkts > 0 { *n as f64 * 100.0 / meta_pkts as f64 } else { 0.0 }
            );
        }
        Ok(())
    }
}
