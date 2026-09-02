use std::fmt::{self, Write as _};
use std::io::{self, ErrorKind, Write};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use maglev::backend::Backend;
use maglev::five_tuple::FiveTuple;
use maglev::flow_meta::FlowMeta;
use maglev::maglev_table::{LUT_SIZE, MaglevTable};
use pnet_datalink::{self as datalink, Channel};
use zerocopy::FromBytes;

use crate::Cli;
use crate::layout::Layout;

const REFRESH: Duration = Duration::from_millis(100);
const HEX_BYTES: usize = 128;
const BAR_WIDTH: usize = 28;

const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const C_META: &str = "\x1b[1;36m"; // cyan    - XDP metadata
const C_ETH: &str = "\x1b[1;32m"; //  green   - Ethernet
const C_IP: &str = "\x1b[1;33m"; //   yellow  - IPv4
const C_L4: &str = "\x1b[1;35m"; //   magenta - L4 header
const C_PAY: &str = "\x1b[0;37m"; //  grey    - L4 payload
const C_OK: &str = "\x1b[1;32m";
const C_BAD: &str = "\x1b[1;31m";

static RUNNING: AtomicBool = AtomicBool::new(true);

pub struct Dashboard {
    iface: String,
    table: MaglevTable,

    total: u64,
    no_meta: u64,
    verified: u64,
    mismatch: u64,
    unparsed: u64,
    hits: Vec<u64>,
    proto: [u64; 256],

    last: Vec<u8>,
    last_len: usize,
    hw: Option<FiveTuple>,
    sw: Option<FiveTuple>,
    layout: Option<Layout>,
    backend: usize,
}

impl Dashboard {
    pub fn new(cli: Cli) -> Self {
        let backends: Vec<Backend> = cli
            .backends
            .iter()
            .map(|ip| Backend::new(&ip.to_string(), ip.octets()))
            .collect();
        let n = backends.len();
        Self {
            iface: cli.iface,
            table: MaglevTable::build(backends),
            total: 0,
            no_meta: 0,
            verified: 0,
            mismatch: 0,
            unparsed: 0,
            hits: vec![0; n],
            proto: [0; 256],
            last: Vec::with_capacity(HEX_BYTES),
            last_len: 0,
            hw: None,
            sw: None,
            layout: None,
            backend: 0,
        }
    }

    pub fn run(mut self) -> anyhow::Result<()> {
        print!("\x1b[?25l"); // hide cursor
        let result = self.main_loop();
        print!("\x1b[?25h{RESET}\n"); // restore
        io::stdout().flush()?;
        result
    }

    fn main_loop(&mut self) -> anyhow::Result<()> {
        ctrlc::set_handler(|| RUNNING.store(false, Ordering::SeqCst))?;

        let iface = datalink::interfaces()
            .into_iter()
            .find(|i| i.name == self.iface)
            .with_context(|| format!("no such interface: {}", self.iface))?;
        let config = datalink::Config { read_timeout: Some(REFRESH), ..Default::default() };
        let mut rx = match datalink::channel(&iface, config)
            .with_context(|| {
                format!("opening AF_PACKET channel on {} (need root / CAP_NET_RAW)", self.iface)
            })? {
            Channel::Ethernet(_tx, rx) => rx,
            _ => bail!("unexpected channel type"),
        };

        let mut out = io::stdout();
        out.write_all(self.render()?.as_bytes())?;
        out.flush()?;
        let mut last_render = Instant::now();

        while RUNNING.load(Ordering::Relaxed) {
            if last_render.elapsed() >= REFRESH {
                out.write_all(self.render()?.as_bytes())?;
                out.flush()?;
                last_render = Instant::now();
            }
            match rx.next() {
                Ok(frame) => self.process(frame),
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::Interrupted
                    ) => {}
                Err(e) => Err(e).context("receiving frame")?,
            }
        }
        Ok(())
    }

    fn process(&mut self, frame: &[u8]) {
        self.total += 1;
        let (meta, rest) = match FlowMeta::ref_from_prefix(frame) {
            Ok((m, rest)) if m.is_valid() => (m, rest),
            _ => {
                self.no_meta += 1;
                return;
            }
        };

        let hw = meta.five_tuple();
        let b = self.table.lookup_index(hw.hash());
        self.hits[b] += 1;
        self.proto[hw.proto as usize] += 1;

        let sw = FiveTuple::from_frame(rest);
        match sw {
            Some(sw) => {
                self.verified += 1;
                if sw != hw {
                    self.mismatch += 1;
                }
            }
            None => self.unparsed += 1,
        }

        self.last.clear();
        self.last.extend_from_slice(&frame[..frame.len().min(HEX_BYTES)]);
        self.last_len = frame.len();
        self.hw = Some(hw);
        self.sw = sw;
        self.layout = Layout::of(rest).map(|l| l.shifted(FlowMeta::SIZE));
        self.backend = b;
    }

    fn color_at(&self, o: usize) -> &'static str {
        if o < FlowMeta::SIZE {
            return C_META;
        }
        let Some(l) = self.layout else { return DIM };
        if o < l.l3 {
            C_ETH
        } else if o < l.l4 {
            C_IP
        } else if o < l.l4_end {
            C_L4
        } else if o < l.ip_end {
            C_PAY
        } else {
            DIM // Ethernet padding
        }
    }

    fn render(&self) -> Result<String, fmt::Error> {
        let mut s = String::from("\x1b[H\x1b[J");
        writeln!(s, "{BOLD}  XDP 5-tuple prefix — live{RESET}{DIM}   source: {}{RESET}\n", self.iface)?;
        writeln!(s, "  packets {:<14} without metadata {}\n", self.total, self.no_meta)?;

        if self.total > 0 && self.no_meta > self.total / 2 {
            writeln!(
                s,
                "  {C_BAD}NO METADATA HEADER DETECTED{RESET}  {}/{} frames carry no prefix.\n  \
                 {DIM}Wrong interface, or the XDP program is not attached.{RESET}\n",
                self.no_meta, self.total
            )?;
        }

        writeln!(s, "  {BOLD}LAST FRAME{RESET}")?;
        if self.last_len > 0 {
            writeln!(s, "    {} bytes on the wire, first {} shown", self.last_len, self.last.len())?;
            for row in (0..self.last.len()).step_by(16) {
                write!(s, "    {row:04x}  ")?;
                for j in 0..16 {
                    let o = row + j;
                    if o >= self.last.len() {
                        s.push_str("   ");
                        continue;
                    }
                    write!(s, "{}{:02x}{RESET}{}", self.color_at(o), self.last[o], if j % 2 == 1 { " " } else { "" })?;
                }
                s.push('\n');
            }
            writeln!(
                s,
                "    {C_META}█ metadata ({} B){RESET}  {C_ETH}█ Ethernet{RESET}  {C_IP}█ IPv4{RESET}  \
                 {C_L4}█ L4 hdr{RESET}  {C_PAY}█ payload{RESET}  {DIM}█ padding{RESET}",
                FlowMeta::SIZE
            )?;
        } else {
            writeln!(s, "{DIM}    waiting for a prefixed frame...{RESET}")?;
        }
        s.push('\n');

        writeln!(s, "  {BOLD}{:<31}{RESET}{BOLD}{}{RESET}", "EXTRACTED BY XDP", "RE-PARSED IN SOFTWARE")?;
        writeln!(s, "  {DIM}{:<31}{}{RESET}", "16 B, fixed offsets, no branch", "ethertype, IHL, L4 offsets")?;
        let (hw, sw) = (self.hw, self.sw);
        let ip = |v: u32| Ipv4Addr::from(v).to_string();
        row(&mut s, "src", hw.map(|t| ip(t.src_ip)), sw.map(|t| ip(t.src_ip)), same(hw, sw, |t| t.src_ip))?;
        row(&mut s, "dst", hw.map(|t| ip(t.dst_ip)), sw.map(|t| ip(t.dst_ip)), same(hw, sw, |t| t.dst_ip))?;
        row(&mut s, "sport", hw.map(|t| t.src_port.to_string()), sw.map(|t| t.src_port.to_string()), same(hw, sw, |t| t.src_port))?;
        row(&mut s, "dport", hw.map(|t| t.dst_port.to_string()), sw.map(|t| t.dst_port.to_string()), same(hw, sw, |t| t.dst_port))?;
        row(&mut s, "proto", hw.map(|t| pname(t.proto).into()), sw.map(|t| pname(t.proto).into()), same(hw, sw, |t| t.proto))?;
        writeln!(
            s,
            "    {DIM}{} packets cross-checked, {RESET}{}{} mismatch{RESET}{DIM}   (not parseable: {}){RESET}\n",
            self.verified,
            if self.mismatch > 0 { C_BAD } else { C_OK },
            self.mismatch,
            self.unparsed
        )?;

        writeln!(s, "  {BOLD}LOAD BALANCER{RESET}{DIM}   table {LUT_SIZE}{RESET}")?;
        let with_meta = self.total - self.no_meta;
        for (i, b) in self.table.backends.iter().enumerate() {
            let frac = if with_meta > 0 { self.hits[i] as f64 / with_meta as f64 } else { 0.0 };
            writeln!(
                s,
                "    {}{:<14}{RESET} {}  {:5.1}%  {}",
                if i == self.backend && self.hw.is_some() { BOLD } else { "" },
                b.name,
                bar(frac),
                100.0 * frac,
                self.hits[i]
            )?;
        }
        s.push('\n');

        write!(s, "  {BOLD}PROTOCOL MIX{RESET}  ")?;
        for (p, &n) in self.proto.iter().enumerate() {
            if n > 0 {
                write!(s, "{} {:.1}%   ", pname(p as u8), 100.0 * n as f64 / with_meta as f64)?;
            }
        }
        write!(s, "\n\n  {DIM}Ctrl-C to quit{RESET}\n")?;
        Ok(s)
    }
}

fn row(s: &mut String, label: &str, hw: Option<String>, sw: Option<String>, equal: bool) -> fmt::Result {
    let verdict = match (&hw, &sw) {
        (None, _) => String::new(),
        (Some(_), None) => format!("{DIM}n/a{RESET}"),
        (Some(_), Some(_)) if equal => format!("{C_OK}match{RESET}"),
        _ => format!("{C_BAD}MISMATCH{RESET}"),
    };
    writeln!(
        s,
        "    {label:<7}{:<24}{:<22}{verdict}",
        hw.as_deref().unwrap_or("-"),
        sw.as_deref().unwrap_or("-")
    )
}

fn same<T: PartialEq>(hw: Option<FiveTuple>, sw: Option<FiveTuple>, f: impl Fn(&FiveTuple) -> T) -> bool {
    matches!((hw, sw), (Some(h), Some(w)) if f(&h) == f(&w))
}

fn pname(p: u8) -> &'static str {
    match p {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        47 => "GRE",
        132 => "SCTP",
        _ => "other",
    }
}

fn bar(frac: f64) -> String {
    let n = ((frac * BAR_WIDTH as f64) + 0.5) as usize;
    let n = n.min(BAR_WIDTH);
    format!("{}{}", "█".repeat(n), "░".repeat(BAR_WIDTH - n))
}
