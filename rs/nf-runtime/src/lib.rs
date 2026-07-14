//! Shared run-to-completion runtime for all NFs — the Rust port of
//! `common/nf_main.h`, over AF_PACKET raw sockets instead of DPDK.
//!
//! An NF implements [`Nf`] and hands it to [`run`]: one worker thread per
//! requested worker, each with its own raw packet socket in a shared
//! `PACKET_FANOUT_HASH` group (the RSS equivalent), building its per-worker
//! state with `Nf::setup()` and then running the RX -> macswap -> `Nf::app`
//! -> TX burst loop, with an end-of-run `PORT_STATS` line. `run` is generic
//! so each NF binary monomorphizes the loop and the per-packet call inlines,
//! like the C demo's single-translation-unit build.

pub mod afpacket;
pub mod hdr;
pub mod jhash;

use afpacket::{PacketSock, BURST_SIZE, FRAME_SIZE};
use std::cell::Cell;
use std::process::exit;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

/// Per-worker network function: `setup` builds the per-worker state (hash
/// tables, rule sets, ...) on the worker thread itself, `app` sees the raw
/// packet data of one frame (L2 start, after the runtime's MAC swap).
pub trait Nf: Sized {
    fn setup() -> Self;
    /// # Safety
    /// `pkt` points at the frame's first byte; the buffer holds at least the
    /// plain eth+ip+l4 headers this demo's benchmark traffic guarantees.
    unsafe fn app(&mut self, pkt: *mut u8);
    /// Runs once per worker after the loop stops (e.g. to report counters).
    fn teardown(&mut self) {}
}

static QUIT: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_signum: libc::c_int) {
    QUIT.store(true, Ordering::Relaxed);
}

thread_local! {
    static WORKER_ID: Cell<usize> = const { Cell::new(0) };
}

/// The calling worker's index, for per-worker reporting.
pub fn worker_id() -> usize {
    WORKER_ID.with(|id| id.get())
}

fn gettid() -> i64 {
    unsafe { libc::syscall(libc::SYS_gettid) as i64 }
}

/// Swap src/dst MACs so frames flow back to the generator on a back-to-back
/// or switched loopback link.
#[inline(always)]
unsafe fn macswap(pkt: *mut u8) {
    let mut tmp = [0u8; 6];
    ptr::copy_nonoverlapping(pkt, tmp.as_mut_ptr(), 6);
    ptr::copy_nonoverlapping(pkt.add(6), pkt, 6);
    ptr::copy_nonoverlapping(tmp.as_ptr(), pkt.add(6), 6);
}

struct WorkerReport {
    processed: u64,
    sent: u64,
    rx_stats: afpacket::PacketStats,
}

fn worker_main<N: Nf>(sock: PacketSock, id: usize) -> WorkerReport {
    WORKER_ID.with(|w| w.set(id));
    let tid = gettid();
    println!("NF running on worker {} (TID={})", id, tid);

    /* Per-worker NF state (hash tables, rule sets, ...). */
    let mut nf = N::setup();

    let mut bufs = Box::new([[0u8; FRAME_SIZE]; BURST_SIZE]);
    let mut lens = [0usize; BURST_SIZE];
    let mut processed: u64 = 0;
    let mut sent: u64 = 0;

    while !QUIT.load(Ordering::Relaxed) {
        let nb_rx = match sock.rx_burst(&mut bufs, &mut lens) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("worker {}: rx error: {}", id, e);
                break;
            }
        };
        if nb_rx == 0 {
            continue;
        }

        for buf in &mut bufs[..nb_rx] {
            let pkt = buf.as_mut_ptr();
            unsafe {
                macswap(pkt);
                nf.app(pkt);
            }
        }

        processed += nb_rx as u64;
        sent += sock.tx_burst(&mut bufs, &lens, nb_rx).unwrap_or(0) as u64;
    }

    nf.teardown();
    println!("WORKER {} (TID={}): pkts_processed={}", id, tid, processed);
    WorkerReport { processed, sent, rx_stats: sock.stats() }
}

fn usage(prog: &str) -> ! {
    eprintln!("Usage: {} <IFACE> [NB_WORKERS]", prog);
    exit(1);
}

/// The NF `main()`: never returns.
pub fn run<N: Nf>() -> ! {
    let args: Vec<String> = std::env::args().collect();
    let prog = args.first().map(String::as_str).unwrap_or("nf");
    if args.len() < 2 || args.len() > 3 {
        usage(prog);
    }
    let iface = &args[1];
    let nb_workers: usize = match args.get(2).map(|w| w.parse()).unwrap_or(Ok(1)) {
        Ok(n) if n >= 1 => n,
        _ => usage(prog),
    };

    unsafe {
        let handler = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }

    println!("NF starting on {} worker(s)/socket(s)", nb_workers);

    let ifindex = afpacket::if_index(iface).unwrap_or_else(|e| {
        eprintln!("interface {} not found: {}", iface, e);
        exit(1);
    });
    let fanout_group = std::process::id() as u16;
    let socks: Vec<PacketSock> = (0..nb_workers)
        .map(|_| {
            PacketSock::open(ifindex, fanout_group).unwrap_or_else(|e| {
                eprintln!("socket setup on {} failed: {} (need CAP_NET_RAW)", iface, e);
                exit(1);
            })
        })
        .collect();

    let reports: Vec<WorkerReport> = std::thread::scope(|s| {
        let handles: Vec<_> = socks
            .into_iter()
            .enumerate()
            .map(|(id, sock)| s.spawn(move || worker_main::<N>(sock, id)))
            .collect();
        handles.into_iter().map(|h| h.join().expect("worker panicked")).collect()
    });

    let ipackets: u64 = reports.iter().map(|r| r.processed).sum();
    let opackets: u64 = reports.iter().map(|r| r.sent).sum();
    let imissed: u64 = reports.iter().map(|r| r.rx_stats.tp_drops as u64).sum();
    let oerrors = ipackets - opackets;
    let offered = ipackets + imissed;
    let drop_pct = if offered != 0 { 100.0 * imissed as f64 / offered as f64 } else { 0.0 };
    println!(
        "PORT_STATS: ipackets={} imissed={} ierrors=0 opackets={} oerrors={} drop_pct={:.4}",
        ipackets, imissed, opackets, oerrors, drop_pct
    );

    println!("NF terminated.");
    exit(0);
}
