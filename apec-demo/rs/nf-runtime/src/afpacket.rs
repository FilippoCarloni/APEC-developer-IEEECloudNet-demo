//! AF_PACKET raw-socket plumbing: `socket2` owns the socket lifecycle and
//! the portable options; `libc` supplies the AF_PACKET-specific structs and
//! setsockopts (`sockaddr_ll`, promiscuous membership, fanout, statistics)
//! that `socket2` doesn't model.
//!
//! One socket per worker, all joined into one `PACKET_FANOUT_HASH` group:
//! the kernel spreads flows across workers by 5-tuple hash, the raw-socket
//! equivalent of the RSS setup in the DPDK original.

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::mem::size_of;
use std::os::fd::AsRawFd;
use std::time::Duration;

/// Per-frame buffer size; frames longer than this are truncated on RX.
pub const FRAME_SIZE: usize = 2048;
/// RX/TX burst size, as in the DPDK original.
pub const BURST_SIZE: usize = 32;

const ETH_P_ALL: u16 = 0x0003;

// AF_PACKET socket options not exposed by the libc crate
// (values from <linux/if_packet.h>).
const PACKET_STATISTICS: libc::c_int = 6;
const PACKET_FANOUT: libc::c_int = 18;
const PACKET_IGNORE_OUTGOING: libc::c_int = 23;
const PACKET_FANOUT_HASH: u32 = 0;

/// tpacket_stats from <linux/if_packet.h>; tp_drops is included in
/// tp_packets, and reading the option resets both.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PacketStats {
    pub tp_packets: u32,
    pub tp_drops: u32,
}

pub fn if_index(name: &str) -> io::Result<u32> {
    let cname = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in interface name"))?;
    match unsafe { libc::if_nametoindex(cname.as_ptr()) } {
        0 => Err(io::Error::last_os_error()),
        idx => Ok(idx),
    }
}

fn setsockopt<T>(fd: libc::c_int, level: libc::c_int, name: libc::c_int, value: &T) -> io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            value as *const T as *const libc::c_void,
            size_of::<T>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub struct PacketSock {
    sock: Socket,
}

impl PacketSock {
    /// Open a raw packet socket on `ifindex`, promiscuous, ignoring its own
    /// transmissions, member of fanout group `fanout_group`, with 100 ms
    /// RX/TX timeouts so workers can poll the quit flag.
    pub fn open(ifindex: u32, fanout_group: u16) -> io::Result<PacketSock> {
        let sock = Socket::new(
            Domain::PACKET,
            Type::RAW,
            Some(Protocol::from((ETH_P_ALL.to_be() as u16) as i32)),
        )?;

        let mut storage: socket2::SockAddrStorage = unsafe { std::mem::zeroed() };
        let sll = &mut storage as *mut socket2::SockAddrStorage as *mut libc::sockaddr_ll;
        unsafe {
            (*sll).sll_family = libc::AF_PACKET as libc::sa_family_t;
            (*sll).sll_protocol = ETH_P_ALL.to_be();
            (*sll).sll_ifindex = ifindex as libc::c_int;
        }
        let addr = unsafe {
            SockAddr::new(storage, size_of::<libc::sockaddr_ll>() as libc::socklen_t)
        };
        sock.bind(&addr)?;

        let fd = sock.as_raw_fd();

        let mreq = libc::packet_mreq {
            mr_ifindex: ifindex as libc::c_int,
            mr_type: libc::PACKET_MR_PROMISC as libc::c_ushort,
            mr_alen: 0,
            mr_address: [0; 8],
        };
        setsockopt(fd, libc::SOL_PACKET, libc::PACKET_ADD_MEMBERSHIP, &mreq)?;

        // Without this every frame we TX comes straight back on RX and the
        // MAC-swap forwarding turns into an infinite reflection (needs
        // kernel >= 4.20).
        setsockopt(fd, libc::SOL_PACKET, PACKET_IGNORE_OUTGOING, &1i32)?;

        sock.set_read_timeout(Some(Duration::from_millis(100)))?;
        sock.set_write_timeout(Some(Duration::from_millis(100)))?;

        let fanout: i32 = (fanout_group as i32) | ((PACKET_FANOUT_HASH as i32) << 16);
        setsockopt(fd, libc::SOL_PACKET, PACKET_FANOUT, &fanout)?;

        Ok(PacketSock { sock })
    }

    /// Receive up to a burst of frames; returns how many landed in `bufs`
    /// with their lengths in `lens` (0 on timeout).
    pub fn rx_burst(
        &self,
        bufs: &mut [[u8; FRAME_SIZE]; BURST_SIZE],
        lens: &mut [usize; BURST_SIZE],
    ) -> io::Result<usize> {
        let mut iovs: [libc::iovec; BURST_SIZE] = unsafe { std::mem::zeroed() };
        let mut msgs: [libc::mmsghdr; BURST_SIZE] = unsafe { std::mem::zeroed() };
        for i in 0..BURST_SIZE {
            iovs[i].iov_base = bufs[i].as_mut_ptr().cast();
            iovs[i].iov_len = FRAME_SIZE;
            msgs[i].msg_hdr.msg_iov = &mut iovs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
        }
        // MSG_WAITFORONE + SO_RCVTIMEO: block up to the timeout for the
        // first frame, then take whatever else is already queued.
        let rc = unsafe {
            libc::recvmmsg(
                self.sock.as_raw_fd(),
                msgs.as_mut_ptr(),
                BURST_SIZE as libc::c_uint,
                libc::MSG_WAITFORONE,
                std::ptr::null_mut(),
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            return match err.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted => Ok(0),
                _ => Err(err),
            };
        }
        let nb_rx = rc as usize;
        for i in 0..nb_rx {
            lens[i] = msgs[i].msg_len as usize;
        }
        Ok(nb_rx)
    }

    /// Send the first `n` frames back out; returns how many the kernel
    /// accepted (the rest are dropped, like a shortfalling tx_burst).
    pub fn tx_burst(
        &self,
        bufs: &mut [[u8; FRAME_SIZE]; BURST_SIZE],
        lens: &[usize; BURST_SIZE],
        n: usize,
    ) -> io::Result<usize> {
        if n == 0 {
            return Ok(0);
        }
        let mut iovs: [libc::iovec; BURST_SIZE] = unsafe { std::mem::zeroed() };
        let mut msgs: [libc::mmsghdr; BURST_SIZE] = unsafe { std::mem::zeroed() };
        for i in 0..n {
            iovs[i].iov_base = bufs[i].as_mut_ptr().cast();
            iovs[i].iov_len = lens[i];
            msgs[i].msg_hdr.msg_iov = &mut iovs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
        }
        let rc = unsafe {
            libc::sendmmsg(self.sock.as_raw_fd(), msgs.as_mut_ptr(), n as libc::c_uint, 0)
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            return match err.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted => Ok(0),
                _ => Err(err),
            };
        }
        Ok(rc as usize)
    }

    /// Kernel-side RX statistics since the last call (the read resets them).
    pub fn stats(&self) -> PacketStats {
        let mut stats = PacketStats::default();
        let mut len = size_of::<PacketStats>() as libc::socklen_t;
        unsafe {
            libc::getsockopt(
                self.sock.as_raw_fd(),
                libc::SOL_PACKET,
                PACKET_STATISTICS,
                &mut stats as *mut PacketStats as *mut libc::c_void,
                &mut len,
            );
        }
        stats
    }
}
