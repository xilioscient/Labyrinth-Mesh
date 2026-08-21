#[cfg(target_os = "linux")]
mod platform {
    use std::collections::VecDeque;
    use std::ffi::CString;
    use std::io;
    use std::mem::size_of;
    use std::os::unix::io::RawFd;
    use std::ptr::{null_mut, read_volatile, write_volatile};
    use std::sync::Arc;

    use libc::{
        c_int, c_void, close, getsockopt, mmap, munmap, poll, sendmsg, setsockopt, socket,
        socklen_t, MAP_ANONYMOUS, MAP_FAILED, MAP_POPULATE, MAP_SHARED, PROT_READ, PROT_WRITE,
        SOCK_RAW,
    };

    const AF_XDP: c_int = 44;
    const SOL_XDP: c_int = 283;
    const XDP_MMAP_OFFSETS: c_int = 1;
    const XDP_RX_RING: c_int = 2;
    const XDP_TX_RING: c_int = 3;
    const XDP_UMEM_REG: c_int = 4;
    const XDP_UMEM_FILL_RING: c_int = 5;
    const XDP_UMEM_COMPLETION_RING: c_int = 6;
    const XDP_PGOFF_RX_RING: libc::off_t = 0;
    const XDP_PGOFF_TX_RING: libc::off_t = 0x8000_0000;
    const XDP_UMEM_PGOFF_FILL_RING: libc::off_t = 0x1_0000_0000;
    const XDP_UMEM_PGOFF_COMPLETION_RING: libc::off_t = 0x1_8000_0000;
    const XDP_COPY: u16 = 2;

    pub const FRAME_SIZE: usize = 2048;
    pub const RING_SIZE: u32 = 2048;

    #[repr(C)]
    struct XdpUmemReg {
        addr: u64,
        len: u64,
        chunk_size: u32,
        headroom: u32,
        flags: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct XdpRingOffset {
        producer: u64,
        consumer: u64,
        desc: u64,
        flags: u64,
    }

    #[repr(C)]
    #[derive(Default)]
    struct XdpMmapOffsets {
        rx: XdpRingOffset,
        tx: XdpRingOffset,
        fr: XdpRingOffset,
        cr: XdpRingOffset,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct XdpDesc {
        addr: u64,
        len: u32,
        options: u32,
    }

    #[repr(C)]
    struct SockaddrXdp {
        sxdp_family: u16,
        sxdp_flags: u16,
        sxdp_ifindex: u32,
        sxdp_queue_id: u32,
        sxdp_shared_umem_fd: u32,
    }

    struct Ring {
        base: *mut u8,
        size_bytes: usize,
        producer: *mut u32,
        consumer: *mut u32,
        desc: *mut u8,
        mask: u32,
    }

    unsafe impl Send for Ring {}
    unsafe impl Sync for Ring {}

    impl Drop for Ring {
        fn drop(&mut self) {
            if !self.base.is_null() {
                unsafe { munmap(self.base as *mut c_void, self.size_bytes) };
            }
        }
    }

    impl Ring {
        unsafe fn read_producer(&self) -> u32 {
            read_volatile(self.producer)
        }
        unsafe fn write_producer(&self, v: u32) {
            write_volatile(self.producer, v);
        }
        unsafe fn write_consumer(&self, v: u32) {
            write_volatile(self.consumer, v);
        }
        unsafe fn desc_u64(&self, idx: u32) -> *mut u64 {
            self.desc.add((idx & self.mask) as usize * 8) as *mut u64
        }
        unsafe fn desc_xdp(&self, idx: u32) -> *mut XdpDesc {
            self.desc.add((idx & self.mask) as usize * 16) as *mut XdpDesc
        }
    }

    pub struct Umem {
        mem: *mut c_void,
        mem_len: usize,
        pub frame_count: usize,
    }

    unsafe impl Send for Umem {}
    unsafe impl Sync for Umem {}

    impl Drop for Umem {
        fn drop(&mut self) {
            if !self.mem.is_null() {
                unsafe { munmap(self.mem, self.mem_len) };
            }
        }
    }

    impl Umem {
        pub fn frame_ptr(&self, addr: u64) -> *mut u8 {
            unsafe { (self.mem as *mut u8).add(addr as usize) }
        }
    }

    pub struct XskSocket {
        fd: RawFd,
        pub umem: Arc<Umem>,
        rx_ring: Ring,
        tx_ring: Ring,
        fill_ring: Ring,
        comp_ring: Ring,
        tx_free: VecDeque<u64>,
        fill_prod: u32,
        rx_cons: u32,
        tx_prod: u32,
        comp_cons: u32,
    }

    unsafe impl Send for XskSocket {}

    impl Drop for XskSocket {
        fn drop(&mut self) {
            unsafe { close(self.fd) };
        }
    }

    impl XskSocket {
        pub fn new(iface: &str, queue_id: u32, umem_frames: usize) -> io::Result<Self> {
            let mem_len = umem_frames * FRAME_SIZE;
            let mem = unsafe {
                mmap(
                    null_mut(),
                    mem_len,
                    PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_SHARED | MAP_POPULATE,
                    -1,
                    0,
                )
            };
            if mem == MAP_FAILED {
                return Err(io::Error::last_os_error());
            }

            let umem = Arc::new(Umem { mem, mem_len, frame_count: umem_frames });

            let fd = unsafe { socket(AF_XDP, SOCK_RAW, 0) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            let reg = XdpUmemReg {
                addr: mem as u64,
                len: mem_len as u64,
                chunk_size: FRAME_SIZE as u32,
                headroom: 0,
                flags: 0,
            };
            let ret = unsafe {
                setsockopt(
                    fd,
                    SOL_XDP,
                    XDP_UMEM_REG,
                    &reg as *const _ as *const c_void,
                    size_of::<XdpUmemReg>() as socklen_t,
                )
            };
            if ret < 0 {
                unsafe { close(fd) };
                return Err(io::Error::last_os_error());
            }

            for opt in [XDP_UMEM_FILL_RING, XDP_UMEM_COMPLETION_RING, XDP_RX_RING, XDP_TX_RING] {
                let ret = unsafe {
                    setsockopt(
                        fd,
                        SOL_XDP,
                        opt,
                        &RING_SIZE as *const u32 as *const c_void,
                        size_of::<u32>() as socklen_t,
                    )
                };
                if ret < 0 {
                    unsafe { close(fd) };
                    return Err(io::Error::last_os_error());
                }
            }

            let mut off = XdpMmapOffsets::default();
            let mut off_len = size_of::<XdpMmapOffsets>() as socklen_t;
            let ret = unsafe {
                getsockopt(
                    fd,
                    SOL_XDP,
                    XDP_MMAP_OFFSETS,
                    &mut off as *mut _ as *mut c_void,
                    &mut off_len,
                )
            };
            if ret < 0 {
                unsafe { close(fd) };
                return Err(io::Error::last_os_error());
            }

            let fill_ring = mmap_ring(fd, &off.fr, RING_SIZE, 8, XDP_UMEM_PGOFF_FILL_RING)
                .inspect_err(|_| { unsafe { close(fd) }; })?;
            let comp_ring = mmap_ring(fd, &off.cr, RING_SIZE, 8, XDP_UMEM_PGOFF_COMPLETION_RING)
                .inspect_err(|_| { unsafe { close(fd) }; })?;
            let rx_ring = mmap_ring(fd, &off.rx, RING_SIZE, 16, XDP_PGOFF_RX_RING)
                .inspect_err(|_| { unsafe { close(fd) }; })?;
            let tx_ring = mmap_ring(fd, &off.tx, RING_SIZE, 16, XDP_PGOFF_TX_RING)
                .inspect_err(|_| { unsafe { close(fd) }; })?;

            let ifindex = iface_index(iface).inspect_err(|_| { unsafe { close(fd) }; })?;
            let sxdp = SockaddrXdp {
                sxdp_family: AF_XDP as u16,
                sxdp_flags: XDP_COPY,
                sxdp_ifindex: ifindex,
                sxdp_queue_id: queue_id,
                sxdp_shared_umem_fd: 0,
            };
            let ret = unsafe {
                libc::bind(
                    fd,
                    &sxdp as *const SockaddrXdp as *const libc::sockaddr,
                    size_of::<SockaddrXdp>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                unsafe { close(fd) };
                return Err(io::Error::last_os_error());
            }

            let half = umem_frames / 2;
            let mut sk = Self {
                fd,
                umem,
                rx_ring,
                tx_ring,
                fill_ring,
                comp_ring,
                tx_free: VecDeque::with_capacity(half),
                fill_prod: 0,
                rx_cons: 0,
                tx_prod: 0,
                comp_cons: 0,
            };

            let fill_count = half.min(RING_SIZE as usize);
            for i in 0..fill_count {
                unsafe {
                    let slot = sk.fill_ring.desc_u64(sk.fill_prod);
                    write_volatile(slot, (i * FRAME_SIZE) as u64);
                }
                sk.fill_prod = sk.fill_prod.wrapping_add(1);
            }
            unsafe { sk.fill_ring.write_producer(sk.fill_prod) };

            for i in half..umem_frames {
                sk.tx_free.push_back((i * FRAME_SIZE) as u64);
            }

            Ok(sk)
        }

        pub fn recv_batch(&mut self, out: &mut Vec<Vec<u8>>) -> usize {
            let prod = unsafe { self.rx_ring.read_producer() };
            let cons = self.rx_cons;
            let avail = prod.wrapping_sub(cons);
            if avail == 0 {
                return 0;
            }

            let mut c = cons;
            let mut n = 0u32;
            while n < avail {
                let desc = unsafe { *self.rx_ring.desc_xdp(c) };
                let ptr = self.umem.frame_ptr(desc.addr);
                let data = unsafe { std::slice::from_raw_parts(ptr, desc.len as usize).to_vec() };
                out.push(data);

                let fp = unsafe { self.fill_ring.read_producer() };
                unsafe {
                    let slot = self.fill_ring.desc_u64(fp);
                    write_volatile(slot, desc.addr & !((FRAME_SIZE as u64).wrapping_sub(1)));
                }
                unsafe { self.fill_ring.write_producer(fp.wrapping_add(1)) };

                c = c.wrapping_add(1);
                n += 1;
            }

            unsafe { self.rx_ring.write_consumer(c) };
            self.rx_cons = c;
            self.reclaim_tx();
            avail as usize
        }

        fn reclaim_tx(&mut self) {
            let prod = unsafe { self.comp_ring.read_producer() };
            let mut cons = self.comp_cons;
            while cons != prod {
                let addr = unsafe { read_volatile(self.comp_ring.desc_u64(cons)) };
                self.tx_free.push_back(addr);
                cons = cons.wrapping_add(1);
            }
            if cons != self.comp_cons {
                unsafe { self.comp_ring.write_consumer(cons) };
                self.comp_cons = cons;
            }
        }

        pub fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
            self.reclaim_tx();
            let addr = self.tx_free.pop_front().ok_or_else(|| {
                io::Error::new(io::ErrorKind::WouldBlock, "AF_XDP TX UMEM exhausted")
            })?;
            let len = data.len().min(FRAME_SIZE);
            unsafe {
                let dst = self.umem.frame_ptr(addr);
                std::ptr::copy_nonoverlapping(data.as_ptr(), dst, len);
            }
            let prod = self.tx_prod;
            unsafe {
                let slot = self.tx_ring.desc_xdp(prod);
                write_volatile(slot, XdpDesc { addr, len: len as u32, options: 0 });
            }
            self.tx_prod = prod.wrapping_add(1);
            unsafe { self.tx_ring.write_producer(self.tx_prod) };
            Ok(())
        }

        pub fn flush_tx(&self) {
            let msg: libc::msghdr = unsafe { std::mem::zeroed() };
            unsafe { sendmsg(self.fd, &msg, libc::MSG_DONTWAIT) };
        }

        pub fn poll_rx(&self, timeout_ms: i32) -> bool {
            let mut pfd = libc::pollfd { fd: self.fd, events: libc::POLLIN, revents: 0 };
            unsafe { poll(&mut pfd, 1, timeout_ms) > 0 }
        }

        pub fn raw_fd(&self) -> RawFd {
            self.fd
        }
    }

    fn mmap_ring(
        fd: RawFd,
        off: &XdpRingOffset,
        ring_size: u32,
        entry_size: usize,
        pgoff: libc::off_t,
    ) -> io::Result<Ring> {
        let size_bytes = off.desc as usize + ring_size as usize * entry_size;
        let base = unsafe {
            mmap(
                null_mut(),
                size_bytes,
                PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_POPULATE,
                fd,
                pgoff,
            )
        };
        if base == MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let base = base as *mut u8;
        Ok(Ring {
            base,
            size_bytes,
            producer: unsafe { base.add(off.producer as usize) as *mut u32 },
            consumer: unsafe { base.add(off.consumer as usize) as *mut u32 },
            desc: unsafe { base.add(off.desc as usize) },
            mask: ring_size - 1,
        })
    }

    fn iface_index(name: &str) -> io::Result<u32> {
        let cname = CString::new(name)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
        if idx == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(idx)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn constants_sanity() {
            assert_eq!(AF_XDP, 44);
            assert_eq!(SOL_XDP, 283);
            assert_eq!(FRAME_SIZE, 2048);
            assert!(RING_SIZE.is_power_of_two());
        }

        #[test]
        fn ring_mask() {
            let mask = RING_SIZE - 1;
            assert_eq!((RING_SIZE & mask), 0);
            assert_eq!((RING_SIZE + 5) & mask, 5);
        }
    }
}

#[cfg(target_os = "linux")]
pub use platform::{Umem, XskSocket, FRAME_SIZE, RING_SIZE};

#[cfg(not(target_os = "linux"))]
pub const FRAME_SIZE: usize = 2048;
#[cfg(not(target_os = "linux"))]
pub const RING_SIZE: u32 = 2048;

#[cfg(not(target_os = "linux"))]
pub struct Umem {
    pub frame_count: usize,
}

#[cfg(not(target_os = "linux"))]
pub struct XskSocket;

#[cfg(not(target_os = "linux"))]
impl XskSocket {
    pub fn new(_iface: &str, _queue_id: u32, _umem_frames: usize) -> std::io::Result<Self> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "AF_XDP requires Linux",
        ))
    }

    pub fn recv_batch(&mut self, _out: &mut Vec<Vec<u8>>) -> usize {
        0
    }

    pub fn send_frame(&mut self, _data: &[u8]) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "AF_XDP requires Linux",
        ))
    }

    pub fn flush_tx(&self) {}

    pub fn poll_rx(&self, _timeout_ms: i32) -> bool {
        false
    }

    pub fn raw_fd(&self) -> std::os::unix::io::RawFd {
        -1
    }
}
