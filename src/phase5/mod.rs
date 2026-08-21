use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[cfg(target_os = "linux")]
pub fn is_debugger_attached_procfs() -> bool {
    use std::fs;
    let status = match fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return false,
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("TracerPid:") {
            let pid: i64 = rest.trim().parse().unwrap_or(0);
            if pid != 0 {
                return true;
            }
        }
    }
    false
}

#[cfg(target_os = "linux")]
pub fn is_debugger_attached_ptrace() -> bool {
    unsafe {
        let ret = libc::ptrace(libc::PTRACE_TRACEME, 0, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>());
        if ret == -1 {
            return true;
        }
        libc::ptrace(libc::PTRACE_DETACH, 0, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>());
        false
    }
}

#[cfg(target_os = "linux")]
pub fn is_debugger_attached() -> bool {
    is_debugger_attached_procfs() || is_debugger_attached_ptrace()
}

#[cfg(not(target_os = "linux"))]
pub fn is_debugger_attached() -> bool { false }
#[cfg(not(target_os = "linux"))]
pub fn is_debugger_attached_procfs() -> bool { false }
#[cfg(not(target_os = "linux"))]
pub fn is_debugger_attached_ptrace() -> bool { false }

pub struct AntiDebugGuard {
    running: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl AntiDebugGuard {
    pub fn start(interval: Duration) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        let handle = std::thread::Builder::new()
            .name("dmpot-antidebug".into())
            .spawn(move || {
                while running_clone.load(Ordering::Acquire) {
                    if is_debugger_attached() {
                        log::warn!(
                            "Anti-debug: debugger detected (TracerPid/ptrace). Initiating secure shutdown."
                        );
                        std::process::exit(0);
                    }
                    std::thread::sleep(interval);
                }
            })
            .expect("failed to spawn anti-debug thread");

        AntiDebugGuard { running, handle: Some(handle) }
    }
}

impl Drop for AntiDebugGuard {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

const MAX_TEXT_LEN: usize = 256 * 1024 * 1024;

#[cfg(target_os = "linux")]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn hash_memory_range(start: *const u8, len: usize) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    if start.is_null() || len == 0 || len >= MAX_TEXT_LEN {
        log::warn!(
            "hash_memory_range: invalid range start={:?} len={} — returning zero digest",
            start, len,
        );
        return [0u8; 32];
    }

    let slice = unsafe { std::slice::from_raw_parts(start, len) };
    let digest = Sha256::digest(slice);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

#[cfg(target_os = "linux")]
pub fn find_text_section() -> Option<(usize, usize)> {
    use procfs::process::{MMPermissions, Process};

    let proc = Process::myself().ok()?;
    let maps = proc.maps().ok()?;

    for map in maps.iter() {
        let perms = map.perms;

        if !perms.contains(MMPermissions::READ | MMPermissions::EXECUTE) {
            continue;
        }
        if perms.contains(MMPermissions::WRITE) {
            continue;
        }

        let start = map.address.0 as usize;
        let end   = map.address.1 as usize;

        if end <= start {
            continue;
        }
        let len = end - start;

        if start == 0 || len == 0 || len >= MAX_TEXT_LEN {
            log::debug!(
                "find_text_section: skipping suspicious region start=0x{start:x} len={len}"
            );
            continue;
        }

        return Some((start, len));
    }

    None
}

#[cfg(target_os = "linux")]
pub struct MemoryIntegrityChecker {
    baseline_hash: [u8; 32],
    #[allow(dead_code)]
    start: usize,
    #[allow(dead_code)]
    len: usize,
    running: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

#[cfg(target_os = "linux")]
impl MemoryIntegrityChecker {
    pub fn start(interval: Duration) -> Option<Self> {
        let (start, len) = find_text_section()?;
        let baseline_hash = hash_memory_range(start as *const u8, len);

        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        let handle = std::thread::Builder::new()
            .name("dmpot-integrity".into())
            .spawn(move || {
                while running_clone.load(Ordering::Acquire) {
                    std::thread::sleep(interval);
                    let current = hash_memory_range(start as *const u8, len);
                    if current != baseline_hash {
                        log::error!(
                            "Memory integrity check FAILED: .text section modified at runtime"
                        );
                        std::process::exit(1);
                    }
                }
            })
            .ok()?;

        Some(MemoryIntegrityChecker {
            baseline_hash,
            start,
            len,
            running,
            handle: Some(handle),
        })
    }

    pub fn baseline_hash(&self) -> &[u8; 32] { &self.baseline_hash }
}

#[cfg(target_os = "linux")]
impl Drop for MemoryIntegrityChecker {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
        if let Some(h) = self.handle.take() { let _ = h.join(); }
    }
}

struct RawPtrEntry(*mut u8, usize);
unsafe impl Send for RawPtrEntry {}
unsafe impl Sync for RawPtrEntry {}

static PANIC_WIPE_REGISTRY: std::sync::OnceLock<
    std::sync::Mutex<Vec<RawPtrEntry>>
> = std::sync::OnceLock::new();

#[allow(clippy::missing_safety_doc)]
pub unsafe fn register_for_panic_wipe(ptr: *mut u8, len: usize) {
    let registry = PANIC_WIPE_REGISTRY.get_or_init(|| std::sync::Mutex::new(Vec::new()));
    registry.lock().unwrap().push(RawPtrEntry(ptr, len));
}

pub fn setup_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Some(registry) = PANIC_WIPE_REGISTRY.get() {
            if let Ok(entries) = registry.lock() {
                for entry in entries.iter() {
                    let (ptr, len) = (entry.0, entry.1);
                    if ptr.is_null() { continue; }
                    unsafe {
                        for i in 0..len {
                            (ptr.add(i)).write_volatile(0u8);
                        }
                    }
                }
            }
        }
        default_hook(info);
    }));
}

#[cfg(target_os = "linux")]
pub fn mlock_region(ptr: *const u8, len: usize) -> Result<(), i32> {
    let ret = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
    if ret == 0 { Ok(()) } else { Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)) }
}

#[cfg(not(target_os = "linux"))]
pub fn mlock_region(_ptr: *const u8, _len: usize) -> Result<(), i32> { Ok(()) }

#[cfg(target_os = "linux")]
pub fn munlock_region(ptr: *const u8, len: usize) -> Result<(), i32> {
    let ret = unsafe { libc::munlock(ptr as *const libc::c_void, len) };
    if ret == 0 { Ok(()) } else { Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)) }
}

#[cfg(not(target_os = "linux"))]
pub fn munlock_region(_ptr: *const u8, _len: usize) -> Result<(), i32> { Ok(()) }

pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    pub fn new(size: usize) -> Self {
        let data = vec![0u8; size];
        let _ = mlock_region(data.as_ptr(), size);
        SecureBuffer { data }
    }

    pub fn as_slice(&self) -> &[u8] { &self.data }
    pub fn as_mut_slice(&mut self) -> &mut [u8] { &mut self.data }
    pub fn len(&self) -> usize { self.data.len() }
    pub fn is_empty(&self) -> bool { self.data.is_empty() }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        for b in self.data.iter_mut() {
            unsafe { (b as *mut u8).write_volatile(0u8); }
        }
        let _ = munlock_region(self.data.as_ptr(), self.data.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_debugger_in_normal_test() {
        let attached = is_debugger_attached_procfs();
        let _ = attached;
    }

    #[test]
    fn test_anti_debug_guard_starts_and_stops() {
        let guard = AntiDebugGuard::start(Duration::from_secs(60));
        drop(guard);
    }

    #[test]
    fn test_secure_buffer_zeroize() {
        let mut buf = SecureBuffer::new(32);
        buf.as_mut_slice().fill(0xAA);
        assert!(buf.as_slice().iter().all(|&b| b == 0xAA));
        drop(buf);
    }

    #[test]
    fn test_panic_hook_setup() {
        setup_panic_hook();
    }

    #[test]
    fn test_mlock_unlock() {
        let data = vec![0u8; 4096];
        let r = mlock_region(data.as_ptr(), data.len());
        if r.is_ok() {
            let _ = munlock_region(data.as_ptr(), data.len());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_find_text_section() {
        let result = find_text_section();
        assert!(result.is_some(), "should find an executable region");
        let (start, len) = result.unwrap();
        assert!(start > 0);
        assert!(len > 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_memory_integrity_stable() {
        let (start, len) = find_text_section().expect("text section");
        let h1 = hash_memory_range(start as *const u8, len);
        let h2 = hash_memory_range(start as *const u8, len);
        assert_eq!(h1, h2, "text section hash should be stable");
    }
}
