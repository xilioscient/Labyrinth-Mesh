//! Build script: compile embedded eBPF C sources with clang.
//!
//! For each of the four XDP/TC programs the C source text is extracted from
//! the corresponding Rust source file (where it lives as a `pub const &str`),
//! written to OUT_DIR as a temporary `.c` file, compiled with
//! `clang -O2 -target bpf -c`, and stripped with `llvm-strip -g`.
//!
//! If clang is not present, or compilation fails, stub empty `.o` files are
//! created so the rest of the project compiles without XDP support.
//!
//! Header search path resolution
//! ─────────────────────────────
//! With `-target bpf`, clang does NOT use glibc / musl paths.  The kernel
//! and libbpf headers must be found via an explicit `-I` search path.
//! Standard locations (checked in order):
//!   /usr/include          — linux-api-headers (linux/*.h) + libbpf (bpf/*.h)
//!   /usr/local/include    — custom libbpf installs
//!
//! Additionally, several constants that are normally in `<linux/in.h>` or
//! `<linux/in6.h>` are injected with `-D` flags so that BPF sources that do
//! not include those headers still compile.

use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

/// Constants injected via `-D` that may be missing when compiling with
/// `-target bpf` (no glibc, limited kernel header subset).
/// Values are stable across all Linux architectures and kernel versions.
const BPF_DEFINES: &[&str] = &[
    // IP protocol numbers (linux/in.h)
    "IPPROTO_TCP=6",
    "IPPROTO_UDP=17",
    "IPPROTO_ICMP=1",
    "IPPROTO_IPV6=41",
    // POSIX clock IDs (linux/time.h) — bpf_timer_init uses CLOCK_MONOTONIC
    "CLOCK_REALTIME=0",
    "CLOCK_MONOTONIC=1",
    // TC actions (linux/pkt_cls.h) — TC_ACT_DROP was added in 5.8, may be absent
    "TC_ACT_OK=0",
    "TC_ACT_DROP=2",
    "TC_ACT_REDIRECT=7",
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/phase4/bpf_xdp.rs");
    println!("cargo:rerun-if-changed=src/v2/cover_traffic.rs");
    println!("cargo:rerun-if-changed=src/v2/xdp_tx.rs");
    println!("cargo:rerun-if-changed=src/v2/xdp_rx.rs");
    println!("cargo:rerun-if-changed=src/v2/bpf_lsm.rs");

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let out = Path::new(&out_dir);

    // Check if clang is available.
    let clang_ok = Command::new("clang")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !clang_ok {
        println!(
            "cargo:warning=clang not found — XDP/TC programs compiled as empty stubs. \
             Install LLVM/clang to enable kernel bypass."
        );
        for name in &["dmpot_xdp", "labyrinth_cover", "labyrinth_tx", "labyrinth_rx", "labyrinth_lsm"] {
            fs::write(out.join(format!("{name}.o")), b"").expect("write stub .o");
        }
        return;
    }

    // Locate include directories that contain `linux/bpf.h` and `bpf/bpf_helpers.h`.
    let include_dirs = find_bpf_include_dirs();
    if include_dirs.is_empty() {
        println!(
            "cargo:warning=BPF headers not found (install libbpf-dev or linux-headers) — \
             compiling XDP stubs"
        );
        for name in &["dmpot_xdp", "labyrinth_cover", "labyrinth_tx", "labyrinth_rx", "labyrinth_lsm"] {
            fs::write(out.join(format!("{name}.o")), b"").expect("write stub .o");
        }
        return;
    }

    // (rust_source_file, const_name, output_stem)
    let sources: &[(&str, &str, &str)] = &[
        ("src/phase4/bpf_xdp.rs",   "DMPOT_XDP_SOURCE",         "dmpot_xdp"),
        ("src/v2/cover_traffic.rs",  "COVER_TRAFFIC_XDP_SOURCE", "labyrinth_cover"),
        ("src/v2/xdp_tx.rs",         "LABYRINTH_TX_XDP_SOURCE",  "labyrinth_tx"),
        ("src/v2/xdp_rx.rs",         "LABYRINTH_RX_XDP_SOURCE",  "labyrinth_rx"),
        ("src/v2/bpf_lsm.rs",        "LABYRINTH_LSM_SOURCE",     "labyrinth_lsm"),
    ];

    for &(rs_file, const_name, stem) in sources {
        let c_src = match extract_c_source(rs_file, const_name) {
            Some(s) => s,
            None => {
                println!(
                    "cargo:warning=Could not extract {const_name} from {rs_file} — stub .o"
                );
                fs::write(out.join(format!("{stem}.o")), b"").unwrap();
                continue;
            }
        };

        let c_path = out.join(format!("{stem}.c"));
        let o_path = out.join(format!("{stem}.o"));

        fs::write(&c_path, c_src.as_bytes())
            .unwrap_or_else(|e| panic!("write {}: {e}", c_path.display()));

        // Build the clang argument list.
        let mut args: Vec<String> = vec![
            "-O2".into(),
            "-g".into(),
            "-target".into(), "bpf".into(),
            "-c".into(),
            c_path.to_str().unwrap().into(),
            "-o".into(),
            o_path.to_str().unwrap().into(),
        ];
        // Include dirs.
        for dir in &include_dirs {
            args.push("-I".into());
            args.push(dir.clone());
        }
        // Protocol-constant defines.
        for def in BPF_DEFINES {
            args.push(format!("-D{def}"));
        }

        let output = Command::new("clang").args(&args).output();

        match output {
            Ok(o) if o.status.success() => {
                // Strip debug info to keep .o compact. 
                /*
                let _ = Command::new("llvm-strip")
                    .args(["-g", o_path.to_str().unwrap()])
                    .status();
                */
                let size = fs::metadata(&o_path).map(|m| m.len()).unwrap_or(0);
                println!("cargo:warning={stem}.o compiled ({size} bytes)");
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                let log = format!("/tmp/bpf_build_{stem}.log");
                let _ = fs::write(&log, format!("exit: {}\nstderr:\n{}\n", o.status, stderr));
                println!(
                    "cargo:warning=clang failed for {stem} (exit {}) — stub .o — see {log}",
                    o.status,
                );
                fs::write(&o_path, b"").unwrap();
            }
            Err(e) => {
                println!("cargo:warning=clang error for {stem}: {e} — stub .o");
                fs::write(&o_path, b"").unwrap();
            }
        }
    }
}

/// Return the list of directories that should be passed as `-I` to clang for
/// BPF compilation.  We require at minimum:
///   <dir>/linux/bpf.h       — core BPF types
///   <dir>/bpf/bpf_helpers.h — BPF helper prototypes (libbpf)
fn find_bpf_include_dirs() -> Vec<String> {
    let candidates = [
        "/usr/include",
        "/usr/local/include",
        "/opt/homebrew/include",          // macOS Homebrew (no-op on Linux)
    ];

    let mut dirs = Vec::new();
    for &dir in &candidates {
        let has_bpf_h = Path::new(dir).join("linux/bpf.h").exists();
        let has_helpers = Path::new(dir).join("bpf/bpf_helpers.h").exists();
        if has_bpf_h || has_helpers {
            dirs.push(dir.to_string());
        }
    }

    // Only fall back to the kernel build tree if neither /usr/include nor
    // /usr/local/include already has linux/bpf.h. The kernel build headers
    // are not safe for BPF target compilation with modern clang (>=22) because
    // they pull in kernel-internal structs and asm/ paths that crash the frontend.
    let already_have_bpf_h = dirs.iter()
        .any(|d| Path::new(d).join("linux/bpf.h").exists());
    if !already_have_bpf_h {
        if let Ok(uname) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
            let kdir = format!("/usr/lib/modules/{}/build/include", uname.trim());
            if Path::new(&kdir).exists() {
                dirs.push(kdir);
            }
        }
    }

    dirs
}

/// Extract the C source text from a Rust file that contains:
/// ```rust,ignore
/// pub const CONST_NAME: &str = r#"…"#;
/// ```
fn extract_c_source(rs_file: &str, const_name: &str) -> Option<String> {
    let content = fs::read_to_string(rs_file).ok()?;
    let needle = format!("pub const {const_name}: &str = r#\"");
    let body_start = content.find(&needle)? + needle.len();
    let rest = &content[body_start..];
    let body_end = rest.find("\"#;")?;
    Some(rest[..body_end].to_string())
}
