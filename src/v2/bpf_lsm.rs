pub const LABYRINTH_LSM_SOURCE: &str = r#"
// SPDX-License-Identifier: GPL-2.0
// Labyrinth-Mesh eBPF LSM — kernel-enforced process security policy
// Requires: Linux >= 5.7, CONFIG_BPF_LSM=y, lsm=bpf in kernel cmdline

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef EPERM
#define EPERM 1
#endif

#ifndef AF_INET
#define AF_INET   2
#endif
#ifndef AF_INET6
#define AF_INET6  10
#endif
#ifndef AF_UNIX
#define AF_UNIX   1
#endif
#ifndef AF_XDP
#define AF_XDP    44
#endif
#ifndef AF_NETLINK
#define AF_NETLINK 16
#endif

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} policy_active SEC(".maps");

/*
 * Block all ptrace attempts when the LSM policy is active.
 * ptrace_access_check is called when a tracer tries to access any tracee.
 * We block all ptrace unconditionally while the policy flag is set —
 * appropriate for a hardened container/daemon deployment.
 * The child parameter is a forward-declared struct task_struct; we do NOT
 * access its fields directly to avoid requiring BTF / vmlinux.h at compile time.
 */
SEC("lsm/ptrace_access_check")
int BPF_PROG(lsm_ptrace_check, struct task_struct *child, unsigned int mode)
{
    __u32 zero = 0;
    __u32 *active = bpf_map_lookup_elem(&policy_active, &zero);
    if (!active || *active == 0)
        return 0;
    return -EPERM;
}

SEC("lsm/socket_create")
int BPF_PROG(lsm_socket_create, int family, int type, int protocol, int kern)
{
    if (kern)
        return 0;
    if (family == AF_INET   ||
        family == AF_INET6  ||
        family == AF_UNIX   ||
        family == AF_XDP    ||
        family == AF_NETLINK)
        return 0;
    return -EPERM;
}

char LICENSE[] SEC("license") = "GPL";
"#;

#[cfg(target_os = "linux")]
pub struct LsmHandle {
    _bpf: Box<aya::Bpf>,
}

#[cfg(target_os = "linux")]
pub fn load_lsm_policy(bpf_obj: &[u8]) -> Option<LsmHandle> {
    use aya::{programs::Lsm, Bpf, BtfError};

    let btf = match aya::Btf::from_sys_fs() {
        Ok(b) => b,
        Err(e) => {
            log::debug!("BTF unavailable: {e} — LSM policy not loaded");
            return None;
        }
    };

    let mut bpf = match Bpf::load(bpf_obj) {
        Ok(b) => b,
        Err(e) => {
            log::debug!("LSM bpf load: {e}");
            return None;
        }
    };

    for name in ["lsm_ptrace_check", "lsm_socket_create"] {
        let prog: &mut Lsm = match bpf.program_mut(name) {
            Some(p) => match p.try_into() {
                Ok(p) => p,
                Err(e) => {
                    log::debug!("LSM {name} try_into: {e}");
                    return None;
                }
            },
            None => {
                log::debug!("LSM program {name} not found");
                return None;
            }
        };
        if let Err(e) = prog.load(name, &btf) {
            log::debug!("LSM {name} load: {e}");
            return None;
        }
        if let Err(e) = prog.attach() {
            log::debug!("LSM {name} attach: {e}");
            return None;
        }
    }

    let tgid = unsafe { libc::getpid() };
    if let Some(map) = bpf.map_mut("policy_active") {
        use aya::maps::Array;
        if let Ok(mut arr) = Array::<_, u32>::try_from(map) {
            let _ = arr.set(0, 1u32, 0);
        }
    }
    let _ = tgid;

    log::info!("eBPF LSM policy active (tgid={tgid})");
    Some(LsmHandle { _bpf: Box::new(bpf) })
}

#[cfg(not(target_os = "linux"))]
pub struct LsmHandle;

#[cfg(not(target_os = "linux"))]
pub fn load_lsm_policy(_obj: &[u8]) -> Option<LsmHandle> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lsm_source_non_empty() {
        assert!(LABYRINTH_LSM_SOURCE.len() > 200);
        assert!(LABYRINTH_LSM_SOURCE.contains("ptrace_access_check"));
        assert!(LABYRINTH_LSM_SOURCE.contains("socket_create"));
        assert!(LABYRINTH_LSM_SOURCE.contains("policy_active"));
    }
}
