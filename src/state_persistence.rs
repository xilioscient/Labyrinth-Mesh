use std::net::SocketAddr;
use std::path::PathBuf;

fn state_dir() -> PathBuf {
    if let Ok(d) = std::env::var("LABYRINTH_STATE_DIR") {
        return PathBuf::from(d);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".labyrinth").join("state")
}

pub fn load_seq(listen: SocketAddr) -> u64 {
    let path = state_dir().join(format!("seq_{}.dat", listen.port()));
    match std::fs::read_to_string(&path) {
        Ok(s) => s.trim().parse::<u64>().unwrap_or_else(|_| {
            log::warn!("seq file {:?} contains invalid data — starting from 0", path);
            0
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => {
            log::warn!("could not read seq file {:?}: {e} — starting from 0", path);
            0
        }
    }
}

pub fn save_seq(listen: SocketAddr, seq: u64) {
    let dir = state_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        log::warn!("could not create state dir {:?}: {e}", dir);
        return;
    }
    let path = dir.join(format!("seq_{}.dat", listen.port()));
    if let Err(e) = std::fs::write(&path, seq.to_string()) {
        log::warn!("could not write seq file {:?}: {e}", path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_seq() {
        let addr: SocketAddr = "127.0.0.1:19988".parse().unwrap();
        let path = state_dir().join(format!("seq_{}.dat", addr.port()));
        let _ = std::fs::remove_file(&path);

        assert_eq!(load_seq(addr), 0, "should start at 0");
        save_seq(addr, 42);
        assert_eq!(load_seq(addr), 42, "should load saved value");
        save_seq(addr, 99999);
        assert_eq!(load_seq(addr), 99999, "should update on overwrite");

        let _ = std::fs::remove_file(&path);
    }
}
