pub struct ReplayWindow {
    last: u64,
    window: u128,
    initialized: bool,
}

impl ReplayWindow {
    pub fn new() -> Self {
        ReplayWindow { last: 0, window: 0, initialized: false }
    }

    pub fn from_saved(last_accepted: u64) -> Self {
        if last_accepted == 0 {
            Self::new()
        } else {
            ReplayWindow { last: last_accepted, window: u128::MAX, initialized: true }
        }
    }

    pub fn is_processed(&self, seq: u64) -> bool {
        if !self.initialized { return false; }
        if seq > self.last { return false; }
        if seq == self.last { return true; }
        let offset = self.last - seq;
        if offset > 128 { return true; }
        self.window & (1u128 << (offset - 1)) != 0
    }

    pub fn mark_processed(&mut self, seq: u64) {
        if !self.initialized {
            self.last = seq;
            self.window = 0;
            self.initialized = true;
            return;
        }
        if seq > self.last {
            let shift = seq - self.last;
            let shifted = if shift >= 128 { 0 } else { self.window << shift };
            let mark = if shift <= 128 { 1u128 << (shift - 1).min(127) } else { 0 };
            self.window = shifted | mark;
            self.last = seq;
        } else if seq < self.last {
            let offset = self.last - seq;
            if offset <= 128 {
                self.window |= 1u128 << (offset - 1);
            }
        }
    }

    pub fn last_accepted(&self) -> u64 {
        self.last
    }
}

impl Default for ReplayWindow {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_replay_rejected() {
        let mut w = ReplayWindow::new();
        assert!(!w.is_processed(1));
        w.mark_processed(1);
        assert!(w.is_processed(1));
        assert!(!w.is_processed(2));
    }

    #[test]
    fn out_of_order_accepted() {
        let mut w = ReplayWindow::new();
        w.mark_processed(10);
        w.mark_processed(12);
        assert!(!w.is_processed(11));
        w.mark_processed(11);
        assert!(w.is_processed(11));
    }

    #[test]
    fn too_old_rejected() {
        let mut w = ReplayWindow::new();
        w.mark_processed(200);
        assert!(w.is_processed(70));
        assert!(!w.is_processed(100));
    }

    #[test]
    fn from_saved_seals_window() {
        let w = ReplayWindow::from_saved(50);
        assert!(w.is_processed(50));
        assert!(w.is_processed(1));
        assert!(!w.is_processed(51));
    }
}
