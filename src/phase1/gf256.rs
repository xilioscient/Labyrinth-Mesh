use rand::Rng;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GF256(u8);

#[allow(clippy::should_implement_trait)]
impl GF256 {
    pub const ONE: Self = GF256(1);
    pub const ZERO: Self = GF256(0);

    #[inline] pub const fn new(value: u8) -> Self { GF256(value) }
    #[inline] pub const fn to_u8(self) -> u8 { self.0 }

    #[inline]
    pub fn add(self, other: GF256) -> GF256 {
        GF256(self.0 ^ other.0)
    }

    #[inline]
    pub fn sub(self, other: GF256) -> GF256 {
        GF256(self.0 ^ other.0)
    }

    #[inline]
    pub fn mul(self, other: GF256) -> GF256 {
        if self.0 == 0 || other.0 == 0 {
            return GF256(0);
        }
        let log_a = LOG_TABLE[self.0 as usize] as usize;
        let log_b = LOG_TABLE[other.0 as usize] as usize;
        GF256(EXP_TABLE[(log_a + log_b) % 255])
    }

    #[inline]
    pub fn xtime(self) -> GF256 {
        let hi = self.0 & 0x80;
        let mut result = self.0 << 1;
        if hi != 0 {
            result ^= 0x1B;
        }
        GF256(result)
    }

    #[inline]
    pub fn div(self, other: GF256) -> GF256 {
        if self.0 == 0 {
            return GF256(0);
        }
        debug_assert_ne!(other.0, 0, "division by zero in GF(2^8)");
        if other.0 == 0 {
            return GF256(0);
        }
        let log_a = LOG_TABLE[self.0 as usize] as usize;
        let log_b = LOG_TABLE[other.0 as usize] as usize;
        GF256(EXP_TABLE[(log_a + 255 - log_b) % 255])
    }

    #[inline]
    pub fn inv(self) -> GF256 {
        GF256::ONE.div(self)
    }

    #[inline]
    pub fn random<R: Rng>(rng: &mut R) -> Self {
        GF256(rng.gen_range(1..=255))
    }

    #[inline]
    pub fn random_coefficient<R: Rng>(rng: &mut R, k: usize) -> Vec<GF256> {
        (0..k).map(|_| GF256(rng.gen_range(1..=255))).collect()
    }
}

impl From<u8> for GF256 {
    #[inline] fn from(value: u8) -> Self { GF256(value) }
}

impl From<GF256> for u8 {
    #[inline] fn from(value: GF256) -> u8 { value.0 }
}

const EXP_TABLE: [u8; 512] = {
    let mut exp = [0u8; 512];
    let mut val = 1u8;
    let mut i = 0usize;
    while i < 255 {
        exp[i] = val;
        exp[i + 255] = val;
        let hi = val & 0x80;
        let xt = if hi != 0 { (val << 1) ^ 0x1Bu8 } else { val << 1 };
        val = xt ^ val;
        i += 1;
    }
    exp[255] = exp[0];
    exp[510] = exp[0];
    exp[511] = exp[1];
    exp
};

const LOG_TABLE: [u8; 256] = {
    let mut log = [0u8; 256];
    let mut val = 1u8;
    let mut i = 0usize;
    while i < 255 {
        log[val as usize] = i as u8;
        let hi = val & 0x80;
        let xt = if hi != 0 { (val << 1) ^ 0x1Bu8 } else { val << 1 };
        val = xt ^ val;
        i += 1;
    }
    log
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addition() {
        assert_eq!(GF256(0x57).add(GF256(0x83)), GF256(0x57 ^ 0x83));
    }

    #[test]
    fn test_multiplication_aes_vector() {
        let a = GF256(0x53);
        let inv_a = a.inv();
        assert_eq!(a.mul(inv_a), GF256(1), "a * a^-1 should be 1");
    }

    #[test]
    fn test_mul_commutativity() {
        let a = GF256(0x57);
        let b = GF256(0x83);
        assert_eq!(a.mul(b), b.mul(a));
    }

    #[test]
    fn test_div_inverse() {
        let a = GF256(0xAB);
        let b = GF256(0xCD);
        let q = a.div(b);
        assert_eq!(q.mul(b), a);
    }
}
