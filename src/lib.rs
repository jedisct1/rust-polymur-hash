pub struct PolymurHash {
    k: u64,
    k2: u64,
    k7: u64,
    s: u64,
}

impl PolymurHash {
    pub fn new(seed: u128) -> Self {
        let k_seed = seed as u64;
        let s_seed = (seed >> 64) as u64;
        Self::from_u64x2_seed(k_seed, s_seed)
    }

    pub fn from_u64_seed(seed: u64) -> Self {
        let k_seed = Self::mix(seed.wrapping_add(POLYMUR_ARBITRARY3));
        let s_seed = Self::mix(seed.wrapping_add(POLYMUR_ARBITRARY4));
        Self::from_u64x2_seed(k_seed, s_seed)
    }

    pub fn from_u64x2_seed(mut k_seed: u64, s_seed: u64) -> Self {
        let s = s_seed ^ POLYMUR_ARBITRARY1;
        let mut pow37 = [0u64; 64];
        pow37[0] = 37;
        pow37[32] = 559096694736811184;
        for i in 0..31 {
            pow37[i + 1] = extrared611(red611(mul128(pow37[i], pow37[i])));
            pow37[i + 33] = extrared611(red611(mul128(pow37[i + 32], pow37[i + 32])));
        }

        loop {
            k_seed = k_seed.wrapping_add(POLYMUR_ARBITRARY2);
            let mut e = (k_seed >> 3) | 1;
            if e % 3 == 0 {
                continue;
            }
            if ((e % 5) & (e % 7)) == 0 {
                continue;
            }
            if ((e % 11) & (e % 13) & (e % 31)) == 0 {
                continue;
            }
            if ((e % 41) & (e % 61) & (e % 151) & (e % 331) & (e % 1321)) == 0 {
                continue;
            }
            let (mut ka, mut kb): (u64, u64) = (1, 1);
            let mut i: usize = 0;
            while e > 0 {
                if (e & 1) != 0 {
                    ka = extrared611(red611(mul128(ka, pow37[i])));
                }
                if (e & 2) != 0 {
                    kb = extrared611(red611(mul128(kb, pow37[i + 1])));
                }
                e >>= 2;
                i += 2;
            }
            let k = extrared611(red611(mul128(ka, kb)));

            let k = extrared611(k);
            let k2 = extrared611(red611(mul128(k, k)));
            let k3 = red611(mul128(k, k2));
            let k4 = red611(mul128(k2, k2));
            let k7 = extrared611(red611(mul128(k3, k4)));
            if k7 < (1_u64 << 60) - (1_u64 << 56) {
                return Self { k, k2, k7, s };
            }
        }
    }

    pub fn hash_with_tweak(&self, buf: impl AsRef<[u8]>, tweak: u64) -> u64 {
        let h = self.poly1611(buf, tweak);
        Self::mix(h).wrapping_add(self.s)
    }

    pub fn hash(&self, buf: impl AsRef<[u8]>) -> u64 {
        let h = self.poly1611(buf, 0);
        Self::mix(h).wrapping_add(self.s)
    }

    fn poly1611(&self, buf: impl AsRef<[u8]>, tweak: u64) -> u64 {
        let mut buf = buf.as_ref();
        let mut m = [0u64; 7];
        let mut poly_acc = tweak;
        if buf.len() <= 7 {
            m[0] = le_u64_0_8(buf);
            return poly_acc.wrapping_add(red611(mul128(
                self.k.wrapping_add(m[0]),
                self.k2.wrapping_add(buf.len() as u64),
            )));
        }

        let k3 = red611(mul128(self.k, self.k2));
        let k4 = red611(mul128(self.k2, self.k2));
        if buf.len() >= 50 {
            let k5 = extrared611(red611(mul128(self.k, k4)));
            let k6 = extrared611(red611(mul128(self.k2, k4)));
            let k3 = extrared611(k3);
            let k4 = extrared611(k4);
            let mut h: u64 = 0;
            loop {
                for i in 0..7 {
                    let mut tmp = [0u8; 8];
                    tmp.copy_from_slice(&buf[7 * i..][..8]);
                    m[i] = u64::from_le_bytes(tmp) & 0x00ffffffffffffff;
                }
                let t0 = mul128(self.k + m[0], k6 + m[1]);
                let t1 = mul128(self.k2 + m[2], k5 + m[3]);
                let t2 = mul128(k3 + m[4], k4 + m[5]);
                let t3 = mul128(h + m[6], self.k7);
                let s = t0.wrapping_add(t1).wrapping_add(t2).wrapping_add(t3);
                h = red611(s);
                buf = &buf[49..];
                if buf.len() < 50 {
                    break;
                }
            }
            let k14 = red611(mul128(self.k7, self.k7));
            let hk14 = red611(mul128(extrared611(h), k14));
            poly_acc += extrared611(hk14);
        }

        if buf.len() >= 8 {
            let mut tmp = [0u8; 8];
            tmp.copy_from_slice(&buf[..8]);
            m[0] = u64::from_le_bytes(tmp) & 0x00ffffffffffffff;
            tmp.copy_from_slice(&buf[(buf.len() - 7) / 2..][0..8]);
            m[1] = u64::from_le_bytes(tmp) & 0x00ffffffffffffff;
            tmp.copy_from_slice(&buf[buf.len() - 8..][0..8]);
            m[2] = u64::from_le_bytes(tmp) >> 8;
            let t0 = mul128(self.k2 + m[0], self.k7.wrapping_add(m[1]));
            let t1 = mul128(self.k + m[2], k3.wrapping_add(buf.len() as _));
            if buf.len() <= 21 {
                return poly_acc + red611(t0.wrapping_add(t1));
            }
            tmp.copy_from_slice(&buf[7..][0..8]);
            m[3] = u64::from_le_bytes(tmp) & 0x00ffffffffffffff;
            tmp.copy_from_slice(&buf[14..][0..8]);
            m[4] = u64::from_le_bytes(tmp) & 0x00ffffffffffffff;
            tmp.copy_from_slice(&buf[buf.len() - 21..][0..8]);
            m[5] = u64::from_le_bytes(tmp) & 0x00ffffffffffffff;
            tmp.copy_from_slice(&buf[buf.len() - 14..][0..8]);
            m[6] = u64::from_le_bytes(tmp) & 0x00ffffffffffffff;
            let t0r = red611(t0);
            let t2 = mul128(self.k2 + m[3], self.k7 + m[4]);
            let t3 = mul128(t0r + m[5], k4 + m[6]);
            let s = t1.wrapping_add(t2).wrapping_add(t3);
            return poly_acc + red611(s);
        }

        m[0] = le_u64_0_8(buf);
        poly_acc.wrapping_add(red611(mul128(
            self.k.wrapping_add(m[0]),
            self.k2.wrapping_add(buf.len() as _),
        )))
    }

    #[inline(always)]
    fn mix(mut x: u64) -> u64 {
        x ^= x >> 32;
        x = x.wrapping_mul(0xe9846af9b1a615d);
        x ^= x >> 32;
        x = x.wrapping_mul(0xe9846af9b1a615d);
        x ^= x >> 28;
        x
    }
}

const POLYMUR_P611: u64 = 0x1fffffffffffffff;
const POLYMUR_ARBITRARY1: u64 = 0x6a09e667f3bcc908;
const POLYMUR_ARBITRARY2: u64 = 0xbb67ae8584caa73b;
const POLYMUR_ARBITRARY3: u64 = 0x3c6ef372fe94f82b;
const POLYMUR_ARBITRARY4: u64 = 0xa54ff53a5f1d36f1;

#[inline(always)]
fn mul128(a: u64, b: u64) -> u128 {
    (a as u128) * (b as u128)
}

#[inline(always)]
fn red611(x: u128) -> u64 {
    ((x as u64) & POLYMUR_P611) + ((x >> 61) as u64)
}

#[inline(always)]
fn extrared611(x: u64) -> u64 {
    (x & POLYMUR_P611) + (x >> 61)
}

#[inline(always)]
fn le_u64_0_8(buf: &[u8]) -> u64 {
    let len = buf.len();
    if len < 4 {
        if len == 0 {
            return 0;
        }
        let mut v = buf[0] as u64;
        v |= (buf[len / 2] as u64) << (8 * (len / 2));
        v |= (buf[len - 1] as u64) << (8 * (len - 1));
        return v;
    }

    let mut tmp = [0u8; 4];
    tmp.copy_from_slice(&buf[0..4]);
    let lo = u32::from_le_bytes(tmp) as u64;
    tmp.copy_from_slice(&buf[len - 4..][..4]);
    let hi = u32::from_le_bytes(tmp) as u64;

    lo | (hi << (8 * (len - 4)))
}

#[test]
fn test() {
    let mut t = 0;

    for i in 0..1000 {
        let hasher = PolymurHash::new(i as u128 * 0x419a02900419a02900419a02900419);
        let mut size = 1;
        loop {
            let mut m = vec![0u8; size];
            m.iter_mut().for_each(|x| *x = i as u8);
            let res = hasher.hash(&m);
            t += res as u128;
            debug_assert!(t != 0);
            if size >= 65536 {
                break;
            }
            size *= 2;
        }

        let hasher = PolymurHash::from_u64_seed(i * 0x419a02900419a0);
        let mut size = 1;
        loop {
            let mut m = vec![0u8; size];
            m.iter_mut().for_each(|x| *x = i as u8);
            let res = hasher.hash(&m);
            t += res as u128;
            debug_assert!(t != 0);
            if size >= 65536 {
                break;
            }
            size *= 3;
        }
    }

    assert_eq!(t, 0x38e2c3f5e905d22cf8d4);
}
