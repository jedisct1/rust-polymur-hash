#![doc = include_str!("../README.md")]
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::hash::Hasher;

/// A fast, non-cryptographic hash function based on polynomial evaluation.
///
/// PolymurHash is a universal hash function that provides excellent performance
/// and good distribution properties. It's particularly well-suited for hash tables
/// and other non-cryptographic applications.
///
/// # Examples
///
/// Basic usage:
/// ```
/// use polymur_hash::PolymurHash;
///
/// let hasher = PolymurHash::new(0);
/// let data = b"Hello, world!";
/// let hash = hasher.hash(data);
/// ```
///
/// Using with a custom seed:
/// ```
/// use polymur_hash::PolymurHash;
///
/// let seed = 0xDEADBEEFCAFEBABE_u64;
/// let hasher = PolymurHash::from_u64_seed(seed);
/// let hash = hasher.hash(b"Some data");
/// ```
///
/// Hash with tweak for additional randomization:
/// ```
/// use polymur_hash::PolymurHash;
///
/// let hasher = PolymurHash::new(42);
/// let tweak = 0x123456789ABCDEF0;
/// let hash = hasher.hash_with_tweak(b"Data", tweak);
/// ```
#[derive(Clone, Debug)]
pub struct PolymurHash {
    k: u64,
    k2: u64,
    k7: u64,
    s: u64,
}

impl PolymurHash {
    /// Creates a new PolymurHash instance from a 128-bit seed.
    ///
    /// # Arguments
    ///
    /// * `seed` - A 128-bit seed value to initialize the hasher
    ///
    /// # Examples
    ///
    /// ```
    /// use polymur_hash::PolymurHash;
    ///
    /// let hasher = PolymurHash::new(0x123456789ABCDEF0123456789ABCDEF0);
    /// ```
    pub fn new(seed: u128) -> Self {
        let k_seed = seed as u64;
        let s_seed = (seed >> 64) as u64;
        Self::from_u64x2_seed(k_seed, s_seed)
    }

    /// Creates a new PolymurHash instance from a 64-bit seed.
    ///
    /// This method expands the 64-bit seed into the required internal state.
    ///
    /// # Arguments
    ///
    /// * `seed` - A 64-bit seed value to initialize the hasher
    ///
    /// # Examples
    ///
    /// ```
    /// use polymur_hash::PolymurHash;
    ///
    /// let hasher = PolymurHash::from_u64_seed(0xDEADBEEF);
    /// ```
    pub fn from_u64_seed(seed: u64) -> Self {
        let k_seed = Self::mix(seed.wrapping_add(POLYMUR_ARBITRARY3));
        let s_seed = Self::mix(seed.wrapping_add(POLYMUR_ARBITRARY4));
        Self::from_u64x2_seed(k_seed, s_seed)
    }

    /// Creates a new PolymurHash instance from two 64-bit seeds.
    ///
    /// This provides direct control over the key and state seeds.
    ///
    /// # Arguments
    ///
    /// * `k_seed` - Seed for the polynomial key generation
    /// * `s_seed` - Seed for the final mixing state
    ///
    /// # Examples
    ///
    /// ```
    /// use polymur_hash::PolymurHash;
    ///
    /// let hasher = PolymurHash::from_u64x2_seed(0x12345678, 0x9ABCDEF0);
    /// ```
    pub fn from_u64x2_seed(mut k_seed: u64, s_seed: u64) -> Self {
        let s = s_seed ^ POLYMUR_ARBITRARY1;
        let mut pow37 = [0u64; 64];
        pow37[0] = 37;
        pow37[32] = 559096694736811184;
        for i in 0..31 {
            pow37[i + 1] = extrared611(red611(mul128(pow37[i], pow37[i])));
            pow37[i + 33] = extrared611(red611(mul128(pow37[i + 32], pow37[i + 32])));
        }

        'retry: loop {
            k_seed = k_seed.wrapping_add(POLYMUR_ARBITRARY2);
            let mut e = (k_seed >> 3) | 1;
            const PRIMES: [u64; 11] = [3, 5, 7, 11, 13, 31, 41, 61, 151, 331, 1321];
            for &p in PRIMES.iter() {
                if (e % p) == 0 {
                    continue 'retry;
                }
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
            let k = extrared611(extrared611(red611(mul128(ka, kb))));
            let k2 = extrared611(red611(mul128(k, k)));
            let k3 = red611(mul128(k, k2));
            let k4 = red611(mul128(k2, k2));
            let k7 = extrared611(red611(mul128(k3, k4)));
            if k7 < (1_u64 << 60) - (1_u64 << 56) {
                return Self { k, k2, k7, s };
            }
        }
    }

    /// Computes the hash of the given data with an additional tweak value.
    ///
    /// The tweak allows for additional randomization without changing the key.
    /// This is useful for applications that need multiple independent hash values
    /// from the same key.
    ///
    /// # Arguments
    ///
    /// * `buf` - The data to hash
    /// * `tweak` - An additional value to mix into the hash
    ///
    /// # Examples
    ///
    /// ```
    /// use polymur_hash::PolymurHash;
    ///
    /// let hasher = PolymurHash::new(0);
    /// let data = b"Hello, world!";
    /// let hash1 = hasher.hash_with_tweak(data, 1);
    /// let hash2 = hasher.hash_with_tweak(data, 2);
    /// assert_ne!(hash1, hash2); // Different tweaks produce different hashes
    /// ```
    pub fn hash_with_tweak(&self, buf: impl AsRef<[u8]>, tweak: u64) -> u64 {
        let h = self.poly1611(buf, tweak);
        Self::mix(h).wrapping_add(self.s)
    }

    /// Computes the hash of the given data.
    ///
    /// # Arguments
    ///
    /// * `buf` - The data to hash
    ///
    /// # Returns
    ///
    /// A 64-bit hash value
    ///
    /// # Examples
    ///
    /// ```
    /// use polymur_hash::PolymurHash;
    ///
    /// let hasher = PolymurHash::new(0);
    /// let hash = hasher.hash(b"Hello, world!");
    /// ```
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
            return poly_acc.wrapping_add(red611(s));
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

/// A hasher that implements the core library's `Hasher` trait.
///
/// This allows PolymurHash to be used with HashMap and HashSet, even in no_std environments
/// (requires `alloc` for the internal buffer).
///
/// # Examples
///
/// Using with HashMap:
/// ```
/// # #[cfg(feature = "std")] {
/// use std::collections::HashMap;
/// use std::hash::BuildHasherDefault;
/// use polymur_hash::PolymurHasher;
///
/// type PolymurHashMap<K, V> = HashMap<K, V, BuildHasherDefault<PolymurHasher>>;
///
/// let mut map: PolymurHashMap<String, i32> = PolymurHashMap::default();
/// map.insert("hello".to_string(), 42);
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct PolymurHasher {
    hasher: PolymurHash,
    buffer: Vec<u8>,
}

impl Default for PolymurHasher {
    fn default() -> Self {
        Self {
            hasher: PolymurHash::new(0),
            buffer: Vec::new(),
        }
    }
}

impl PolymurHasher {
    /// Creates a new PolymurHasher with a specific seed.
    pub fn with_seed(seed: u128) -> Self {
        Self {
            hasher: PolymurHash::new(seed),
            buffer: Vec::new(),
        }
    }
}

impl Hasher for PolymurHasher {
    fn finish(&self) -> u64 {
        self.hasher.hash(&self.buffer)
    }

    fn write(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    fn write_u8(&mut self, i: u8) {
        self.buffer.push(i);
    }

    fn write_u16(&mut self, i: u16) {
        self.buffer.extend_from_slice(&i.to_le_bytes());
    }

    fn write_u32(&mut self, i: u32) {
        self.buffer.extend_from_slice(&i.to_le_bytes());
    }

    fn write_u64(&mut self, i: u64) {
        self.buffer.extend_from_slice(&i.to_le_bytes());
    }

    fn write_u128(&mut self, i: u128) {
        self.buffer.extend_from_slice(&i.to_le_bytes());
    }

    fn write_usize(&mut self, i: usize) {
        self.buffer.extend_from_slice(&i.to_le_bytes());
    }

    fn write_i8(&mut self, i: i8) {
        self.write_u8(i as u8);
    }

    fn write_i16(&mut self, i: i16) {
        self.write_u16(i as u16);
    }

    fn write_i32(&mut self, i: i32) {
        self.write_u32(i as u32);
    }

    fn write_i64(&mut self, i: i64) {
        self.write_u64(i as u64);
    }

    fn write_i128(&mut self, i: i128) {
        self.write_u128(i as u128);
    }

    fn write_isize(&mut self, i: isize) {
        self.write_usize(i as usize);
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edge_cases() {
        let hasher = PolymurHash::new(0);

        // Empty input
        assert_eq!(hasher.hash(b""), hasher.hash([]));

        // Single byte
        assert_ne!(hasher.hash(b"a"), hasher.hash(b"b"));

        // Same data with different seeds produces different hashes
        let hasher2 = PolymurHash::new(0xDEADBEEFCAFEBABE);
        assert_ne!(hasher.hash(b"test"), hasher2.hash(b"test"));

        // Verify tweaks work correctly
        let data = b"test data";
        assert_ne!(
            hasher.hash_with_tweak(data, 0),
            hasher.hash_with_tweak(data, 1)
        );
        assert_eq!(hasher.hash(data), hasher.hash_with_tweak(data, 0));
    }

    #[test]
    fn test_different_lengths() {
        let hasher = PolymurHash::new(42);

        // Test various lengths to hit different code paths
        let lengths = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 15, 16, 31, 32, 48, 49, 50, 63, 64, 127, 128, 255, 256,
            1023, 1024,
        ];

        for &len in &lengths {
            let data = vec![0xABu8; len];
            let hash = hasher.hash(&data);

            // Verify that changing any byte changes the hash
            if len > 0 {
                let mut modified = data.clone();
                modified[len / 2] = 0xCD;
                assert_ne!(
                    hash,
                    hasher.hash(&modified),
                    "Hash collision at length {}",
                    len
                );
            }
        }
    }

    #[test]
    fn test_seed_variants() {
        let data = b"test data for seed variants";

        // Test that different seed creation methods with same values produce same results
        let seed_high = 0x123456789ABCDEF0_u64;
        let seed_low = 0x0123456789ABCDEF0_u64;
        let seed_128 = ((seed_high as u128) << 64) | (seed_low as u128);
        let h1 = PolymurHash::new(seed_128);
        let h2 = PolymurHash::from_u64x2_seed(seed_low, seed_high);

        // These should produce the same hash since they use the same seed values
        assert_eq!(h1.hash(data), h2.hash(data));

        // Different seeds should produce different hashes
        let h3 = PolymurHash::from_u64_seed(0x123456789ABCDEF0);
        assert_ne!(h1.hash(data), h3.hash(data));
    }

    #[test]
    fn test_hasher_trait() {
        use core::hash::{Hash, Hasher as _};

        let mut hasher1 = PolymurHasher::default();
        let mut hasher2 = PolymurHasher::default();

        // Hash the same string using the Hash trait
        "Hello, world!".hash(&mut hasher1);
        "Hello, world!".hash(&mut hasher2);

        assert_eq!(hasher1.finish(), hasher2.finish());

        // Test integer hashing
        let mut hasher3 = PolymurHasher::default();
        let mut hasher4 = PolymurHasher::default();

        42u32.hash(&mut hasher3);
        hasher4.write_u32(42);

        assert_eq!(hasher3.finish(), hasher4.finish());
    }

    #[test]
    fn test_hashmap_integration() {
        use core::hash::BuildHasherDefault;
        use std::collections::HashMap;

        type PolymurHashMap<K, V> = HashMap<K, V, BuildHasherDefault<PolymurHasher>>;

        let mut map: PolymurHashMap<String, i32> = PolymurHashMap::default();

        map.insert("foo".to_string(), 42);
        map.insert("bar".to_string(), 123);
        map.insert("baz".to_string(), 456);

        assert_eq!(map.get("foo"), Some(&42));
        assert_eq!(map.get("bar"), Some(&123));
        assert_eq!(map.get("baz"), Some(&456));
        assert_eq!(map.get("qux"), None);
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

        assert_eq!(t, 0x38e01175b44e95e6e0f6);
    }

    #[test]
    fn test_vectors() {
        // Tests from https://github.com/orlp/polymur-hash/blob/a7cc6b00051b4b579d718a4f26428098580029ec/test.c#L7

        const POLYMUR_TEST_STRINGS: [&str;100] = [
    "",
    "i",
    "es",
    "vca",
    "bdxa",
    "bbbmc",
    "vn5719",
    "lpvif62",
    "1fcjgark",
    "1jlz2nr6w",
    "g4q6ebxvod",
    "ehiybujo2n1",
    "6u2990ulzi7m",
    "c3xcb4ew8v678",
    "bhcaqrm221pea1",
    "oyl3iqxqr85eeve",
    "b41kacwmnim8rup5",
    "563ug64z3zdtlj438",
    "3spvl57qfg4udw2l3s",
    "297r1bqesqdhb3jd50g",
    "kbc5btot9x1fqslddmha",
    "r0vxw6kk8tc6pk0oxnr6m",
    "wkgmmma9icgky3bnj5bjir",
    "5eslfmq1w3i7wvd89ls7nvf",
    "40ytv0ye8cq49no6ys1pdrot",
    "p3mbto6bl36g3cx9sstyiugsd",
    "m0ylpn0wh5krbebs0j5trzgveb",
    "qsy8gpheo76vb8g0ivaojk1zgk4",
    "dwqf8tpad4k3x69sah7pstrg8zxx",
    "ls3zrsjf1o3cr5sjy7dzp98198i3y",
    "xvhvx3wbzer9b7kr4jqg2ok9e3mv5d",
    "yapzlwab361wvh0xf1rydn5ynqx8cz0",
    "nj56v1p9dc7qdmcn2wksfg5kic1uegm2",
    "hlebeoafjqtqxfwd9ge94z3ofk88c4a5x",
    "6li8qyu0n8nwoggm4hqzqdamem5barzjyw",
    "wj7sp7dhpfapsd8w2nzn8s7xtnro9g45x7t",
    "ahio6so1x30oziw54ux5iojjdfvkwpw2v14d",
    "wm6yacnl6k3kj3c6i1jeajuwmquv9yujms0wq",
    "kzs6xfhmc4ifmstnekcze4y1l83ddvxust2r0o",
    "ckamexupx7cmsuza9nssw6n45e7go4s3osr1903",
    "nob5bj9tok346dg62jbfjfrhg5l6itsno2hkhfru",
    "vgo0ko42n5jvrvnv3ddpwg8h7gkqoxbllv2fdy0no",
    "dgs47djqzq3czo0i0v1u3d3x72vtvi3w2tsf9shx6k",
    "8vjrw7jz90kf969txb5qrh0u5332zf5epsp8aes4aqh",
    "3ni9vtqiq6vnxipfa2wag8vfwq2nyce1kgq5nj3razx9",
    "u29xjkod6rtu5j5tlwkydt9khih6o2do84q6ukwlr00xf",
    "yxxubvyxuusw827qctqr6tmm69rij5ex2zk1etps8qh61e",
    "p7lh4mvadnp6uw0vt7bnzcbv1wjswuuc6gjmu684yznx8lp",
    "8c27lotvnab6ra8pq9aon0w30ydyulesinew3akqrhhmm39e",
    "ttipbm97gpk7tiog1doncalwgpb7alk16dapga2ekzjt59pv6",
    "mbbtplseab2mgtgh8uwlhbmdrwxae3tc2mtf98bwuhmz4bfjnf",
    "shnjeydnj8awrkz3rd69wqqd9srie4eo6gc6ylhz2ouv4t4qbar",
    "lckl12agnpr6q5053h9v38lyk71emkvwdzrv0ic3a4a4pn3w3o4x",
    "7927wqjo5jiecfk0bbtt6065j5jl7x0vv1mcxxxl0j1oatrom44zp",
    "bajk3ff026vx0u7o5d7ry7w7n07sqdy4urv4psr79jp13e0mxsks1r",
    "en6j5o90gmgj7ssbz6jv3kzdsbzczu518c3zmezkp02rtvo1s88n9pu",
    "58fkwyf44tjnrytgplb5qfbvlwtav3zutxowoor2mklkr2up4nzpefos",
    "cep02qfl6swv1j3mwy5kprm4p8drszchufrkyr5ejbtzgu5cti6fqab5c",
    "lr5q0p1dljga8h4vruy1doa79hntwbdyolnh1fbe3phfk7f5rgs4815foj",
    "hmnjq6h1sslivjzmbxbpqba29f6kvbea6n6c4sanm40nzmrxt8hm61ooq3e",
    "ae43xxu1mqrbynmctit7m4wf02o0kf2vvw1l3y51n4cu5v5ba4dia67wf0bo",
    "qz9ye2ur849obmm23d5tnfc3xdaeajil0gm2pz8z9psedj50h5hcwbcn8n2lo",
    "w3xar1pzaff7fhyw6cshdgechm2pj1ebwrbkdct5xfbmxskr3937dodvky62i8",
    "ypy5k197quc9ypqoj9kle2eky307jnnd7tu52hqhn6mo7jj1fvmi42kkgq40iy6",
    "k1bp6qwiul8fnd6rfe42ge6gskk0jkr9fjgmuujey3kn8ie88h9qguw2gboo7i80",
    "begb64jkzfujx7ch3ain1iixidnbhcbcglcuf7nys8eansnkewtiye9xv7s2ksuev",
    "vf5d8vdjtwp5vo1ocb274nkl6h8vg97m4v5htfwv02tj9u68vdnteeim6q0zllxflj",
    "dcg9osulcdw9sqaue4cfz6k990vpstoxmvwbxzhzichkhdujy36v556u7oxug51gdup",
    "1rtgdtibcaos4ebzrbl1fkjahtbel6fyqipuu8lxfrwnggjr8wgoscfxp46wv9wjk315",
    "r27qj342zj4anpkqpr9yqo7udnldwiqqpq667zzjgw33yia3wt2p6t221onq4pvfaywbj",
    "2yzxskad06pt9zvjmiobfz12a3q6wqgpj4450rpxj0jvjk3cx39qo6cbpukxqsy6idqd40",
    "813zultj26k3gn6gibolpuozgaxu8exfatf4iqqugelcf6k8dnzvsjb9s25g3gyess2uscc",
    "i4p0jkxf3ajc02x330y3tg8l521fzootabn53ovru20ph3n17hfygaz1axs61jxipz6jac5z",
    "5bk748kkvww7toeyeueukk2qyin2o5ohnvj7l1cqs9zgy92n6ujxg6sxdjw81hfd29nzrb4kh",
    "uvhy62avo1wqms1rrtefth84xhnv1a59aez6r4xq0pla74036o3vznihxexwydnfjojmk6ipl6",
    "0t0dlfopg27cqv1xp4qfgwdlivvgqz204hkh5ianbb4abgk0yjolcwhhitrcksha5s6otmps0hd",
    "vrbhcwrmn5xbq8f518ntvmaeg89n7nh1uxebfsmd7smoog3k2w12zv0px32pf4b78er5f3pgy7b9",
    "x5bmnefocbtxm8avt22ekuy5hcdyxh86is5fnns9ycfm7o25x9frwv9kfv2ohyd3txlc8zlg5rjjx",
    "ttfrgnfvvj552vjymrqqd1yjlyff7vkffprnvu3co4vuah8y0s56tziih3yowm64ja810gb1sgk0um",
    "a66t43i9vrr3cmg5qf52akuk8bxl4rm3i86rm7h5brjou9k2egrzy3h19hh8kqr2queyvrwb673qikj",
    "mfuwhbvd88n21obpmwx273mmeqiz98qfmb04z0ute54kc1d9bbdyfbx2sc4em6t4pfektm05qs7bgc9z",
    "x8wbm0kjpyua8wpgsejgxc06geitm1c0bxihvcwnxnif63dj7cygzk7led0z49ol6zf2xwcmf99n4osip",
    "fvba43myr0ozab882crozdz0zx4lfl2h7xe2phfqte97g58fake2fzi87mpftz9qdmt45gm79xl43k1hji",
    "wnr0pz08rm3j65b7pl116l59pxy6prnydf9xod1qdi3hp3lod2vuzy1v7gt2g72sejaomn5u53daxjrr9xk",
    "bwo7nfqda6w56voyvg1nr7vkq61zi7gy0aggn6pic3gup7uy18zzsc7y5yz3ptvp5cd53i95dj521k4n6n7t",
    "mromebynw459uydhhgcgrate6hnst5srng9knfjc02vtg1vywok3rdbw935pf1qwghnh0nibyb60l9elkmajg",
    "59dcjawsd4kjjcceco3hphizua88l0qtrfd000iam3rnb4tmy6kzf5bhkc9ud1hsg3dd53tlsxarcl0n59081h",
    "odgdgfkwcpz0zjcwsz9is5h4nhebzht7fqa1b4g8e2snb6bn5hu3ixyd2pk1ey5g3eab0m3aoknfi9ctkpxz07j",
    "0ljqm7r10ns2pjo8x69oi0zuqss9y7301yd6rmex8djwrbqmvh2mbwscgj9pmrgul5ao0tvpefpe5a9cac5xbdwb",
    "b449ak3ihp8tdrbteffru5vboeh1z63c55at3qz70p13d2fim50q8i06zjyb53i4gqzunx6rsl07jxjd9g77me1ww",
    "oqzf6c40snvrjz4v0f4h8p0ozjfy1y4xihxwaz16vbxf3qsa805xodw8z5xq3hb7dag8fnxtlsc62150kk253i3buj",
    "2eicp9a5aq2uycq55y7rsixlg3pfk7gyin65fghf03kks18dixbckxmbv5xnhyrir7qm8maz4rk2bi3zs9chidlhehf",
    "7k1wyjs6fxss4e0ywqfurgop6f7y7e97f3mr5hnb0hlhqkqbqvi1e1z3qfyxc3te75r67fc4h9li06rl9zadg3v9zmz6",
    "k3e403zdtia8i0gpodm00yaujr1w474bh3985o3csbfjp3dll4t98i5lesloo6rqjec2aycb3ttx1t6lg0cl9hrjkgheb",
    "2fv8zdl1ljmpjbvaan0nt99tra48yjmc5pv91n1c5l8qp5pv77zwsx75ouay7bmgy2tjc1aazyu5zj7oimesavv9n2h7ky",
    "ghxs7uejpzpbxjsdmc2w9fabrg4j4pwwbn0wjxux2luk1k0ciror4gcvww18e610u2wpczuwrcphy2xr1129vweqhhgitge",
    "vk7wfi9hhi0j9n2grs8rxgq68kw54dbdviuxnvtwgz77h0qkbzqw7pgm7zgn21cxlxnyzigeyz2rzrj3awloq86tqe60e070",
    "d1aot9216s547uk1rg651iscb1bjpgth5j4f6arx1902npcykk8niz3ffpbed47idgzvt4u59fyi5e0e2afpjb5gjk4rysn8j",
    "2jef2xl4o9yub0z6jnxu8gm87g9iv9zdtu9yolvxtensjrtgplnmnuhz43nsxztk8s936k6eruckkiwc5hnch4qdzft093986x",
    "oo70ed77jci4bgodhnyf37axrx4f8gf8qs94f4l9xi9h0jkdl2ozoi2p7q7qu1945l21dzj6rhvqearzrmblfo3ljjldj0m9fue",
];

        const POLYMUR_REFERENCE_VALUES: [u64; 100] = [
            0x1a6ef9f9d6c576fb,
            0xd16d059771c65e13,
            0x5ee4e0c09f562f87,
            0x535b5311db007b0b,
            0xd17124f14bd16b5d,
            0xe84c87105c5b5cad,
            0xb16ce684b89df9c0,
            0x656525cace200667,
            0x92b460794885d16d,
            0xe6cc0fd9725b46b9,
            0xc875ade1929bc93d,
            0x68a2686ced37268a,
            0x1d1809fd7e7e14ef,
            0x699b8f31fc40c137,
            0xd10dca2605654d2d,
            0xd6bc75cb729f18d7,
            0xfe0c617e7cb1bffe,
            0xf5f14c731c1b9a22,
            0x7a0382228d248631,
            0x6c3a5f49d8a48bc0,
            0x3606ebe637bb4ebc,
            0xeb4854d75431ad1d,
            0xfa8ff1a34793ebb0,
            0x7e46ad8e2338cc38,
            0xf8ff088ada3154b4,
            0x706669bf0925914f,
            0x70fc5fbcd3485ace,
            0x96fd279baed2f2ab,
            0x6403a64c68d7bf68,
            0x3f8f532e1df472e5,
            0xbfc49c083515596f,
            0xd678a4b338fbf03b,
            0x127142a2f38b70a1,
            0x8a1a56fbb85b71f6,
            0x961d22b14e6f1932,
            0xa166b0326c942c30,
            0x0f3d837dddb86ae2,
            0x0f8164504b4ea8b1,
            0xe4f6475d5a739af4,
            0xbf535ad625c0d51f,
            0x47f10a5a13be50ad,
            0x3dc5ce9c148969b3,
            0x8dc071fb4df8e144,
            0x9d0a83586cbed3b8,
            0xc4379e22f2809b99,
            0x42010c7dd7657650,
            0xcc31a6fbcdab8be8,
            0x7bad06c38400138a,
            0x0178b41584eb483d,
            0x78afc38d52514efc,
            0x65a57c4e59288dc7,
            0x86e7cc3e273e4e47,
            0xeb99661fb41a6bd2,
            0xea0979aa6cd70feb,
            0xa64a347c0b8e007b,
            0x3692969270fe8fa4,
            0x17640c6052e26555,
            0xdf9e0fd276291357,
            0x64cca6ebf4580720,
            0xf82b33f6399c3f49,
            0xbe3ccb7526561379,
            0x8c796fce8509c043,
            0x9849fded8c92ce51,
            0xa0e744d838dbc4ef,
            0x8e4602d33a961a65,
            0xda381d6727886a7e,
            0xa503a344fc066833,
            0xbf8ff5bc36d5dc7b,
            0x795ae9ed95bca7e9,
            0x19c80807dc900762,
            0xea7d27083e6ca641,
            0xeba7e4a637fe4fb5,
            0x34ac9bde50ce9087,
            0xe290dd0393f2586a,
            0xbd7074e9843d9dca,
            0x66c17140a05887e6,
            0x4ad7b3e525e37f94,
            0xde0d009c18880dd6,
            0x1516bbb1caca46d3,
            0xe9c907ec28f89499,
            0xd677b655085e1e14,
            0xac5f949b08f29553,
            0xd353b06cb49b5503,
            0x9c25eb30ffa8cc78,
            0x6cf18c91658e0285,
            0x99264d2b2cc86a77,
            0x8b438cd1bb8fb65d,
            0xdfd56cf20b217732,
            0x71f4e35bf761bacf,
            0x87d7c01f2b11659c,
            0x95de608c3ad2653c,
            0x51b50e6996b8de93,
            0xd21e837b2121e8c9,
            0x73d07c7cb3fa0ba7,
            0x8113fab03cab6df3,
            0x57cdddea972cc490,
            0xc3df94778f1eec30,
            0x7509771e4127701e,
            0x28240c74c56f8f7c,
            0x194fa4f68aab8e27,
        ];

        let hasher = PolymurHash::from_u64_seed(0xfedbca9876543210);
        let tweak = 0xabcdef0123456789;
        for (i, s) in POLYMUR_TEST_STRINGS.iter().enumerate() {
            let hash = hasher.hash_with_tweak(s.as_bytes(), tweak);
            assert_eq!(
                POLYMUR_REFERENCE_VALUES[i], hash,
                "i={}; expected={:x}; got={:x}",
                i, POLYMUR_REFERENCE_VALUES[i], hash
            );
        }
    }
}
