# PolymurHash for Rust

[![Crates.io](https://img.shields.io/crates/v/polymur-hash.svg)](https://crates.io/crates/polymur-hash)
[![Documentation](https://docs.rs/polymur-hash/badge.svg)](https://docs.rs/polymur-hash)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A fast, non-cryptographic hash function for Rust. This is a Rust port of the [PolymurHash](https://github.com/orlp/polymur-hash) universal hash function.

## Features

- 🚀 **High Performance**: Optimized for speed with performance comparable to XXH3
- 🔒 **No Unsafe Code**: Completely safe Rust implementation
- 📦 **No Dependencies**: Zero runtime dependencies
- 🎯 **`no_std` Compatible**: Can be used in embedded and kernel contexts
- 🔧 **Flexible Seeding**: Multiple ways to initialize with different seed types

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
polymur-hash = "0.2"
```

## Usage

### Basic Usage

```rust
use polymur_hash::PolymurHash;

// Create a hasher with a default seed
let hasher = PolymurHash::new(0);

// Hash some data
let data = b"Hello, world!";
let hash = hasher.hash(data);
println!("Hash: {:x}", hash);
```

### Custom Seeds

```rust
use polymur_hash::PolymurHash;

// From a 64-bit seed
let hasher = PolymurHash::from_u64_seed(0xDEADBEEF);

// From a 128-bit seed
let hasher = PolymurHash::new(0x123456789ABCDEF0u128 << 64 | 0xFEDCBA9876543210u128);

// From two 64-bit seeds (key and state)
let hasher = PolymurHash::from_u64x2_seed(0x12345678, 0x9ABCDEF0);
```

### Using Tweaks

Tweaks allow you to generate different hash values from the same key without reinitializing:

```rust
use polymur_hash::PolymurHash;

let hasher = PolymurHash::new(42);
let data = b"Some data";

// Generate multiple independent hashes
let hash1 = hasher.hash_with_tweak(data, 0);
let hash2 = hasher.hash_with_tweak(data, 1);
let hash3 = hasher.hash_with_tweak(data, 2);

// All hashes will be different
assert_ne!(hash1, hash2);
assert_ne!(hash2, hash3);
```

## Performance

PolymurHash is designed for high performance. On modern processors, it achieves speeds comparable to other fast non-cryptographic hash functions like XXH3.

To run the benchmarks:

```bash
cargo bench
```

## Algorithm Details

PolymurHash is based on polynomial evaluation in the finite field GF(2^61-1). It uses:
- Efficient 61-bit arithmetic with lazy reduction
- Optimized mixing functions for good avalanche properties
- Different code paths for small (<= 7 bytes), medium (8-49 bytes), and large (>= 50 bytes) inputs

## Safety

This implementation:
- Uses no `unsafe` code
- Is `#![forbid(unsafe_code)]` enforced
- Has been tested against the reference C implementation test vectors

## License

This project is licensed under the MIT License - see the LICENSE file for details.