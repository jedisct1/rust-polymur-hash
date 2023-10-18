use benchmark_simple::*;
use core::hash::Hasher;
use fnv::*;
use fxhash::*;
use polymur_hash::*;
use xxhash_rust::xxh3::xxh3_64;

fn bench_polymur() {
    println!("\n* PolymurHash\n");

    let bench = Bench::new();

    let options = &Options {
        iterations: 100_000,
        warmup_iterations: 1_000,
        min_samples: 5,
        max_samples: 10,
        max_rsd: 1.0,
        ..Default::default()
    };

    let hasher = PolymurHash::new(0);
    let mut size = 1;
    loop {
        let m = vec![0u8; size];
        let res = bench.run(options, || hasher.hash(&m));
        println!("{} bytes:\t{}", size, res.throughput(m.len() as _));
        if size >= 65536 {
            break;
        }
        size *= 2;
    }
}

fn bench_fnv() {
    println!("\n* FNV Hash\n");

    let bench = Bench::new();

    let options = &Options {
        iterations: 100_000,
        warmup_iterations: 1_000,
        min_samples: 5,
        max_samples: 10,
        max_rsd: 1.0,
        ..Default::default()
    };

    let mut size = 1;
    loop {
        let m = vec![0u8; size];
        let res = bench.run(options, || {
            let mut hasher = FnvHasher::default();
            hasher.write(&m);
            hasher.finish()
        });
        println!("{} bytes:\t{}", size, res.throughput(m.len() as _));
        if size >= 65536 {
            break;
        }
        size *= 2;
    }
}

fn bench_fxhash() {
    println!("\n* FxHash\n");

    let bench = Bench::new();

    let options = &Options {
        iterations: 100_000,
        warmup_iterations: 1_000,
        min_samples: 5,
        max_samples: 10,
        max_rsd: 1.0,
        ..Default::default()
    };

    let mut size = 1;
    loop {
        let m = vec![0u8; size];
        let res = bench.run(options, || {
            let mut hasher = FxHasher::default();
            hasher.write(&m);
            hasher.finish()
        });
        println!("{} bytes:\t{}", size, res.throughput(m.len() as _));
        if size >= 65536 {
            break;
        }
        size *= 2;
    }
}

fn bench_xxh3() {
    println!("\n* XXH3\n");

    let bench = Bench::new();

    let options = &Options {
        iterations: 100_000,
        warmup_iterations: 1_000,
        min_samples: 5,
        max_samples: 10,
        max_rsd: 1.0,
        ..Default::default()
    };

    let mut size = 1;
    loop {
        let m = vec![0u8; size];
        let res = bench.run(options, || xxh3_64(&m));
        println!("{} bytes:\t{}", size, res.throughput(m.len() as _));
        if size >= 65536 {
            break;
        }
        size *= 2;
    }
}

fn main() {
    bench_xxh3();
    bench_fxhash();
    bench_polymur();
    bench_fnv();
}
