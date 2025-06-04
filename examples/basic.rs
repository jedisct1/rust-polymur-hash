use polymur_hash::PolymurHash;

fn main() {
    // Create a hasher with a default seed
    let hasher = PolymurHash::new(0);

    // Hash some data
    let data = b"Hello, world!";
    let hash = hasher.hash(data);
    println!("Hash of {:?}: 0x{:016x}", data, hash);

    // Using different seeds produces different hashes
    let hasher_with_seed = PolymurHash::from_u64_seed(0xDEADBEEF);
    let hash_with_seed = hasher_with_seed.hash(data);
    println!("Hash with custom seed: 0x{:016x}", hash_with_seed);

    // Demonstrate hash stability
    let hash2 = hasher.hash(data);
    assert_eq!(hash, hash2, "Hashes should be stable!");
    println!("Hash stability verified!");
}
