use polymur_hash::PolymurHash;

fn main() {
    // Create a hasher
    let hasher = PolymurHash::new(42);

    let data = b"Important message";

    // Use tweaks to generate multiple independent hashes from the same data
    // This is useful for applications like:
    // - Bloom filters (multiple hash functions)
    // - Consistent hashing
    // - Hash tables with multiple hash functions

    println!("Hashing {:?} with different tweaks:", data);

    for tweak in 0..5 {
        let hash = hasher.hash_with_tweak(data, tweak);
        println!("  Tweak {}: 0x{:016x}", tweak, hash);
    }

    // Verify that tweak 0 is equivalent to regular hash
    let hash_no_tweak = hasher.hash(data);
    let hash_tweak_0 = hasher.hash_with_tweak(data, 0);
    assert_eq!(hash_no_tweak, hash_tweak_0);
    println!("\nVerified: hash() == hash_with_tweak(data, 0)");

    // Demonstrate use case: simple bloom filter simulation
    println!("\nSimple bloom filter example:");
    let num_bits = 64;
    let mut bloom_filter = vec![false; num_bits];

    // Add an item using 3 hash functions (tweaks)
    let item = b"example@email.com";
    for k in 0..3 {
        let hash = hasher.hash_with_tweak(item, k);
        let bit_index = (hash % num_bits as u64) as usize;
        bloom_filter[bit_index] = true;
        println!("  Set bit {} for hash function {}", bit_index, k);
    }
}
