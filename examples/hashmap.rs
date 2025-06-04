use polymur_hash::PolymurHasher;
use std::collections::HashMap;
use std::hash::BuildHasherDefault;

// Create a type alias for convenience
type PolymurHashMap<K, V> = HashMap<K, V, BuildHasherDefault<PolymurHasher>>;

fn main() {
    // Create a HashMap using PolymurHash
    let mut scores: PolymurHashMap<String, u32> = PolymurHashMap::default();

    // Insert some data
    scores.insert("Alice".to_string(), 100);
    scores.insert("Bob".to_string(), 87);
    scores.insert("Charlie".to_string(), 95);
    scores.insert("David".to_string(), 78);

    // Access the data
    println!("Scores:");
    for (name, score) in &scores {
        println!("  {}: {}", name, score);
    }

    // Look up a specific value
    if let Some(score) = scores.get("Alice") {
        println!("\nAlice's score: {}", score);
    }

    // Demonstrate that it works like a regular HashMap
    scores.entry("Eve".to_string()).or_insert(92);
    println!("\nAfter adding Eve: {} students", scores.len());
}
