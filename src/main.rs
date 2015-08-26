extern crate crypto;
extern crate rand;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use rand::Rng;
use std::mem;

// The number of leading zeros required in hash to reach difficulty target
const DIFFICULT_ZEROS: &'static str = "00";


fn get_hash(nonce: u64,
            prev_hash: &String,
            transactions: &Vec<&'static str>) -> String {
    let mut hasher = Sha256::new();

    unsafe {
        let nonce_bytes = mem::transmute::<u64, [u8; 8]>(nonce);
        hasher.input(&nonce_bytes);
    }
    hasher.input(prev_hash.as_bytes());
    for each in transactions.iter() {
        hasher.input(each.as_bytes());
    }

    return hasher.result_str();
}


fn hits_difficulty(hash: &String) -> bool {
    return hash.starts_with(DIFFICULT_ZEROS);
}


fn main() {
    let mut hasher = Sha256::new();
    hasher.input(b"TEST");
    
    let prev_hash: String = hasher.result_str();
    let transactions: Vec<&'static str> = vec!["Give A 0.1BTC", "Give B 1.5BTC"];

    let mut rng = rand::thread_rng();
    let mut nonce: u64 = rng.gen::<u64>();

    loop {
        let result = get_hash(nonce, &prev_hash, &transactions);
        
        if hits_difficulty(&result) {
            println!("\n[Found Nonce]");
            println!("nonce: {}", nonce);
            println!("{}", result);
            break;
        }

        nonce += 1;
        println!("{}", nonce);
    }
}
