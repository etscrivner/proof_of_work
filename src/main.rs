extern crate crypto;
extern crate rand;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use rand::Rng;
use std::mem;

// The number of leading zeros required in hash to reach difficulty target
const DIFFICULT_ZEROS: &'static str = "00";

fn main() {
    let mut hasher = Sha256::new();
    hasher.input(b"TEST");
    
    let prev_hash = hasher.result_str();
    let transactions = [b"Give A 0.1BTC", b"Give B 1.5BTC"];

    let mut rng = rand::thread_rng();
    let mut nonce = rng.gen::<u64>();

    loop {
        hasher = Sha256::new();

        unsafe {
            let nonce_bytes = mem::transmute::<u64, [u8; 8]>(nonce);
            hasher.input(&nonce_bytes);
        }
        hasher.input(prev_hash.as_bytes());
        let trans_iter = transactions.into_iter();
        for &each in trans_iter {
            hasher.input(each);
        }

        let result = hasher.result_str();
        if result.starts_with(DIFFICULT_ZEROS) {
            println!("\n[Found Nonce]");
            println!("nonce: {}", nonce);
            println!("{}", result);
            break;
        }

        nonce += 1;
        println!("{}", nonce);
    }
}
