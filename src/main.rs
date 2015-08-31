extern crate crypto;
extern crate rand;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use rand::{Rng, ThreadRng};
use std::mem;
use std::iter::repeat;

static BITMASKS: [u16; 17] = [
    0x0000, 0x8000, 0xC000, 0xE000, 0xF000, 0xF800, 0xFC00, 0xFE00, 0xFF00,
    0xFF80, 0xFFC0, 0xFFE0, 0xFFF0, 0xFFF8, 0xFFFC, 0xFFFE, 0xFFFF
];

fn get_hash(nonce: u64,
            prev_hash: &String,
            transactions: &Vec<String>) -> Box<Sha256> {
    let mut hasher = Sha256::new();

    unsafe {
        let nonce_bytes = mem::transmute::<u64, [u8; 8]>(nonce);
        hasher.input(&nonce_bytes);
    }
    hasher.input(prev_hash.as_bytes());
    for each in transactions.iter() {
        hasher.input(each.as_bytes());
    }

    return Box::new(hasher);
}

fn get_hasher_bytes(hasher: Box<Sha256>) -> Vec<u8> {
    let mut buf: Vec<u8> = repeat(0).take((hasher.output_bits() + 7) / 8).collect();
    let mut unboxed_hasher = *hasher;
    unboxed_hasher.result(&mut buf);
    return buf;
}

fn hits_difficulty(bitmask: u16, hash: &mut [u8]) -> bool {
    let upper_mask: u8 = hash[0] & (((bitmask >> 8) & 0xFF) as u8);
    let lower_mask: u8 = hash[1] & ((bitmask & 0xFF) as u8);
    return upper_mask == 0 && lower_mask == 0;
}

fn random_transaction(rng: &mut ThreadRng) -> String {
    return format!("Give B {} BTC", rng.gen::<f64>().to_string());
}

fn main() {
    let mut hasher = Sha256::new();

    hasher.input(b"PREV HASH");
    let prev_hash: String = hasher.result_str();
    let mut rng = rand::thread_rng();

    for &mask in BITMASKS.iter() {
        println!("\n\nBitmask: {:x}", mask);

        let mut transactions: Vec<String> = vec![
            "Give A 0.1BTC".to_owned(), "Give B 1.5BTC".to_owned()
        ];
        let mut nonce: u64 = rng.gen::<u64>();

        loop {
            let hasher = get_hash(nonce, &prev_hash, &transactions);
            let mut unboxed_hasher = *hasher;
            let hash_str = unboxed_hasher.result_str();
            let mut bytes = get_hasher_bytes(hasher);
            
            if hits_difficulty(mask, &mut bytes) {
                println!("\n[Found Nonce]");
                println!("Nonce: {}", nonce);
                println!("# Transactions: {}", transactions.len());
                println!("{}", hash_str);
                break;
            }

            if transactions.len() < 50000 {
                transactions.extend(vec![random_transaction(&mut rng)]);
            }

            nonce += 1;
        }
    }
}
