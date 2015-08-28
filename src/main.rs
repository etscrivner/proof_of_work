extern crate crypto;
extern crate rand;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use rand::{Rng, ThreadRng};
use std::mem;
use std::iter::repeat;

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

fn hits_difficulty(hash: &mut [u8]) -> bool {
    return (hash[0] == 0x00) && (hash[1] & 0xF0 == 0x00);
}


fn random_transaction(rng: &mut ThreadRng) -> String {
    return format!("Give B {} BTC", rng.gen::<f64>().to_string());
}


fn main() {
    let mut hasher = Sha256::new();

    hasher.input(b"PREV HASH");
    let prev_hash: String = hasher.result_str();
    let mut rng = rand::thread_rng();

    let mut transactions: Vec<String> = vec![
        "Give A 0.1BTC".to_owned(), "Give B 1.5BTC".to_owned()
            ];
    let mut nonce: u64 = rng.gen::<u64>();

    loop {
        let hasher = get_hash(nonce, &prev_hash, &transactions);
        let mut unboxed_hasher = *hasher;
        let hash_str = unboxed_hasher.result_str();
        let mut bytes = get_hasher_bytes(hasher);
        
        if hits_difficulty(&mut bytes) {
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
