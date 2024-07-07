use std::convert::TryInto;
use std::str;
use rug::{float, Float};

const BLOCK_SIZE: usize = 32; // Size of each block in bits
const HASH_SIZE: usize = 32; // Size of the hash code in bits

struct SHA512Hasher {
    state: [u8; HASH_SIZE],
    block_count: usize,
}

impl SHA512Hasher {
    fn new() -> Self {
        let mut initial_state = [0; HASH_SIZE];
        let initializing_primes: [f64; 8] = [2.0, 3.0, 5.0, 7.0, 11.0, 13.0, 17.0, 19.0];

        for (id, prime) in initializing_primes.iter().enumerate() {
            let fract_sqrt = convert_f64_to_bytes(prime);

            println!("prime: {:?}; fract_sqrt: {:?}", prime, fract_sqrt);
            initial_state[id * 8..(id + 1) * 8].copy_from_slice(&fract_sqrt.to_be_bytes());
        } 

        SHA512Hasher {
            state: initial_state,
            block_count: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        while offset < data.len() {
            let mut block = [0u8; BLOCK_SIZE];
            let remaining = data.len() - offset;
            let block_size = remaining.min(BLOCK_SIZE);

            block[..block_size].copy_from_slice(&data[offset..offset + block_size]);
            self.process_block(&block);

            offset += block_size;
            self.block_count += 1;
        }
    }

    fn finalize(self) -> [u8; HASH_SIZE] {
        self.state
    }

    fn process_block(&mut self, block: &[u8; BLOCK_SIZE]) {
        for i in 0..HASH_SIZE {
            // since we have HASH_SIZE == BLOCK_SIZE this is easy
            self.state[i] ^= block[i];
        }
    }

    /// The SHA-512 padding method is described by Willian in his  book
    /// The message is split into 1024-bit blocks first.
    /// The message is padded to length ~== 896 % 1024;
    /// The length of the message is also appended to the message
    fn pad(mut message: Vec<u8>) -> Vec<u8> {
        // the message length (in bits): 8 bits = 1 byte
        let original_len = message.len() as u64 * 8;

        // append 1 byte to the message
        message.push(0x80);

        // append 0 bits so message.len() ~= 896 % 1024
        while (message.len() * 8) % 1024 != 896 {
            message.push(0x00);
        }

        // append the original length as a 128-bit value
        // append to the last 
        let mut length_bytes = [0u8; 16];
        length_bytes[8..].copy_from_slice(&original_len.to_be_bytes());

        message.extend_from_slice(&length_bytes);
        message
    }
}

fn convert_f64_to_bytes(value: &f64) -> u64 {
    let precision = 256;
    let float = Float::with_val(precision, *value);
    let fractional_part = float.sqrt().fract();

    fractional_part.to_integer_round(float::Round::Down).unwrap().0.to_u64().unwrap()
}

fn xor_hash(data: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = SHA512Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

fn xor_hash_attack(data: &[u8]) -> Vec<u8> {
    let mut padded_data = Vec::new();
    let r = BLOCK_SIZE - (data.len() % BLOCK_SIZE);

    if r != 0 {
        let padding = vec![0; r];
        padded_data.extend_from_slice(data);
        padded_data.extend(padding);
    }
    let mut mathcing_message = Vec::new();

    for _ in 1..=3 {
        mathcing_message.extend_from_slice(&padded_data);
    }
    mathcing_message
}

#[cfg(test)]
mod tests {

    use quickcheck::QuickCheck;

    use super::*;

    #[test]
    fn test_xor_attack() {
        fn prop(data: Vec<u8>) -> bool {
            xor_hash(&data) == xor_hash(&xor_hash_attack(&data))
        }
        QuickCheck::new().quickcheck(prop as fn(Vec<u8>) -> bool);
    }

    #[test]
    fn attack_demo() {
        let data = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0];
        println!("{}", data.len());
        let attack = xor_hash_attack(&data);
        println!("{:?}", attack.len());
        println!("{:?}", xor_hash(&data));
        println!("{:?}", xor_hash(&attack));
    }

    #[test]
    fn padding_message_works() {
        let message = b"abc".to_vec();
        let padded_message = SHA512Hasher::pad(message.clone());

        println!("padded message length{:?}; message length {:?}", padded_message.len(), message.len());
        assert_eq!((padded_message.len() * 8) % 1024, 0);
    }
}

fn main() {
    println!("Hello, world!");
}
