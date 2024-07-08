use std::convert::TryInto;
use std::str;
use rug::{float, ops::Pow, Float};

#[inline(always)]
fn rotate_right(x: u64, n: u32) -> u64 {
    (x >> n) | (x << (64 - n))
}

#[inline(always)]
fn ms_sigma0(x: u64) -> u64 {
    rotate_right(x, 1) ^ rotate_right(x, 8) ^ (x >> 7)
}

#[inline(always)]
fn ms_sigma1(x: u64) -> u64 {
    rotate_right(x, 19) ^ rotate_right(x, 61) ^ (x >> 6)
}

#[inline(always)]
fn main_sigma0(x: u64) -> u64 {
    rotate_right(x, 28) ^ rotate_right(x, 34) ^ rotate_right(x, 39)
}

#[inline(always)]
fn main_sigma1(x: u64) -> u64 {
    rotate_right(x, 14) ^ rotate_right(x, 18) + rotate_right(x, 41)
}

#[inline(always)]
fn choice(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn majority(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

// These 80 constants must be defined for SHA512 algorithm
// The words are used each in the 80 rounds of the algorithm
// logically, they are derived from the fractional part of the cube root of the first 80 prime numbers
const SHA_CONSTANTS: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

const BLOCK_SIZE: usize = 64; // Size of each block in bits
const HASH_SIZE: usize = 8; // Size of the hash code in bits

struct SHA512Hasher {
    state: [u64; HASH_SIZE],
    block_count: usize,
}

impl SHA512Hasher {
    fn new() -> Self {
        let mut initial_state = [0u64; HASH_SIZE];
        let initializing_primes: [f64; 8] = [2.0, 3.0, 5.0, 7.0, 11.0, 13.0, 17.0, 19.0];

        for (id, prime) in initializing_primes.iter().enumerate() {
            let fract_sqrt = convert_f64_to_bytes(prime);

            initial_state[id] = fract_sqrt;
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

    fn finalize(self) -> [u64; HASH_SIZE] {
        println!("FInal state of hash: {:?}", self.state);
        self.state
    }

    // performs the equivalent of the SHA512 80-round function
    fn process_block(&mut self, block: &[u8; BLOCK_SIZE]) {
        let mut words = [0u64; 80];

        // prepare the message schedule
        for t in 0..16 {
            words[t] = u64::from_be_bytes([
                block[t * 8 + 0], block[t * 8 + 1], block[t * 8 + 2],
                block[t * 8 + 3], block[t * 8 + 4], block[t * 8 + 5],
                block[t * 8 + 6], block[t * 8 + 7]
            ]);
        }

        for t in 16..80 {
            words[t] = ms_sigma1(words[t - 2])
                .wrapping_add(words[t - 7])
                .wrapping_add(ms_sigma0(words[t - 15]))
                .wrapping_add(words[t - 16]);
        }

        // define the working variable
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        
        for t in 0..80 {
            let t1 = (h as u64)
                .wrapping_add(choice(e.into(), f.into(), g.into()))
                .wrapping_add(main_sigma1(e.into()))
                .wrapping_add(words[t])
                .wrapping_add(SHA_CONSTANTS[t]);

            let t2 = main_sigma0(a.into())
                .wrapping_add(majority(a.into(), b.into(), c.into()));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1.try_into().unwrap());
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2).try_into().unwrap();
        }

        // Update the state
        self.state[0] = a.wrapping_add(self.state[0]);
        self.state[1] = b.wrapping_add(self.state[1]);
        self.state[2] = c.wrapping_add(self.state[2]);
        self.state[3] = d.wrapping_add(self.state[3]);
        self.state[4] = e.wrapping_add(self.state[4]);
        self.state[5] = f.wrapping_add(self.state[5]);
        self.state[6] = g.wrapping_add(self.state[6]);
        self.state[7] = h.wrapping_add(self.state[8]);
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
    let mut fractional_part = float.sqrt().fract();
    println!("Fractional part, {}", fractional_part);

    fractional_part *= Float::with_val(precision, 2).pow(64);
    fractional_part.to_integer_round(float::Round::Down).unwrap().0.to_u64().unwrap()
}

fn xor_hash(data: &[u8]) -> [u64; HASH_SIZE] {
    let mut hasher = SHA512Hasher::new();
    let padded_message = SHA512Hasher::pad(data.to_vec());
    hasher.update(&padded_message);
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
    fn initialize_hasher_state_works() {
        // Calling the new method should initialize state: [u8; 8];
        let hasher = SHA512Hasher::new();

        let mut bytes = [0u64; HASH_SIZE];
        bytes.copy_from_slice(&hasher.state[..hasher.state.len()]);

        assert_eq!(bytes[1], 0xBB67AE8584CAA73B, "State could not be validated");
        assert_eq!(bytes[6], 0x1F83D9ABFB41BD6B, "State could not be validated");
    }

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
