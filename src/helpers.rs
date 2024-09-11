/**
 * This file holds functions, and variables that are used within the ``main.rs``
 * 
 * Some of these functions use bitwise operations.
 * Be sure to understand bits(-bytes) and hexadecimal values
 */

// Performs a left-cyclic rotation on 64-bit integer by shift positions
pub fn rotate_right(val: u64, shift: u32) -> u64 {
    (val >> shift) | (val << (64 - shift))
}

/// Represents the shift of the bits in the message schedule
/// Used for the 16-80th round of the 80-round SHA-512 algorithm
/// Mathematically = ROTR<sup>1</sup>(x) + ROTR<sup>8</sup>(x) + SHR<sup>7</sup>(x)
#[inline(always)]
pub fn intermediate_hash_sigma0(val: u64) -> u64 {
    rotate_right(val, 1) ^ rotate_right(val, 8) ^ (val >> 7)
}

/// Represents the shift of the bits in the message schedule
/// Used for the 16-80th round of the 80-round SHA-512 algorithm
/// Mathematically = ROTR<sup>19</sup>(x) + ROTR<sup>61</sup>(x) + SHR<sup>6</sup>(x)
#[inline(always)]
pub fn intermediate_hash_sigma1(val: u64) -> u64 {
    rotate_right(val, 19) ^ rotate_right(val, 61) ^ (val >> 6)
}

/// Represents the shift of bit in the SHA state.
/// This is used in the main round function to compute the intermediate digest
/// Mathematically: ROTR<sup>28</sup>(x) + ROTR<sup>34</sup>(x) + ROTR<sup>39</sup>(x)
#[inline(always)]
pub fn final_hash_sigma0(val: u64) -> u64 {
    rotate_right(val, 28) ^ rotate_right(val, 34) ^ rotate_right(val, 39)
}

/// Represents the shift of bit in the SHA state.
/// This is used in the main round function to compute the intermediate digest
/// Mathematically: ROTR<sup>14</sup>(x) + ROTR<sup>18</sup>(x) + ROTR<sup>41</sup>(x)
#[inline(always)]
pub fn final_hash_sigma1(val: u64) -> u64 {
    rotate_right(val, 14) ^ rotate_right(val, 18) ^ rotate_right(val, 41)
}

/// Conditional function to be used to calculate the SHA512 intermediate digest for each round
/// If x then y else z
#[inline(always)]
pub fn choice(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
pub fn majority(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}