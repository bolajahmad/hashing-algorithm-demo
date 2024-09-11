# Implementing an SHA-512 Algorithm

> <h2 style="color: red;">Disclaimer!</h2>
>
> This code is intended as a demo and should not be used in production as-is.
>

## SHA512 Logic

Sha is Single Hash Algorithm and is a reliable one-way hashing algorithm that is used to create cryptographic specific length texts from a list of characters. This demo presents the algorithm for the SHA512 algorithm (there's a list of supported SHA algorithms involving, SHA1|SHA2).

## How it works

This SHA512 algorithm takes as input (as message) with `maximum length, L` less than *2<sup>128</sup>* amd produces an output of 512-bit digest. The input passed is processed in different blocks, each 1024-bit long.

The message (to be hashed) is padded, so that `L == 896 mod 1024`, with single 1-bit, followed by as many 0-bit as needed.

## Algorithm Preparation

The SHA ritual consists of some prerequisite data that need to be provided. Think of them as ritual ingredient without which, the algorithm might be lacking.

- First 8 prime numbers: these sets of integers from 2-19 are used as a buffer (state) to hold the results of the SHA algorithm at every block computation. We will understand why there are various block computations. These prime numbers are computed to the _first 64-bit of the fractional parts of their square roots_.

- 80 SHA Constants: These are used in the SHA512 hashing rounds as additive constants. They are derived from using the _first 64-bit of the fractional parts of the cube roots of the first 80 prime integers_. It's usually referred to as the message schedule.


## Key Logic

SHA512 is made up of 80 rounds of hashing that the code will depict. For each round we will use the buffer defined and also the Hashing constants defined to compute the digest. The digest at the end of the 80th round is also computed to give the final output digest. This 80 round hashing is done for each (1024bit) block of the message input.


## What makes the SHA (512) secure?

Refer Chapter 11 of William Stallings - Cryptography and Network Security Principles and Practice, Global Edition-Pearson (2022) book.
