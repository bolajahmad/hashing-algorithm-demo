This `SHA512Hasher` is for demonstration purpose. You can create a new `SHA512Hasher` type
with the following fields which may potentially affect hash value of the input.

1. `state: [u32; 8]`:
   - The `state` field is an array of 8 `u32` values that represent the internal state of the hash function.
   - It is initialized with specific initial values in the `new()` function.
   - During the hash computation process, the `state` is iteratively updated based on the input data.
   - The final hash value is derived from the `state` after processing all the input data.

<!-- 2. `block: [u8; BLOCK_SIZE]`:
   - The `block` field is an array of `BLOCK_SIZE` bytes (64 bytes in this case) that serves as a buffer to store the input data.
   - It is used to accumulate the input data until a full block is obtained.
   - When a full block is available, it is processed by the `process_block()` function to update the `state`.
   - After processing a block, the `block` is cleared or reused for the next block of data. -->

2. `block_count: usize`:
   - The `block_count` field keeps track of the number of bytes currently stored in the `block` buffer.
   - It is used to determine when a full block of data is available for processing.
   - When `block_count` reaches `BLOCK_SIZE`, it indicates that a complete block is ready to be processed by the `process_block()` function.
   - After processing a block, `block_count` is reset to 0 to start accumulating the next block of data.

3. `length: u64`:
   - The `length` field represents the total number of bytes processed by the hash function so far.
   - It keeps track of the cumulative length of the input data.
   - The `length` is updated whenever new data is added to the `block` buffer.
   - In the `finalize()` function, the `length` is used to append the message length as a 64-bit value to the final block before processing.

You can add or remove fields as you desire.

These fields work together to maintain the state and handle the input data during the hash computation process:

- The `update()` function takes the input data and incrementally fills an intermediate `block` buffer. It updates `block_count` accordingly. When a full block is available, it calls `process_block()` to update the `state` based on the current block. The current state is used in the `process_block()` until all blocks are used.

- The `process_block()` function performs the core hash computation logic. It takes the current `block` and updates the `state` based on the block data. The specific processing logic depends on the hash algorithm being implemented. The logic here is as defined in the SHA512 algorithm formulae.

- The `finalize()` function is called to complete the hash computation. This is called to return the digest.

The `state`, `block_count`, and `block` (calculated in the `update()`) fields collectively maintain the necessary information and data structures to perform the hash computation incrementally and produce the final hash value.
