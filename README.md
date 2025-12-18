# SHA-256-Hardware-Accelerator
This is a hardware SHA-256 hashing core in SystemVerilog as a part of a Bitcoin style block hashing pipeline. Includes message scheduling, compression rounds, and control logic. Verified correctness using known test vectors and simulation, with a focus on clean RTL structure and predictable timing behavior.

SHA-256 is a cryptographic hash function that takes an input message (up to 2^64 - 1 bits in the spec) and compresses it into a fixed 256 bit output (the digest). A tiny change in the input produces a completely different output, and the process is designed to be infeasible to reverse. Internally, the message is padded and processed in 512-bit blocks, running 64 rounds per block using rotates, XORs, ANDs, and modular additions with a fixed table of constants, while chaining a running hash state (h0–h7) across blocks.

## The SHA-256 Algorithm:
I implemented SHA-256 as an FSM that reads the message from memory, applies SHA padding, computes the hash block-by-block, and writes the result back to memory. Padding is handled while filling each 512-bit block: it reads real words while idx < NUM_OF_WORDS, inserts 0x80000000 at the first padding word, fills zeros, and writes the message length (in bits) into the last word of the final block (matching the constraints of this project/testbench). For each block, it initializes working registers A-H from the current hash state, runs 64 rounds using sha256_op (Σ0/Σ1, Ch, Maj, K[t], and the schedule word), and uses a 16-word rolling buffer to generate schedule words on the fly.

## Bitcoin Hashing Algorithm:
My module performs the “miner loop” on a small nonce range. It reads the fixed block header 
words from memory, then repeatedly plugs in a changing nonce and
computes the block’s hash. Concretely, it implements the Bitcoin-style hashing as double
SHA-256. It hashes the 80 byte header once (split across two 512-bit SHA blocks with correct
padding and length), then hashes that 256 bit result again (single padded block). Instead of
searching millions of nonces, it sweeps nonce = 0 to 15 (16 total) and writes the resulting hash
output for each nonce to memory, which is the concept of “try different nonce values until the
signature works.”
