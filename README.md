# SHA-256-Hardware-Accelerator
A hardware SHA-256 hashing core in SystemVerilog as part of a Bitcoin style block hashing pipeline. Includes message scheduling, compression rounds, and control logic. Verified correctness using known test vectors and simulation, with a focus on clean RTL structure and predictable timing behavior.

The SHA256 is a hash function that takes an input message (≤ 26^4
bits) and compresses it into a fixed 256-bit output (called the message digest or signature). It’s designed so that even a tiny
change in the input completely scrambles the output, making it essentially impossible to reverse.
Internally, it pads the message to 512-bit blocks, then runs 64 rounds per block using rotations,
XORs, ANDs, and additions with a fixed table of constants, while “chaining” the blocks together
through the running hash state (h0 to h7).

## The SHA-256 Algorithm:
I implemented SHA-256 as an FSM that reads the message from memory, applies SHA
padding, computes the hash block-by-block, and then writes the final 256-bit digest back to
memory. The padding logic is handled while filling each 512-bit block: it reads real words while
idx < NUM_OF_WORDS, inserts 0x80000000 at the first padding word, fills zeros, and puts the
message length (in bits) into the last word of the final block. For each block, it initializes
working registers A through H from the current hash state, then runs 64 rounds using sha256_op,
which matches the SHA-256 round formula (Σ0/Σ1, Ch, Maj, K[t], and the schedule word).
Instead of storing all 64 schedule words, it maintains a 16 word buffer and generates the next
word each round.
