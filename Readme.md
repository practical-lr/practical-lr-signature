# Introduction
This repository implements a practical leakage resilient signature with *Rust* languge.

For LR-Okamoto, LR-Schnorr and LR-ECDSA, the Curve25519 is adopted to acheive better performance.

For LR-BLS and LR-BB3 which rely on the pairing, we choose BLS12-381 as the pairing friendly curve.

To benchmark all the scheme, just simply run
`
cargo bench
`
and the results will be shown in the terminal.

Alternatively, you could check `./target/criterion` for detailed result (need to manually enable if Criterion updates).