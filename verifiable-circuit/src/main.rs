//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_std]
#![no_main]
extern crate alloc;

zkm_zkvm::entrypoint!(main);
use garbled_snark_verifier::core::utils::check_guest;
use zkm_zkvm::lib::ciphertext_check::ciphertext_check;
fn main() {
    let buf = zkm_zkvm::io::read_vec();
    let input = check_guest(&buf);
    let output = ciphertext_check(&input);
    assert!(output);
}
