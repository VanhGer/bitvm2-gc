//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_std]
#![no_main]
zkm_zkvm::entrypoint!(main);

use garbled_snark_verifier::circuits::bn254::fp254impl::Fp254Impl;
use garbled_snark_verifier::circuits::bn254::fq::Fq;

use garbled_snark_verifier::bag::{new_wirex, Wires, Wirex};
use garbled_snark_verifier::circuits::bigint::add::add_generic;
use rand;

fn new_wirex_with_random_value() -> Wirex {
    let mut wire = new_wirex();
    wire.borrow_mut().set(rand::random::<bool>());
    wire
}

fn n_random_wires(n: usize) -> Wires {
    (0..n).map(|_| new_wirex_with_random_value()).collect()
}

fn main() {
    let a_wires = n_random_wires(1747627);
    let b_wires = n_random_wires(1747627);

    let mut circuit = add_generic(a_wires, b_wires, 1747627);
    circuit.gate_counts().print();
    for gate in &mut circuit.1 {
        gate.evaluate();
    }

    let garbled = circuit.garbled_gates();
    zkm_zkvm::io::commit(&garbled.len());
}
