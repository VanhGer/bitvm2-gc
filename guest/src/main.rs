//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_std]
#![no_main]
zkm_zkvm::entrypoint!(main);

use garbled_snark_verifier::circuits::bigint::{
    U254,
    utils::{biguint_from_wires, random_biguint_n_bits},
};

//#[cfg(feature = "garbled")]
fn main() {
    let a = random_biguint_n_bits(254);
    let mut circuit = U254::odd_part(U254::wires_set_from_number(&a));
    circuit.gate_counts().print();

    for gate in &mut circuit.1 {
        gate.evaluate();
    }
    let c = biguint_from_wires(circuit.0[0..U254::N_BITS].to_vec());
    let d = biguint_from_wires(circuit.0[U254::N_BITS..2 * U254::N_BITS].to_vec());
    assert_eq!(a, c * d);

    let _garbled = circuit.garbled_gates();
    //println!("garbled gate size: {}", garbled.len());
    // Reveal: a  = 0, b = 1
    //zkvm_sdk::commit();
}
