//! cargo run -r --example gen-sub-circuits -- --nocapture

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
    for mut gate in &mut circuit.1 {
        gate.evaluate();
    }

    let garbled = circuit.garbled_gates();

    // split the GC into sub-circuits
    println!("garbled:{:?}", garbled.len());
}
