use std::{cell::RefCell, rc::Rc};

use serde::{Deserialize, Serialize};

use crate::{
    bag::{Circuit, Gate, S, Wire},
    core::gate::GateType,
};

pub fn bit_to_usize(bit: bool) -> usize {
    if bit { 1 } else { 0 }
}

#[allow(unused_variables)]
pub fn hash(input: &[u8]) -> [u8; 32] {
    #[allow(unused_assignments)]
    let mut output = [0u8; 32];

    #[cfg(feature = "_blake3")]
    {
        use blake3::hash;
        output = *hash(input).as_bytes();
    }

    #[cfg(feature = "_sha2")]
    {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(input);
        let result = hasher.finalize();
        output.copy_from_slice(&result[..32]);
    }

    #[cfg(feature = "_poseidon2")]
    {
        use poseidon2::poseidon2;
        output = poseidon2(input);
    }
    output
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct SerializableGate {
    pub wire_a: Wire,
    pub wire_b: Wire,
    pub wire_c: Wire,
    pub gate_type: GateType,
}

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct SerializableCircuit {
    pub gates: Vec<SerializableGate>, // Must also be serializable
    pub garblings: Vec<Vec<S>>,
}

impl From<&Circuit> for SerializableCircuit {
    fn from(c: &Circuit) -> Self {
        //let wires = c.0.iter().map(|w| w.borrow().clone()).collect();
        let gates =
            c.1.iter()
                .map(|w| SerializableGate {
                    wire_a: w.wire_a.borrow().clone(),
                    wire_b: w.wire_b.borrow().clone(),
                    wire_c: w.wire_c.borrow().clone(),
                    gate_type: w.gate_type,
                })
                .collect();
        Self { gates, garblings: Vec::new() }
    }
}

impl From<&SerializableCircuit> for Circuit {
    fn from(sc: &SerializableCircuit) -> Self {
        //let wires = sc.wires.into_iter().map(|w| Rc::new(RefCell::new(w))).collect();
        let mut wires = vec![];
        let gates = sc
            .gates
            .iter()
            .map(|g| {
                let a_wirex = Rc::new(RefCell::new(g.wire_a.clone()));
                let b_wirex = Rc::new(RefCell::new(g.wire_b.clone()));
                let c_wirex = Rc::new(RefCell::new(g.wire_c.clone()));
                wires.push(a_wirex);
                wires.push(b_wirex);
                wires.push(c_wirex);
                Gate {
                    wire_a: wires[wires.len() - 3].clone(),
                    wire_b: wires[wires.len() - 2].clone(),
                    wire_c: wires[wires.len() - 1].clone(),
                    gate_type: g.gate_type,
                }
            })
            .collect();
        Self(wires, gates)
    }
}

pub fn gen_sub_circuits(circuit: &mut Circuit, max_gates: usize) -> Vec<SerializableCircuit> {
    let mut gates = circuit.garbled_gates();
    let mut result = Vec::new();

    let size = circuit.1.len().div_ceil(max_gates);
    let mut serialized_gates: Vec<Vec<SerializableGate>> = vec![Vec::new(); size];

    let _: Vec<_> = serialized_gates
        .iter_mut()
        .zip(circuit.1.chunks(max_gates))
        .map(|(out, w)| {
            *out = w
                .iter()
                .map(|w| SerializableGate {
                    wire_a: w.wire_a.borrow().clone(),
                    wire_b: w.wire_b.borrow().clone(),
                    wire_c: w.wire_c.borrow().clone(),
                    gate_type: w.gate_type,
                })
                .collect();
        })
        .collect();

    let mut i = 0;
    while !gates.is_empty() {
        let chunk_size = max_gates.min(gates.len());
        let garblings: Vec<Vec<S>> = gates.drain(0..chunk_size).collect();

        let sc = SerializableCircuit { gates: std::mem::take(&mut serialized_gates[i]), garblings };
        result.push(sc);
        i = i + 1;
    }

    result
}

pub fn check_guest(buf: &[u8]) {
    let sc: SerializableCircuit = bincode::deserialize(buf).unwrap();
    let circuit: Circuit = (&sc).into();
    let garblings = circuit.garbled_gates();
    assert!(garblings == sc.garblings);
}
