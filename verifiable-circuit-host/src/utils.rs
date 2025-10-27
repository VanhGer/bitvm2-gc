use std::collections::{HashMap, HashSet};
use crate::mem_fs;
use garbled_snark_verifier::bag::{Circuit, Wire};
use garbled_snark_verifier::core::utils::{SerializableCircuit, SerializableGate};
use std::time::Instant;
use tracing::info;

pub fn gen_sub_circuits(circuit: &mut Circuit, max_gates: usize) {
    let start = Instant::now();
    let mut garbled_gates = circuit.garbled_gates();
    let elapsed = start.elapsed();
    info!(step = "garble gates", elapsed =? elapsed, "garbled gates: {}", garbled_gates.len());

    let size = circuit.1.len().div_ceil(max_gates);

    let start = Instant::now();
    let wires: Vec<Wire> = circuit.0.iter().map(|w| w.borrow().clone()).collect();
    let wire_id_map: HashMap<Wire, u32> = wires
        .iter()
        .cloned()
        .enumerate()
        .map(|(i, w)| (w, i as u32))
        .collect();
    circuit.1.chunks(max_gates).enumerate().zip(garbled_gates.chunks_mut(max_gates)).for_each(
        |((i, w), garblings)| {
            if i == 0 {
                info!(step = "gen_sub_circuits", "Split batch {i}/{size}");
                let ciphertexts: Vec<_> = garblings
                    .iter()
                    .filter_map(|g| g.as_ref().cloned())
                    .collect();

                let sub_wires = {
                    let mut wire_set: HashSet<Wire> = HashSet::new();
                    for gate in w.iter() {
                        wire_set.insert(gate.wire_a.borrow().clone());
                        wire_set.insert(gate.wire_b.borrow().clone());
                        wire_set.insert(gate.wire_c.borrow().clone());
                    }
                    let mut sub_wires: Vec<Wire> = wire_set.into_iter().collect();
                    sub_wires.sort_by_key(|w| wire_id_map.get(w).unwrap());
                    sub_wires
                };
                let sub_wire_id_map: HashMap<Wire, u32> = sub_wires
                    .iter()
                    .cloned()
                    .enumerate()
                    .map(|(i, w)| (w, i as u32))
                    .collect();


                let out = SerializableCircuit {
                    gates: w
                        .iter()
                        .map(|w| SerializableGate {
                            gate_type: w.gate_type,
                            wire_a_id: *sub_wire_id_map.get(&*w.wire_a.borrow()).unwrap(),
                            wire_b_id: *sub_wire_id_map.get(&*w.wire_b.borrow()).unwrap(),
                            wire_c_id: *sub_wire_id_map.get(&*w.wire_c.borrow()).unwrap(),
                            gid: w.gid,
                        })
                        .collect(),
                    garblings: ciphertexts,
                    wires: sub_wires,
                };
                // In this demo, we only save the first sub-circuit
                let start = Instant::now();
                bincode::serialize_into(
                    //std::fs::File::create(format!("garbled_{i}.bin")).unwrap(),
                    mem_fs::MemFile::create(format!("garbled_{i}.bin")).unwrap(),
                    &out,
                )
                    .unwrap();
                let elapsed = start.elapsed();
                info!(step = "gen_sub_circuits", elapsed = ?elapsed, "Writing garbled_{i}.bin");
            }
        },
    );
    let elapsed = start.elapsed();
    info!(step = "gen_sub_circuits", elapsed =? elapsed, "total time");
}
