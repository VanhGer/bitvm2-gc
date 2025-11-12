use std::collections::{HashMap, HashSet};
use std::io::Write;
use crate::mem_fs;
use garbled_snark_verifier::bag::{Circuit, Wire};
use garbled_snark_verifier::core::utils::{serialize_to_bytes, SerializableCircuit, SerializableGate, SerializableSubCircuitGates, SerializableWire};
use std::time::Instant;
use tracing::info;
use indexmap::IndexMap;

pub const SUB_CIRCUIT_MAX_GATES: usize = 200_000;

pub fn gen_sub_circuits(circuit: &mut Circuit, max_gates: usize) {
    let start = Instant::now();
    let mut garbled_gates = circuit.garbled_gates();
    let elapsed = start.elapsed();
    info!(step = "garble gates", elapsed =? elapsed, "garbled gates: {}", garbled_gates.len());

    let size = circuit.1.len().div_ceil(max_gates);

    let start = Instant::now();
    let wires: Vec<Wire> = circuit.0.iter().map(|w| w.borrow().clone()).collect();
    let mut finest = 269;
    let mut finest_id = 0;
    circuit.1.chunks(max_gates).enumerate().zip(garbled_gates.chunks_mut(max_gates)).for_each(
        |((i, w), garblings)| {
            info!(step = "gen_sub_circuits", "Split batch {i}/{size}");
            let ciphertexts: Vec<_> = garblings
                .iter()
                .filter_map(|g| g.as_ref().cloned())
                .collect();

            // All of this should be removed.
            let start = Instant::now();
            let mut sub_wires_map: IndexMap<u32, u32> = IndexMap::new();
            let mut next_sub_id = 0;
            for gate in w {
                let wire_a_id = gate.wire_a.borrow().id.unwrap();
                sub_wires_map.entry(wire_a_id).or_insert_with(|| {
                    let id = next_sub_id;
                    next_sub_id += 1;
                    id
                });
                let wire_b_id = gate.wire_b.borrow().id.unwrap();
                sub_wires_map.entry(wire_b_id).or_insert_with(|| {
                    let id = next_sub_id;
                    next_sub_id += 1;
                    id
                });
                let wire_c_id = gate.wire_c.borrow().id.unwrap();
                sub_wires_map.entry(wire_c_id).or_insert_with(|| {
                    let id = next_sub_id;
                    next_sub_id += 1;
                    id
                });
            }
            // Build the vector of sub wires
            let sub_wires: Vec<_> = sub_wires_map
                .keys()
                .map(|&id| {
                    SerializableWire {
                        label: wires[id as usize].label.unwrap(),
                        value: wires[id as usize].value,
                    }
                })
                .collect();
            let elapsed = start.elapsed();
            info!(step = "gen_sub_wires ", elapsed = ?elapsed);

            // let out = SerializableCircuit {
            //     gates: w
            //         .iter()
            //         .map(|w| SerializableGate {
            //                 gate_type: w.gate_type as u8,
            //                 wire_a_id: *sub_wires_map.get(&w.wire_a.borrow().id.unwrap()).unwrap(),
            //                 wire_b_id: *sub_wires_map.get(&w.wire_b.borrow().id.unwrap()).unwrap(),
            //                 wire_c_id: *sub_wires_map.get(&w.wire_c.borrow().id.unwrap()).unwrap(),
            //                 gid: w.gid,
            //             }
            //         )
            //         .collect(),
            //     ciphertexts,
            //     wires: sub_wires,
            // };

            let mut gates: Vec<_> = w.iter().map(|w| SerializableGate {
                    gate_type: w.gate_type as u8,
                    wire_a_id: *sub_wires_map.get(&w.wire_a.borrow().id.unwrap()).unwrap(),
                    wire_b_id: *sub_wires_map.get(&w.wire_b.borrow().id.unwrap()).unwrap(),
                    wire_c_id: *sub_wires_map.get(&w.wire_c.borrow().id.unwrap()).unwrap(),
                    gid: w.gid,
                }
            ).collect();
            let dummy_gate = gates.last().unwrap().clone();
            while gates.len() < SUB_CIRCUIT_MAX_GATES {
                gates.push(dummy_gate.clone());
            }
            let array_gates: [SerializableGate; SUB_CIRCUIT_MAX_GATES] = gates.try_into().unwrap();
            let sub_gates: SerializableSubCircuitGates<SUB_CIRCUIT_MAX_GATES> = SerializableSubCircuitGates {
                gates: array_gates,
            };

            /// compute non-free gates ratio
            let non_free_gates = ciphertexts.len();
            if non_free_gates != 0 {
                let ratio = SUB_CIRCUIT_MAX_GATES / non_free_gates;
                let dif = {
                    if 270 > ratio {
                        270 - ratio
                    } else {
                        ratio - 270
                    }
                };
                if dif < finest {
                    finest = dif;
                    finest_id = i;
                }
            }

            if i == 0 {
                // In this demo, we only save the first sub-circuit
                let start = Instant::now();
                // bincode::serialize_into(
                //     //std::fs::File::create(format!("garbled_{i}.bin")).unwrap(),
                //     mem_fs::MemFile::create(format!("garbled_{i}.bin")).unwrap(),
                //     &out,
                // )
                //     .unwrap();

                /// sub_gates
                let bytes = serialize_to_bytes(&sub_gates);
                let mut file =  mem_fs::MemFile::create(format!("garbled_gates_{i}.bin")).unwrap();
                file.write_all(&bytes).unwrap();

                bincode::serialize_into(
                    mem_fs::MemFile::create(format!("garbled_wires_{i}.bin")).unwrap(),
                    &sub_wires,
                )
                    .unwrap();

                bincode::serialize_into(
                    mem_fs::MemFile::create(format!("garbled_ciphertexts_{i}.bin")).unwrap(),
                    &ciphertexts,
                )
                    .unwrap();

                let elapsed = start.elapsed();
                info!(step = "gen_sub_circuits", elapsed = ?elapsed, "Writing garbled_{i}.bin");
            }
        }
    );
    info!("finest id: {}, finest dif: {}", finest_id, finest);
    let elapsed = start.elapsed();
    info!(step = "gen_sub_circuits", elapsed =? elapsed, "total time");
}
