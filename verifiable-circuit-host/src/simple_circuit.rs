use std::time::Instant;
use num_bigint::BigUint;
use tracing::info;

use zkm_sdk::{ProverClient, ZKMProofWithPublicValues, ZKMStdin, include_elf, utils as sdk_utils};

use garbled_snark_verifier::circuits::dv_snark::dv_snark_verifier_circuit;
use garbled_snark_verifier::{bag::Circuit, circuits::sect233k1::types::load_witness_from_files};
use garbled_snark_verifier::circuits::bn254::fq2::Fq2;
use garbled_snark_verifier::circuits::sect233k1::builder::{CircuitAdapter, CircuitTrait};
use garbled_snark_verifier::circuits::sect233k1::fr_ckt::Fr;
use garbled_snark_verifier::circuits::sect233k1::fr_ref::frref_to_bits;
use garbled_snark_verifier::core::utils::deserialize_from_bytes;
use crate::utils::{SUB_CIRCUIT_MAX_GATES, SUB_INPUT_GATES_PARTS};

mod mem_fs;
mod utils;

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("verifiable-circuit");

// this circuit have 500 gates, and
// return the selected number
fn custom_simple_circuit() -> Circuit {
    let mut bld = CircuitAdapter::default();
    let a = bld.fresh_one();
    let b = bld.fresh_one();

    let mut l = a;
    let mut r = b;
    for i in 0..498150 {
        let o = bld.xor_wire(l, r);
        l = r;
        r = o;
    }
    for i in 0..1850 {
        let o = bld.and_wire(l, r);
        l = r;
        r = o;
    }

    let witness = vec![false, true];
    let circuit = bld.build(&witness);
    circuit
}

fn split_circuit() {
    let mut circuit = custom_simple_circuit();
    circuit.gate_counts().print();
    println!("Wires: {}", circuit.0.len());
    let num_gates = circuit.1.len();
    let non_free_gates = circuit.gate_counts().nonfree_gate_count();
    let finest_ratio = num_gates / (non_free_gates as usize);
    utils::gen_sub_circuits(&mut circuit, SUB_CIRCUIT_MAX_GATES, finest_ratio);
}

fn main() {
    // Setup logging.
    sdk_utils::setup_logger();

    let start_total = Instant::now();

    let start = Instant::now();
    split_circuit();
    let elapsed = start.elapsed();
    info!(elapsed = ?elapsed, "split circuit");

    // The input stream that the guest will read from using `zkm_zkvm::io::read`. Note that the
    // types of the elements in the input stream must match the types being read in the guest.
    let mut stdin = ZKMStdin::new();

    let mut sub_gates: [Vec<u8>; SUB_INPUT_GATES_PARTS] =
        std::array::from_fn(|_| Vec::new());

    for part in 0..SUB_INPUT_GATES_PARTS {
        sub_gates[part] = mem_fs::MemFile::read(format!("garbled_gates_{}.bin", part)).unwrap();
        // sub_gates[part] = std::fs::read(format!("garbled_gates_{}.bin", part)).unwrap();
        info!("sub_gates part {} size: {:?} bytes", part, sub_gates[part].len());
    }
    let sub_wires = mem_fs::MemFile::read("garbled_wires.bin").unwrap();
    // let sub_wires = std::fs::read("garbled_wires.bin").unwrap();
    info!("sub_wires size: {:?} bytes", sub_wires.len());

    let sub_ciphertexts = mem_fs::MemFile::read("garbled_ciphertexts.bin").unwrap();
    // let sub_ciphertexts = std::fs::read("garbled_ciphertexts.bin").unwrap();
    info!("sub_ciphertexts size: {:?} bytes", sub_ciphertexts.len());

    // Write the read sub-circuit to a file for inspection or later use.
    for part in 0..SUB_INPUT_GATES_PARTS {
        std::fs::write(format!("garbled_gates_{}.bin", part), &sub_gates[part])
            .expect("Failed to write sub-gate to garbled_gates.bin");
    }
    std::fs::write("garbled_wires.bin", &sub_wires)
        .expect("Failed to write sub-wires to garbled_wires.bin");
    std::fs::write("garbled_ciphertexts.bin", &sub_ciphertexts)
        .expect("Failed to write sub-ciphertexts to garbled_ciphertexts.bin");
    info!("Saved sub-circuit to file");

    for i in 0..SUB_INPUT_GATES_PARTS {
        stdin.write_vec(sub_gates[i].clone());
    }
    stdin.write_vec(sub_wires);
    stdin.write_vec(sub_ciphertexts);

    // Create a `ProverClient` method.
    let client = ProverClient::new();

    let start = Instant::now();
    // Execute the guest using the `ProverClient.execute` method, without generating a proof.
    let (_public_values, report) = client.execute(ELF, stdin.clone()).run().unwrap();

    let elapsed = start.elapsed();
    info!(elapsed = ?elapsed, "executed program with {} cycles", report.total_instruction_count());

    let start = Instant::now();
    // Generate the proof for the given guest and input.
    let (pk, vk) = client.setup(ELF);
    let proof = client.prove(&pk, stdin).run().unwrap();

    let elapsed = start.elapsed();
    info!(step = "generated proof", elapsed =? elapsed, "finish proof generation");

    // Verify proof and public values
    client.verify(&proof, &vk).expect("verification failed");
    //
    // // Test a round trip of proof serialization and deserialization.
    // proof.save("proof-with-pis.bin").expect("saving proof failed");
    // let deserialized_proof =
    //     ZKMProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");
    //
    // // Verify the deserialized proof.
    // client.verify(&deserialized_proof, &vk).expect("verification failed");
    //
    // info!("successfully generated and verified proof for the program!");
    // let total_elapsed = start_total.elapsed();
    // info!(elapsed = ?total_elapsed, "total time");
}