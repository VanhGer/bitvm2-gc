/// One-time binary to compile, compact, and write the garbled circuit artifacts.
///
/// Produces:
///   fgc_gates.bin + fgc_out_indices.bin   (FGC — evaluates ū(π₁))
///   sgc_gates.bin + sgc_out_indices.bin   (SGC Part 1 — evaluates Q = x_d·L₂ + B)
///
/// Output paths are controlled by env vars:
///   FGC_GATES_PATH, FGC_OUT_INDICES_PATH, SGC_GATES_PATH, SGC_OUT_INDICES_PATH
/// (defaulting to ./fgc_gates.bin etc. in the current working directory)
///
/// Run with:
///   cargo run --release --bin generate_artifacts
use ark_bn254::Fr;
use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
use rand::SeedableRng;
use verifiable_circuit_babe::babe::DummyMulCircuit;
use verifiable_circuit_babe::gc::generate_compact_artifacts;
use verifiable_circuit_babe::prover::GROTH_16_SEED;

fn main() {
    // Use the same VK as all tests so the artifacts are compatible.
    let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(GROTH_16_SEED);
    let a = Fr::from(3u64);
    let b = Fr::from(7u64);

    println!("Setting up Groth16 VK (seed={GROTH_16_SEED})...");
    let (_pk, vk) = ark_groth16::Groth16::<ark_bn254::Bn254>::setup(
        DummyMulCircuit::<Fr> { a: Some(a), b: Some(b) },
        &mut rng,
    ).expect("groth16 setup");

    // l2_point = gamma_abc_g1[2] — the G1 generator for the dynamic public input x_d.
    // SGC Part 1 computes Q = x_d · l2_point + B; this point is baked into the circuit
    // as constant wires, so it must match the VK used at runtime.
    let l2_point = vk.gamma_abc_g1[2];

    generate_compact_artifacts(l2_point);
}
