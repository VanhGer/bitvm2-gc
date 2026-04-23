use ark_bn254::G1Affine;
use sha2::{Digest, Sha256};
use garbled_snark_verifier::circuits::sect233k1::builder::{CircuitAdapter, CircuitTrait};
use garbled_snark_verifier::dv_bn254::basic::selector;
use garbled_snark_verifier::dv_bn254::fp254impl::Fp254Impl;
use garbled_snark_verifier::dv_bn254::{fq::Fq, fr::Fr};
use garbled_snark_verifier::dv_bn254::g1::G1Projective as GcG1Projective;

use crate::dre::{L, N, U_BAR_SIZE};

// Unsigned 8-bit windowed scalar-mul parameters. Must match the `SCALAR_WINDOW_*`
// constants in garbled-snark-verifier's dv_bn254::g1. With w=8 we do 32 mixed-adds
// over a full 256-entry precomputed table. x_d is supplied as plain Fr bits (LSB-first).
pub const WINDOW_BITS: usize = 8;
pub const WINDOW_COUNT: usize = (Fr::N_BITS + WINDOW_BITS - 1) / WINDOW_BITS; // 32
pub const WINDOW_ENTRIES: usize = 1 << WINDOW_BITS; // 256
pub const PRECOMP_TABLE_BITS: usize = WINDOW_COUNT * WINDOW_ENTRIES * 2 * N;
pub const CONSTANT_SIZE: usize = 2 + 2 * N + PRECOMP_TABLE_BITS;

/// Compile the DSGC circuit structure without fixing witness values.
///
/// Input wire allocation order:
///   [0..N)                       pi_x — x-coordinate of the proof point π
///   [N..2·N)                     pi_y — y-coordinate of π
///   [2·N..2·N+Fr::N_BITS)        x_d — raw scalar bits, LSB-first (evaluator input)
///   [2·N+Fr::N_BITS..3·N+Fr::N_BITS)   r·B_x — x-coordinate of blinding point, Montgomery form
///   [..+N)                       r·B_y — y-coordinate of blinding point, Montgomery form
///   [..+PRECOMP_TABLE_BITS)      unsigned w=8 table for Base,
///                                WINDOW_COUNT windows × WINDOW_ENTRIES affine points
///                                (entry j = j·256^i·P), Montgomery form; j=0 is infinity
///
pub fn compile_dsgc(g: G1Affine) -> (CircuitAdapter, Vec<usize>) {
    let mut bld = CircuitAdapter::default();

    // π input wires (evaluator)
    let pi_x = Fq::wires(&mut bld);
    let pi_y = Fq::wires(&mut bld);

    // x_d raw scalar bits (evaluator input)
    let x_d: Vec<usize> = (0..Fr::N_BITS).map(|_| bld.fresh_one()).collect();

    // r·B and precomputed table — garbler-private
    let rb_x = Fq::wires(&mut bld);
    let rb_y = Fq::wires(&mut bld);
    let mut table_wires = Vec::with_capacity(PRECOMP_TABLE_BITS);
    for _ in 0..(WINDOW_COUNT * WINDOW_ENTRIES * 2) {
        table_wires.extend(Fq::wires(&mut bld).0);
    }

    let output_indices = emit_dsgc(
        &mut bld,
        &table_wires,
        &x_d,
        &pi_x.0,
        &pi_y.0,
        g,
        &rb_x.0,
        &rb_y.0,
    );
    (bld, output_indices)
}

/// Number of input bits contributed by the blinding point r·B (x and y, normal form).
pub const R_B_BITS: usize = 2 * N;

/// Output layout (total L = U_BAR_SIZE + R_PD_SIZE = 2033 bits):
///   [0..U_BAR_SIZE)  ū(π) or ū(g) — 1 + 5·N bits, LSB-first
///   [U_BAR_SIZE..L)  (X,Y,Z) of x_d·P_D + r·B — 3·N bits, projective Montgomery form
fn emit_dsgc(
    bld: &mut CircuitAdapter,
    table_wires: &[usize],
    x_d: &[usize],
    pi_x: &[usize],
    pi_y: &[usize],
    g: G1Affine,
    rb_x_wires: &[usize],
    rb_y_wires: &[usize],
) -> Vec<usize> {
    assert_eq!(table_wires.len(), PRECOMP_TABLE_BITS);

    // R² mod p — multiply by this to convert normal → Montgomery form
    let r_sq = Fq::as_montgomery(Fq::as_montgomery(ark_bn254::Fq::from(1u64)));

    // ── ū(π) subcircuit ───────────────────────────────────────────────────────

    let x_m = Fq::mul_by_constant_montgomery(bld, pi_x, r_sq);
    let y_m = Fq::mul_by_constant_montgomery(bld, pi_y, r_sq);

    let x_sq_m = Fq::square_montgomery(bld, &x_m);
    let y_sq_m = Fq::square_montgomery(bld, &y_m);
    let xy_m = Fq::mul_montgomery(bld, &x_m, &y_m);
    let x_cu_m = Fq::mul_montgomery(bld, &x_sq_m, &x_m);

    let three_mont = Fq::as_montgomery(ark_bn254::Fq::from(3u64));
    let rhs_m = Fq::add_constant(bld, &x_cu_m, three_mont);
    let on_curve = Fq::equal(bld, &y_sq_m, &rhs_m);

    // montgomery_reduce(A·R ‖ 0) = A — converts each back to standard form
    let x_sq = Fq::mul_by_constant_montgomery(bld, &x_sq_m, ark_bn254::Fq::from(1u64));
    let y_sq = Fq::mul_by_constant_montgomery(bld, &y_sq_m, ark_bn254::Fq::from(1u64));
    let xy = Fq::mul_by_constant_montgomery(bld, &xy_m, ark_bn254::Fq::from(1u64));

    let mut pi_u_bar: Vec<usize> = Vec::with_capacity(U_BAR_SIZE);
    pi_u_bar.push(bld.one());
    pi_u_bar.extend_from_slice(pi_x);
    pi_u_bar.extend_from_slice(pi_y);
    pi_u_bar.extend(x_sq);
    pi_u_bar.extend(y_sq);
    pi_u_bar.extend(xy);
    assert_eq!(pi_u_bar.len(), U_BAR_SIZE);

    let g_u_bar = g_u_bar_indices(bld, g);

    let mut output_indices: Vec<usize> = (0..U_BAR_SIZE)
        .map(|k| selector(bld, pi_u_bar[k], g_u_bar[k], on_curve))
        .collect();

    // ── x_d · Base subcircuit (unsigned 8-bit windowed private table) ─────────
    let prod_proj_m =
        GcG1Projective::scalar_mul_private_table_circuit(bld, x_d, table_wires);

    // ── Blinding: add r·B (garbler-private affine, already in Montgomery form) ─
    let mut rb_affine_m: Vec<usize> = rb_x_wires.to_vec();
    rb_affine_m.extend_from_slice(rb_y_wires);
    let blinded_proj_m =
        GcG1Projective::add_mixed_montgomery_no_inf(bld, &prod_proj_m, &rb_affine_m);

    // Output stays in Montgomery form (X·R, Y·R, Z·R).
    output_indices.extend_from_slice(&blinded_proj_m[..N]);
    output_indices.extend_from_slice(&blinded_proj_m[N..2 * N]);
    output_indices.extend_from_slice(&blinded_proj_m[2 * N..]);
    assert_eq!(output_indices.len(), L);

    output_indices
}

/// Build constant wire indices for ū(g)
fn g_u_bar_indices(bld: &mut CircuitAdapter, g: G1Affine) -> Vec<usize> {
    let x = g.x;
    let y = g.y;
    let x_sq = x * x;
    let y_sq = y * y;
    let xy   = x * y;

    let mut indices: Vec<usize> = Vec::with_capacity(U_BAR_SIZE);
    indices.push(bld.one());

    for val in [x, y, x_sq, y_sq, xy] {
        let bits = Fq::to_bits(val);
        for &b in bits.iter().take(N) {
            indices.push(if b { bld.one() } else { bld.zero() });
        }
    }

    assert_eq!(indices.len(), U_BAR_SIZE);
    indices
}

/// SHA256 commitment to a `Vec<Option<S>>` GC ciphertext list.
pub fn gc_ciphertexts_commit(ciphertexts: &[Option<garbled_snark_verifier::bag::S>]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for ct in ciphertexts {
        match ct {
            None => hasher.update([0u8]),
            Some(s) => { hasher.update([1u8]); hasher.update(s.0); }
        }
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use std::time::Instant;
    use super::*;
    use ark_ec::CurveGroup;
    use ark_ff::{AdditiveGroup, UniformRand, Zero};
    use garbled_snark_verifier::bag::S;
    use garbled_snark_verifier::core::utils::reset_gid;
    use crate::dre::matrices::u_bar_vec;
    use crate::dre::R_PD_SIZE;

    fn random_g1_affine() -> G1Affine {
        let mut rng = rand::thread_rng();
        ark_bn254::G1Projective::rand(&mut rng).into_affine()
    }

    /// Build the unsigned w=8 Base table.
    ///
    /// Layout: window `i` (i = 0..WINDOW_COUNT), entry `j` (j = 0..WINDOW_ENTRIES) stores
    /// `j · 256^i · Base` in affine Montgomery form. Entry j=0 is the point at infinity.
    fn build_base_table_bits(base: &G1Affine) -> Vec<bool> {
        let mut bits = Vec::with_capacity(PRECOMP_TABLE_BITS);
        let mut window_base = ark_bn254::G1Projective::from(base.clone());

        for _ in 0..WINDOW_COUNT {
            let mut multiple = ark_bn254::G1Projective::zero(); // j=0: infinity
            for _ in 0..WINDOW_ENTRIES {
                let aff = multiple.into_affine();
                bits.extend(Fq::to_bits(Fq::as_montgomery(aff.x)));
                bits.extend(Fq::to_bits(Fq::as_montgomery(aff.y)));
                multiple += window_base;
            }

            for _ in 0..WINDOW_BITS {
                window_base.double_in_place();
            }
        }
        bits
    }

    /// Build a full witness: pi_x, pi_y, x_d raw bits, r·B (Montgomery), precomputed table.
    fn build_witness(pi: &G1Affine, base: &G1Affine, x_d: ark_bn254::Fr, r_b: &G1Affine) -> Vec<bool> {
        Fq::to_bits(pi.x).into_iter()
            .chain(Fq::to_bits(pi.y))
            .chain(Fr::to_bits(x_d))
            .chain(Fq::to_bits(Fq::as_montgomery(r_b.x)))
            .chain(Fq::to_bits(Fq::as_montgomery(r_b.y)))
            .chain(build_base_table_bits(base))
            .collect()
    }

    #[test]
    fn test_babe_gc_on_curve() {
        let pi = random_g1_affine();
        let g  = random_g1_affine();
        let base = random_g1_affine();
        let r_b = random_g1_affine();
        let x_d = ark_bn254::Fr::from(1u64);

        let witness = build_witness(&pi, &base, x_d, &r_b);

        reset_gid();
        let (bld, output_indices) = compile_dsgc(g);
        let mut circuit = bld.build(&witness);
        circuit.gate_counts().print();

        for gate in &mut circuit.1 {
            gate.evaluate();
        }

        let output: Vec<bool> = output_indices
            .iter()
            .map(|&i| circuit.0[i].borrow().get_value())
            .collect();

        assert_eq!(output.len(), L);

        // u₀ = 1
        assert!(output[0]);

        let x_bits = Fq::to_bits(pi.x);
        for k in 0..N {
            assert_eq!(output[1 + k], x_bits[k], "x bit {k} mismatch");
        }

        let y_bits = Fq::to_bits(pi.y);
        for k in 0..N {
            assert_eq!(output[1 + N + k], y_bits[k], "y bit {k} mismatch");
        }

        let x_sq_bits = Fq::to_bits(pi.x * pi.x);
        for k in 0..N {
            assert_eq!(output[1 + 2 * N + k], x_sq_bits[k], "x² bit {k} mismatch");
        }

        let y_sq_bits = Fq::to_bits(pi.y * pi.y);
        for k in 0..N {
            assert_eq!(output[1 + 3 * N + k], y_sq_bits[k], "y² bit {k} mismatch");
        }

        let xy_bits = Fq::to_bits(pi.x * pi.y);
        for k in 0..N {
            assert_eq!(output[1 + 4 * N + k], xy_bits[k], "xy bit {k} mismatch");
        }
    }

    #[test]
    fn test_babe_gc_off_curve_falls_back_to_g() {
        let pi = random_g1_affine();
        let g  = random_g1_affine();
        let base = random_g1_affine();
        let r_b = random_g1_affine();
        let x_d = ark_bn254::Fr::from(1u64);

        let bad_y = pi.y + ark_bn254::Fq::from(1u64);
        let mut off_pi = pi;
        off_pi.y = bad_y;
        let witness = build_witness(&off_pi, &base, x_d, &r_b);

        reset_gid();
        let (bld, output_indices) = compile_dsgc(g);
        let mut circuit = bld.build(&witness);
        for gate in &mut circuit.1 {
            gate.evaluate();
        }

        let output: Vec<bool> = output_indices
            .iter()
            .map(|&i| circuit.0[i].borrow().get_value())
            .collect();
        assert_eq!(output.len(), L);

        assert!(output[0]);

        let gx_bits = Fq::to_bits(g.x);
        for k in 0..N {
            assert_eq!(output[1 + k], gx_bits[k], "g.x bit {k} mismatch");
        }

        let gy_bits = Fq::to_bits(g.y);
        for k in 0..N {
            assert_eq!(output[1 + N + k], gy_bits[k], "g.y bit {k} mismatch");
        }
    }

    /// Plain (non-garbled) evaluation: verify x_d · P_D + r·B projective output.
    #[test]
    fn test_babe_gc_xd_base_output() {
        let mut rng = rand::thread_rng();
        let g  = random_g1_affine();
        let base = random_g1_affine();
        let r_b = random_g1_affine();
        let pi = random_g1_affine();
        let x_d = ark_bn254::Fr::rand(&mut rng);

        let witness = build_witness(&pi, &base, x_d, &r_b);

        reset_gid();
        let (bld, output_indices) = compile_dsgc(g);
        let mut circuit = bld.build(&witness);
        for gate in &mut circuit.1 {
            gate.evaluate();
        }

        let output: Vec<bool> = output_indices
            .iter()
            .map(|&i| circuit.0[i].borrow().get_value())
            .collect();

        assert_eq!(output.len(), L);

        // Reconstruct projective point (X,Y,Z) in normal form from R_PD bits
        let x = Fq::from_montgomery(Fq::from_bits(output[U_BAR_SIZE..U_BAR_SIZE + N].to_vec()));
        let y = Fq::from_montgomery(Fq::from_bits(output[U_BAR_SIZE + N..U_BAR_SIZE + 2 * N].to_vec()));
        let z = Fq::from_montgomery(Fq::from_bits(output[U_BAR_SIZE + 2 * N..L].to_vec()));

        let result_proj = ark_bn254::G1Projective::new(x, y, z);
        let expected_affine = (ark_bn254::G1Projective::from(base) * x_d
            + ark_bn254::G1Projective::from(r_b))
        .into_affine();

        assert_eq!(
            result_proj.into_affine(), expected_affine,
            "x_d · P_D + r·B projective output represents wrong affine point"
        );
    }

    /// Full garbled-circuit e2e test:
    ///   1. Generate circuit.
    ///   2. Generate a fresh set of random wire labels (encoding keys).
    ///   3. Derive input labels from concrete input values.
    ///   4. Evaluate garbled circuit from those labels.
    ///   5. Verify output labels are correct for both ū(π) and x_d·P_D.
    #[cfg(feature = "garbled")]
    #[test]
    fn test_babe_gc_garbled_e2e() {
        let mut rng = rand::thread_rng();
        let g  = random_g1_affine();
        let base = random_g1_affine();
        let r_b = random_g1_affine();
        let pi = random_g1_affine();
        let x_d = ark_bn254::Fr::rand(&mut rng);

        // 1. Generate circuit
        let now = Instant::now();
        reset_gid();
        let (bld, output_indices) = compile_dsgc(g);
        let mut circuit = bld.build(&[]);
        println!("circuit generate time: {:?}", now.elapsed());

        // 2. Generate a new set of labels — one label0 per input wire.
        // Input wires: 2·N (π) + Fr::N_BITS (x_d) + R_B_BITS (r·B) + PRECOMP_TABLE_BITS (table)
        let now = Instant::now();
        let total_input_wires = 2 * N + Fr::N_BITS + R_B_BITS + PRECOMP_TABLE_BITS;
        let encoding_keys: Vec<S> = (0..total_input_wires).map(|_| S::random()).collect();
        for (i, &key) in encoding_keys.iter().enumerate() {
            circuit.0[2 + i].borrow_mut().label = Some(key);
        }
        println!("encoding time: {:?}", now.elapsed());

        // 3. Derive input label values from concrete inputs
        let witness = build_witness(&pi, &base, x_d, &r_b);

        // 4. Evaluate garbled circuit
        let now = Instant::now();
        circuit.set_witness_value(&witness);
        for gate in &mut circuit.1 {
            gate.evaluate();
        }
        println!("evaluation time: {:?}", now.elapsed());
        let now = Instant::now();
        let ciphertext = circuit.garbled_gates();
        println!("garbled gates time: {:?}", now.elapsed());

        let now = Instant::now();
        let _ = circuit.garbled_evaluate(&ciphertext);
        println!("garbled evaluate time: {:?}", now.elapsed());

        // Collect all output labels
        let output_labels: Vec<S> = output_indices
            .iter()
            .map(|&i| {
                let w = &circuit.0[i];
                w.borrow().select(w.borrow().get_value())
            })
            .collect();
        assert_eq!(output_labels.len(), L);

        // 5a. Verify ū(π) labels match u_bar_vec(pi)
        let u_bar = u_bar_vec(&pi);
        assert_eq!(u_bar.len(), U_BAR_SIZE);
        for k in 0..U_BAR_SIZE {
            let expected_bit   = !u_bar[k].is_zero();
            let expected_label = circuit.0[output_indices[k]].borrow().select(expected_bit);
            assert_eq!(output_labels[k], expected_label, "ū label mismatch at k={k}");
        }

        // 5b. Verify x_d·Base output labels
        //     Get the actual output bits, verify they represent the correct point,
        //     then confirm the labels encode exactly those bits.
        let rpd_bits: Vec<bool> = output_indices[U_BAR_SIZE..]
            .iter()
            .map(|&i| circuit.0[i].borrow().get_value())
            .collect();
        assert_eq!(rpd_bits.len(), R_PD_SIZE);

        let x = Fq::from_montgomery(Fq::from_bits(rpd_bits[..N].to_vec()));
        let y = Fq::from_montgomery(Fq::from_bits(rpd_bits[N..2 * N].to_vec()));
        let z = Fq::from_montgomery(Fq::from_bits(rpd_bits[2 * N..].to_vec()));

        let result_proj     = ark_bn254::G1Projective::new(x, y, z);
        let expected_affine = ark_bn254::G1Projective::from(base) * x_d
            + ark_bn254::G1Projective::from(r_b);
        assert_eq!(
            result_proj.into_affine(), expected_affine,
            "x_d · Base projective output represents wrong affine point"
        );

        for k in 0..R_PD_SIZE {
            let bit            = rpd_bits[k];
            let expected_label = circuit.0[output_indices[U_BAR_SIZE + k]].borrow().select(bit);
            assert_eq!(output_labels[U_BAR_SIZE + k], expected_label, "R_PD label mismatch at k={k}");
        }
    }
}
