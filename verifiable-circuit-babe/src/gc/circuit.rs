use ark_bn254::G1Affine;
use sha2::{Digest, Sha256};
use garbled_snark_verifier::circuits::sect233k1::builder::{CircuitAdapter, CircuitTrait};
use garbled_snark_verifier::dv_bn254::basic::selector;
use garbled_snark_verifier::dv_bn254::fp254impl::Fp254Impl;
use garbled_snark_verifier::dv_bn254::{fq::Fq, fr::Fr};
use garbled_snark_verifier::dv_bn254::g1::G1Projective as GcG1Projective;

use crate::dre::{L, N, U_BAR_SIZE, R_PD_SIZE};

/// Compile the BABE circuit structure without fixing witness values.
///
/// Input wire allocation order (each 254 bits, LSB-first, normal form):
///   [0..N,..2N)       const_x/const_y — coordinates of the scalar-mul base point
///   [2N..3N)     pi_x     — x-coordinate of the proof point π
///   [3N..4N)     pi_y     — y-coordinate of π
///   [4N..5N)     x_d      — scalar (Fr element)
pub fn compile_dsgc(g: G1Affine) -> (CircuitAdapter, Vec<usize>) {
    let mut bld = CircuitAdapter::default();
    // base input wires — allocated before π so evaluator can supply them first
    let const_x = Fq::wires(&mut bld);
    let const_y = Fq::wires(&mut bld);
    // π input wires
    let pi_x = Fq::wires(&mut bld);
    let pi_y = Fq::wires(&mut bld);
    let x_d = Fr::wires(&mut bld);
    let output_indices = emit_dsgc(
        &mut bld, &const_x.0, &const_y.0, &pi_x.0, &pi_y.0, &x_d.0, g,
    );
    (bld, output_indices)
}

/// Output layout (total L = U_BAR_SIZE + R_PD_SIZE = 2033 bits):
///   [0..U_BAR_SIZE)  ū(π) or ū(g) — 1 + 5·N bits, LSB-first
///   [U_BAR_SIZE..L)  (X,Y,Z) of x_d·P_D — 3·N bits, projective normal form
fn emit_dsgc(
    bld: &mut CircuitAdapter,
    const_x: &[usize],
    const_y: &[usize],
    pi_x: &[usize],
    pi_y: &[usize],
    x_d: &[usize],
    g: G1Affine,
) -> Vec<usize> {
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

    // ── x_d · base subcircuit ─────────────────────────────────────────────────

    // Convert base coordinates to Montgomery form
    let base_x = Fq::mul_by_constant_montgomery(bld, const_x, r_sq);
    let base_y = Fq::mul_by_constant_montgomery(bld, const_y, r_sq);
    let base_z = Fq::wires_set(bld, Fq::as_montgomery(ark_bn254::Fq::from(1u64))).0.to_vec();

    // Flat 762-wire projective point (X·R, Y·R, Z·R)
    let mut base_wires = base_x;
    base_wires.extend(base_y);
    base_wires.extend(base_z);

    // Double-and-add: scalar x_d (raw bits) × Montgomery projective point
    let prod_proj_m = GcG1Projective::scalar_mul_montgomery_circuit(bld, x_d, &base_wires);

    // Normalize each coordinate: (X·R, Y·R, Z·R) → (X, Y, Z)
    let x_out = Fq::mul_by_constant_montgomery(bld, &prod_proj_m[..N],      ark_bn254::Fq::from(1u64));
    let y_out = Fq::mul_by_constant_montgomery(bld, &prod_proj_m[N..2 * N],  ark_bn254::Fq::from(1u64));
    let z_out = Fq::mul_by_constant_montgomery(bld, &prod_proj_m[2 * N..],   ark_bn254::Fq::from(1u64));

    output_indices.extend(x_out);
    output_indices.extend(y_out);
    output_indices.extend(z_out);
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
    use super::*;
    use ark_ec::CurveGroup;
    use ark_ff::{UniformRand, Zero};
    use garbled_snark_verifier::bag::{Circuit, S};
    use garbled_snark_verifier::core::utils::reset_gid;
    use crate::dre::matrices::u_bar_vec;

    fn random_g1_affine() -> G1Affine {
        let mut rng = rand::thread_rng();
        ark_bn254::G1Projective::rand(&mut rng).into_affine()
    }

    /// Build a full witness: const_x, const_y, pi_x, pi_y, x_d (each N bits, LSB-first).
    fn build_witness(
        const_point: &G1Affine,
        pi: &G1Affine,
        x_d: ark_bn254::Fr,
    ) -> Vec<bool> {
        Fq::to_bits(const_point.x)
            .into_iter()
            .chain(Fq::to_bits(const_point.y))
            .chain(Fq::to_bits(pi.x))
            .chain(Fq::to_bits(pi.y))
            .chain(Fr::to_bits(x_d))
            .collect()
    }

    #[test]
    fn test_babe_gc_on_curve() {
        let pi = random_g1_affine();
        let g  = random_g1_affine();
        let const_point = random_g1_affine();
        let x_d = ark_bn254::Fr::from(1u64);

        let witness = build_witness(&const_point, &pi, x_d);

        reset_gid();
        let (bld, output_indices) = compile_dsgc(g);
        let mut circuit = bld.build(&witness);
        circuit.gate_counts().print();

        // for gate in &mut circuit.1 {
        //     gate.evaluate();
        // }
        //
        // let output: Vec<bool> = output_indices
        //     .iter()
        //     .map(|&i| circuit.0[i].borrow().get_value())
        //     .collect();
        //
        // assert_eq!(output.len(), L);
        //
        // // u₀ = 1
        // assert!(output[0]);
        //
        // let x_bits = Fq::to_bits(pi.x);
        // for k in 0..N {
        //     assert_eq!(output[1 + k], x_bits[k], "x bit {k} mismatch");
        // }
        //
        // let y_bits = Fq::to_bits(pi.y);
        // for k in 0..N {
        //     assert_eq!(output[1 + N + k], y_bits[k], "y bit {k} mismatch");
        // }
        //
        // let x_sq_bits = Fq::to_bits(pi.x * pi.x);
        // for k in 0..N {
        //     assert_eq!(output[1 + 2 * N + k], x_sq_bits[k], "x² bit {k} mismatch");
        // }
        //
        // let y_sq_bits = Fq::to_bits(pi.y * pi.y);
        // for k in 0..N {
        //     assert_eq!(output[1 + 3 * N + k], y_sq_bits[k], "y² bit {k} mismatch");
        // }
        //
        // let xy_bits = Fq::to_bits(pi.x * pi.y);
        // for k in 0..N {
        //     assert_eq!(output[1 + 4 * N + k], xy_bits[k], "xy bit {k} mismatch");
        // }
    }

    #[test]
    fn test_babe_gc_off_curve_falls_back_to_g() {
        let pi = random_g1_affine();
        let g  = random_g1_affine();
        let const_point = random_g1_affine();
        let x_d = ark_bn254::Fr::from(1u64);

        let bad_y = pi.y + ark_bn254::Fq::from(1u64);
        let mut off_pi = pi;
        off_pi.y = bad_y;
        let witness = build_witness(&const_point, &off_pi, x_d);

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

    /// Plain (non-garbled) evaluation: verify x_d · P_D projective output.
    #[test]
    fn test_babe_gc_xd_pd_output() {
        let mut rng = rand::thread_rng();
        let g           = random_g1_affine();
        let const_point = random_g1_affine();
        let pi          = random_g1_affine();
        let x_d         = ark_bn254::Fr::rand(&mut rng);

        let witness = build_witness(&const_point, &pi, x_d);

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
        let X = Fq::from_bits(output[U_BAR_SIZE..U_BAR_SIZE + N].to_vec());
        let Y = Fq::from_bits(output[U_BAR_SIZE + N..U_BAR_SIZE + 2 * N].to_vec());
        let Z = Fq::from_bits(output[U_BAR_SIZE + 2 * N..L].to_vec());

        let result_proj   = ark_bn254::G1Projective::new(X, Y, Z);
        let expected_affine = (ark_bn254::G1Projective::from(const_point) * x_d).into_affine();

        assert_eq!(
            result_proj.into_affine(), expected_affine,
            "x_d · P_D projective output represents wrong affine point"
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
        let mut rng     = rand::thread_rng();
        let g           = random_g1_affine();
        let const_point = random_g1_affine();
        let pi          = random_g1_affine();
        let x_d         = ark_bn254::Fr::rand(&mut rng);

        // 1. Generate circuit
        reset_gid();
        let (bld, output_indices) = compile_dsgc(g);
        let mut circuit = bld.build(&[]);

        // 2. Generate a new set of labels — one label0 per input wire (5·N wires)
        let encoding_keys: Vec<S> = (0..5 * N).map(|_| S::random()).collect();
        for (i, &key) in encoding_keys.iter().enumerate() {
            circuit.0[2 + i].borrow_mut().label = Some(key);
        }

        // 3. Derive input label values from concrete inputs
        let witness = build_witness(&const_point, &pi, x_d);

        // 4. Evaluate garbled circuit
        circuit.set_witness_value(&witness);
        for gate in &mut circuit.1 {
            gate.evaluate();
        }
        let garblings = circuit.garbled_gates();
        let _ = circuit.garbled_evaluate(&garblings);

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

        // 5b. Verify x_d·P_D output labels
        //     Get the actual output bits, verify they represent the correct point,
        //     then confirm the labels encode exactly those bits.
        let pd_bits: Vec<bool> = output_indices[U_BAR_SIZE..]
            .iter()
            .map(|&i| circuit.0[i].borrow().get_value())
            .collect();
        assert_eq!(pd_bits.len(), R_PD_SIZE);

        let X = Fq::from_bits(pd_bits[..N].to_vec());
        let Y = Fq::from_bits(pd_bits[N..2 * N].to_vec());
        let Z = Fq::from_bits(pd_bits[2 * N..].to_vec());

        let result_proj    = ark_bn254::G1Projective::new(X, Y, Z);
        let expected_affine = (ark_bn254::G1Projective::from(const_point) * x_d).into_affine();
        assert_eq!(
            result_proj.into_affine(), expected_affine,
            "x_d · P_D projective output represents wrong affine point"
        );

        for k in 0..R_PD_SIZE {
            let bit            = pd_bits[k];
            let expected_label = circuit.0[output_indices[U_BAR_SIZE + k]].borrow().select(bit);
            assert_eq!(output_labels[U_BAR_SIZE + k], expected_label, "R_PD label mismatch at k={k}");
        }
    }

    #[cfg(feature = "garbled")]
    #[test]
    fn test_babe_gc_garbled_labels() {
        let pi          = random_g1_affine();
        let g           = random_g1_affine();
        let const_point = random_g1_affine();
        let x_d         = ark_bn254::Fr::from(1u64);

        reset_gid();
        let (bld, output_indices) = compile_dsgc(g);
        let mut circuit = bld.build(&vec![]);

        let witness = build_witness(&const_point, &pi, x_d);
        circuit.set_witness_value(&witness);
        for gate in &mut circuit.1 {
            gate.evaluate();
        }
        let garblings = circuit.garbled_gates();
        let _ = circuit.garbled_evaluate(&garblings);

        let output_labels: Vec<S> = output_indices
            .iter()
            .map(|&i| {
                let w = &circuit.0[i];
                w.borrow().select(w.borrow().get_value())
            }).collect();
        assert_eq!(output_labels.len(), L);

        let u_bar = u_bar_vec(&pi);
        assert_eq!(u_bar.len(), U_BAR_SIZE);
        for k in 0..U_BAR_SIZE {
            let expected_bit   = !u_bar[k].is_zero();
            let expected_label = circuit.0[output_indices[k]].borrow().select(expected_bit);
            assert_eq!(
                output_labels[k],
                expected_label,
                "garbled output label mismatch at ū[{k}]"
            );
        }
    }

    #[cfg(feature = "garbled")]
    #[test]
    fn test_output_labels() {
        use garbled_snark_verifier::core::utils::NON_CAC_DELTA;

        let g           = random_g1_affine();
        let const_point = random_g1_affine();
        let x_d         = ark_bn254::Fr::from(1u64);

        reset_gid();
        let (bld, output_indices) = compile_dsgc(g);
        let mut circuit = bld.build(&[]);

        // Encoding keys for all 5·N input wires
        let encoding_keys: Vec<S> = (0..5 * N).map(|_| S::random()).collect();
        for (i, &key) in encoding_keys.iter().enumerate() {
            circuit.0[2 + i].borrow_mut().label = Some(key);
        }

        let mut rng = rand::thread_rng();
        let p1a = ark_bn254::G1Projective::rand(&mut rng).into_affine();
        let p1b = ark_bn254::G1Projective::rand(&mut rng).into_affine();

        let eval = |circuit: &mut Circuit, p: &ark_bn254::G1Affine| -> Vec<S> {
            let witness = build_witness(&const_point, p, x_d);

            for wire in circuit.0.iter().skip(2) {
                wire.borrow_mut().value = None;
            }
            circuit.set_witness_value(&witness);
            for gate in &mut circuit.1 {
                gate.evaluate();
            }
            let garblings = circuit.garbled_gates();
            let _ = circuit.garbled_evaluate(&garblings);

            output_indices
                .iter()
                .map(|&i| {
                    let w = &circuit.0[i];
                    w.borrow().select(w.borrow().get_value())
                })
                .collect()
        };

        let labels_a = eval(&mut circuit, &p1a);
        let labels_b = eval(&mut circuit, &p1b);

        // Verify Free XOR property on the ū part only (R_PD uses the same P_D/x_d so labels
        // are identical for both evaluations and trivially equal — not tested here)
        let u_bar_a = u_bar_vec(&p1a);
        let u_bar_b = u_bar_vec(&p1b);
        assert_eq!(u_bar_a.len(), U_BAR_SIZE);
        assert_eq!(u_bar_b.len(), U_BAR_SIZE);

        for k in 0..U_BAR_SIZE {
            let bit_a = !u_bar_a[k].is_zero();
            let bit_b = !u_bar_b[k].is_zero();
            if bit_a == bit_b {
                assert_eq!(labels_a[k], labels_b[k], "k={k}: same u_bar bit → equal output labels");
            } else {
                assert_eq!(
                    labels_a[k] ^ labels_b[k],
                    NON_CAC_DELTA,
                    "k={k}: different u_bar bits → labels must differ by DELTA"
                );
            }
        }
    }
}
