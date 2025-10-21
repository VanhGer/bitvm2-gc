//! Binary circuit implementation of DV Verifier Program
//!
use super::{
    blake3_ckt,
    builder::{CircuitAdapter, CircuitTrait},
    curve_ckt::AffinePointRef,
    fr_ckt::{
        FR_LEN, Fr, const_mod_n, emit_fr_add as fr_add, emit_fr_mul as fr_mul,
        emit_fr_sub as fr_sub, ge_unsigned,
    },
    fr_ref::{FrRef, frref_to_bits},
};
use crate::circuits::sect233k1::curve_ckt::{AffinePoint, CurvePoint, emit_affine_point_is_on_curve, emit_point_equals, emit_neg_point_with_neg_selector, emit_neg_point_with_pos_selector};
use crate::circuits::sect233k1::curve_scalar_mul_ckt::hinted_double_scalar_mul::emit_hinted_double_scalar_mul;
use crate::circuits::sect233k1::fr_ckt::{emit_fr_mul, emit_neg_fr_with_selector, two_to_156};
use crate::circuits::sect233k1::gf_ckt::GF_LEN;

#[derive(Debug)]
/// VerifierPayloadRef
pub struct VerifierPayloadRef {
    /// proof
    pub proof: ProofRef,
    /// public_input
    pub public_input: PublicInputsRef,
    /// trapdoor
    pub trapdoor: TrapdoorRef,
}

#[derive(Debug)]
/// ProofRef
pub struct ProofRef {
    /// commit_p
    pub commit_p: AffinePointRef, // commitment to witness folding & quotient
    /// kzg_k
    pub kzg_k: AffinePointRef, // combined KZG evaluation proof
    /// a0
    pub a0: FrRef,
    /// b0
    pub b0: FrRef,
    // x1, x2, z for hinted scalar mul
    pub x1: (FrRef, bool),
    pub x2: (FrRef, bool),
    pub z: (FrRef, bool),
}

const PROOF_BIT_LEN: usize = GF_LEN * 2 * 2 + FR_LEN * 5 + 3;
const PUBINP_BIT_LEN: usize = 2 * FR_LEN;
const TRAPDOOR_BIT_LEN: usize = 696;

pub(crate) const WITNESS_BIT_LEN: usize = PROOF_BIT_LEN + PUBINP_BIT_LEN + TRAPDOOR_BIT_LEN;

impl ProofRef {
    /// Serialize ProofRef into Lopez–Dahab affine coordinates
    pub fn to_bits(&self) -> [bool; PROOF_BIT_LEN] {
        let mut commit_p = self.commit_p.to_bits();
        let mut kzg_k = self.kzg_k.to_bits();
        let mut a0 = frref_to_bits(&self.a0).to_vec();
        let mut b0 = frref_to_bits(&self.b0).to_vec();
        let mut x1 = frref_to_bits(&self.x1.0).to_vec();
        let mut x2 = frref_to_bits(&self.x2.0).to_vec();
        let mut z = frref_to_bits(&self.z.0).to_vec();

        let mut witness = vec![];

        witness.append(&mut commit_p);
        witness.append(&mut kzg_k);
        witness.append(&mut a0);
        witness.append(&mut b0);
        witness.append(&mut x1);
        witness.push(self.x1.1);
        witness.append(&mut x2);
        witness.push(self.x2.1);
        witness.append(&mut z);
        witness.push(self.z.1);

        witness.try_into().unwrap()
    }
}

/// RawPublicInputsRef
#[derive(Debug)]
pub struct PublicInputsRef {
    pub public_inputs: [FrRef; 2],
}

impl PublicInputsRef {
    pub fn to_bits(&self) -> [bool; PUBINP_BIT_LEN] {
        let witness: Vec<_> =
            self.public_inputs.iter().flat_map(|fr_ref| frref_to_bits(fr_ref)).collect();

        witness.try_into().unwrap()
    }
}

/// TrapdoorRef
#[derive(Debug)]
pub struct TrapdoorRef {
    /// tau
    pub tau: FrRef, // trapdoor (only known to verifier)
    /// delta
    pub delta: FrRef,
    /// epsilon
    pub epsilon: FrRef,
}

impl TrapdoorRef {
    /// Serialize TrapdoorRef
    pub fn to_bits(&self) -> [bool; TRAPDOOR_BIT_LEN] {
        let mut tau = frref_to_bits(&self.tau).to_vec();
        let mut delta = frref_to_bits(&self.delta).to_vec();
        let mut epsilon = frref_to_bits(&self.epsilon).to_vec();

        let mut witness = vec![];
        witness.append(&mut tau);
        witness.append(&mut delta);
        witness.append(&mut epsilon);

        witness.try_into().unwrap()
    }
}

pub(crate) fn u8_to_bits_le(n: u8) -> [bool; 8] {
    let v: Vec<bool> = (0..8).map(|i| (n >> i) & 1 != 0).collect();
    v.try_into().unwrap()
}

impl VerifierPayloadRef {
    fn get_indexes(bld: &mut CircuitAdapter) -> (Proof, PublicInputs, Trapdoor) {
        let secrets = Trapdoor { tau: bld.fresh(), delta: bld.fresh(), epsilon: bld.fresh() };
        let rpin = PublicInputs { public_inputs: [bld.fresh(), bld.fresh()] };

        let commit_p = AffinePoint { x: bld.fresh(), s: bld.fresh() };
        let kzg_k = AffinePoint { x: bld.fresh(), s: bld.fresh() };

        let proof = Proof {
            commit_p,
            kzg_k,
            a0: bld.fresh(),
            b0: bld.fresh(),
            x1: (bld.fresh(), bld.fresh_one()),
            x2: (bld.fresh(), bld.fresh_one()),
            z: (bld.fresh(), bld.fresh_one()),
        };
        (proof, rpin, secrets)
    }

    /// Serialize VerifierPayloadRef
    pub fn to_bits(&self) -> [bool; WITNESS_BIT_LEN] {
        let mut secret_bits = self.trapdoor.to_bits().to_vec();
        let mut public_inputs = self.public_input.to_bits().to_vec();
        let mut proof_bits = self.proof.to_bits().to_vec();

        let mut witness = vec![];

        witness.append(&mut secret_bits);
        witness.append(&mut public_inputs);
        witness.append(&mut proof_bits);

        witness.try_into().unwrap()
    }
}

/// Proof wires (Lopez–Dahab under test, compressed otherwise).
#[derive(Debug, Clone)]
pub(crate) struct Proof {
    /// commit_p
    pub commit_p: AffinePoint, // commitment to witness folding & quotient
    /// kzg_k
    pub kzg_k: AffinePoint, // combined KZG evaluation proof
    /// a0
    pub a0: Fr,
    /// b0
    pub b0: Fr,
    /// x1, x2, z for hinted scalar mul
    pub x1: (Fr, usize),
    pub x2: (Fr, usize),
    pub z: (Fr, usize),
}

/// RawPublicInputs
#[derive(Debug)]
pub struct PublicInputs {
    pub public_inputs: [Fr; 2],
}

/// Trapdoor
#[derive(Debug)]
pub struct Trapdoor {
    /// tau
    pub tau: Fr, // trapdoor (only known to verifier)
    /// delta
    pub delta: Fr,
    /// epsilon
    pub epsilon: Fr,
}

/// Label Info
// Fr:232 x 5 + Pt:240 x 2 + Pub:64 = 1704 bits
// 0 -> const_zero
// 1 -> const_one
// (2, 1705) -> input wires
#[derive(Debug)]
pub struct IndexInfo {
    /// input wire inclusive range
    pub input_wire_range: (usize, usize),
    /// const zero wire label
    pub const_zero: usize,
    /// const one wire label
    pub const_one: usize,
    /// output index
    pub output_index: usize,
}

fn u8_arr_to_labels_le<T: CircuitTrait>(bld: &mut T, ns: &[u8]) -> Vec<[usize; 8]> {
    let zero = bld.zero();
    let one = bld.one();
    let mut vs: Vec<[usize; 8]> = Vec::new();
    for n in ns {
        let v: Vec<usize> = (0..8)
            .map(|i| {
                let r = (n >> i) & 1 != 0;
                if r { one } else { zero }
            })
            .collect();
        let v: [usize; 8] = v.try_into().unwrap();
        vs.push(v);
    }
    vs
}

fn get_fs_challenge<T: CircuitTrait>(
    bld: &mut T,
    commit_p: AffinePoint,
    public_inputs: [Fr; 2],
    srs_bytes: Vec<u8>,
    circuit_info_bytes: Vec<u8>,
) -> Fr {
    // convert affine (x, λ) into byte-aligned representation (30 bytes per coordinate)
    let zero = bld.zero();
    let mut commit_bits = commit_p.x.to_vec();
    commit_bits.resize(240, zero);
    commit_bits.extend_from_slice(&commit_p.s);
    commit_bits.resize(480, zero);

    let commit_p_u8 = commit_bits.chunks(8).map(|chunk| chunk.try_into().unwrap()).collect();

    let witness_commitment_hash = blake3_ckt::hash(bld, commit_p_u8);

    let public_inputs_hash = {
        let mut buf = Vec::new();
        for pubin in public_inputs {
            let mut pubin_240 = [bld.zero(); FR_LEN];
            pubin_240.copy_from_slice(&pubin[0..FR_LEN]);
            let mut r: Vec<[usize; 8]> = pubin_240
                .chunks(8)
                .map(|x| {
                    let y: [usize; 8] = x.try_into().unwrap();
                    y
                })
                .collect();
            buf.append(&mut r);
        }

        blake3_ckt::hash(bld, buf)
    };

    let compile_time_hash = {
        let srs_bytes = u8_arr_to_labels_le(bld, &srs_bytes);
        let srs_hash = blake3_ckt::hash(bld, srs_bytes);
        let circuit_info_bytes = u8_arr_to_labels_le(bld, &circuit_info_bytes);
        let circuit_info_hash = blake3_ckt::hash(bld, circuit_info_bytes);
        let mut compile_time_bytes: Vec<[usize; 8]> = Vec::new();
        compile_time_bytes.extend_from_slice(&srs_hash);
        compile_time_bytes.extend_from_slice(&circuit_info_hash);
        blake3_ckt::hash(bld, compile_time_bytes)
    };

    let runtime_hash = {
        let mut runtime_bytes: Vec<[usize; 8]> = Vec::new();
        runtime_bytes.extend_from_slice(&witness_commitment_hash);
        runtime_bytes.extend_from_slice(&public_inputs_hash);

        blake3_ckt::hash(bld, runtime_bytes)
    };

    let mut root_hash = {
        let mut root_bytes: Vec<[usize; 8]> = Vec::new();
        root_bytes.extend_from_slice(&compile_time_hash);
        root_bytes.extend_from_slice(&runtime_hash);

        blake3_ckt::hash(bld, root_bytes)
    };

    let zero_byte = [bld.zero(); 8];
    // truncate msb
    root_hash[28..].copy_from_slice(&[zero_byte; 4]); // mask top 3 bytes, 256-24=232 bits

    // convert to Fr
    let root_hash_flat: Vec<usize> = root_hash.into_iter().flatten().collect();
    let root_fr: Fr = root_hash_flat[0..FR_LEN].try_into().unwrap();
    root_fr
}

// /// Convert raw public inputs into scalar field element as done by Ziren
// fn get_pub_hash_from_raw_pub_inputs<T: CircuitTrait>(bld: &mut T, raw_pub_in: &PublicInputs) -> Fr {
//     let inps: Vec<[usize; 8]> = raw_pub_in
//         .deposit_index
//         .chunks(8)
//         .map(|x| {
//             let y: [usize; 8] = x.try_into().unwrap();
//             y
//         })
//         .collect();
//     let mut out_hash = blake3_ckt::hash(bld, inps);
//     let zero_byte = [bld.zero(); 8];
//     out_hash[0..4].copy_from_slice(&[zero_byte; 4]); // MSB masked assuming BE
//     out_hash.reverse();
//
//     let out_hash_flat: Vec<usize> = out_hash.into_iter().flatten().collect();
//     let out_fr: Fr = out_hash_flat[0..FR_LEN].try_into().unwrap();
//     out_fr
// }

/// Function to compile dvsnark verifier circuit
pub fn compile_verifier() -> (CircuitAdapter, IndexInfo) {
    let mut bld = CircuitAdapter::default();

    let input_wire_start = bld.next_wire();
    let (proof, rpin, secrets) = VerifierPayloadRef::get_indexes(&mut bld);
    let input_wire_end = bld.next_wire();

    // Prepare
    let passed_index = verify(&mut bld, proof, rpin, secrets);
    let index_info = IndexInfo {
        input_wire_range: (input_wire_start, input_wire_end - 1), // -1 because inclusive range
        const_zero: bld.zero(),
        const_one: bld.one(),
        output_index: passed_index,
    };
    (bld, index_info)
}

/// evaluate verifier
pub fn evaluate_verifier(
    bld: &mut CircuitAdapter,
    witness: [bool; WITNESS_BIT_LEN],
    output_wire_index: usize,
) -> bool {
    let wires = bld.eval_gates(&witness);

    wires[output_wire_index]
}

/// verify
pub(crate) fn verify<T: CircuitTrait>(
    bld: &mut T,
    proof: Proof,
    public_inputs: PublicInputs,
    secrets: Trapdoor,
) -> usize {
    let (proof_commit_p, is_proof_commit_p_on_curve) =
        emit_affine_point_is_on_curve(bld, &proof.commit_p);
    let (proof_kzg_k, is_proof_kzg_k_on_curve) = emit_affine_point_is_on_curve(bld, &proof.kzg_k);

    let one_wire = bld.one();
    let fr_modulus = const_mod_n(bld);
    let proof_a0_invalid = ge_unsigned(bld, &proof.a0, &fr_modulus); // a0 should be less than modulus
    let proof_b0_invalid = ge_unsigned(bld, &proof.b0, &fr_modulus);
    let proof_scalars_invalid = bld.or_wire(proof_a0_invalid, proof_b0_invalid); // either invalid
    let proof_scalars_valid = bld.xor_wire(proof_scalars_invalid, one_wire); // both scalars valid
    let decoded_points_valid = bld.and_wire(is_proof_commit_p_on_curve, is_proof_kzg_k_on_curve); // both points valid

    // decompose
    let two_to_156 = two_to_156(bld);
    let proof_x1_invalid = ge_unsigned(bld, &proof.x1.0, &two_to_156);
    let proof_x2_invalid = ge_unsigned(bld, &proof.x2.0, &two_to_156);
    let proof_z_invalid = ge_unsigned(bld, &proof.z.0, &two_to_156);

    let x1x2_invalid = bld.or_wire(proof_x1_invalid, proof_x2_invalid); // either x1, x2 invalid
    let decompose_invalid = bld.or_wire(x1x2_invalid, proof_z_invalid); // either x1, x2, z invalid
    let decompose_valid = bld.xor_wire(decompose_invalid, one_wire); // all valid

    let proof_scalars_valid = bld.and_wire(proof_scalars_valid, decompose_valid);

    let fs_challenge_alpha =
        get_fs_challenge(bld, proof.commit_p, public_inputs.public_inputs.clone(), vec![], vec![]);

    let i0 = {
        let t0 = fr_mul(bld, &public_inputs.public_inputs[1], &fs_challenge_alpha);
        fr_add(bld, &t0, &public_inputs.public_inputs[0])
    };

    let r0 = {
        //&proof.a0 * &proof.b0 - &proof.i0
        let t0 = fr_mul(bld, &proof.a0, &proof.b0);

        fr_sub(bld, &t0, &i0)
    };

    // Step 3. Compute u₀ and v₀
    let u0 = {
        //(proof.a0 + secrets.delta * (proof.b0 + secrets.delta * r0)) * secrets.epsilon
        let delta_r0 = fr_mul(bld, &secrets.delta, &r0);
        let b0_plus = fr_add(bld, &proof.b0, &delta_r0);
        let inner = fr_mul(bld, &secrets.delta, &b0_plus);
        let sum = fr_add(bld, &proof.a0, &inner);

        fr_mul(bld, &sum, &secrets.epsilon)
    };
    let tmp0 = fr_sub(bld, &secrets.tau, &fs_challenge_alpha);
    let v0 = fr_mul(bld, &tmp0, &secrets.epsilon);
    let generator = CurvePoint::generator(bld);
    let identity = CurvePoint::identity(bld);
    let mut fr_one = Fr::from([bld.zero(); FR_LEN]);
    fr_one[0] = one_wire;

    // check the validation of x1, x2, z:
    // u0 = x1/z mod r,  v0 = x2/z mod r
    let new_x1 = emit_neg_fr_with_selector(bld, &proof.x1.0, proof.x1.1);
    let new_x2 = emit_neg_fr_with_selector(bld, &proof.x2.0, proof.x2.1);
    let new_z = emit_neg_fr_with_selector(bld, &proof.z.0, proof.z.1);

    let k1z = emit_fr_mul(bld, &u0, &new_z);
    let k2z = emit_fr_mul(bld, &v0, &new_z);
    let diff1 = fr_sub(bld, &k1z, &new_x1);
    let diff2 = fr_sub(bld, &k2z, &new_x2);

    let diff1_not_zero = ge_unsigned(bld, &diff1, &fr_one);
    let diff2_not_zero = ge_unsigned(bld, &diff2, &fr_one);
    let diff_not_zero = bld.or_wire(diff1_not_zero, diff2_not_zero);
    let diff_zero = bld.xor_wire(diff_not_zero, one_wire); // both zero

    // check the validation of hinted double scalar multiplication
    // u0 * G + v0 * KZG_K == COMMIT_P
    // <=> x1G + x2KZG_K + (-zP) = 0
    let new_p1 = emit_neg_point_with_neg_selector(bld, &generator, proof.x1.1);
    let new_p2 = emit_neg_point_with_neg_selector(bld, &proof_kzg_k, proof.x2.1);
    let new_p3 = emit_neg_point_with_pos_selector(bld, &proof_commit_p, proof.z.1);
    let res = emit_hinted_double_scalar_mul(
        bld,
        &proof.x1.0,
        &new_p1,
        &proof.x2.0,
        &new_p2,
        &proof.z.0,
        &new_p3,
    );
    let verify_success = emit_point_equals(bld, &res, &identity);
    let hinted_success = bld.and_wire(verify_success, diff_zero);
    let scalar_valid = bld.and_wire(proof_scalars_valid, decompose_valid);
    let scalar_point_valid = bld.and_wire(scalar_valid, decoded_points_valid);
    bld.and_wire(hinted_success, scalar_point_valid)
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::{AffinePoint, get_fs_challenge};
    use crate::circuits::sect233k1::curve_ckt::AffinePointRef;
    use crate::circuits::sect233k1::dv_ref;
    use crate::circuits::sect233k1::{
        builder::{CircuitAdapter, CircuitTrait},
        curve_ref::CurvePointRef,
        dv_ckt::{
            ProofRef, PublicInputsRef, TrapdoorRef, VerifierPayloadRef, compile_verifier,
            evaluate_verifier,
        },
        fr_ckt::Fr,
        fr_ref::{FrRef, frref_to_bits},
        gf_ref::gfref_to_bits,
    };
    use num_bigint::BigUint;

    #[test]
    #[ignore] // ignore because of being long running
    fn test_verify_over_mock_inputs() {
        let (mut bld, index_info) = compile_verifier();

        // Prepare VerifierPayloadRef
        let tau = FrRef::from_str(
            "2730322210350266333305929438402339624225511456370264338590718619370571",
        )
        .unwrap();
        let delta = FrRef::from_str(
            "1668197219006303135911300995268563595632072044933469744573172589503162",
        )
        .unwrap();
        let epsilon = FrRef::from_str(
            "180534986784443382108991383036395393569817197959638310564367496650276",
        )
        .unwrap();
        let commit_p = AffinePointRef {
            x: [243, 1, 124, 124, 28, 184, 224, 34, 217, 222, 182, 31, 42, 252, 194, 222, 40, 36, 80, 223, 106, 184, 193, 142, 55, 102, 25, 112, 7, 0],
            s: [229, 76, 122, 168, 191, 162, 130, 195, 248, 229, 89, 69, 135, 106, 178, 161, 172, 29, 249, 224, 109, 160, 41, 54, 63, 164, 235, 10, 145, 1]
        };
        let kzg_k = AffinePointRef {
            x: [240, 171, 68, 224, 177, 62, 73, 178, 215, 175, 231, 231, 151, 89, 104, 111, 7, 40, 91, 33, 151, 83, 118, 199, 88, 68, 165, 164, 151, 1],
            s: [182, 120, 142, 188, 144, 198, 242, 204, 84, 254, 121, 254, 72, 190, 109, 99, 198, 59, 168, 17, 124, 224, 37, 14, 69, 114, 133, 198, 2, 1],
        };
        let a0 = FrRef::from_str(
            "1132675792798759308127577893315934115126328231089219585842855711650311",
        )
        .unwrap();
        let b0 = FrRef::from_str(
            "3028379641311591322528948616897330931030750894712035609973261306086667",
        )
        .unwrap();

        let x1 = (FrRef::from_str("8201062243878067778315015938357284675413750549").unwrap(), false);
        let x2 = (FrRef::from_str("12188555815513519027948129212942953563582264060").unwrap(), true);
        let z = (FrRef::from_str("2328416288857173011062977552890912854869626082").unwrap(), true);

        let public_inputs = [
            FrRef::from_str("24")
                .unwrap(),
            FrRef::from_str("13")
                .unwrap(),
        ];

        let verifier_payload = VerifierPayloadRef {
            proof: ProofRef { commit_p, kzg_k, a0, b0, x1, x2, z },
            public_input: PublicInputsRef { public_inputs },
            trapdoor: TrapdoorRef { tau, delta, epsilon },
        };
        let witness = verifier_payload.to_bits();

        let stats = bld.gate_counts();
        println!("{stats}");
        println!("label_info {:?}", index_info);

        let passed_val = evaluate_verifier(&mut bld, witness, index_info.output_index);
        assert!(passed_val, "verification failed");
    }

    #[test]
    #[ignore] // ignore because of being long running
    fn test_invalid_proof_over_mock_inputs() {
        let (mut bld, index_info) = compile_verifier();

        // Prepare VerifierPayloadRef
        let tau = FrRef::from_str(
            "2730322210350266333305929438402339624225511456370264338590718619370571",
        )
            .unwrap();
        let delta = FrRef::from_str(
            "1668197219006303135911300995268563595632072044933469744573172589503162",
        )
            .unwrap();
        let epsilon = FrRef::from_str(
            "180534986784443382108991383036395393569817197959638310564367496650276",
        )
            .unwrap();
        let commit_p = AffinePointRef {
            x: [243, 1, 124, 124, 28, 184, 224, 34, 217, 222, 182, 31, 42, 252, 194, 222, 40, 36, 80, 223, 106, 184, 193, 142, 55, 102, 25, 112, 7, 0],
            s: [229, 76, 122, 168, 191, 162, 130, 195, 248, 229, 89, 69, 135, 106, 178, 161, 172, 29, 249, 224, 109, 160, 41, 54, 63, 164, 235, 10, 145, 1]
        };
        let kzg_k = AffinePointRef {
            x: [240, 171, 68, 224, 177, 62, 73, 178, 215, 175, 231, 231, 151, 89, 104, 111, 7, 40, 91, 33, 151, 83, 118, 199, 88, 68, 165, 164, 151, 1],
            s: [182, 120, 142, 188, 144, 198, 242, 204, 84, 254, 121, 254, 72, 190, 109, 99, 198, 59, 168, 17, 124, 224, 37, 14, 69, 114, 133, 198, 2, 1],
        };
        let a0 = FrRef::from_str(
            "1132675792798759308127577893315934115126328231089219585842855711650311",
        )
            .unwrap();
        let b0 = FrRef::from_str(
            "3028379641311591322528948616897330931030750894712035609973261306086667",
        )
            .unwrap();

        let x1 = (FrRef::from_str("8201062243878067778315015938357284675413750549").unwrap(), false);
        let x2 = (FrRef::from_str("12188555815513519027948129212942953563582264060").unwrap(), true);
        let z = (FrRef::from_str("2328416288857173011062977552890912854869626082").unwrap(), true);

        let public_inputs = [
            FrRef::from_str("25")
                .unwrap(),
            FrRef::from_str("13")
                .unwrap(),
        ];

        let verifier_payload = VerifierPayloadRef {
            proof: ProofRef { commit_p, kzg_k, a0, b0, x1, x2, z },
            public_input: PublicInputsRef { public_inputs },
            trapdoor: TrapdoorRef { tau, delta, epsilon },
        };
        let witness = verifier_payload.to_bits();

        let stats = bld.gate_counts();
        println!("{stats}");

        println!("label_info {:?}", index_info);
        let passed_val = evaluate_verifier(&mut bld, witness, index_info.output_index);
        assert!(!passed_val, "verification should have failed but passed");
    }

    #[test]
    fn test_get_fs_challenge() {
        let mut bld = CircuitAdapter::default();

        let commit_p = AffinePoint { x: bld.fresh(), s: bld.fresh() };

        let pub0: Fr = bld.fresh();
        let pub1: Fr = bld.fresh();
        let pubs = [pub0, pub1];

        let challenge_labels = get_fs_challenge(&mut bld, commit_p, pubs, vec![], vec![]);

        let mut witness = Vec::new();
        let commit_p_ref = AffinePointRef {
            x: [
                130, 249, 227, 133, 241, 141, 173, 8, 217, 155, 78, 16, 150, 181, 1, 85, 184, 26,
                181, 124, 96, 138, 22, 114, 229, 195, 239, 193, 112, 1,
            ],
            s: [
                78, 81, 53, 143, 80, 62, 204, 162, 70, 108, 219, 212, 41, 18, 17, 195, 99, 212,
                133, 145, 119, 185, 20, 230, 218, 109, 147, 98, 173, 1,
            ],
        };
        let (commit_ref, success) = CurvePointRef::from_affine_point(&commit_p_ref);
        assert!(success);

        let mut commit_x_bits = gfref_to_bits(&commit_ref.x).to_vec();
        let mut commit_y_bits = gfref_to_bits(&commit_ref.s).to_vec();

        let public_inputs: Vec<_> = [
            "7527402554317099476086310993202889463751940730940407143885949231928",
            "19542051593079647282099705468191403958371264520862632234952945594121",
        ]
        .iter()
        .map(|s| BigUint::from_str(s).unwrap())
        .collect();
        let mut public_inputs_bits =
            public_inputs.iter().flat_map(|fr| frref_to_bits(fr)).collect::<Vec<_>>();

        witness.append(&mut commit_x_bits);
        witness.append(&mut commit_y_bits);
        witness.append(&mut public_inputs_bits);

        let wires = bld.eval_gates(&witness);
        let challenge_val: BigUint = challenge_labels
            .iter()
            .enumerate()
            .fold(BigUint::ZERO, |acc, (i, &w_id)| acc + (BigUint::from(wires[w_id] as u16) << i));
        let challenge_val_ref =
            dv_ref::get_fs_challenge(&commit_p_ref, &public_inputs, vec![], vec![]);

        assert_eq!(challenge_val, challenge_val_ref);
    }
}
