//! Reference implementation of DV Verifier Program
//!
use super::{
    curve_ref::{CurvePointRef, point_add, point_equals, point_scalar_multiplication},
    dv_ckt::{ProofRef, PublicInputsRef, TrapdoorRef},
    fr_ckt::FR_LEN,
    fr_ref::FrRef,
};
use crate::circuits::sect233k1::curve_ckt::AffinePointRef;
use num_traits::{Num, Zero};
use crate::circuits::sect233k1::curve_ref::neg_point;

pub(crate) fn get_fs_challenge(
    commit_p: &AffinePointRef,
    public_inputs: &[FrRef],
    srs_bytes: Vec<u8>,
    circuit_info_bytes: Vec<u8>,
) -> FrRef {
    let witness_commitment_hash = {
        let (curve_point, success) = CurvePointRef::from_affine_point(commit_p);
        assert!(success, "failed to decode commitment point");

        let mut affine_bytes = Vec::with_capacity(60);
        let mut x_bytes = curve_point.x.to_bytes_le();
        x_bytes.resize(30, 0);
        let mut y_bytes = curve_point.s.to_bytes_le();
        y_bytes.resize(30, 0);
        affine_bytes.extend_from_slice(&x_bytes);
        affine_bytes.extend_from_slice(&y_bytes);

        blake3::hash(&affine_bytes)
    };

    let public_inputs_hash = {
        let mut buf = Vec::new();
        for pubin in public_inputs {
            let mut bytes = pubin.to_bytes_le();
            bytes.resize(FR_LEN / 8, 0);
            buf.append(&mut bytes);
        }
        blake3::hash(&buf)
    };

    let compile_time_hash = {
        let srs_hash = blake3::hash(&srs_bytes);
        let circuit_info_hash = blake3::hash(&circuit_info_bytes);
        let mut compile_time_bytes: Vec<u8> = Vec::new();
        compile_time_bytes.extend_from_slice(srs_hash.as_bytes());
        compile_time_bytes.extend_from_slice(circuit_info_hash.as_bytes());
        blake3::hash(&compile_time_bytes)
    };

    let runtime_hash = {
        let mut runtime_bytes: Vec<u8> = Vec::new();
        runtime_bytes.extend_from_slice(witness_commitment_hash.as_bytes());
        runtime_bytes.extend_from_slice(public_inputs_hash.as_bytes());

        blake3::hash(&runtime_bytes)
    };

    let mut root_hash = {
        let mut root_bytes: Vec<u8> = Vec::new();
        root_bytes.extend_from_slice(compile_time_hash.as_bytes());
        root_bytes.extend_from_slice(runtime_hash.as_bytes());

        let out_hash = blake3::hash(&root_bytes);
        let out_hash = out_hash.as_bytes();
        *out_hash
    };

    // truncate msb
    root_hash[28..].copy_from_slice(&[0, 0, 0, 0]); // mask top 3 bytes, 256-24=232 bits

    FrRef::from_bytes_le(&root_hash)
}

// // Referenced from Ziren's function to convert from raw public inputs to truncated scalar field element
// pub(crate) fn get_pub_hash_from_raw_pub_inputs(raw_pub_in: &PublicInputsRef) -> FrRef {
//     pub(crate) fn babybear_bytes_to_sect_fr(bytes: &[u8; 32]) -> FrRef {
//         let mut result = FrRef::ZERO;
//         for (idx, byte) in bytes.iter().enumerate() {
//             result *= FrRef::from_u16(256).unwrap();
//             let masked = if idx < 4 { 0 } else { *byte };
//             result += FrRef::from_u8(masked).unwrap();
//         }
//         result
//     }
//
//     let inps = raw_pub_in.public_inputs.to_le_bytes().to_vec();
//     let out_hash = blake3::hash(&inps);
//     babybear_bytes_to_sect_fr(&out_hash.into())
// }

const MOD_HEX: &str = "8000000000000000000000000000069d5bb915bcd46efb1ad5f173abdf"; // n
const TWO_TO_156_HEX: &str = "1000000000000000000000000000000000000000";

fn fr_add(a: &FrRef, b: &FrRef) -> FrRef {
    let n = FrRef::from_str_radix(MOD_HEX, 16).unwrap();
    (a + b) % n
}

fn fr_sub(a: &FrRef, b: &FrRef) -> FrRef {
    let modr = FrRef::from_str_radix(MOD_HEX, 16).unwrap();
    if a >= b { a - b } else { a + &modr - b }
}

fn fr_mul(a: &FrRef, b: &FrRef) -> FrRef {
    let n = FrRef::from_str_radix(MOD_HEX, 16).unwrap();
    (a * b) % n
}

pub(crate) fn verify(
    proof: ProofRef,
    public_inputs: PublicInputsRef,
    secrets: TrapdoorRef,
) -> bool {
    let (proof_commit_p, decode_proof_commit_p_success) =
        CurvePointRef::from_affine_point(&proof.commit_p);
    let generator = CurvePointRef::generator();
    let (proof_kzg_k, decode_proof_kzg_k_success) = CurvePointRef::from_affine_point(&proof.kzg_k);
    let n = FrRef::from_str_radix(MOD_HEX, 16).unwrap();
    let decode_scalars_success = proof.a0 < n && proof.b0 < n;

    // decompose
    let two_to_156 = FrRef::from_str_radix(TWO_TO_156_HEX, 16).unwrap();
    let decompose_scalars_check = proof.x1.0 < two_to_156
        && proof.x2.0 < two_to_156
        && proof.z.0 < two_to_156;

    // let public_inputs_1 = get_pub_hash_from_raw_pub_inputs(&raw_public_inputs);
    // let public_inputs_0_vk_const = FrRef::from_str(ziren_vk).unwrap(); // vk

    let fs_challenge_alpha =
        get_fs_challenge(&proof.commit_p, &public_inputs.public_inputs, vec![], vec![]);

    let i0 = {
        let t0 = fr_mul(&public_inputs.public_inputs[1], &fs_challenge_alpha);
        fr_add(&t0, &public_inputs.public_inputs[0])
    };

    let r0 = {
        //&proof.a0 * &proof.b0 - &proof.i0
        let t0 = fr_mul(&proof.a0, &proof.b0);
        fr_sub(&t0, &i0)
    };

    // Step 3. Compute u₀ and v₀
    let delta2 = fr_mul(&secrets.delta, &secrets.delta);
    let u0 = {
        //(&proof.a0 + &secrets.delta * &proof.b0 + &delta2 * &r0) * &secrets.epsilon;
        let db0 = fr_mul(&secrets.delta, &proof.b0);
        let a0_p_db0 = fr_add(&proof.a0, &db0);
        let d2_r0 = fr_mul(&delta2, &r0);
        let t1 = fr_add(&a0_p_db0, &d2_r0);
        fr_mul(&t1, &secrets.epsilon)
    };
    let v0 = fr_mul(&fr_sub(&secrets.tau, &fs_challenge_alpha), &secrets.epsilon);
    let fr_zero = FrRef::ZERO;

    // check x1, x2, z to u0, v0
    // u0 = x1/z mod r,  v0 = x2/z mod r
    let new_x1 = if proof.x1.1 {
        fr_sub(&fr_zero, &proof.x1.0)
    } else {
        proof.x1.0.clone()
    };
    let new_x2 = if proof.x2.1 {
        fr_sub(&fr_zero, &proof.x2.0)
    } else {
        proof.x2.0.clone()
    };
    let new_z = if proof.z.1 {
        fr_sub(&fr_zero, &proof.z.0)
    } else {
        proof.z.0.clone()
    };

    let k1z = fr_mul(&u0, &new_z);
    let k2z = fr_mul(&v0, &new_z);
    let diff1 = fr_sub(&k1z, &new_x1);
    let diff2 = fr_sub(&k2z, &new_x2);
    let check_diff1 = diff1.is_zero();
    let check_diff2 = diff2.is_zero();


    // check the validation of hinted double scalar multiplication
    // u0 * G + v0 * KZG_K == COMMIT_P
    // <=> x1G + x2KZG_K + (-zP) = 0
    let new_p1 = if proof.x1.1 {
        neg_point(&generator)
    } else {
        generator
    };

    let new_p2 = if proof.x2.1 {
        neg_point(&proof_kzg_k)
    } else {
        proof_kzg_k.clone()
    };

    let new_p3 = if proof.z.1 {
        proof_commit_p.clone()
    } else {
        neg_point(&proof_commit_p)
    };

    // x1p1 + x2p2 + zp3 == 0
    let x1p1 = point_scalar_multiplication(&proof.x1.0, &new_p1);
    let x2p2 = point_scalar_multiplication(&proof.x2.0, &new_p2);
    let x3p3 = point_scalar_multiplication(&proof.z.0, &new_p3);
    let sum1 = point_add(&x1p1, &x2p2);
    let lhs = point_add(&sum1, &x3p3);
    let rhs = CurvePointRef::identity();
    let equal = point_equals(&lhs, &rhs);

    decode_scalars_success
    && decode_proof_commit_p_success
    && decode_proof_kzg_k_success
    && decompose_scalars_check
    && check_diff1
    && check_diff2
    && equal
}

#[cfg(test)]
mod test {
    use super::super::fr_ref::FrRef;
    use super::{ProofRef, PublicInputsRef, TrapdoorRef, verify};
    use crate::circuits::sect233k1::curve_ckt::AffinePointRef;
    use std::str::FromStr;

    #[test]
    fn test_verify_over_mock_inputs_ref() {
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
        let proof = ProofRef { commit_p, kzg_k, a0, b0, x1, x2, z };
        let secrets = TrapdoorRef { tau, delta, epsilon };
        let rpin = PublicInputsRef { public_inputs };
        let passed = verify(proof, rpin, secrets);
        assert!(passed);
    }

    #[test]
    fn test_invalid_proof_over_mock_inputs_ref() {
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
        let proof = ProofRef { commit_p, kzg_k, a0, b0, x1, x2, z };
        let secrets = TrapdoorRef { tau, delta, epsilon };
        let rpin = PublicInputsRef { public_inputs };
        let passed = verify(proof, rpin, secrets);
        assert!(!passed);
    }
}
