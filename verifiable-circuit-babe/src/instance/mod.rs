use ark_bn254::Fr;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use garbled_snark_verifier::bag::{Circuit, S};
use crate::babe::WeKnownPi1SetupCt;
use crate::gc::{build_l2_table_bits, SparseAdaptorTable, SGC_PART1_CONSTANT_SIZE, WINDOW_ENTRIES};
use crate::instance::secret::InstanceSecrets;
use ark_groth16::VerifyingKey as Groth16VerifyingKey;
use ark_serialize::CanonicalSerialize;
use garbled_snark_verifier::dv_bn254::fp254impl::Fp254Impl;
use garbled_snark_verifier::dv_bn254::fq::Fq as DvFq;
use garbled_snark_verifier::dv_bn254::fr::Fr as DvFr;
use crate::dre::{N, Q_SIZE, U_BAR_SIZE};
use crate::instance::commit::CACInstanceCommit;
use crate::prover::BABEProver;
use crate::utils::{g2_to_ser, ro_from_pairing_bytes};

pub mod secret;
pub mod commit;

pub struct CACInstance {
    pub seed: u64,
    pub secrets: InstanceSecrets,
    pub ct_setup: WeKnownPi1SetupCt,
    pub adaptor_tables: [SparseAdaptorTable; 2],
    /// for fgc, sgc part 1, sgc part 2
    pub ciphertexts_sets: [Vec<Option<S>>; 3]
}

impl CACInstance {
    /// Construct a instance fully determined by `seed`.
    /// W/O ct_setup.
    pub fn new_from_seed(
        seed: u64,
        vk: &Groth16VerifyingKey<ark_bn254::Bn254>,
        static_inputs: Fr,
    ) -> Result<Self, String> {
        use ark_bn254::G1Projective;

        if vk.gamma_abc_g1.len() != 3 {
            return Err("static/dynamic split does not match vk".to_string());
        }

        // generate artifacts.
        // crate::gc::generate_and_write_fresh_circuit(vk.gamma_abc_g1[2]);

        let secrets = InstanceSecrets::new_from_seed(seed);

        // Load fresh circuit structure from pre-serialized files; drop after use.
        let (mut fgc, fgc_indices, mut sgc, sgc_indices) = crate::gc::read_fresh_gc();

        // Apply encoding keys as 0-labels for evaluator input wires (pi_x, pi_y, x_d).
        for (i, &key) in secrets.encoding_keys[0].iter().enumerate() {
            fgc.0[2 + i].borrow_mut().label = Some(key);
        }
        for (i, &key) in secrets.encoding_keys[1].iter().enumerate() {
            sgc.0[SGC_PART1_CONSTANT_SIZE + i].borrow_mut().label = Some(key);
        }

        // Compute B bit representation (Montgomery form) for use as constant wires.
        let b_x_bits: Vec<bool> = DvFq::to_bits(DvFq::as_montgomery(secrets.b.x));
        let b_y_bits: Vec<bool> = DvFq::to_bits(DvFq::as_montgomery(secrets.b.y));
        // Set constant wire value for sgc part 1
        for (i, bit) in b_x_bits.iter().enumerate() {
            sgc.0[2 + i].borrow_mut().value = Some(*bit);
        }
        for (i, bit) in b_y_bits.iter().enumerate() {
            sgc.0[2 + 254 + i].borrow_mut().value = Some(*bit);
        }

        // set constant labels
        set_gc_const_labels(&mut fgc, &secrets.constant_0labels[0]);
        set_gc_const_labels(&mut sgc, &secrets.constant_0labels[1]);

        // Evaluate circuit at a random pi1 and random x_d to garble
        let pi1 = G1Projective::rand(&mut rand::thread_rng()).into_affine();
        let x_d = ark_bn254::Fr::rand(&mut rand::thread_rng());

        // Fgc
        let fgc_witness: Vec<bool> = DvFq::to_bits(pi1.x)
            .into_iter()
            .chain(DvFq::to_bits(pi1.y))
            .collect();
        let (fgc_ciphertext, fgc_output_labels) = get_ciphertext_and_output_labels(
            &mut fgc,
            &fgc_indices,
            &fgc_witness,
            secrets.delta[0],
            2
        );
        assert_eq!(fgc_output_labels.len(), 2 * U_BAR_SIZE);
        println!("cac instance fgc done");
        // // Sgc - part 1
        // let sgc_part1_witness: Vec<bool> = DvFr::to_bits(x_d);
        // let (sgc_ciphertext_1, sgc_output_labels_1) = get_ciphertext_and_output_labels(
        //     &mut sgc,
        //     &sgc_indices,
        //     &sgc_part1_witness,
        //     secrets.delta[1],
        //     SGC_PART1_CONSTANT_SIZE,
        // );
        // println!("cac instance sgc part1 done");
        // assert_eq!(sgc_output_labels_1.len(), 2 * Q_SIZE);
        // // Sgc - part 2
        // // Reuse the fgc structure, by setting up the input & constant labels again, then evaluate.
        // fgc.reset_circuit_except_constants();
        // // set label of part2 as output of part1
        // for (i, &key) in sgc_output_labels_1.iter().step_by(2).enumerate()  {
        //     fgc.0[2 + i].borrow_mut().label = Some(S(key));
        // }
        // // set constant for part2
        // set_gc_const_labels(&mut fgc, &secrets.constant_0labels[1][0..2]);
        // // random eval
        // let (sgc_ciphertext_2, sgc_output_labels_2) = get_ciphertext_and_output_labels(
        //     &mut fgc,
        //     &fgc_indices,
        //     &fgc_witness,
        //     secrets.delta[1],
        //     2
        // );
        // assert_eq!(sgc_output_labels_2.len(), 2 * U_BAR_SIZE);
        // println!("cac instance sgc part 2 done");
        // generate adaptor table
        // fgc
        let fgc_adaptor_table = SparseAdaptorTable::build_from_r_and_u_bar_labels(
            secrets.r,
            &fgc_output_labels,
            &secrets.rhos[0],
            &secrets.fq_deltas[0],
        );

        // test table

        // size = gc_output_indices
        let output_labels: Vec<[u8; 16]> = fgc_indices
            .iter()
            .map(|idx| {
                let label_0 = fgc.0[*idx]
                    .borrow()
                    .label.unwrap().0;
                label_0
            })
            .collect();

        let ct1_bytes = BABEProver::eval_adaptor_table(
            &output_labels, pi1, &fgc_adaptor_table
        );
        let mut expected_ct1_bytes = Vec::new();
        (pi1 * secrets.r).into_affine().serialize_compressed(&mut expected_ct1_bytes).expect("serialize r·G1P");
        assert_eq!(ct1_bytes, expected_ct1_bytes);
        println!("eval correctly");

        // let sgc_adaptor_table = SparseAdaptorTable::build_from_r_and_u_bar_labels(
        //     secrets.r,
        //     &sgc_output_labels_2,
        //     &secrets.rhos[1],
        //     &secrets.fq_deltas[1],
        // );

        let ct_setup = Self::enc_setup(
            &secrets,
            vk,
            static_inputs,
        )?;

        // circuit is dropped here — not stored in the instance.

        Ok(Self {
            seed,
            secrets,
            ct_setup,
            // adaptor_tables: [fgc_adaptor_table, sgc_adaptor_table],
            adaptor_tables: [fgc_adaptor_table.clone(), fgc_adaptor_table],
            // ciphertexts_sets: [fgc_ciphertext, sgc_ciphertext_1, sgc_ciphertext_2],
            ciphertexts_sets: [fgc_ciphertext.clone(), fgc_ciphertext.clone(), fgc_ciphertext],
        })
    }

    /// Enc*(crs, x_S, |D|, msg; r, r·B):
    ///   P_S = gamma_abc[0] + Σ_{k} x_S[k]·gamma_abc[k+1]
    ///   mask = Y_S^r - e(r·B, γ) where Y_S^r = e(α, r·β) + e(P_S, r·γ)
    fn enc_setup(
        secrets: &InstanceSecrets,
        vk: &Groth16VerifyingKey<ark_bn254::Bn254>,
        static_inputs: Fr,
    ) -> Result<WeKnownPi1SetupCt, String> {
        let r = secrets.r;
        let p_s = vk.gamma_abc_g1[0].into_group() + vk.gamma_abc_g1[1].into_group() * static_inputs;

        let r_b = secrets.b * r;
        let r_delta = vk.delta_g2.into_group() * r;

        let t1 = ark_bn254::Bn254::pairing(vk.alpha_g1, vk.beta_g2.into_group() * r);
        let t2 = ark_bn254::Bn254::pairing(p_s, vk.gamma_g2.into_group() * r);
        let y_s_r = t1 + t2;

        let q_b = ark_bn254::Bn254::pairing(r_b, vk.gamma_g2);
        let mask_gt = y_s_r - q_b;

        let mut mask_bytes = Vec::new();
        mask_gt.serialize_compressed(&mut mask_bytes).or(Err("Failed to serialize mask_bytes"))?;
        let mask = ro_from_pairing_bytes(&mask_bytes, secrets.msg.len());
        let ct3 = secrets.msg.iter().zip(mask.iter()).map(|(a, b)| a ^ b).collect::<Vec<_>>();

        Ok(WeKnownPi1SetupCt {
            ct2_r_delta_g2: g2_to_ser(r_delta),
            ct3_masked_msg: ct3,
        })
    }

    /// Returns the input labels given the bits of pi1.
    /// Use for testing.
    pub fn compute_pi1_labels_based_on_value(&self, pi1: ark_bn254::G1Affine) -> Vec<S> {
        let x_bits = DvFq::to_bits(pi1.x);
        let y_bits = DvFq::to_bits(pi1.y);
        let witness: Vec<bool> = x_bits.into_iter().chain(y_bits).collect();
        let delta = self.secrets.delta[0];

        let labels: Vec<S> = witness.iter().enumerate().map(|(i, &b)| {
            let key = self.secrets.encoding_keys[0][i];
            if b { key ^ delta } else { key }
        }).collect();
        labels
    }

    /// Returns the input labels given the bits of pi1.
    /// Use for testing.
    pub fn compute_x_d_labels_based_on_value(&self, x_d: Fr) -> Vec<S> {
        let witness = DvFr::to_bits(x_d);
        let delta = self.secrets.delta[1];

        let labels: Vec<S> = witness.iter().enumerate().map(|(i, &b)| {
            let key = self.secrets.encoding_keys[1][i];
            if b { key ^ delta } else { key }
        }).collect();
        labels
    }

    pub fn get_b_value_labels(&self) -> Vec<S> {
        let b_x_bits: Vec<bool> = DvFq::to_bits(DvFq::as_montgomery(self.secrets.b.x));
        let b_y_bits: Vec<bool> = DvFq::to_bits(DvFq::as_montgomery(self.secrets.b.y));
        let mut labels = Vec::new();
        for (i, bit) in b_x_bits.iter().enumerate() {
            if *bit {
                labels.push(self.secrets.constant_0labels[1][i + 2] ^ self.secrets.delta[1]);
            } else {
                labels.push(self.secrets.constant_0labels[1][i + 2]);
            }
        }

        for (i, bit) in b_y_bits.iter().enumerate() {
            if *bit {
                labels.push(self.secrets.constant_0labels[1][i + 2 + 254] ^ self.secrets.delta[1]);
            } else {
                labels.push(self.secrets.constant_0labels[1][i + 2 + 254]);
            }
        }

        labels
    }

    // Labels of constants in both circuits
    pub fn get_2_circuit_constant_labels(&self) -> [Vec<S>; 2] {
        let f_01_labels = [
            self.secrets.constant_0labels[0][0], self.secrets.constant_0labels[0][1] ^ self.secrets.delta[0]
        ];

        let s_01_labels = [
            self.secrets.constant_0labels[1][0], self.secrets.constant_0labels[1][1] ^ self.secrets.delta[1]
        ];
        let s_b_labels = self.get_b_value_labels();
        let s_constant_labels: Vec<S> = s_01_labels
            .to_vec().into_iter().chain(s_b_labels).collect();
        [f_01_labels.to_vec(), s_constant_labels]
    }

    pub fn commit(&self) -> CACInstanceCommit {
        CACInstanceCommit::from_instance(self)
    }
}

pub fn set_gc_const_labels(
    circuit: &mut Circuit,
    constant_labels: &[S],
) {
    for i in 0..constant_labels.len() {
        circuit.0[i].borrow_mut().label = Some(constant_labels[i]);
    }
}

/// Generate ciphertexts and all output labels
fn get_ciphertext_and_output_labels(
    circuit: &mut Circuit,
    output_indices: &[usize],
    random_witness: &[bool],
    delta: S,
    const_skip: usize,
) -> (Vec<Option<S>>, Vec<[u8; 16]>) {
    circuit.set_witness_value(&random_witness, const_skip);
    for gate in &mut circuit.1 {
        gate.evaluate();
    }
    let ciphertexts = circuit.garbled_gates_with_delta(delta);

    // size = gc_output_indices x 2
    let output_labels: Vec<[u8; 16]> = output_indices
        .iter()
        .flat_map(|idx| {
            let label_0 = circuit.0[*idx]
                .borrow()
                .select_with_delta(circuit.0[*idx].borrow().get_value(), delta);
            [label_0.0, (label_0 ^ delta).0]
        })
        .collect();

    (ciphertexts, output_labels)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use rand::SeedableRng;
    use crate::babe::DummyMulCircuit;
    use crate::prover::BABEProver;

    #[test]
    fn enc_setup_prove_dec_roundtrip() {
        use crate::babe::{we_known_pi1_dec, WeKnownPi1ProveCt};
        use crate::utils::g1_to_ser;

        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);

        let a = Fr::from(3u64);
        let b = Fr::from(7u64);
        let circuit = DummyMulCircuit::<Fr> { a: Some(a), b: Some(b) };
        let (pk, vk) = ark_groth16::Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng)
            .expect("groth16 setup");
        let proof = ark_groth16::Groth16::<ark_bn254::Bn254>::prove(
            &pk,
            DummyMulCircuit::<Fr> { a: Some(a), b: Some(b) },
            &mut rng,
        ).expect("groth16 prove");

        // |S|=1 (a*b static), |D|=1 (a*a dynamic)
        let static_inputs = a * b;
        let dynamic_inputs = a * a;

        let instance = CACInstance::new_from_seed(42, &vk, static_inputs)
            .expect("new_from_seed");
        println!("generate instance done");

        let r = instance.secrets.r;
        let b_blind = instance.secrets.b;
        let pi1 = proof.a;

        // evaluate the fgc to get the r * pi_1
        let constant_labels = instance.get_2_circuit_constant_labels();
        let pi1_labels = instance.compute_pi1_labels_based_on_value(proof.a);
        // let xd_labels = instance.compute_x_d_labels_based_on_value(dynamic_inputs);
        let (mut fgc, fgc_indices, mut sgc, sgc_indices) = crate::gc::read_fresh_gc();
        set_gc_const_labels(&mut fgc, &constant_labels[0]);
        for (i, &lbl) in pi1_labels.iter().enumerate() {
            fgc.0[i + 2].borrow_mut().label = Some(lbl);
        }
        let fgc_witness: Vec<bool> = DvFq::to_bits(pi1.x)
            .into_iter()
            .chain(DvFq::to_bits(pi1.y).into_iter())
            .collect();
        let fgc_output_labels = BABEProver::eval_circuit_with_ciphertext(
            &mut fgc,
            &fgc_indices,
            &fgc_witness,
            &instance.ciphertexts_sets[0],
            2
        );
        let ct1_bytes = BABEProver::eval_adaptor_table(
            &fgc_output_labels, pi1, &instance.adaptor_tables[0]
        );
        let mut expected_ct1_bytes = Vec::new();
        (pi1 * r).into_affine().serialize_compressed(&mut expected_ct1_bytes).expect("serialize r·G1P");
        assert_eq!(ct1_bytes, expected_ct1_bytes);




        // // Simulate DSGC output: c1' = r·P_D + r·B
        // // P_D = (a*a) · gamma_abc[|S|+1] = (a*a) · gamma_abc[2]
        // let p_d = vk.gamma_abc_g1[2].into_group() * dynamic_inputs;
        // let ct1_prime = (p_d * r + instance.secrets.b * r);
        // let ctprove = WeKnownPi1ProveCt {
        //     ct1_r_pi1: g1_to_ser(proof.a.into_group() * r),
        //     ct1_prime: g1_to_ser(ct1_prime),
        // };
        // let decrypted = we_known_pi1_dec(
        //     &vk, &instance.ct_setup, &ctprove,
        //     proof.b.into_group(), proof.c.into_group(),
        // ).unwrap();
        //
        // println!("decrypted done");
        //
        // assert_eq!(decrypted.as_slice(), &instance.secrets.msg);
    }
}
