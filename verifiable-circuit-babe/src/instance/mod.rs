use ark_bn254::Fr;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use garbled_snark_verifier::bag::{Circuit, S};
use crate::babe::WeKnownPi1SetupCt;
use crate::gc::{build_base_table_bits, SparseAdaptorTable, CONSTANT_SIZE};
use crate::instance::secret::InstanceSecrets;
use ark_groth16::VerifyingKey as Groth16VerifyingKey;
use ark_serialize::CanonicalSerialize;
use garbled_snark_verifier::dv_bn254::fp254impl::Fp254Impl;
use garbled_snark_verifier::dv_bn254::fq::Fq as DvFq;
use garbled_snark_verifier::dv_bn254::fr::Fr as DvFr;
use crate::dre::N;
use crate::instance::commit::CACInstanceCommit;
use crate::utils::{g2_to_ser, ro_from_pairing_bytes};

pub mod secret;
pub mod commit;

pub struct BABEInstance {
    pub seed: u64,
    pub secrets: InstanceSecrets,
    pub ct_setup: WeKnownPi1SetupCt,
    pub adaptor_table: SparseAdaptorTable,
    pub ciphertexts: Vec<Option<S>>,
}

impl BABEInstance {
    /// Construct a instance fully determined by `seed`.
    /// W/O ct_setup.
    pub fn new_from_seed(
        seed: u64,
        vk: &Groth16VerifyingKey<ark_bn254::Bn254>,
        static_inputs: Fr,
    ) -> Result<Self, String> {
        use ark_bn254::G1Projective;

        if vk.gamma_abc_g1.len() != 3{
            return Err("static/dynamic split does not match vk".to_string());
        }

        let secrets = InstanceSecrets::new_from_seed(seed);

        // Load fresh circuit structure from pre-serialized files; drop after use.
        let (mut circuit, gc_output_indices) = crate::gc::read_fresh_circuit();


        // Apply encoding keys as 0-labels for evaluator input wires (pi_x, pi_y, x_d).
        for (i, &key) in secrets.encoding_keys.iter().enumerate() {
            circuit.0[2 + i].borrow_mut().label = Some(key);
        }

        // Compute r·L_i = r * sum(gamma_abc[num_static+1..]) and build the precomputed table.
        let base = vk.gamma_abc_g1[2] * secrets.r;
        let table_bits = build_base_table_bits(&base.into_affine());

        // Compute r·B bit representation (Montgomery form) for use as constant wires.
        let rb_x_bits: Vec<bool> = DvFq::to_bits(DvFq::as_montgomery(secrets.r_b.x));
        let rb_y_bits: Vec<bool> = DvFq::to_bits(DvFq::as_montgomery(secrets.r_b.y));

        // Derive 0-labels for each constant wire from val-labels and actual wire values.
        // constant_val_labels[i] is the label for the actual value of constant wire i:
        //   if value = 0 → val_label IS the 0-label
        //   if value = 1 → val_label IS the 1-label, so 0-label = val_label ^ delta
        let delta = secrets.delta;
        let mut constants_0labels = Vec::with_capacity(CONSTANT_SIZE);
        constants_0labels.push(secrets.constant_val_labels[0]);           // wire 0: value = 0
        constants_0labels.push(secrets.constant_val_labels[1] ^ delta);  // wire 1: value = 1
        for (k, &bit) in rb_x_bits.iter().enumerate() {
            let lv = secrets.constant_val_labels[2 + k];
            constants_0labels.push(if bit { lv ^ delta } else { lv });
        }
        for (k, &bit) in rb_y_bits.iter().enumerate() {
            let lv = secrets.constant_val_labels[2 + N + k];
            constants_0labels.push(if bit { lv ^ delta } else { lv });
        }
        for (k, &bit) in table_bits.iter().enumerate() {
            let lv = secrets.constant_val_labels[2 + 2 * N + k];
            constants_0labels.push(if bit { lv ^ delta } else { lv });
        }

        BABEInstance::set_gc_const_labels(&mut circuit, &constants_0labels);

        // Evaluate circuit at a random pi1 and random x_d to garble.
        let pi1 = G1Projective::rand(&mut rand::thread_rng()).into_affine();
        let x_d = ark_bn254::Fr::rand(&mut rand::thread_rng());
        let witness: Vec<bool> = DvFq::to_bits(pi1.x)
            .into_iter()
            .chain(DvFq::to_bits(pi1.y))
            .chain(DvFr::to_bits(x_d))
            .chain(rb_x_bits)
            .chain(rb_y_bits)
            .chain(table_bits)
            .collect();
        circuit.set_witness_value(&witness);
        for gate in &mut circuit.1 {
            gate.evaluate();
        }
        let ciphertexts = circuit.garbled_gates_with_delta(secrets.delta);

        // Recover label0 for each output wire.
        let delta = secrets.delta;
        let output_labels: Vec<[u8; 16]> = gc_output_indices
            .iter()
            .flat_map(|idx| {
                let label_0 = circuit.0[*idx]
                    .borrow()
                    .select_with_delta(circuit.0[*idx].borrow().get_value(), delta);
                [label_0.0, (label_0 ^ delta).0]
            })
            .collect();

        let adaptor_table = SparseAdaptorTable::build_from_r_and_labels(
            secrets.r,
            &output_labels,
            &secrets.rhos,
            &secrets.fq_deltas,
        );

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
            adaptor_table,
            ciphertexts,
        })
    }

    pub fn set_gc_const_labels(
        circuit: &mut Circuit,
        constant_labels: &[S],
    ) {
        assert_eq!(constant_labels.len(), CONSTANT_SIZE);
        circuit.0[0].borrow_mut().label = Some(constant_labels[0]);
        circuit.0[1].borrow_mut().label = Some(constant_labels[1]);
        for i in 2..CONSTANT_SIZE {
            circuit.0[i + 2 * N + DvFr::N_BITS].borrow_mut().label = Some(constant_labels[i]);
        }
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

        let r_b = secrets.r_b;
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
    pub fn compute_input_labels_based_on_value(&self, pi1: ark_bn254::G1Affine, x_d: ark_bn254::Fr) -> Vec<S> {
        let x_bits = DvFq::to_bits(pi1.x);
        let y_bits = DvFq::to_bits(pi1.y);
        let xd_bits = DvFr::to_bits(x_d);
        let witness: Vec<bool> = x_bits.into_iter().chain(y_bits).chain(xd_bits).collect();
        let delta = self.secrets.delta;

        let labels: Vec<S> = witness.iter().enumerate().map(|(i, &b)| {
            let key = self.secrets.encoding_keys[i];
            if b { key ^ delta } else { key }
        }).collect();
        labels
    }


    pub fn commit(&self) -> CACInstanceCommit {
        CACInstanceCommit::from_instance(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use rand::SeedableRng;
    use crate::babe::DummyMulCircuit;

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
        let dynamic_pin_size = 1usize;

        let instance = BABEInstance::new_from_seed(42, &vk, static_inputs)
            .expect("new_from_seed");

        let r = instance.secrets.r;

        // Simulate DSGC output: c1' = r·P_D + r·B
        // P_D = (a*a) · gamma_abc[|S|+1] = (a*a) · gamma_abc[2]
        let p_d = vk.gamma_abc_g1[2].into_group() * dynamic_inputs;
        let c1_prime = (p_d * r + instance.secrets.r_b.into_group()).into_affine();

        let ctprove = WeKnownPi1ProveCt { ct1_r_pi1: g1_to_ser(proof.a.into_group() * r) };
        let decrypted = we_known_pi1_dec(
            &vk, &instance.ct_setup, &ctprove, c1_prime,
            proof.b.into_group(), proof.c.into_group(),
        ).unwrap();

        assert_eq!(decrypted.as_slice(), &instance.secrets.msg);
    }
}