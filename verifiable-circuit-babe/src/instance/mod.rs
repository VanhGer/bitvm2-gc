use ark_bn254::{Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use garbled_snark_verifier::bag::S;
use garbled_snark_verifier::circuits::bn254::fq::Fq;
use crate::babe::WeKnownPi1SetupCt;
use crate::gc::SparseAdaptorTable;
use crate::instance::secret::InstanceSecrets;
use ark_groth16::VerifyingKey as Groth16VerifyingKey;
use ark_serialize::CanonicalSerialize;
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
    /// Construct a BABE instance fully determined by `seed`.
    /// W/O ct_setup.
    pub fn new_from_seed(seed: u64) -> Self {
        use ark_bn254::G1Projective;
        use ark_ff::Zero;
        use crate::dre::matrices::u_bar_vec;

        let secrets = InstanceSecrets::new_from_seed(seed);

        // Load fresh circuit structure from pre-serialized files; drop after use.
        let (mut circuit, gc_output_indices) = crate::gc::read_fresh_circuit();

        // Apply encoding keys and constant 0-labels to input wires.
        circuit.0[0].borrow_mut().label = Some(secrets.constant_0labels[0]);
        circuit.0[1].borrow_mut().label = Some(secrets.constant_0labels[1]);
        for (i, &key) in secrets.encoding_keys.iter().enumerate() {
            circuit.0[2 + i].borrow_mut().label = Some(key);
        }

        // Evaluate circuit at a random pi1 to obtain output labels.
        let pi1 = G1Projective::rand(&mut rand::thread_rng()).into_affine();
        let witness: Vec<bool> = Fq::to_bits(pi1.x)
            .into_iter()
            .chain(Fq::to_bits(pi1.y).into_iter())
            .collect();
        circuit.set_witness_value(&witness);
        for gate in &mut circuit.1 {
            gate.evaluate();
        }
        let ciphertexts = circuit.garbled_gates_with_delta(secrets.delta);

        // Recover label0 for each output wire.
        let delta = secrets.delta;
        let u_bar_pi1 = u_bar_vec(&pi1);
        let output_labels: Vec<[u8; 16]> = gc_output_indices
            .iter()
            .zip(u_bar_pi1.iter())
            .flat_map(|(idx, u)| {
                let current = circuit.0[*idx]
                    .borrow()
                    .select_with_delta(circuit.0[*idx].borrow().get_value(), delta);
                let label_0 = if u.is_zero() { current } else { current ^ delta };
                [label_0.0, (label_0 ^ delta).0]
            })
            .collect();

        let adaptor_table = SparseAdaptorTable::build_from_r_and_labels(
            secrets.r,
            &output_labels,
            &secrets.rhos,
            &secrets.fq_deltas,
        );

        // circuit is dropped here — not stored in the instance.

        Self {
            seed,
            secrets,
            ct_setup: WeKnownPi1SetupCt { ct2_r_delta_g2: vec![], ct3_masked_msg: vec![] },
            adaptor_table,
            ciphertexts,
        }
    }

    /// Enc*(crs, x_S, |D|, msg; r, r·B):
    ///   P_S = gamma_abc[0] + Σ_{k} x_S[k]·gamma_abc[k+1]
    ///   mask = Y_S^r - e(r·B, γ) where Y_S^r = e(α, r·β) + e(P_S, r·γ)
    pub fn enc_setup(
        &mut self,
        vk: &Groth16VerifyingKey<ark_bn254::Bn254>,
        static_inputs: &[Fr],
        dynamic_pin_size: usize,
    ) -> Result<(), String> {
        let num_static = static_inputs.len();
        if num_static + dynamic_pin_size + 1 != vk.gamma_abc_g1.len() {
            return Err("static/dynamic split does not match vk".to_string());
        }

        let r = self.secrets.r;

        let mut p_s = vk.gamma_abc_g1[0].into_group();
        for (k, x) in static_inputs.iter().enumerate() {
            p_s += vk.gamma_abc_g1[k + 1].into_group() * *x;
        }

        let r_b = self.secrets.r_b;
        let r_delta = vk.delta_g2.into_group() * r;

        let t1 = ark_bn254::Bn254::pairing(vk.alpha_g1, vk.beta_g2.into_group() * r);
        let t2 = ark_bn254::Bn254::pairing(p_s, vk.gamma_g2.into_group() * r);
        let y_s_r = t1 + t2;

        let q_b = ark_bn254::Bn254::pairing(r_b, vk.gamma_g2);
        let mask_gt = y_s_r - q_b;

        let mut mask_bytes = Vec::new();
        mask_gt.serialize_compressed(&mut mask_bytes).or(Err("Failed to serialize mask_bytes"))?;
        let mask = ro_from_pairing_bytes(&mask_bytes, self.secrets.msg.len());
        let ct3 = self.secrets.msg.iter().zip(mask.iter()).map(|(a, b)| a ^ b).collect::<Vec<_>>();

        self.ct_setup = WeKnownPi1SetupCt {
            ct2_r_delta_g2: g2_to_ser(r_delta),
            ct3_masked_msg: ct3,
        };
        Ok(())
    }

    /// Returns the input labels given the bits of pi1.
    pub fn compute_pi1_labels_based_on_value(&self, pi1: ark_bn254::G1Affine) -> Vec<S> {
        let x_bits = Fq::to_bits(pi1.x);
        let y_bits = Fq::to_bits(pi1.y);
        let witness: Vec<bool> = x_bits.into_iter().chain(y_bits.into_iter()).collect();
        let delta = self.secrets.delta;

        let mut labels = Vec::new();
        labels.push(self.secrets.constant_0labels[0]);
        labels.push(self.secrets.constant_0labels[1] ^ delta);
        let tail: Vec<S> = witness.iter().enumerate().map(|(i, &b)| {
            let key = self.secrets.encoding_keys[i];
            if b { key ^ delta } else { key }
        }).collect();
        labels.extend(tail);
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
    use ark_serialize::CanonicalDeserialize;
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
        let static_inputs = vec![a * b];
        let dynamic_pin_size = 1usize;

        let mut instance = BABEInstance::new_from_seed(42);
        instance.enc_setup(&vk, &static_inputs, dynamic_pin_size).unwrap();

        let r = instance.secrets.r;

        // Simulate DSGC output: c1' = r·P_D + r·B
        // P_D = (a*a) · gamma_abc[|S|+1] = (a*a) · gamma_abc[2]
        let p_d = vk.gamma_abc_g1[2].into_group() * (a * a);
        let c1_prime = (p_d * r + instance.secrets.r_b.into_group()).into_affine();

        let ctprove = WeKnownPi1ProveCt { ct1_r_pi1: g1_to_ser(proof.a.into_group() * r) };
        let decrypted = we_known_pi1_dec(
            &vk, &instance.ct_setup, &ctprove, c1_prime,
            proof.b.into_group(), proof.c.into_group(),
        ).unwrap();

        assert_eq!(decrypted.as_slice(), &instance.secrets.msg);
    }
}