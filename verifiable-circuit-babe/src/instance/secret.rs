use ark_bn254::{Fq, Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::{UniformRand, Zero};
use garbled_snark_verifier::bag::S;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use garbled_snark_verifier::dv_bn254::fp254impl::Fp254Impl;
use garbled_snark_verifier::dv_bn254::fr::Fr as DvFr;
use crate::dre::{N, utils::sample_rhos};
use crate::gc::CONSTANT_SIZE;

pub struct InstanceSecrets {
    pub delta:         S,
    pub r:             Fr,
    pub msg:           [u8; 32],
    /// label0 per input wire, size = 2 * N + Fr::N (3 * N)
    pub encoding_keys: Vec<S>,
    /// Constant value-based labels. For example, if constant x = 1
    /// this contains 1-label of x. Size = CONSTANT_SIZE
    pub constant_val_labels: Vec<S>,
    pub rhos:          Vec<G1Affine>,
    pub fq_deltas:     Vec<Fq>,
    /// Blinding point r·B baked into the DSGC circuit.
    pub r_b:           G1Affine,
}

impl InstanceSecrets {
    pub fn new_from_seed(seed: u64) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);

        let mut delta_bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rng, &mut delta_bytes);
        delta_bytes[15] |= 1;
        let delta = S(delta_bytes);

        let r = Fr::rand(&mut rng);

        let mut msg = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut msg);

        let encoding_keys: Vec<S> = (0..2 * N + DvFr::N_BITS)
            .map(|_| {
                let mut b = [0u8; 16];
                rand::RngCore::fill_bytes(&mut rng, &mut b);
                S(b)
            })
            .collect();

        let constant_val_labels: Vec<S> = (0..CONSTANT_SIZE)
            .map(|_| {
                let mut b = [0u8; 16];
                rand::RngCore::fill_bytes(&mut rng, &mut b);
                S(b)
            })
            .collect();

        let rhos = sample_rhos(&mut rng);

        let fq_deltas: Vec<Fq> = (0..N)
            .map(|_| loop {
                let v = Fq::rand(&mut rng);
                if !v.is_zero() {
                    break v;
                }
            })
            .collect();

        let b_blind = G1Affine::rand(&mut rng);
        use ark_ec::CurveGroup;
        let r_b = (b_blind.into_group() * r).into_affine();

        Self { delta, r, msg, encoding_keys, constant_val_labels, rhos, fq_deltas, r_b }
    }
}
