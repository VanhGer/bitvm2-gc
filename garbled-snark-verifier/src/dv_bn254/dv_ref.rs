use num_bigint::BigUint;
use crate::dv_bn254::fr::FR_LEN;
use crate::dv_bn254::g1::{G1Projective, G1_PROJECTIVE_LEN};

const PROOF_BIT_LEN: usize = G1_PROJECTIVE_LEN * 2 + FR_LEN * 2;
const PUBINP_BIT_LEN: usize = 2 * FR_LEN;
const TRAPDOOR_BIT_LEN: usize = FR_LEN * 3;
pub(crate) const WITNESS_BIT_LEN: usize = PROOF_BIT_LEN + PUBINP_BIT_LEN + TRAPDOOR_BIT_LEN;


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

impl VerifierPayloadRef {
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

#[derive(Debug)]
/// ProofRef
pub struct ProofRef {
    /// commit_p
    pub mont_commit_p: ark_bn254::G1Projective, // commitment to witness folding & quotient in montgomery form
    /// kzg_k
    pub mont_kzg_k: ark_bn254::G1Projective, // combined KZG evaluation proof in montgomery form
    /// a0
    pub a0: FrRef,
    /// b0
    pub b0: FrRef,
}

#[derive(Debug)]
pub struct PublicInputsRef {
    pub public_inputs: [FrRef; 2],
}

impl ProofRef {
    pub fn to_bits(&self) -> [bool; PROOF_BIT_LEN] {
        let mut commit_p = G1Projective::to_bits(self.mont_commit_p);
        let mut kzg_k = G1Projective::to_bits(self.mont_kzg_k);
        let mut a0 = frref_to_bits(&self.a0).to_vec();
        let mut b0 = frref_to_bits(&self.b0).to_vec();

        let mut witness = vec![];

        witness.append(&mut commit_p);
        witness.append(&mut kzg_k);
        witness.append(&mut a0);
        witness.append(&mut b0);

        witness.try_into().unwrap()
    }
}

impl PublicInputsRef {
    pub fn to_bits(&self) -> [bool; PUBINP_BIT_LEN] {
        let witness: Vec<_> =
            self.public_inputs.iter().flat_map(|fr_ref| frref_to_bits(fr_ref)).collect();

        witness.try_into().unwrap()
    }
}

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

pub(crate) type FrRef = BigUint;

pub fn frref_to_bits(n: &FrRef) -> [bool; FR_LEN] {
    let bytes = n.to_bytes_le();
    let mut bits = [false; FR_LEN];
    for i in 0..FR_LEN {
        let byte = if i / 8 < bytes.len() { bytes[i / 8] } else { 0 };
        let r = (byte >> (i % 8)) & 1;
        bits[i] = r != 0;
    }
    bits
}
