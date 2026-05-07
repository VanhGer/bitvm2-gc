use ark_bn254::{Fr, G1Affine};
use ark_groth16::VerifyingKey as Groth16VerifyingKey;
use rand::Rng;
use garbled_snark_verifier::bag::S;
use garbled_snark_verifier::dv_bn254::fq::Fq as DvFq;
use garbled_snark_verifier::dv_bn254::fr::Fr as DvFr;
use crate::instance::CACInstance;
use crate::instance::commit::CACInstanceCommit;

/// Number of instances generated in parallel per batch during the commitment phase.
/// Tune to match available RAM: peak ≈ BATCH_SIZE × ~6 GB.
const BATCH_SIZE: usize = 8;

/// Minimal per-instance secrets retained after commitment phase.
/// Only encoding keys and deltas are kept — all heavy GC data is dropped.
pub struct InstanceLightSecrets {
    pub delta: [S; 2],
    pub encoding_keys: [Vec<S>; 2],
}

/// The C&C Verifier: manages N_CC garbled-circuit instances for Cut-and-Choose.
///
/// Instances are generated in batches of BATCH_SIZE. After each batch the heavy
/// GC data (ciphertexts, adaptor tables) is dropped immediately; only the
/// commitment hash and minimal secrets are retained. Peak memory is therefore
/// BATCH_SIZE × ~6 GB rather than N_CC × ~6 GB.
pub struct BABEVerifier {
    seeds: Vec<u64>,
    commits: Vec<CACInstanceCommit>,
    /// Encoding keys and deltas for every instance — needed for label computation
    /// without re-deriving the full garbled circuit.
    pub light_secrets: Vec<InstanceLightSecrets>,
    pub temp_val: [u8; 32],
    vk: Groth16VerifyingKey<ark_bn254::Bn254>,
    static_public_inputs: Fr,
}

impl BABEVerifier {
    /// Create `n_cc` fresh instances processed in batches of BATCH_SIZE.
    ///
    /// For each batch: instances are generated in parallel, their commitments
    /// and minimal secrets extracted, then the heavy GC data is dropped.
    pub fn new(
        n_cc: usize,
        vk: &Groth16VerifyingKey<ark_bn254::Bn254>,
        static_public_inputs: Fr,
    ) -> Result<Self, String> {
        use p3_maybe_rayon::prelude::*;

        let seeds: Vec<u64> = (0..n_cc).map(|_| rand::random()).collect();

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(BATCH_SIZE)
            .build()
            .map_err(|e| e.to_string())?;

        let mut commits = Vec::with_capacity(n_cc);
        let mut light_secrets = Vec::with_capacity(n_cc);

        for batch_seeds in seeds.chunks(BATCH_SIZE) {
            // Generate up to BATCH_SIZE instances in parallel. For each instance,
            // stream-hash the ciphertexts and adaptor table without materializing them.
            // Peak memory per batch: BATCH_SIZE × O(circuit_size) instead of
            // BATCH_SIZE × O(circuit_size + ciphertexts + adaptor_tables).
            let batch_results: Vec<Result<(CACInstanceCommit, InstanceLightSecrets), String>> =
                pool.install(|| {
                    batch_seeds
                        .par_iter()
                        .map(|&seed| {
                            let (commit, secrets) =
                                CACInstance::commit_from_seed(seed, vk, static_public_inputs)?;
                            let ls = InstanceLightSecrets {
                                delta: secrets.delta,
                                encoding_keys: secrets.encoding_keys,
                            };
                            Ok((commit, ls))
                        })
                        .collect()
                });

            for result in batch_results {
                let (commit, ls) = result?;
                commits.push(commit);
                light_secrets.push(ls);
            }
        }

        let rng = &mut rand::thread_rng();
        let mut temp_val = [0u8; 32];
        rng.fill(&mut temp_val);

        Ok(Self {
            seeds,
            commits,
            light_secrets,
            temp_val,
            vk: vk.clone(),
            static_public_inputs,
        })
    }

    /// Return the C&C commit package from pre-computed commitments.
    pub fn commit(&self) -> crate::cac::CACSetupPackage {
        crate::cac::CACSetupPackage {
            commits: self.commits.clone(),
        }
    }

    /// After receiving the finalized indices, reveal:
    /// - seeds for the non-finalized instances (N_CC - M_CC)
    /// - full GC data for the M_CC finalized instances, regenerated one-by-one
    ///
    /// Peak memory during this call: 1 × ~6 GB (sequential regeneration).
    pub fn open(
        &self,
        finalized_indices: &[usize],
    ) -> Result<(Vec<(usize, u64)>, Vec<crate::cac::FinalizedInstanceData>), String> {
        let finalized_set: std::collections::HashSet<usize> =
            finalized_indices.iter().copied().collect();

        let opened: Vec<(usize, u64)> = (0..self.seeds.len())
            .filter(|i| !finalized_set.contains(i))
            .map(|i| (i, self.seeds[i]))
            .collect();

        // Regenerate all M_CC finalized instances in parallel (M_CC <= 4,
        // so peak memory is at most 4 × ~6 GB).
        use p3_maybe_rayon::prelude::*;
        let finalized: Vec<Result<crate::cac::FinalizedInstanceData, String>> = finalized_indices
            .par_iter()
            .map(|&i| {
                let inst = CACInstance::new_from_seed(
                    self.seeds[i],
                    &self.vk,
                    self.static_public_inputs,
                )?;

                let constant_labels_0 = [
                    inst.secrets.constant_0labels[0][0],
                    inst.secrets.constant_0labels[0][1] ^ inst.secrets.delta[0],
                ];
                let mut constant_labels_1 = vec![
                    inst.secrets.constant_0labels[1][0],
                    inst.secrets.constant_0labels[1][1] ^ inst.secrets.delta[1],
                ];
                constant_labels_1.extend(inst.get_b_value_labels());

                Ok(crate::cac::FinalizedInstanceData {
                    index: i,
                    ciphertext_sets: inst.ciphertexts_sets,
                    adaptor_tables: inst.adaptor_tables,
                    ct_setup: inst.ct_setup,
                    constant_labels_0,
                    constant_labels_1: constant_labels_1.try_into().unwrap(),
                    b: inst.secrets.b,
                })
                // inst is dropped here
            })
            .collect();
        let finalized = finalized.into_iter().collect::<Result<Vec<_>, _>>()?;

        Ok((opened, finalized))
    }

    /// Compute the active π₁ input labels for instance `idx` given a concrete π₁.
    pub fn compute_pi1_labels(&self, idx: usize, pi1: G1Affine) -> Vec<S> {
        let ls = &self.light_secrets[idx];
        let delta = ls.delta[0];
        DvFq::to_bits(pi1.x)
            .into_iter()
            .chain(DvFq::to_bits(pi1.y))
            .enumerate()
            .map(|(i, b)| {
                let key = ls.encoding_keys[0][i];
                if b { key ^ delta } else { key }
            })
            .collect()
    }

    /// Compute the active x_d input labels for instance `idx` given a concrete x_d.
    pub fn compute_x_d_labels(&self, idx: usize, x_d: Fr) -> Vec<S> {
        let ls = &self.light_secrets[idx];
        let delta = ls.delta[1];
        DvFr::to_bits(x_d)
            .into_iter()
            .enumerate()
            .map(|(i, b)| {
                let key = ls.encoding_keys[1][i];
                if b { key ^ delta } else { key }
            })
            .collect()
    }
}
