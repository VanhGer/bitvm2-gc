// ─── Transaction locking script ───────────────────────────────────────────────

use serde::{Deserialize, Serialize};
use crate::babe::{BabeBtcSig, BtcPk, BTC_SIG_BYTES, MSG_BYTES};
use crate::wots::{Wots96, Wots96Sig};
use bitvm::signatures::Wots;

/// Constants embedded in the locking script of tx_Deposit output 0.
/// Script: CheckSig(pk_P) ∧ CheckSig(pk_V)
#[derive(Debug, Clone)]
pub struct TxDepositLock {
    pub pk_p: BtcPk,
    pub pk_v: BtcPk,
    pub amount: u64,
}

#[derive(Debug, Clone)]
pub struct TxChallengeAssertOutputLock {
    pub pk_p: BtcPk,
    pub pk_v: BtcPk,
    pub h_msgs: Vec<[u8; 20]>,
}

// ─── Transaction witnesses (on-chain data) ────────────────────────────────────

/// tx_Assert — witness for input 0.
/// Input spends a UTXO with: CheckWotsSig(wots_pk_P)
/// Script verifies the Wots96 signature over the 96-byte message (π₁.x ∥ π₁.y ∥ x_d).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxAssertWitness {
    /// Compressed G1Affine, 33 bytes — the asserted proof element.
    /// In practice, this is not onchain.
    pub pi1: Vec<u8>,
    /// Dynamic public input scalar x_d, 32 bytes (little-endian Fr).
    /// This is not onchain.
    pub x_d: Vec<u8>,
    /// Wots96 signature over the 96-byte message (π₁.x LE-32 ∥ π₁.y LE-32 ∥ x_d LE-32).
    /// This is submitted onchain.
    pub wots_sig: Wots96Sig,
}

/// tx_ChallengeAssert — witness for input 0.
/// Input spends tx_Assert output 1: CheckSigsConsistent(wots_pk_P, epk_V) ∧ CheckSig(pk_V) ∧ CheckSig(pk_P)
/// Script verifies:
///   (a) Wots96 sig is valid for some 96-byte message m — binds π₁ and x_d to the prover
///   (b) SHA256(L[i]) == epk_V[i][bit_i(m)]  — L[i] is the correct GC label for bit_i under epk
///   (c) Wots96 sig and epk labels are consistent over the same message m — both sign/encode the same bits
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxChallengeAssertWitness {
    /// L₁…L_M — one GC input label per bit of π₁ and x_d, LAMPORT_N × 16 bytes.
    pub input_labels: Vec<[u8; 16]>,
    /// Wots96 sig re-posted from TxAssertWitness to bind the labels to π₁ and x_d.
    /// The script checks that the bit sequence recovered from this sig matches the
    /// bit indices used to select each label in input_labels.
    pub wots_sig: Wots96Sig,
    /// VerifierLiveSig
    pub sig_v: BabeBtcSig,
    /// ProverPresigChallengeAssert
    pub sig_p: BabeBtcSig,
}

/// tx_WronglyChallenged — witness for input 0.
/// Input spends tx_ChallengeAssert output 0: HashLock(h_msg) ∧ CheckSig(pk_P)
/// Script verifies: SHA256(msg) == h_msg.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxWronglyChallengedWitness {
    /// ProverLiveSig
    pub sig_p: BabeBtcSig,
    /// Decrypted secret — preimage of h_msg = SHA256(msg).
    pub msg: [u8; 32],
}

/// tx_NoWithdraw — witnesses for inputs 0 and 1.
/// Input 0 spends tx_Assert output 0:          CheckSig(pk_P) ∧ CheckSig(pk_V)
/// Input 1 spends tx_ChallengeAssert output 0: RelTimelock(Δ₁) ∧ CheckSig(pk_V)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxNoWithdrawWitness {
    /// ProverPresigNoWithdraw — for input 0
    pub input0_sig_p: BabeBtcSig,
    /// VerifierLiveSig — for input 0
    pub input0_sig_v: BabeBtcSig,
    /// VerifierLiveSig — for input 1, after RelTimelock(Δ₁)
    pub input1_sig_v: BabeBtcSig,
}

/// tx_Withdraw — witnesses for inputs 0 and 1.
/// Input 0 spends tx_Deposit output 0: CheckSig(pk_P) ∧ CheckSig(pk_V)
/// Input 1 spends tx_Assert output 0:  RelTimelock(Δ₂) ∧ CheckSig(pk_P) ∧ CheckSig(pk_V)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxWithdrawWitness {
    /// ProverLiveSig — for input 0
    pub input0_sig_p: BabeBtcSig,
    /// VerifierPresigWithdraw — for input 0
    pub input0_sig_v: BabeBtcSig,
    /// ProverLiveSig — for input 1, after RelTimelock(Δ₂)
    pub input1_sig_p: BabeBtcSig,
    /// VerifierPresigWithdraw — for input 1
    pub input1_sig_v: BabeBtcSig,
}

// ─── OnchainSize trait ────────────────────────────────────────────────────────

pub trait OnchainSize {
    fn size_bytes(&self) -> usize;
}

impl OnchainSize for TxAssertWitness {
    fn size_bytes(&self) -> usize {
        // TOTAL_DIGIT_LEN hash-chain preimages, each 20 bytes.
        Wots96::TOTAL_DIGIT_LEN as usize * 20
    }
}

impl OnchainSize for TxChallengeAssertWitness {
    fn size_bytes(&self) -> usize {
        self.input_labels.len() * 16                 // LAMPORT_N × 16 bytes
            + Wots96::TOTAL_DIGIT_LEN as usize * 20  // wots_sig preimages
            + BTC_SIG_BYTES                          // sig_v: 32 bytes
            + BTC_SIG_BYTES                          // sig_p: 32 bytes
    }
}

impl OnchainSize for TxWronglyChallengedWitness {
    fn size_bytes(&self) -> usize {
        BTC_SIG_BYTES // sig_p: 32 bytes
            + MSG_BYTES   // msg:   32 bytes
    }
}

impl OnchainSize for TxNoWithdrawWitness {
    fn size_bytes(&self) -> usize {
        BTC_SIG_BYTES * 3 // 3 sigs × 32 bytes = 96 bytes
    }
}

impl OnchainSize for TxWithdrawWitness {
    fn size_bytes(&self) -> usize {
        BTC_SIG_BYTES * 4 // 4 sigs × 32 bytes = 128 bytes
    }
}
