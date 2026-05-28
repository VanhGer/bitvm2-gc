mod adaptor;
pub mod artifact;
pub mod utils;
pub mod circuit;

use std::cell::RefCell;
use std::fs;
use std::rc::Rc;
use std::sync::OnceLock;
pub use artifact::*;
pub use circuit::*;
pub use adaptor::*;
use garbled_snark_verifier::bag::{Circuit, Gate, S, Wire};
use garbled_snark_verifier::core::gate::{gate_garbled_with_delta, GateType};
use garbled_snark_verifier::core::utils::SerializableGate;
pub use utils::*;

// ── Original artifact paths (unique wire IDs, used by read_fresh_gc) ─────────
// garbled_evaluate_without_delta requires each Wire to be the output of exactly
// one gate. These are the pre-compaction artifacts that preserve that invariant.
fn fgc_gates_path() -> String {
    std::env::var("FGC_GATES_PATH").unwrap_or_else(|_| "./fgc_gates.bin".to_string())
}

fn fgc_indices_path() -> String {
    std::env::var("FGC_OUT_INDICES_PATH").unwrap_or_else(|_| "./fgc_out_indices.bin".to_string())
}

fn sgc_gates_path() -> String {
    std::env::var("SGC_GATES_PATH").unwrap_or_else(|_| "./sgc_gates.bin".to_string())
}

fn sgc_indices_path() -> String {
    std::env::var("SGC_OUT_INDICES_PATH").unwrap_or_else(|_| "./sgc_out_indices.bin".to_string())
}

// ── Compact artifact paths (slot-reused wire IDs, used by read_flat_gc) ───────
// Wire IDs are remapped to minimise FlatEvalBuffer size. Each slot may be reused
// across gate steps (safe for Vec<[u8;16]> reads-before-write, not for RefCell).
fn fgc_compact_gates_path() -> String {
    std::env::var("FGC_COMPACT_GATES_PATH").unwrap_or_else(|_| "./fgc_compact_gates.bin".to_string())
}

fn fgc_compact_indices_path() -> String {
    std::env::var("FGC_COMPACT_OUT_INDICES_PATH").unwrap_or_else(|_| "./fgc_compact_out_indices.bin".to_string())
}

fn sgc_compact_gates_path() -> String {
    std::env::var("SGC_COMPACT_GATES_PATH").unwrap_or_else(|_| "./sgc_compact_gates.bin".to_string())
}

fn sgc_compact_indices_path() -> String {
    std::env::var("SGC_COMPACT_OUT_INDICES_PATH").unwrap_or_else(|_| "./sgc_compact_out_indices.bin".to_string())
}

// ── Flat circuit ──────────────────────────────────────────────────────────────

/// Compact gate topology loaded once and shared read-only across all instances.
pub struct FlatGates {
    pub num_wires: usize,
    /// (wire_a_id, wire_b_id, wire_c_id, gate_type_u8, gid) — 20 bytes/gate,
    /// contiguous in memory so the hardware prefetcher can work effectively.
    pub gates: Vec<(u32, u32, u32, u8, u32)>,
}

/// Per-instance mutable label state for the flat garble path.
pub struct FlatEvalBuffer {
    pub labels: Vec<[u8; 16]>,
}

impl FlatEvalBuffer {
    pub fn new(num_wires: usize) -> Self {
        Self { labels: vec![[0u8; 16]; num_wires] }
    }

    #[inline]
    pub fn set_label(&mut self, wire_id: usize, label: [u8; 16]) {
        self.labels[wire_id] = label;
    }

    /// Garble every gate, stream-hash all ciphertexts, and return
    /// `(com_gc, output_label_pairs)` where each pair is `[l0, l1]`
    /// with `l1 = l0 ^ delta`.
    pub fn garble_and_hash(
        &mut self,
        flat: &FlatGates,
        output_indices: &[usize],
        delta: [u8; 16],
    ) -> ([u8; 32], Vec<[u8; 16]>) {
        use sha2::{Digest, Sha256};

        let delta_s = S(delta);
        let mut hasher = Sha256::new();

        for &(a, b, c, gt, gid) in &flat.gates {
            let a0 = S(self.labels[a as usize]);
            let b0 = S(self.labels[b as usize]);
            let gate_type = GateType::try_from(gt).expect("unknown gate type");
            let (c0, ct) = gate_garbled_with_delta(a0, b0, gid, gate_type, delta_s);
            self.labels[c as usize] = c0.0;
            match ct {
                None    => hasher.update([0u8]),
                Some(s) => { hasher.update([1u8]); hasher.update(s.0); }
            }
        }

        let hash: [u8; 32] = hasher.finalize().into();
        let output_labels: Vec<[u8; 16]> = output_indices
            .iter()
            .flat_map(|&idx| {
                let l0 = S(self.labels[idx]);
                [l0.0, (l0 ^ delta_s).0]
            })
            .collect();
        (hash, output_labels)
    }

    /// Like `garble_and_hash` but materializes ciphertexts for the evaluator path.
    pub fn garble_and_collect(
        &mut self,
        flat: &FlatGates,
        output_indices: &[usize],
        delta: [u8; 16],
    ) -> (Vec<Option<S>>, Vec<[u8; 16]>) {
        let delta_s = S(delta);
        let mut ciphertexts = Vec::with_capacity(flat.gates.len());

        for &(a, b, c, gt, gid) in &flat.gates {
            let a0 = S(self.labels[a as usize]);
            let b0 = S(self.labels[b as usize]);
            let gate_type = GateType::try_from(gt).expect("unknown gate type");
            let (c0, ct) = gate_garbled_with_delta(a0, b0, gid, gate_type, delta_s);
            self.labels[c as usize] = c0.0;
            ciphertexts.push(ct);
        }

        let output_labels: Vec<[u8; 16]> = output_indices
            .iter()
            .flat_map(|&idx| {
                let l0 = S(self.labels[idx]);
                [l0.0, (l0 ^ delta_s).0]
            })
            .collect();
        (ciphertexts, output_labels)
    }
}

static FLAT_CIRCUIT_1: OnceLock<(FlatGates, Vec<usize>)> = OnceLock::new();
static FLAT_CIRCUIT_2: OnceLock<(FlatGates, Vec<usize>)> = OnceLock::new();

/// Load flat FGC and SGC gate data, cached on first call.
/// Raw bytes are read once per OnceLock init then dropped — not retained in static memory.
pub fn read_flat_gc() -> (
    &'static FlatGates, &'static Vec<usize>,
    &'static FlatGates, &'static Vec<usize>,
) {
    let (fgc_flat, fgc_idx) = FLAT_CIRCUIT_1.get_or_init(|| {
        let gates_path = fgc_compact_gates_path();
        let indices_path = fgc_compact_indices_path();
        let gates_bytes = fs::read(&gates_path)
            .unwrap_or_else(|_| panic!("'{}' not found — run generate_compact_artifacts()", gates_path));
        let idx_bytes = fs::read(&indices_path)
            .unwrap_or_else(|_| panic!("'{}' not found — run generate_compact_artifacts()", indices_path));
        flat_from_bytes(&gates_bytes, &idx_bytes)
    });
    let (sgc_flat, sgc_idx) = FLAT_CIRCUIT_2.get_or_init(|| {
        let gates_path = sgc_compact_gates_path();
        let indices_path = sgc_compact_indices_path();
        let gates_bytes = fs::read(&gates_path)
            .unwrap_or_else(|_| panic!("'{}' not found — run generate_compact_artifacts()", gates_path));
        let idx_bytes = fs::read(&indices_path)
            .unwrap_or_else(|_| panic!("'{}' not found — run generate_compact_artifacts()", indices_path));
        flat_from_bytes(&gates_bytes, &idx_bytes)
    });
    (fgc_flat, fgc_idx, sgc_flat, sgc_idx)
}

fn flat_from_bytes(gates_bytes: &[u8], output_indices_bytes: &[u8]) -> (FlatGates, Vec<usize>) {
    let (num_wires, gates_read): (u32, Vec<SerializableGate>) =
        bincode::deserialize(gates_bytes).expect("deserialize gates");
    let output_indices: Vec<usize> =
        bincode::deserialize(output_indices_bytes).expect("deserialize indices");
    let flat = FlatGates {
        num_wires: num_wires as usize,
        gates: gates_read
            .iter()
            .map(|g| (g.wire_a_id, g.wire_b_id, g.wire_c_id, g.gate_type, g.gid))
            .collect(),
    };
    (flat, output_indices)
}

/// Load both circuits as Rc/RefCell-based `Circuit` for evaluation.
/// Reads from the ORIGINAL (non-compacted) artifacts — garbled_evaluate_without_delta
/// requires each Wire to be the output of exactly one gate, which slot-reused
/// compacted wire IDs would violate.
pub fn read_fresh_gc() -> (Circuit, Vec<usize>, Circuit, Vec<usize>) {
    let fgc_gates_bytes = fs::read(fgc_gates_path())
        .unwrap_or_else(|_| panic!("'{}' not found — run generate_compact_artifacts()", fgc_gates_path()));
    let fgc_idx_bytes = fs::read(fgc_indices_path())
        .unwrap_or_else(|_| panic!("'{}' not found — run generate_compact_artifacts()", fgc_indices_path()));
    let (fgc, fgc_indices) = deserialize_circuit(&fgc_gates_bytes, &fgc_idx_bytes);

    let sgc_gates_bytes = fs::read(sgc_gates_path())
        .unwrap_or_else(|_| panic!("'{}' not found — run generate_compact_artifacts()", sgc_gates_path()));
    let sgc_idx_bytes = fs::read(sgc_indices_path())
        .unwrap_or_else(|_| panic!("'{}' not found — run generate_compact_artifacts()", sgc_indices_path()));
    let (sgc, sgc_indices) = deserialize_circuit(&sgc_gates_bytes, &sgc_idx_bytes);

    (fgc, fgc_indices, sgc, sgc_indices)
}

fn deserialize_circuit(gates_bytes: &[u8], output_indices_bytes: &[u8]) -> (Circuit, Vec<usize>) {
    let (num_wires, gates_read): (u32, Vec<SerializableGate>) =
        bincode::deserialize(gates_bytes).expect("deserialize gates");
    let output_indices: Vec<usize> =
        bincode::deserialize(output_indices_bytes).expect("deserialize indices");

    let wires: Vec<_> = (0..num_wires)
        .map(|id| Rc::new(RefCell::new(Wire { label: None, value: None, id: Some(id) })))
        .collect();
    wires[0].borrow_mut().value = Some(false);
    wires[1].borrow_mut().value = Some(true);

    let gates: Vec<Gate> = gates_read.iter().map(|sg| {
        Gate::new_with_gid(
            wires[sg.wire_a_id as usize].clone(),
            wires[sg.wire_b_id as usize].clone(),
            wires[sg.wire_c_id as usize].clone(),
            GateType::try_from(sg.gate_type).expect("unknown gate type"),
            sg.gid,
        )
    }).collect();

    (Circuit(wires, gates), output_indices)
}
