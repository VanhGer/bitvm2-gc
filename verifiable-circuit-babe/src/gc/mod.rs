mod adaptor;
pub mod utils;
pub mod circuit;

use std::cell::RefCell;
use std::fs;
use std::rc::Rc;
use std::sync::OnceLock;
use ark_bn254::G1Affine;
use ark_ec::AffineRepr;
pub use circuit::*;
pub use adaptor::*;
use garbled_snark_verifier::bag::{Circuit, Gate, S, Wire};
use garbled_snark_verifier::core::gate::{gate_garbled_with_delta, GateType};
use garbled_snark_verifier::core::utils::{reset_gid, SerializableGate};
pub use utils::*;

fn fgc_gates_path() -> String {
    std::env::var("FGC_GATES_PATH").unwrap_or_else(|_| "./fgc_gates.bin".to_string())
}

fn fgc_indices_path() -> String {
    std::env::var("FGC_OUT_INDICES_PATH").unwrap_or_else(|_| "./fgc_out_indices.bin".to_string())
}

fn sgc_part1_gates_path() -> String {
    std::env::var("SGC_GATES_PATH").unwrap_or_else(|_| "./sgc_gates.bin".to_string())
}

fn sgc_part1_indices_path() -> String {
    std::env::var("SGC_OUT_INDICES_PATH").unwrap_or_else(|_| "./sgc_out_indices.bin".to_string())
}

/// Raw circuit bytes cached on first read.
static CIRCUIT_1_BYTES: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
static CIRCUIT_2_BYTES: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();

// ── Flat circuit (Fix 1: cache-efficient commit path) ─────────────────────────

/// Compact gate topology loaded once and shared read-only across all instances.
///
/// Replaces `Rc<RefCell<Wire>>` pointer-chasing with flat index arithmetic,
/// eliminating the dominant cache-miss source in `commit_from_seed`.
pub struct FlatGates {
    pub num_wires: usize,
    /// (wire_a_id, wire_b_id, wire_c_id, gate_type_u8, gid) — 20 bytes/gate,
    /// contiguous in memory so the hardware prefetcher can work effectively.
    pub gates: Vec<(u32, u32, u32, u8, u32)>,
}

/// Per-instance mutable label state for the flat garble path.
///
/// `labels[i]` holds the 0-label for wire `i`. Every access is a plain array
/// index — no `Rc`, no `RefCell`, no per-gate heap allocation.
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
    ///
    /// Fix 2 is implicit here: there is no evaluate step. Garbling only reads
    /// wire *labels* (never wire *values*), so `gate.evaluate()` is dead work.
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
}

static FLAT_CIRCUIT_1: OnceLock<(FlatGates, Vec<usize>)> = OnceLock::new();
static FLAT_CIRCUIT_2: OnceLock<(FlatGates, Vec<usize>)> = OnceLock::new();

/// Returns static references to the flat FGC and SGC gate data.
/// Files are read at most once (bytes cached in `CIRCUIT_1/2_BYTES`),
/// flat conversion at most once (cached in `FLAT_CIRCUIT_1/2`).
pub fn read_flat_gc() -> (
    &'static FlatGates, &'static Vec<usize>,
    &'static FlatGates, &'static Vec<usize>,
) {
    let (fgc_bytes, fgc_idx_bytes) = CIRCUIT_1_BYTES.get_or_init(|| {
        let gates_path = fgc_gates_path();
        let indices_path = fgc_indices_path();
        let g = fs::read(&gates_path)
            .unwrap_or_else(|_| panic!("'{}' not found — run generate_and_write_fresh_circuit()", gates_path));
        let i = fs::read(&indices_path)
            .unwrap_or_else(|_| panic!("'{}' not found — run generate_and_write_fresh_circuit()", indices_path));
        (g, i)
    });
    let (sgc_bytes, sgc_idx_bytes) = CIRCUIT_2_BYTES.get_or_init(|| {
        let gates_path = sgc_part1_gates_path();
        let indices_path = sgc_part1_indices_path();
        let g = fs::read(&gates_path)
            .unwrap_or_else(|_| panic!("'{}' not found — run generate_and_write_fresh_circuit()", gates_path));
        let i = fs::read(&indices_path)
            .unwrap_or_else(|_| panic!("'{}' not found — run generate_and_write_fresh_circuit()", indices_path));
        (g, i)
    });

    let (fgc_flat, fgc_idx) = FLAT_CIRCUIT_1.get_or_init(|| flat_from_bytes(fgc_bytes, fgc_idx_bytes));
    let (sgc_flat, sgc_idx) = FLAT_CIRCUIT_2.get_or_init(|| flat_from_bytes(sgc_bytes, sgc_idx_bytes));
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

pub fn read_fresh_gc() -> (Circuit, Vec<usize>, Circuit, Vec<usize>) {
    let (fgc_bytes, fgc_indices_bytes) = CIRCUIT_1_BYTES.get_or_init(|| {
        let gates_path = fgc_gates_path();
        let indices_path = fgc_indices_path();
        let g = fs::read(&gates_path)
            .unwrap_or_else(|_| panic!("'{}' not found — run function generate_and_write_fresh_circuit() to generate it.", gates_path));
        let i = fs::read(&indices_path)
            .unwrap_or_else(|_| panic!("'{}' not found — run function generate_and_write_fresh_circuit() to generate it.", indices_path));
        (g, i)
    });
    let (fgc, fgc_indices) = deserialize_circuit(fgc_bytes, fgc_indices_bytes);

    let (sgc_bytes, sgc_indices_bytes) = CIRCUIT_2_BYTES.get_or_init(|| {
        let gates_path = sgc_part1_gates_path();
        let indices_path = sgc_part1_indices_path();
        let g = fs::read(&gates_path)
            .unwrap_or_else(|_| panic!("'{}' not found — run function generate_and_write_fresh_circuit() to generate it.", gates_path));
        let i = fs::read(&indices_path)
            .unwrap_or_else(|_| panic!("'{}' not found — run function generate_and_write_fresh_circuit() to generate it.", indices_path));
        (g, i)
    });

    let (sgc, sgc_indices) = deserialize_circuit(sgc_bytes, sgc_indices_bytes);

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

pub fn generate_and_write_fresh_circuit(l2_point: ark_bn254::G1Affine) {
    reset_gid();
    let g = G1Affine::generator();
    let (bld, fgc_output_indices) = compile_fgc(g);
    let fgc_circuit = bld.build(&[]);

    let (bld, sgc_output_indices) = compile_sgc_part1(l2_point);
    let sgc_circuit = bld.build(&[]);

    // --- Serialize ---
    write_fresh_circuit(fgc_circuit, fgc_output_indices, fgc_gates_path(), fgc_indices_path());
    write_fresh_circuit(sgc_circuit, sgc_output_indices, sgc_part1_gates_path(), sgc_part1_indices_path());
}

fn write_fresh_circuit(
    circuit: Circuit,
    output_indices: Vec<usize>,
    gates_path: String,
    output_indices_path: String,
) {
    let num_wires = circuit.0.len() as u32;
    let gates: Vec<SerializableGate> = circuit.1.iter().map(|gate| SerializableGate {
        gate_type: gate.gate_type as u8,
        wire_a_id: gate.wire_a.borrow().id.unwrap(),
        wire_b_id: gate.wire_b.borrow().id.unwrap(),
        wire_c_id: gate.wire_c.borrow().id.unwrap(),
        gid: gate.gid,
    }).collect();
    let gates_bytes = bincode::serialize(&(num_wires, &gates)).expect("serialize gates");
    fs::write(gates_path, &gates_bytes).expect("write gates");

    // File 2: Vec<usize> output indices
    let indices_bytes = bincode::serialize(&output_indices).expect("serialize indices");
    fs::write(output_indices_path, &indices_bytes).expect("write indices");
}

#[cfg(test)]
mod tests {
    use ark_bn254::G1Affine;
    use ark_ec::AffineRepr;
    use garbled_snark_verifier::core::utils::reset_gid;
    use super::{compile_fgc, compile_sgc_part1, generate_and_write_fresh_circuit};

    #[test]
    #[ignore]
    fn test_babe_gc_serialize_roundtrip() {
        let l2_point: G1Affine = G1Affine::generator();
        generate_and_write_fresh_circuit(l2_point);

        reset_gid();
        let g = G1Affine::generator();
        let (bld, fgc_output_indices) = compile_fgc(g);
        let f_circuit = bld.build(&[]);
        let (bld, sgc_output_indices) = compile_sgc_part1(l2_point);
        let s_circuit = bld.build(&[]);

        // --- Reconstruct Circuit ---

        let (fgc, fgc_indices, sgc, sgc_indices) = super::read_fresh_gc();

        assert_eq!(fgc.0.len(), f_circuit.0.len(), "reconstructed wire count mismatch");
        assert_eq!(sgc.0.len(), s_circuit.0.len(), "reconstructed wire count mismatch");
        assert_eq!(fgc.1.len(), f_circuit.1.len(), "reconstructed gate count mismatch");
        assert_eq!(sgc.1.len(), s_circuit.1.len(), "reconstructed gate count mismatch");
        assert_eq!(fgc_indices, fgc_output_indices, "reconstructed output wire mismatch");
        assert_eq!(sgc_indices, sgc_output_indices, "reconstructed output wire mismatch");
        for (i, (orig, rec)) in f_circuit.1.iter().zip(fgc.1.iter()).enumerate() {
            assert_eq!(orig.gate_type, rec.gate_type, "reconstructed gate[{i}] type mismatch");
            assert_eq!(orig.wire_a.borrow().id, rec.wire_a.borrow().id, "reconstructed gate[{i}] wire_a id mismatch");
            assert_eq!(orig.wire_b.borrow().id, rec.wire_b.borrow().id, "reconstructed gate[{i}] wire_b id mismatch");
            assert_eq!(orig.wire_c.borrow().id, rec.wire_c.borrow().id, "reconstructed gate[{i}] wire_c id mismatch");
            assert_eq!(orig.gid, rec.gid, "reconstructed gate[{i}] gid mismatch");
        }

        for (i, (orig, rec)) in s_circuit.1.iter().zip(sgc.1.iter()).enumerate() {
            assert_eq!(orig.gate_type, rec.gate_type, "reconstructed gate[{i}] type mismatch");
            assert_eq!(orig.wire_a.borrow().id, rec.wire_a.borrow().id, "reconstructed gate[{i}] wire_a id mismatch");
            assert_eq!(orig.wire_b.borrow().id, rec.wire_b.borrow().id, "reconstructed gate[{i}] wire_b id mismatch");
            assert_eq!(orig.wire_c.borrow().id, rec.wire_c.borrow().id, "reconstructed gate[{i}] wire_c id mismatch");
            assert_eq!(orig.gid, rec.gid, "reconstructed gate[{i}] gid mismatch");
        }

        println!("Circuit reconstructed successfully from serialized data.");
    }
}
