//! Curve Point representation and operations are referenced from xs233-sys library

use std::str::FromStr;

use super::{
    builder::{CircuitTrait, GateOperation, Template},
    gf_ckt::{GF_LEN, Gf, emit_gf_add, emit_gf_equals, emit_gf_square},
    gf_mul_ckt::emit_gf_mul,
};
use crate::circuits::sect233k1::builder::{CircuitAdapter, Operation};
use crate::circuits::sect233k1::dv_ckt::u8_to_bits_le;
use num_bigint::BigUint;
use serde::Deserialize;

/// Representation of a point, on the xsk233 curve in projective co-ordinates, as wire labels
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub(crate) struct CurvePoint {
    pub x: Gf,
    pub s: Gf,
    pub z: Gf,
    pub t: Gf,
}

/// Representation of a point in Lopez–Dahab affine (λ) coordinates.
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub(crate) struct AffinePoint {
    pub x: Gf,
    pub s: Gf,
}

/// Lopez–Dahab λ coordinates (x, λ(=s)) for a curve point over GF(2^233).
#[derive(Debug, Deserialize)]
pub struct AffinePointRef {
    pub x: [u8; 30],
    pub s: [u8; 30],
}

impl AffinePointRef {
    pub fn to_bits(&self) -> Vec<bool> {
        let mut bits = Vec::with_capacity(GF_LEN * 2);

        // Helper to extract 233 little-endian bits from a 30-byte array.
        let bytes_to_exact_bits = |bytes: &[u8]| -> Vec<bool> {
            bytes.iter().flat_map(|&byte| u8_to_bits_le(byte)).take(GF_LEN).collect()
        };

        bits.extend(bytes_to_exact_bits(&self.x));
        bits.extend(bytes_to_exact_bits(&self.s));
        bits
    }
}

/// Wire labels representing base field element ZERO
fn gf_zero<T: CircuitTrait>(b: &mut T) -> Gf {
    let z = b.zero();
    [z; GF_LEN]
}

/// Wire labels representing base field element ONE
fn gf_one<T: CircuitTrait>(b: &mut T) -> Gf {
    let z = b.zero();
    let o = b.one();
    let mut zs = [z; GF_LEN];
    zs[0] = o; // lsb at 0 bit
    zs
}

/// Equality of CurvePoints
pub(crate) fn emit_point_equals<T: CircuitTrait>(
    bld: &mut T,
    p1: &CurvePoint,
    p2: &CurvePoint,
) -> usize {
    // tmp1 = S₁·T₂
    let tmp1: Gf = emit_gf_mul(bld, &p1.s, &p2.t);

    // tmp2 = S₂·T₁
    let tmp2: Gf = emit_gf_mul(bld, &p2.s, &p1.t);

    let mut or_res = bld.zero();
    tmp1.iter().zip(tmp2).for_each(|(a, b)| {
        let a_xor_b = bld.xor_wire(*a, b);
        or_res = bld.or_wire(a_xor_b, or_res);
    });
    let one = bld.one();

    bld.xor_wire(or_res, one)
}

impl CurvePoint {
    /// Returns the identity element (point at infinity) of the curve.
    pub(crate) fn identity<T: CircuitTrait>(bld: &mut T) -> Self {
        CurvePoint {
            x: gf_zero(bld),
            s: gf_one(bld), // Or Y=1
            z: gf_one(bld),
            t: gf_zero(bld), // Often X*Z = 0 for identity
        }
    }

    /// Generator, actual values referenced from xs233-sys lib
    pub(crate) fn generator<T: CircuitTrait>(bld: &mut T) -> Self {
        fn gfref_to_bits(n: &BigUint) -> [bool; 233] {
            let bytes = n.to_bytes_le();
            let mut bits = [false; 233];
            for i in 0..233 {
                let byte = if i / 8 < bytes.len() { bytes[i / 8] } else { 0 };
                let r = (byte >> (i % 8)) & 1;
                bits[i] = r != 0;
            }
            bits
        }

        let x = BigUint::from_str(
            "13283792768796718556929275469989697816663440403339868882741001477299174",
        )
        .unwrap();
        let s = BigUint::from_str(
            "6416386389908495168242210184454780244589215014363767030073322872085145",
        )
        .unwrap();
        let z = BigUint::from_str("1").unwrap();
        let t = BigUint::from_str(
            "13283792768796718556929275469989697816663440403339868882741001477299174",
        )
        .unwrap();

        let x = gfref_to_bits(&x);
        let s = gfref_to_bits(&s);
        let z = gfref_to_bits(&z);
        let t = gfref_to_bits(&t);

        let x = x.map(|xi| if xi { bld.one() } else { bld.zero() });
        let s = s.map(|xi| if xi { bld.one() } else { bld.zero() });
        let z = z.map(|xi| if xi { bld.one() } else { bld.zero() });
        let t = t.map(|xi| if xi { bld.one() } else { bld.zero() });

        CurvePoint { x, s, z, t }
    }
}

/// Add points in curve
pub(crate) fn emit_point_add<T: CircuitTrait>(
    bld: &mut T,
    p1: &CurvePoint,
    p2: &CurvePoint,
) -> CurvePoint {
    /*
     * x1x2 <- X1*X2
     * s1s2 <- S1*S2
     * z1z2 <- Z1*Z2
     * d <- (S1 + T1)*(S2 + T2)
     * f <- x1x2^2
     * g <- z1z2^2
     * X3 <- d + s1s2
     * S3 <- sqrt(b)*(g*s1s2 + f*d) note: sqrt(b) = 1 for xsk233
     * Z3 <- sqrt(b)*(f + g)
     * T3 <- X3*Z3
     */

    // Step 1: Calculate products
    let x1x2 = emit_gf_mul(bld, &p1.x, &p2.x);
    let s1s2 = emit_gf_mul(bld, &p1.s, &p2.s);
    let z1z2 = emit_gf_mul(bld, &p1.z, &p2.z);

    // Step 2: Calculate d = (S1 + T1)*(S2 + T2)
    let tmp1 = emit_gf_add(bld, &p1.s, &p1.t);
    let tmp2 = emit_gf_add(bld, &p2.s, &p2.t);
    let d = emit_gf_mul(bld, &tmp1, &tmp2);

    // Step 3: Calculate squares
    let f = emit_gf_square(bld, &x1x2);
    let g = emit_gf_square(bld, &z1z2);

    // Step 4: Calculate output coordinates
    let p3_x = emit_gf_add(bld, &d, &s1s2);

    let tmp1 = emit_gf_mul(bld, &s1s2, &g);
    let tmp2 = emit_gf_mul(bld, &d, &f);
    let p3_s = emit_gf_add(bld, &tmp1, &tmp2);

    let p3_z = emit_gf_add(bld, &f, &g);
    let p3_t = emit_gf_mul(bld, &p3_x, &p3_z);

    CurvePoint { x: p3_x, s: p3_s, z: p3_z, t: p3_t }
}

/// Apply the Frobenius endomorphism on a point (i.e. square all coordinates).
///
/// Squares all coordinates of a xsk233 curve point.
pub(crate) fn emit_point_frob<T: CircuitTrait>(bld: &mut T, p1: &CurvePoint) -> CurvePoint {
    // Square all coordinates
    let p3_x = emit_gf_square(bld, &p1.x);
    let p3_z = emit_gf_square(bld, &p1.z);
    let p3_s = emit_gf_square(bld, &p1.s);
    let p3_t = emit_gf_square(bld, &p1.t);
    CurvePoint { x: p3_x, s: p3_s, z: p3_z, t: p3_t }
}

/// Converts an affine Lopez–Dahab point to projective representation and validates it.
/// Verify that (x, s) lies on the curve: s^2 + x*s == x^4 + 1.
pub(crate) fn emit_affine_point_is_on_curve<T: CircuitTrait>(
    bld: &mut T,
    p: &AffinePoint,
) -> (CurvePoint, usize) {
    let one = gf_one(bld);
    let lhs = {
        let s_squared = emit_gf_square(bld, &p.s);
        let s_mul_x = emit_gf_mul(bld, &p.s, &p.x);
        emit_gf_add(bld, &s_squared, &s_mul_x)
    };
    let rhs = {
        let x_squared = emit_gf_square(bld, &p.x);
        let x_fourth = emit_gf_square(bld, &x_squared);
        emit_gf_add(bld, &x_fourth, &one)
    };

    let is_on_curve = emit_gf_equals(bld, &lhs, &rhs);
    let projective_p = CurvePoint { x: p.x, s: p.s, z: one, t: p.x };

    (projective_p, is_on_curve)
}

// Generate Circuit Configuration for Point Addition
pub(crate) fn template_emit_point_add() -> Template {
    println!("Initializing template_emit_point_add");
    let mut bld = CircuitAdapter::default();
    // define const wires
    let const_wire_zero = bld.zero();
    let const_wire_one = bld.one();
    let p1 = CurvePoint { x: bld.fresh(), s: bld.fresh(), z: bld.fresh(), t: bld.fresh() };
    let p2 = CurvePoint { x: bld.fresh(), s: bld.fresh(), z: bld.fresh(), t: bld.fresh() };
    // serialize wire labels in a known order
    // this same order is respected when these specific wire labels are later referenced
    // for evaluation or to generate instance of PointAdd Circuit
    let mut input_wires = vec![];
    input_wires.extend_from_slice(&p1.x);
    input_wires.extend_from_slice(&p1.s);
    input_wires.extend_from_slice(&p1.z);
    input_wires.extend_from_slice(&p1.t);

    input_wires.extend_from_slice(&p2.x);
    input_wires.extend_from_slice(&p2.s);
    input_wires.extend_from_slice(&p2.z);
    input_wires.extend_from_slice(&p2.t);

    let start_wire_idx = bld.next_wire();
    let res = emit_point_add(&mut bld, &p1, &p2);
    let end_wire_idx = bld.next_wire();

    let mut output_wires = vec![];
    output_wires.extend_from_slice(&res.x);
    output_wires.extend_from_slice(&res.s);
    output_wires.extend_from_slice(&res.z);
    output_wires.extend_from_slice(&res.t);

    let gates = bld.get_gates();

    let stats = {
        let mut temp_and_gates_count = 0;
        let mut temp_xor_gates_count = 0;
        let mut temp_or_gates_count = 0;
        for g in gates {
            if let GateOperation::Base(bg) = g {
                match bg {
                    Operation::Add(_, _, _) => {
                        temp_xor_gates_count += 1;
                    }
                    Operation::Mul(_, _, _) => {
                        temp_and_gates_count += 1;
                    }
                    Operation::Or(_, _, _) => {
                        temp_or_gates_count += 1;
                    }
                    _ => unreachable!(),
                }
            }
        }
        (temp_and_gates_count, temp_xor_gates_count, temp_or_gates_count)
    };

    Template {
        input_wires,
        output_wires,
        gates: gates.clone(),
        start_wire_idx,
        end_wire_idx,
        const_wire_one,
        const_wire_zero,
        stats,
    }
}

#[cfg(test)]
mod test {
    use std::{os::raw::c_void, str::FromStr, time::Instant};

    use crate::circuits::sect233k1::{
        builder::CircuitTrait,
        gf_ref::bits_to_gfref,
    };
    use num_bigint::{BigUint, RandomBits};
    use rand::Rng;
    use xs233_sys::xsk233_generator;

    use crate::circuits::sect233k1::{
        builder::CircuitAdapter,
        curve_ref::{CurvePointRef as InnerPointRef, point_add as ref_point_add},
        gf_ref::{gfref_mul, gfref_to_bits},
    };

    use super::{CurvePoint, emit_point_add};

    // Creates a random point ensuring T = X*Z
    fn random_point() -> InnerPointRef {
        let mut rng = rand::thread_rng();
        let max_bit_len = 232;
        let x = rng.sample(RandomBits::new(max_bit_len));
        let s = rng.sample(RandomBits::new(max_bit_len));
        let z = rng.sample(RandomBits::new(max_bit_len));

        let t = gfref_mul(&x, &z);

        InnerPointRef { x, s, z, t }
    }

    #[test]
    fn test_point_add() {
        let pt = InnerPointRef {
            x: BigUint::from_str(
                "13283792768796718556929275469989697816663440403339868882741001477299174",
            )
            .unwrap(),
            s: BigUint::from_str(
                "6416386389908495168242210184454780244589215014363767030073322872085145",
            )
            .unwrap(),
            z: BigUint::from_str("1").unwrap(),
            t: BigUint::from_str(
                "13283792768796718556929275469989697816663440403339868882741001477299174",
            )
            .unwrap(),
        };

        let pt2 = random_point();
        let ptadd = ref_point_add(&pt, &pt2);

        let mut bld = CircuitAdapter::default();
        let c_pt = CurvePoint { x: bld.fresh(), s: bld.fresh(), z: bld.fresh(), t: bld.fresh() };

        let c_pt2 = CurvePoint { x: bld.fresh(), s: bld.fresh(), z: bld.fresh(), t: bld.fresh() };

        let st = Instant::now();
        let c_ptadd = emit_point_add(&mut bld, &c_pt, &c_pt2);
        let el = st.elapsed();
        println!("emit_point_add took {} seconds to compile ", el.as_secs());
        let stats = bld.gate_counts();
        println!("{stats}");

        let mut witness = Vec::<bool>::with_capacity(233 * 8);
        witness.extend(gfref_to_bits(&pt.x));
        witness.extend(gfref_to_bits(&pt.s));
        witness.extend(gfref_to_bits(&pt.z));
        witness.extend(gfref_to_bits(&pt.t));

        witness.extend(gfref_to_bits(&pt2.x));
        witness.extend(gfref_to_bits(&pt2.s));
        witness.extend(gfref_to_bits(&pt2.z));
        witness.extend(gfref_to_bits(&pt2.t));

        let wires = bld.eval_gates(&witness);

        let c_ptadd_x = bits_to_gfref(&c_ptadd.x.map(|w_id| wires[w_id]));
        let c_ptadd_s = bits_to_gfref(&c_ptadd.s.map(|w_id| wires[w_id]));
        let c_ptadd_z = bits_to_gfref(&c_ptadd.z.map(|w_id| wires[w_id]));
        let c_ptadd_t = bits_to_gfref(&c_ptadd.t.map(|w_id| wires[w_id]));

        let c_ptadd_val = InnerPointRef { x: c_ptadd_x, s: c_ptadd_s, z: c_ptadd_z, t: c_ptadd_t };
        assert_eq!(c_ptadd_val, ptadd);
    }
}
