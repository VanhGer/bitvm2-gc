use crate::{
    dv_bn254::{fp254impl::Fp254Impl},
    circuits::bn254::utils::create_rng
};
use ark_ff::{AdditiveGroup, UniformRand};
use num_bigint::BigUint;
use crate::circuits::sect233k1::builder::CircuitTrait;
use crate::dv_bn254::basic::not;
use crate::dv_bn254::bigint::U254;

pub const FR_LEN: usize = 254;
#[derive(Debug, Clone)]
pub struct Fr(pub [usize; FR_LEN]);

impl Fp254Impl for Fr {
    const MODULUS: &'static str =
        "21888242871839275222246405745257275088548364400416034343698204186575808495617";
    const MONTGOMERY_M_INVERSE: &'static str =
        "5441563794177615591428663161977496376097281981129373443346157590346630955009";
    const MONTGOMERY_R_INVERSE: &'static str =
        "17773755579518009376303681366703133516854333631346829854655645366227550102839";
    const N_BITS: usize = 254;

    fn half_modulus() -> BigUint {
        BigUint::from(ark_bn254::Fr::from(1) / ark_bn254::Fr::from(2))
    }

    fn one_third_modulus() -> BigUint {
        BigUint::from(ark_bn254::Fr::from(1) / ark_bn254::Fr::from(3))
    }
    fn two_third_modulus() -> BigUint {
        BigUint::from(ark_bn254::Fr::from(2) / ark_bn254::Fr::from(3))
    }

    fn neg<T: CircuitTrait>(bld: &mut T, a: &[usize]) -> Vec<usize> {
        assert_eq!(a.len(), Self::N_BITS);
        let mut not_a =  Vec::new();
        for i in 0..Self::N_BITS {
            not_a.push(not(bld, a[i]));
        }

        let wires = Self::add_constant(
            bld,
            &not_a,
            ark_bn254::Fr::from(1) - ark_bn254::Fr::from(Self::not_modulus_as_biguint()),
        );
        wires
    }
}

impl Fr {
    pub fn as_montgomery(a: ark_bn254::Fr) -> ark_bn254::Fr {
        a * ark_bn254::Fr::from(Self::montgomery_r_as_biguint())
    }

    pub fn from_montgomery(a: ark_bn254::Fr) -> ark_bn254::Fr {
        a / ark_bn254::Fr::from(Self::montgomery_r_as_biguint())
    }

    pub fn random() -> ark_bn254::Fr {
        let mut prng = create_rng();
        ark_bn254::Fr::rand(&mut prng)
    }

    pub fn to_bits(u: ark_bn254::Fr) -> Vec<bool> {
        let mut bytes = BigUint::from(u).to_bytes_le();
        bytes.extend(vec![0_u8; 32 - bytes.len()]);
        let mut bits = Vec::new();
        for byte in bytes {
            for i in 0..8 {
                bits.push(((byte >> i) & 1) == 1)
            }
        }
        bits.pop();
        bits.pop();
        bits
    }

    pub fn from_bits(bits: Vec<bool>) -> ark_bn254::Fr {
        let zero = BigUint::ZERO;
        let one = BigUint::from(1_u8);
        let mut u = zero.clone();
        for bit in bits.iter().rev() {
            u = u.clone() + u.clone() + if *bit { one.clone() } else { zero.clone() };
        }
        ark_bn254::Fr::from(u)
    }

    pub fn wires<T: CircuitTrait>(bld: &mut T) -> Self {
        let inner: [usize; FR_LEN] = bld.fresh();
        Self(inner)
    }

    pub fn wires_set<T: CircuitTrait>(bld: &mut T, u: ark_bn254::Fr) -> Self {
        let inner = Self::to_bits(u)[0..Self::N_BITS]
            .iter()
            .map(|bit| {
                if *bit {
                    bld.one()
                } else {
                    bld.zero()
                }
            })
            .collect::<Vec<usize>>();
        Self(inner.try_into().unwrap())
    }
    pub fn wires_set_montgomery<T: CircuitTrait>(bld: &mut T, u: ark_bn254::Fr) -> Self {
        Self::wires_set(bld, Self::as_montgomery(u))
    }

    pub fn from_wires<T: CircuitTrait>(bld: &mut T, fr: Fr) -> ark_bn254::Fr {
        Self::from_bits(fr.0.iter().map(|wire| {
            if *wire != bld.one() || *wire != bld.zero() {
                panic!("wire value is not set properly");
            }
            *wire == bld.one()
        }).collect())
    }

    pub fn from_montgomery_wires<T: CircuitTrait>(bld: &mut T, fr: Fr) -> ark_bn254::Fr {
        Self::from_montgomery(Self::from_wires(bld, fr))
    }

    fn add_constant<T: CircuitTrait>(bld: &mut T, a: &[usize], b: ark_bn254::Fr) -> Vec<usize> {
        assert_eq!(a.len(), Self::N_BITS);
        if b == ark_bn254::Fr::ZERO {
            return a.to_vec();
        }

        let mut wires_1 = U254::add_constant(bld, a, &BigUint::from(b));
        let u = wires_1.pop().unwrap();
        let c = Self::not_modulus_as_biguint();
        let mut wires_2 = U254::add_constant(bld, &wires_1, &c);
        wires_2.pop();
        let v = U254::less_than_constant(bld, &wires_1, &Self::modulus_as_biguint());

        // Ncimp
        let not_a = not(bld, u);
        let s = bld.and_wire(not_a, v);
        U254::select(bld, &wires_1, &wires_2, s)
    }

    // mont_mont_r: montgomery form of Fr::montgomery_r_as_biguint()
    pub fn to_montgomery_circuit<T: CircuitTrait>(bld: &mut T, a: &[usize]) -> Vec<usize> {
        let mont_mont_r = Fr::as_montgomery(ark_bn254::Fr::from(Fr::montgomery_r_as_biguint()));
        let mont_mont_r_wires = Fr::wires_set(bld, mont_mont_r);
        let mont_a = Fr::mul_montgomery(bld, a, &mont_mont_r_wires.0);
        mont_a
    }

    // little-endian bit vector of the 2^170
    pub fn two_to_170<T: CircuitTrait>(b: &mut T) -> Vec<usize> {
        let mut out = vec![b.zero(); FR_LEN];
        out[170] = b.one();
        out
    }
}

#[cfg(test)]
mod tests {
    use crate::circuits::sect233k1::builder::{CircuitAdapter, CircuitTrait};
    use crate::dv_bn254::fp254impl::Fp254Impl;
    use crate::dv_bn254::fr::Fr;

    #[test]
    fn test_negate_fr_with_selector() {
        let a = Fr::random();
        let neg_a = -a;
        let negate = false;

        let mut bld = CircuitAdapter::default();
        let a_wires = Fr::wires(&mut bld);
        let negate_wire = bld.fresh_one();

        let neg_a_sel = Fr::negate_with_selector(&mut bld, &a_wires.0, negate_wire);

        let witness = Fr::to_bits(a).iter().chain(&[negate]).copied().collect::<Vec<_>>();
        let wires_bits = bld.eval_gates(&witness);
        let neg_a_val = Fr::from_bits(
            neg_a_sel
                .iter()
                .map(|w| wires_bits[*w])
                .collect(),
        );
        assert_eq!(a, neg_a_val);
    }
}
