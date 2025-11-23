use crate::circuits::sect233k1::builder::CircuitTrait;

pub mod add;
pub mod cmp;
pub mod mul;
pub mod utils;

pub struct U254(pub [usize; 254]);

impl U254 {
    pub const N_BITS: usize = 254;
    pub fn wires<T: CircuitTrait>(bld: &mut T) -> Vec<usize> {
        let wires: [usize; Self::N_BITS] = bld.fresh();
        wires.to_vec()
    }
    // pub fn wires_set_from_number(u: &BigUint) -> Wires {
    //     bits_from_biguint(u)[0..N_BITS]
    //         .iter()
    //         .map(|bit| {
    //             let wire = new_wirex();
    //             wire.borrow_mut().set(*bit);
    //             wire
    //         })
    //         .collect()
    // }
}