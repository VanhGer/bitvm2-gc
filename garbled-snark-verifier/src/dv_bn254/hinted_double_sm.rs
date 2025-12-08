pub(crate) mod hinted_double_scalar_mul {
    use std::str::FromStr;
    use ark_ec::PrimeGroup;
    use ark_ff::AdditiveGroup;
    use crate::circuits::sect233k1::builder::{CircuitAdapter, CircuitTrait, Template};
    use crate::dv_bn254::fp254impl::Fp254Impl;
    use crate::dv_bn254::fq::{Fq, FQ_LEN};
    use crate::dv_bn254::g1::{G1Projective, G1_PROJECTIVE_LEN};
    use crate::dv_bn254::fr::Fr;

    const HINTED_DOUBLE_SCALAR_BITS_LENGTH: usize = 170;  // 2/3 * 254
    const NUMBER_OF_POINTS: usize = 1;
    /// lookup precompute table
    // indices in little-endian form
    // table: [0..2^w-1]P
    pub(crate) fn emit_lookup<T: CircuitTrait>(
        bld: &mut T,
        table: &Vec<Vec<usize>>,
        indices: &[usize],
    ) -> Vec<usize> {

        fn mux<T: CircuitTrait>(
            bld: &mut T,
            s: &[usize],
            other: &[usize],
            sel: &[usize],
        ) -> Vec<usize> {
            assert_eq!(s.len(), other.len());
            assert_eq!(s.len(), sel.len());

            let s_g1 = G1Projective::from_vec_wires(s);
            let other_g1 = G1Projective::from_vec_wires(other);
            let sel_g1 = G1Projective::from_vec_wires(sel);

            let mut r = s_g1.clone();

            for i in 0..FQ_LEN {
                let d = bld.xor_wire(s_g1.x.0[i], other_g1.x.0[i]);
                let xd = bld.and_wire(sel_g1.x.0[i], d);
                r.x.0[i] = bld.xor_wire(xd, s_g1.x.0[i]);
            }
            for i in 0..FQ_LEN {
                let d = bld.xor_wire(s_g1.y.0[i], other_g1.y.0[i]);
                let xd = bld.and_wire(sel_g1.y.0[i], d);
                r.y.0[i] = bld.xor_wire(xd, s_g1.y.0[i]);
            }
            for i in 0..FQ_LEN {
                let d = bld.xor_wire(s_g1.z.0[i], other_g1.z.0[i]);
                let xd = bld.and_wire(sel_g1.z.0[i], d);
                r.z.0[i] = bld.xor_wire(xd, s_g1.z.0[i]);
            }
            r.to_vec_wires()
        }

        assert!(table.len().is_power_of_two(), "table length must be a power-of-two");
        for i in 0..table.len() {
            assert_eq!(table[i].len(), G1_PROJECTIVE_LEN)
        }
        let mut level= table.clone();

        let mut bit = 0;
        while level.len() > 1 {
            let sel_mask = G1Projective {
                x: Fq([indices[bit]; FQ_LEN]),
                y: Fq([indices[bit]; FQ_LEN]),
                z: Fq([indices[bit]; FQ_LEN]),
            };
            let mut next = Vec::<Vec<usize>>::with_capacity(level.len() / 2);
            for j in 0..(level.len() / 2) {
                let a = &level[2 * j];
                let b = &level[2 * j + 1];
                next.push(mux(bld, a, b, &sel_mask.to_vec_wires()));
            }
            level = next;
            bit += 1;
        }
        level[0].clone()
    }

    // Compute [x1]P1 + x2[P2] + x3[P3].
    pub(crate) fn emit_hinted_double_scalar_mul<T: CircuitTrait>(
        bld: &mut T,
        scalars: &[Vec<usize>],
        points: &[Vec<usize>]
    ) -> Vec<usize> {
        // check size
        assert_eq!(scalars.len(), points.len());
        assert_eq!(scalars.len(), NUMBER_OF_POINTS);
        for i in 0..NUMBER_OF_POINTS {
            assert_eq!(scalars[i].len(), Fr::N_BITS);
            assert_eq!(points[i].len(), G1_PROJECTIVE_LEN);
        }

        let g1_zero_mont = G1Projective::as_montgomery(ark_bn254::G1Projective::ZERO);
        let g1_zero_mont_wires = G1Projective::wires_set(bld, g1_zero_mont).to_vec_wires();

        // precompute table for 3 points
        let table = emit_precompute_hinted_table(bld, points, &g1_zero_mont_wires);

        let mut r = g1_zero_mont_wires;

        for i in (0..HINTED_DOUBLE_SCALAR_BITS_LENGTH).rev() {
            r = G1Projective::add_montgomery(bld, &r, &r); // r = r * 2
            // get the msb i-th bit of k1, k2, k3
            // let lidx = vec![scalars[0][i], scalars[1][i], scalars[2][i]];
            let lidx = vec![scalars[0][i]];
            let t_i = emit_lookup(bld, &table, &lidx);
            r = G1Projective::add_montgomery(bld, &r, &t_i);
        }
        r
    }

    // generate precompute table for hinted double scalar multiplication
    pub(crate) fn emit_precompute_hinted_table<T: CircuitTrait>(
        bld: &mut T,
        points: &[Vec<usize>],
        g1_zero_mont_wires: &[usize],
    ) -> Vec<Vec<usize>> {
        // check size
        assert_eq!(points.len(), NUMBER_OF_POINTS);
        assert_eq!(g1_zero_mont_wires.len(), G1_PROJECTIVE_LEN);
        for i in 0..NUMBER_OF_POINTS {
            assert_eq!(points[i].len(), G1_PROJECTIVE_LEN);
        }

        let bs = [
            // [0, 0, 0],
            // [1, 0, 0],
            // [0, 1, 0],
            // [1, 1, 0],
            // [0, 0, 1],
            // [1, 0, 1],
            // [0, 1, 1],
            // [1, 1, 1],
            [0],
            [1],
        ];

        let table_size = bs.len();
        let mut table = Vec::with_capacity(table_size);

        let tmp = g1_zero_mont_wires.clone().to_vec();
        table.push(tmp);

        for i in 1..table_size {
            // let temp_point = add_2_points_with_selects(
            //     bld,
            //     bs[i][0],
            //     &points[0],
            //     bs[i][1],
            //     &points[1],
            //     g1_zero_mont_wires,
            // );
            // let sel_temp = usize::from((bs[i][0] != 0) || (bs[i][1] != 0));
            // let res_point = add_2_points_with_selects(
            //     bld,
            //     sel_temp,
            //     &temp_point,
            //     bs[i][2],
            //     &points[2],
            //     g1_zero_mont_wires,
            // );
            table.push(points[0].clone());
        }
        table
    }

    fn add_2_points_with_selects<T: CircuitTrait>(
        bld: &mut T,
        select0: usize,
        p0: &[usize],
        select1: usize,
        p1: &[usize],
        identity: &[usize],
    ) -> Vec<usize> {
        if select0 == 0 && select1 == 0 {
            return identity.to_vec();
        }
        if select0 == 0 {
            return p1.to_vec();
        }
        if select1 == 0 {
            return p0.to_vec();
        }
        G1Projective::add_montgomery(bld, p0, p1)
    }

    #[test]
    fn test_hinted_double_scalar_mul() {
        // test with one point first

        let scalar1 = ark_bn254::Fr::from_str("117254209170240570118468483301402360720011190156626").unwrap();
        let point1_mont = G1Projective::as_montgomery(ark_bn254::G1Projective::generator());

        let res = ark_bn254::G1Projective::generator() * scalar1;
        println!("res: {:?}", res);
        let mont_res = G1Projective::as_montgomery(res);
        println!("mont_res: {:?}", mont_res);


        let mut bld = CircuitAdapter::default();
        let scalar_wires = Fr::wires(&mut bld).0.to_vec();
        let point1_mont_wires = G1Projective::wires(&mut bld).to_vec_wires();

        let out_wires = emit_hinted_double_scalar_mul(
            &mut bld,
            &vec![scalar_wires],
            &vec![point1_mont_wires],
        );

        let witness = Fr::to_bits(scalar1).into_iter()
            .chain(G1Projective::to_bits(point1_mont).into_iter())
            .collect::<Vec<bool>>();

        let wires_bits = bld.eval_gates(&witness);
        let out_bits = out_wires.iter().map(|&w| wires_bits[w]).collect::<Vec<bool>>();
        let out_point = G1Projective::from_bits_unchecked(out_bits);

        println!("out_point: {:?}", out_point);

    }
}
