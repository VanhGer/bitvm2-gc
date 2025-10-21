use crate::bag::Circuit;
use crate::circuits::sect233k1::dv_ckt::{VerifierPayloadRef, compile_verifier};
use std::time::Instant;

pub fn dv_snark_verifier_circuit(witness: &VerifierPayloadRef) -> Circuit {
    let start = Instant::now();
    let (builder, _) = compile_verifier();
    println!("Compile time: {:?}", start.elapsed());

    let start = Instant::now();
    let circuit = builder.build(&witness.to_bits());
    println!("build circuit time:{:?}", start.elapsed());

    circuit
}

#[cfg(test)]
mod test {
    use crate::circuits::dv_snark::dv_snark_verifier_circuit;
    use crate::circuits::sect233k1::curve_ckt::AffinePointRef;
    use crate::circuits::sect233k1::dv_ckt::{ProofRef, PublicInputsRef, TrapdoorRef, VerifierPayloadRef};
    use crate::circuits::sect233k1::fr_ref::FrRef;
    use std::str::FromStr;
    use std::time::Instant;
    // todo: remove ignore after debugging
    #[test]
    // #[ignore]
    fn test_dv_snark_verifier_circuit() {
        // Prepare VerifierPayloadRef
        let tau = FrRef::from_str(
            "2730322210350266333305929438402339624225511456370264338590718619370571",
        )
            .unwrap();
        let delta = FrRef::from_str(
            "1668197219006303135911300995268563595632072044933469744573172589503162",
        )
            .unwrap();
        let epsilon = FrRef::from_str(
            "180534986784443382108991383036395393569817197959638310564367496650276",
        )
            .unwrap();
        let commit_p = AffinePointRef {
            x: [243, 1, 124, 124, 28, 184, 224, 34, 217, 222, 182, 31, 42, 252, 194, 222, 40, 36, 80, 223, 106, 184, 193, 142, 55, 102, 25, 112, 7, 0],
            s: [229, 76, 122, 168, 191, 162, 130, 195, 248, 229, 89, 69, 135, 106, 178, 161, 172, 29, 249, 224, 109, 160, 41, 54, 63, 164, 235, 10, 145, 1]
        };
        let kzg_k = AffinePointRef {
            x: [240, 171, 68, 224, 177, 62, 73, 178, 215, 175, 231, 231, 151, 89, 104, 111, 7, 40, 91, 33, 151, 83, 118, 199, 88, 68, 165, 164, 151, 1],
            s: [182, 120, 142, 188, 144, 198, 242, 204, 84, 254, 121, 254, 72, 190, 109, 99, 198, 59, 168, 17, 124, 224, 37, 14, 69, 114, 133, 198, 2, 1],
        };
        let a0 = FrRef::from_str(
            "1132675792798759308127577893315934115126328231089219585842855711650311",
        )
            .unwrap();
        let b0 = FrRef::from_str(
            "3028379641311591322528948616897330931030750894712035609973261306086667",
        )
            .unwrap();

        let x1 = (FrRef::from_str("8201062243878067778315015938357284675413750549").unwrap(), false);
        let x2 = (FrRef::from_str("12188555815513519027948129212942953563582264060").unwrap(), true);
        let z = (FrRef::from_str("2328416288857173011062977552890912854869626082").unwrap(), true);

        let public_inputs = [
            FrRef::from_str("24")
                .unwrap(),
            FrRef::from_str("13")
                .unwrap(),
        ];

        let witness = VerifierPayloadRef {
            proof: ProofRef { commit_p, kzg_k, a0, b0, x1, x2, z },
            public_input: PublicInputsRef { public_inputs },
            trapdoor: TrapdoorRef { tau, delta, epsilon },
        };

        let mut circuit = dv_snark_verifier_circuit(&witness);
        let start = Instant::now();
        let total_gates = circuit.gate_counts();
        println!("gate_counts time: {:?}", start.elapsed());
        total_gates.print();

        for gate in &mut circuit.1 {
            gate.evaluate();
        }
        assert!(circuit.0[0].borrow().get_value());
    }
}
