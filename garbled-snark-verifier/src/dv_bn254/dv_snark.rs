use crate::bag::Circuit;
use std::time::Instant;
use crate::dv_bn254::dv_ckt::{compile_verifier, Proof, PublicInputs, Trapdoor};
use crate::dv_bn254::dv_ref::VerifierPayloadRef;

pub fn dv_snark_verifier_circuit(
    witness: &VerifierPayloadRef
) -> Circuit {
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
    use crate::dv_bn254::dv_snark::dv_snark_verifier_circuit;
    use std::str::FromStr;
    use std::time::Instant;
    use crate::dv_bn254::dv_ckt::compile_verifier;
    use crate::dv_bn254::dv_ref::{FrRef, ProofRef, PublicInputsRef, TrapdoorRef, VerifierPayloadRef};
    use crate::dv_bn254::g1::G1Projective;

    #[test]
    fn test_dv_snark_verifier_circuit_vjp() {
        // Prepare VerifierPayloadRef
        let tau = FrRef::from_str(
            "8394308267859526971427261347904600926161705976009524430024764996871930415753",
        )
        .unwrap();
        let delta = FrRef::from_str(
            "2315944369284919926487619960559204810245744361589040386877369624317266598723",
        )
        .unwrap();
        let epsilon = FrRef::from_str(
            "20365422208426833139762019841150639793663904968329808095541144150505142236868",
        )
        .unwrap();
        let commit_p = ark_bn254::G1Projective::new_unchecked(
            ark_bn254::Fq::from_str("2121570113010389316890442213309414071744704356520894752339889877176854443744").unwrap(),
            ark_bn254::Fq::from_str("4892155479458348771080447112094084931787174043819461167942019258686944314003").unwrap(),
            ark_bn254::Fq::from_str("5055789294285647412717430892520958619052898701937057204143167799707953106762").unwrap(),
        );
        let kzg_k = ark_bn254::G1Projective::new_unchecked(
            ark_bn254::Fq::from_str("16027325412906133013858175866261096009145914989003926168290324786792888829350").unwrap(),
            ark_bn254::Fq::from_str("8693180677941531579496297991403830076108213989581560982254647630789131970841").unwrap(),
            ark_bn254::Fq::from_str("8899119832449135265353778893496596074092244492907284134188871091963473212800").unwrap(),
        );
        let mont_commit_p = G1Projective::as_montgomery(commit_p);
        let mont_kzg_k = G1Projective::as_montgomery(kzg_k);

        let a0 = FrRef::from_str(
            "6339121914397328097234812768100087874574742286341493600824062223536658813291",
        )
        .unwrap();
        let b0 = FrRef::from_str(
            "12575186484628904884739983179878638738990539668840694458511669784668380053721",
        )
        .unwrap();

        let public_inputs = [
            FrRef::from_str("24")
                .unwrap(),
            FrRef::from_str("13")
                .unwrap(),
        ];

        let witness = VerifierPayloadRef {
            proof: ProofRef { mont_commit_p, mont_kzg_k, a0, b0 },
            public_input: PublicInputsRef { public_inputs },
            trapdoor: TrapdoorRef { tau, delta, epsilon },
        };

        let (bld, info) = compile_verifier();
        let wires_bits = bld.eval_gates(&witness.to_bits());

        let output_value = wires_bits[info.output_index];
        println!("output_value");
        // let start = Instant::now();
        // let total_gates = circuit.gate_counts();
        // println!("gate_counts time: {:?}", start.elapsed());
        // total_gates.print();
        //
        // for gate in &mut circuit.1 {
        //     gate.evaluate();
        // }
        // assert!(circuit.0[0].borrow().get_value());
    }
}
