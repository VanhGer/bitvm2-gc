use verifiable_circuit_babe::babe::run_babe_e2e_cac;

#[test]
fn e2e_babe_cac() {
    use verifiable_circuit_babe::transactions::OnchainSize;
    let run = run_babe_e2e_cac();
    assert_eq!(run.assert_witness.size_bytes(), 1960); // 98 * 20
    assert_eq!(run.challenge_assert_witness.size_bytes(), 14312);
    assert_eq!(run.wrongly_challenged_witness.size_bytes(), 64);
}
