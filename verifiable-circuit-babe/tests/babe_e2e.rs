use verifiable_circuit_babe::babe::run_babe_e2e_cac;

#[test]
fn e2e_babe_cac() {
    use verifiable_circuit_babe::transactions::OnchainSize;
    let run = run_babe_e2e_cac();
    assert_eq!(run.assert_witness.size_bytes(), 12192); // 762 * 16
    assert_eq!(run.challenge_assert_witness.size_bytes(), 24448); // 762 * 16 * 2 + 64
    assert_eq!(run.wrongly_challenged_witness.size_bytes(), 64);
}
