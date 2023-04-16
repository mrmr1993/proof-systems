use crate::circuits::domains::EvaluationDomains;
use crate::mips::{proof::Proof, prover_index::ProverIndex, witness::Witness};
use groupmap::GroupMap;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use poly_commitment::{commitment::CommitmentCurve, srs::SRS};
use std::sync::Arc;
use std::time::Instant;

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;
type G = Vesta;
type F = Fp;

#[test]
fn test_mips() {
    let start = Instant::now();

    let domain_size = 1 << 16;

    let domain = EvaluationDomains::<F>::create(domain_size).unwrap();
    let mut srs = SRS::<G>::create(domain.d1.size as usize);
    srs.add_lagrange_basis(domain.d1);
    let srs = Arc::new(srs);

    let memory_offsets = vec![0u32];

    let prover_index = ProverIndex::create(srs, domain, memory_offsets);
    println!(
        "- time to create prover index: {:?}s",
        start.elapsed().as_secs()
    );

    // generate the witness
    let start = Instant::now();
    let mut initial_memory = vec![0u8; domain_size];

    let data = vec![
        0x24, 0x0a, 0x00, 0x1a, 0x3c, 0x0b, 0x00, 0x00, 0x8d, 0x6b, 0x00, 0x08, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x4b, 0x60, 0x20, 0x08, 0x00, 0x00, 0x05, 0x01, 0x4b, 0x68, 0x22, 0x3c, 0x01,
        0x00, 0x00, 0xac, 0x2d, 0x00, 0x0c, 0x24, 0x02, 0x00, 0x04, 0x3c, 0x04, 0x00, 0x00, 0x24,
        0x84, 0x00, 0x10, 0x00, 0x00, 0x00, 0x0c, 0x24, 0x02, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x0c,
        0x00, 0x00, 0x00, 0x00,
    ];

    for (i, value) in data.into_iter().enumerate() {
        initial_memory[i] = value;
    }
    let witness = Witness::create(domain_size, 0u32, vec![(0u32, initial_memory)]);

    println!(
        "- time to create execution trace: {:?}s",
        start.elapsed().as_secs()
    );

    // add the proof to the batch
    let start = Instant::now();

    let group_map = <G as CommitmentCurve>::Map::setup();

    let proof =
        Proof::create::<BaseSponge, ScalarSponge>(&group_map, witness, &prover_index).unwrap();
    println!("- time to create proof: {:?}s", start.elapsed().as_secs());

    // verify the proof (propagate any errors)
    let start = Instant::now();
    proof
        .verify::<BaseSponge, ScalarSponge>(&group_map, &prover_index.verifier_index())
        .unwrap();
    println!("- time to verify: {}ms", start.elapsed().as_millis());
}
