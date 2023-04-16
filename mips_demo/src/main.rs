use elf::endian::AnyEndian;
use elf::section::SectionHeader;
use elf::ElfBytes;
use kimchi::mips::instructions::decoding::decode_selector;

// To generate input:
// mips-linux-gnu-as foo.mips -o foo.bin
// mips-linux-gnu-ld foo.bin -o foo
//
// To run:
// cargo run --release --bin mips_demo -- foo
pub fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args
        .get(1)
        .expect("First argument should be a path to a MIPS ELF file.");
    let path = std::path::PathBuf::from(path);
    let file_data = std::fs::read(path).expect("Could not read file.");
    let slice = file_data.as_slice();
    let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Could not parse file.");

    let mut memory = vec![];

    // Get the ELF file's code
    let text_header: SectionHeader = file
        .section_header_by_name(".text")
        .expect("section table should be parseable")
        .expect("file should have a .text section");

    println!("{:?}", text_header);
    println!("{:#0x}", text_header.sh_addr);

    let (code, compression_header) = file
        .section_data(&text_header)
        .expect("Should be able to get note section data");
    if let Some(compression_header) = compression_header {
        panic!("{:?}", compression_header);
    }
    memory.push((
        text_header.sh_addr as u32,
        (code).iter().map(|x| *x).collect(),
    ));

    // Get the ELF file's data
    let data_header: SectionHeader = file
        .section_header_by_name(".data")
        .expect("section table should be parseable")
        .expect("file should have a .data section");

    println!("{:?}", data_header);
    println!("{:#0x}", data_header.sh_addr);

    let (data, compression_header) = file
        .section_data(&data_header)
        .expect("Should be able to get note section data");
    if let Some(compression_header) = compression_header {
        panic!("{:?}", compression_header);
    }
    memory.push((
        data_header.sh_addr as u32,
        (data).iter().map(|x| *x).collect(),
    ));

    for (i, word) in code.chunks(4).enumerate() {
        println!("{:?}", word);
        let mut acc = 0u32;
        for chunk in word {
            acc <<= 8;
            acc |= *chunk as u32;
        }
        println!("{:#0x}: {:#02b}", i * 4, acc);
        let opcode = (acc >> 26) & ((1 << (32 - 26)) - 1);
        let rs = (acc >> 21) & ((1 << (26 - 21)) - 1);
        let rt = (acc >> 16) & ((1 << (21 - 16)) - 1);
        let rd = (acc >> 11) & ((1 << (16 - 11)) - 1);
        let shamt = (acc >> 6) & ((1 << (11 - 6)) - 1);
        let funct = (acc >> 0) & ((1 << (6 - 0)) - 1);
        let imm = (acc >> 0) & ((1 << (16 - 0)) - 1);
        let address = (acc >> 0) & ((1 << (26 - 0)) - 1);
        println!(
            "opcode: {}, rs: {}, rt: {}, rd: {}, shamt: {}, funct: {}",
            opcode, rs, rt, rd, shamt, funct
        );
        println!("opcode: {}, rs: {}, rt: {}, imm: {}", opcode, rs, rt, imm);
        println!("opcode: {}, address: {}", opcode, address);
        let selector = decode_selector((opcode, funct));
        println!("selector: {:?}", selector);
    }

    for byte in data.iter() {
        println!("{:#0x}: {}", byte, *byte as char);
    }

    prove(memory[0].0 as u32, memory);
}

use groupmap::GroupMap;
use kimchi::circuits::domains::EvaluationDomains;
use kimchi::mips::{proof::Proof, prover_index::ProverIndex, witness::Witness};
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

pub fn prove(entrypoint: u32, initial_memory: Vec<(u32, Vec<u8>)>) {
    let start = Instant::now();

    let domain_size = 1 << 16;

    let domain = EvaluationDomains::<F>::create(domain_size).unwrap();
    let mut srs = SRS::<G>::create(domain.d1.size as usize);
    srs.add_lagrange_basis(domain.d1);
    let srs = Arc::new(srs);

    let prover_index = ProverIndex::create(
        srs,
        domain,
        initial_memory.iter().map(|(offset, _)| *offset).collect(),
    );
    println!(
        "- time to create prover index: {:?}s",
        start.elapsed().as_secs()
    );

    // generate the witness
    let start = Instant::now();

    let witness = Witness::create(domain_size, entrypoint, initial_memory);

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

    println!("Proof: {:?}", proof);

    // verify the proof (propagate any errors)
    let start = Instant::now();
    proof
        .verify::<BaseSponge, ScalarSponge>(&group_map, &prover_index.verifier_index())
        .unwrap();
    println!("- time to verify: {}ms", start.elapsed().as_millis());
}
