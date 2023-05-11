use elf::endian::AnyEndian;
use elf::section::SectionHeader;
use elf::ElfBytes;
use kimchi::mips::{
    instructions::decoding::decode_selector,
    witness::{CODE_PAGE, DATA_PAGE},
};
use serde::ser::Serialize;
use std::{
    fs::OpenOptions,
    io::{BufWriter, Write},
};

// TODOs:
//   - program state
//     - dump initial and final memory to files
//     - dump initial and final registers to files
//   - dump proof to file, print size
//   - tool to check memory commitments in proof
//      - in demo, modify the output, show that the program now fails

// To generate input:
// mips-elf-as foo.mips -o foo.bin
// mips-elf-ld foo.bin -o foo
// mips-elf-objdump -s foo
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

    // Get the ELF file's code
    let text_header: SectionHeader = file
        .section_header_by_name(".text")
        .expect("section table should be parseable")
        .expect("file should have a .text section");

    let (code, compression_header) = file
        .section_data(&text_header)
        .expect("Should be able to get note section data");
    if let Some(compression_header) = compression_header {
        panic!("{:?}", compression_header);
    }
    let initial_program_memory = {
        let mut memory = Vec::with_capacity(1 << 16);
        let addr = text_header.sh_addr as u32;
        memory.extend((CODE_PAGE..addr).map(|_| 0u8));
        memory.extend(code.iter().map(|x| *x));
        memory
    };

    // Get the ELF file's data
    let data_header: SectionHeader = file
        .section_header_by_name(".data")
        .expect("section table should be parseable")
        .expect("file should have a .data section");

    let (data, compression_header) = file
        .section_data(&data_header)
        .expect("Should be able to get note section data");
    if let Some(compression_header) = compression_header {
        panic!("{:?}", compression_header);
    }
    let initial_data_memory = {
        let mut memory = Vec::with_capacity(1 << 16);
        let addr = data_header.sh_addr as u32;
        memory.extend((DATA_PAGE..addr).map(|_| 0u8));
        memory.extend(code.iter().map(|x| *x));
        memory
    };

    /*
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
    */

    prove(initial_program_memory, initial_data_memory);
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

pub fn prove(initial_program_memory: Vec<u8>, initial_data_memory: Vec<u8>) {
    let start = Instant::now();

    let domain_size = 1 << 16;

    let domain = EvaluationDomains::<F>::create(domain_size).unwrap();
    let mut srs = SRS::<G>::create(domain.d1.size as usize);
    srs.add_lagrange_basis(domain.d1);
    let srs = Arc::new(srs);

    let prover_index = ProverIndex::create(srs, domain);
    println!(
        "- time to create prover index: {:?}ms",
        start.elapsed().as_millis()
    );

    // generate the witness
    let start = Instant::now();

    let witness = Witness::create(domain_size, initial_program_memory, initial_data_memory);

    println!(
        "- time to create execution trace: {:?}ms",
        start.elapsed().as_millis()
    );

    // Write initial program memory to file
    {
        let path = "initial_program_memory";
        print!("Writing file {}.. ", path);
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .append(false)
            .open(path)
            .unwrap();
        let mut w = BufWriter::new(file);
        let (addr, initial_memory) = &witness.initial_memory[0];
        w.write_all(initial_memory.as_slice()).unwrap();
        println!("Done.");
    }

    // Write initial data memory to file
    {
        let path = "initial_data_memory";
        print!("Writing file {}.. ", path);
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .append(false)
            .open(path)
            .unwrap();
        let mut w = BufWriter::new(file);
        let (addr, initial_memory) = &witness.initial_memory[1];
        w.write_all(initial_memory.as_slice()).unwrap();
        println!("Done.");
    }

    // Write initial program registers
    {
        let path = "initial_registers";
        print!("Writing file {}.. ", path);
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .append(false)
            .open(path)
            .unwrap();
        let w = BufWriter::new(file);
        witness
            .initial_registers
            .serialize(&mut serde_json::Serializer::new(w))
            .unwrap();
        println!("Done.");
    }

    // Write final program memory to file
    {
        let path = "final_program_memory";
        print!("Writing file {}.. ", path);
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .append(false)
            .open(path)
            .unwrap();
        let mut w = BufWriter::new(file);
        let (addr, final_memory) = &witness.final_memory[0];
        w.write_all(final_memory.as_slice()).unwrap();
        println!("Done.");
    }

    // Write final data memory to file
    {
        let path = "final_data_memory";
        print!("Writing file {}.. ", path);
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .append(false)
            .open(path)
            .unwrap();
        let mut w = BufWriter::new(file);
        let (addr, final_memory) = &witness.final_memory[1];
        w.write_all(final_memory.as_slice()).unwrap();
        println!("Done.");
    }

    // Write final program registers
    {
        let path = "final_registers";
        print!("Writing file {}.. ", path);
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .append(false)
            .open(path)
            .unwrap();
        let w = BufWriter::new(file);
        witness
            .final_registers
            .serialize(&mut serde_json::Serializer::new(w))
            .unwrap();
        println!("Done.");
    }

    // add the proof to the batch
    let start = Instant::now();

    let group_map = <G as CommitmentCurve>::Map::setup();

    let proof =
        Proof::create::<BaseSponge, ScalarSponge>(&group_map, witness, &prover_index).unwrap();

    println!(
        "- time to create proof: {:?}ms",
        start.elapsed().as_millis()
    );

    let serialized_proof = proof.clone().to_serializable();

    let serialized_bytes = rmp_serde::to_vec(&serialized_proof).unwrap();

    println!("Proof size: {} bytes", serialized_bytes.len());

    // Write proof to file
    {
        let path = "proof";
        print!("Writing file {}.. ", path);
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .append(false)
            .open(path)
            .unwrap();
        let w = BufWriter::new(file);
        serialized_proof
            .serialize(&mut rmp_serde::Serializer::new(w))
            .unwrap();
        println!("Done");
    }

    // verify the proof (propagate any errors)
    let start = Instant::now();
    proof
        .verify::<BaseSponge, ScalarSponge>(&group_map, &prover_index.verifier_index())
        .unwrap();
    println!("- time to verify: {}ms", start.elapsed().as_millis());
}
