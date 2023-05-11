use elf::endian::AnyEndian;
use elf::section::SectionHeader;
use elf::ElfBytes;
use kimchi::mips::{
    instructions::decoding::decode_selector,
    witness::{CODE_PAGE, DATA_PAGE},
};
use serde::{de::Deserialize, ser::Serialize};
use std::{
    fs::OpenOptions,
    io::{BufReader, BufWriter, Read, Write},
    process::ExitCode,
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
// To create a proof and witness files:
// cargo run --release --bin mips_demo -- foo
//
// To validate the proof against the witness files:
// cargo run --release --bin mips_demo
pub fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
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

        prove(initial_program_memory, initial_data_memory)
    } else {
        verify_commitments()
    }
}

use ark_ff::Zero;
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain as Domain};
use groupmap::GroupMap;
use kimchi::circuits::domains::EvaluationDomains;
use kimchi::mips::{
    proof::{Proof, SerializableProof},
    prover_index::ProverIndex,
    registers::Registers,
    witness::Witness,
};
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use poly_commitment::{commitment::CommitmentCurve, srs::SRS, PolyComm};
use std::sync::Arc;
use std::time::Instant;

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;
type G = Vesta;
type F = Fp;

pub fn prove(initial_program_memory: Vec<u8>, initial_data_memory: Vec<u8>) -> ExitCode {
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

    ExitCode::SUCCESS
}

pub fn commit_memory(srs: &SRS<G>, domain: Domain<F>, memory: Vec<u8>) -> PolyComm<G> {
    let evals = memory
        .into_iter()
        .map(|x| F::from(x as u64))
        .collect::<Vec<_>>();
    let evals = Evaluations::<F, Domain<F>>::from_vec_and_domain(evals, domain);
    srs.commit_evaluations_non_hiding(domain, &evals)
}

pub fn commit_registers(srs: &SRS<G>, domain: Domain<F>, registers: Registers<u32>) -> PolyComm<G> {
    let mut evals = registers
        .iter()
        .map(|x| F::from(*x as u64))
        .collect::<Vec<_>>();
    evals.extend((evals.len()..domain.size()).map(|_| F::zero()));
    let evals = Evaluations::<F, Domain<F>>::from_vec_and_domain(evals, domain);
    srs.commit_evaluations_non_hiding(domain, &evals)
}

pub fn verify_commitments() -> ExitCode {
    let mut exit_code = ExitCode::SUCCESS;
    let mut check_commitment = |msg, comm1: &PolyComm<G>, comm2: &PolyComm<G>| {
        if comm1 == comm2 {
            println!(
                "Computed {} commitment matches the proof:\n{}",
                msg, comm1.unshifted[0]
            )
        } else {
            exit_code = ExitCode::FAILURE;
            println!(
                "Difference in {} commitments:\n{}\nvs\n{}",
                msg, comm1.unshifted[0], comm2.unshifted[0]
            )
        }
    };

    let start = Instant::now();

    let domain_size = 1 << 16;

    let domain = EvaluationDomains::<F>::create(domain_size).unwrap();
    let mut srs = SRS::<G>::create(domain.d1.size as usize);
    srs.add_lagrange_basis(domain.d1);
    println!(
        "- time to create generate URS: {:?}ms",
        start.elapsed().as_millis()
    );

    let proof = {
        let path = "proof";
        print!("Reading file {}.. ", path);
        let file = OpenOptions::new().read(true).open(path).unwrap();
        let r = BufReader::new(file);

        let serialized_proof =
            SerializableProof::<G>::deserialize(&mut rmp_serde::Deserializer::new(r)).unwrap();
        println!("Done");
        serialized_proof.to_proof()
    };

    // Reading initial program memory from file
    let initial_program_memory = {
        let path = "initial_program_memory";
        print!("Reading file {}.. ", path);
        let file = OpenOptions::new().read(true).open(path).unwrap();
        let r = BufReader::new(file);
        let initial_memory: Vec<u8> = r.bytes().map(Result::unwrap).collect();
        println!("Done.");
        initial_memory
    };

    // Check initial program memory
    {
        let comm = commit_memory(&srs, domain.d1, initial_program_memory);
        check_commitment(
            "initial program memory",
            &comm,
            &proof.commitments.initial_memory[0],
        )
    };

    // Read initial data memory from file
    let initial_data_memory = {
        let path = "initial_data_memory";
        print!("Reading file {}.. ", path);
        let file = OpenOptions::new().read(true).open(path).unwrap();
        let r = BufReader::new(file);
        let initial_memory: Vec<u8> = r.bytes().map(Result::unwrap).collect();
        println!("Done.");
        initial_memory
    };

    // Check initial data memory
    {
        let comm = commit_memory(&srs, domain.d1, initial_data_memory);
        check_commitment(
            "initial data memory",
            &comm,
            &proof.commitments.initial_memory[1],
        )
    };

    // Read initial registers
    let initial_registers = {
        let path = "initial_registers";
        print!("Reading file {}.. ", path);
        let file = OpenOptions::new().read(true).open(path).unwrap();
        let r = BufReader::new(file);
        let initial_registers =
            Registers::<u32>::deserialize(&mut serde_json::Deserializer::from_reader(r)).unwrap();
        println!("Done.");
        initial_registers
    };

    // Check initial registers
    {
        let comm = commit_registers(&srs, domain.d1, initial_registers);
        check_commitment(
            "initial registers",
            &comm,
            &proof.commitments.initial_registers,
        )
    };

    // Reading final program memory from file
    let final_program_memory = {
        let path = "final_program_memory";
        print!("Reading file {}.. ", path);
        let file = OpenOptions::new().read(true).open(path).unwrap();
        let r = BufReader::new(file);
        let final_memory: Vec<u8> = r.bytes().map(Result::unwrap).collect();
        println!("Done.");
        final_memory
    };

    // Check final program memory
    {
        let comm = commit_memory(&srs, domain.d1, final_program_memory);
        check_commitment(
            "final program memory",
            &comm,
            &proof.commitments.final_memory[0],
        )
    };

    // Read final data memory from file
    let final_data_memory = {
        let path = "final_data_memory";
        print!("Reading file {}.. ", path);
        let file = OpenOptions::new().read(true).open(path).unwrap();
        let r = BufReader::new(file);
        let final_memory: Vec<u8> = r.bytes().map(Result::unwrap).collect();
        println!("Done.");
        final_memory
    };

    // Check final data memory
    {
        let comm = commit_memory(&srs, domain.d1, final_data_memory);
        check_commitment(
            "final data memory",
            &comm,
            &proof.commitments.final_memory[1],
        )
    };

    // Read final registers
    let final_registers = {
        let path = "final_registers";
        print!("Reading file {}.. ", path);
        let file = OpenOptions::new().read(true).open(path).unwrap();
        let r = BufReader::new(file);
        let final_registers =
            Registers::<u32>::deserialize(&mut serde_json::Deserializer::from_reader(r)).unwrap();
        println!("Done.");
        final_registers
    };

    // Check final registers
    {
        let comm = commit_registers(&srs, domain.d1, final_registers);
        check_commitment("final registers", &comm, &proof.commitments.final_registers)
    };

    exit_code
}
