use crate::circuits::expr::{ColumnEvaluations, ExprError};
use crate::mips::columns::{
    Column, FixedColumns, InstructionParts, InstructionSelectors, LookupCounters, NUM_LOOKUP_TERMS,
    SCRATCH_SIZE,
};
use crate::proof::PointEvaluations;
use ark_ec::AffineCurve;
use poly_commitment::{commitment::PolyComm, evaluation_proof::OpeningProof};

#[derive(Debug)]
pub struct ProofCommitments<G: AffineCurve> {
    pub instruction_parts: InstructionParts<PolyComm<G>>,
    pub instruction_selectors: InstructionSelectors<PolyComm<G>>,
    pub initial_memory: Vec<PolyComm<G>>,
    pub final_memory: Vec<PolyComm<G>>,
    pub final_memory_write_index: Vec<PolyComm<G>>,
    pub initial_registers: PolyComm<G>,
    pub final_registers: PolyComm<G>,
    pub final_registers_write_index: PolyComm<G>,
    pub lookup_terms: [PolyComm<G>; NUM_LOOKUP_TERMS],
    pub lookup_aggregation: PolyComm<G>,
    pub instruction_pointer: PolyComm<G>,
    pub scratch_state: [PolyComm<G>; SCRATCH_SIZE],
    pub lookup_counters: LookupCounters<PolyComm<G>>,
    pub halt: PolyComm<G>,
}

#[derive(Debug)]
pub struct ProofEvaluations<F> {
    pub instruction_parts: InstructionParts<PointEvaluations<F>>,
    pub instruction_selectors: InstructionSelectors<PointEvaluations<F>>,
    pub fixed_columns: FixedColumns<PointEvaluations<F>>,
    pub initial_memory: Vec<PointEvaluations<F>>,
    pub final_memory: Vec<PointEvaluations<F>>,
    pub final_memory_write_index: Vec<PointEvaluations<F>>,
    pub initial_registers: PointEvaluations<F>,
    pub final_registers: PointEvaluations<F>,
    pub final_registers_write_index: PointEvaluations<F>,
    pub lookup_terms: [PointEvaluations<F>; NUM_LOOKUP_TERMS],
    pub lookup_aggregation: PointEvaluations<F>,
    pub instruction_pointer: PointEvaluations<F>,
    pub scratch_state: [PointEvaluations<F>; SCRATCH_SIZE],
    pub lookup_counters: LookupCounters<PointEvaluations<F>>,
    pub halt: PointEvaluations<F>,
}

#[derive(Debug)]
pub struct Proof<G: AffineCurve> {
    pub opening_proof: OpeningProof<G>,

    pub ft_eval1: G::ScalarField,

    pub t_comm: PolyComm<G>,

    pub commitments: ProofCommitments<G>,

    pub evaluations: ProofEvaluations<G::ScalarField>,
}

impl<F: Clone> ColumnEvaluations<F> for ProofEvaluations<F> {
    type Column = Column;
    fn evaluate(&self, col: Self::Column) -> Result<PointEvaluations<F>, ExprError<Self::Column>> {
        match col {
            Column::InstructionPart(instr_part) => Ok(self.instruction_parts[instr_part].clone()),
            Column::InstructionSelector(selector) => {
                Ok(self.instruction_selectors[selector].clone())
            }
            Column::FixedColumn(col) => Ok(self.fixed_columns[col].clone()),
            Column::InitialMemory(idx) => Ok(self.initial_memory[idx].clone()),
            Column::FinalMemory(idx) => Ok(self.final_memory[idx].clone()),
            Column::LookupTerm(idx) => Ok(self.lookup_terms[idx].clone()),
            Column::LookupAggregation => Ok(self.lookup_aggregation.clone()),
            Column::FinalMemoryWriteIndex(idx) => Ok(self.final_memory_write_index[idx].clone()),
            Column::InitialRegisters => Ok(self.initial_registers.clone()),
            Column::FinalRegisters => Ok(self.final_registers.clone()),
            Column::FinalRegistersWriteIndex => Ok(self.final_registers_write_index.clone()),
            Column::InstructionPointer => Ok(self.instruction_pointer.clone()),
            Column::ScratchState(idx) => Ok(self.scratch_state[idx].clone()),
            Column::LookupCounter(col) => Ok(self.lookup_counters[col].clone()),
            Column::Halt => Ok(self.halt.clone()),
        }
    }
}
