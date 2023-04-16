use crate::mips::{
    columns::{InstructionPart, InstructionSelector},
    witness::{Lookup, TableID},
};
use std::array;

pub mod decoding;

pub trait InstructionEnvironment {
    type Column;
    type Variable: std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + Clone;
    type Fp: std::ops::Neg<Output = Self::Fp>;

    fn current_row(&self) -> Self::Variable;

    fn constant(x: u32) -> Self::Variable;

    fn to_fp(x: Self::Variable) -> Self::Fp;

    fn hi_register_idx() -> Self::Variable {
        Self::constant(32)
    }

    fn lo_register_idx() -> Self::Variable {
        Self::constant(33)
    }

    fn instruction_pointer(&self) -> Self::Variable;

    fn set_instruction_pointer(&mut self, ip: &Self::Variable);

    fn halted(&self) -> Self::Variable;

    fn set_halted(&mut self, value: &Self::Variable);

    fn memory_accessible(
        &mut self,
        is_enabled: &Self::Variable,
        column: Self::Column,
        addresses: Vec<&Self::Variable>,
    ) -> Self::Variable;

    fn read_memory(
        &mut self,
        output: Self::Column,
        address: &Self::Variable,
        accessible: &Self::Variable,
    ) -> Self::Variable;

    fn get_register_value(
        &mut self,
        register_idx: &Self::Variable,
        output_value: Self::Column,
    ) -> Self::Variable;

    fn set_register_value(&mut self, register_idx: &Self::Variable, value: &Self::Variable);

    fn last_register_write(
        &mut self,
        register_idx: &Self::Variable,
        output_last_write: Self::Column,
    ) -> Self::Variable;

    fn set_last_register_write(
        &mut self,
        register_idx: &Self::Variable,
        last_write: &Self::Variable,
    );

    fn fetch_register(
        &mut self,
        register_idx: &Self::Variable,
        output_value: Self::Column,
        output_last_write: Self::Column,
    ) -> (Self::Variable, Self::Variable) {
        let value = self.get_register_value(register_idx, output_value);

        let update_row = self.current_row();

        // Insert new values
        self.add_lookup(Lookup {
            numerator: Self::to_fp(Self::constant(1)),
            table_id: Self::to_fp(Self::constant(TableID::Registers as u32)),
            value: vec![
                Self::to_fp(value.clone()),
                Self::to_fp(register_idx.clone()),
                Self::to_fp(update_row.clone()),
            ],
        });

        let last_write = self.last_register_write(&register_idx, output_last_write);
        self.set_last_register_write(&register_idx, &update_row);

        // Remove old values
        self.add_lookup(Lookup {
            numerator: -Self::to_fp(Self::constant(1)),
            table_id: Self::to_fp(Self::constant(TableID::Registers as u32)),
            value: vec![
                Self::to_fp(value.clone()),
                Self::to_fp(register_idx.clone()),
                Self::to_fp(last_write.clone()),
            ],
        });

        (value, last_write)
    }

    fn overwrite_register(
        &mut self,
        register_idx: &Self::Variable,
        value: &Self::Variable,
        output_last_write: Self::Column,
    ) -> Self::Variable {
        let update_row = self.current_row();

        // Insert new values
        self.add_lookup(Lookup {
            numerator: Self::to_fp(Self::constant(1)),
            table_id: Self::to_fp(Self::constant(TableID::Registers as u32)),
            value: vec![
                Self::to_fp(value.clone()),
                Self::to_fp(register_idx.clone()),
                Self::to_fp(update_row.clone()),
            ],
        });

        let output_old_value = self.alloc_scratch();
        let old_value = self.get_register_value(&register_idx, output_old_value);
        self.set_register_value(&register_idx, &value);

        let last_write = self.last_register_write(&register_idx, output_last_write);
        self.set_last_register_write(&register_idx, &update_row);

        // Remove old values
        self.add_lookup(Lookup {
            numerator: -Self::to_fp(Self::constant(1)),
            table_id: Self::to_fp(Self::constant(TableID::Registers as u32)),
            value: vec![
                Self::to_fp(old_value),
                Self::to_fp(register_idx.clone()),
                Self::to_fp(last_write.clone()),
            ],
        });

        last_write
    }

    fn get_memory_value(
        &mut self,
        address: &Self::Variable,
        enabled_if: &Self::Variable,
        output_value: Self::Column,
    ) -> Self::Variable;

    fn set_memory_value(
        &mut self,
        address: &Self::Variable,
        enabled_if: &Self::Variable,
        value: &Self::Variable,
    );

    fn last_memory_write(
        &mut self,
        address: &Self::Variable,
        enabled_if: &Self::Variable,
        output_last_write: Self::Column,
    ) -> Self::Variable;

    fn set_last_memory_write(
        &mut self,
        address: &Self::Variable,
        enabled_if: &Self::Variable,
        last_write: &Self::Variable,
    );

    fn fetch_memory(
        &mut self,
        address: &Self::Variable,
        enabled_if: &Self::Variable,
        output_value: Self::Column,
        output_last_write: Self::Column,
    ) -> (Self::Variable, Self::Variable) {
        let value = self.get_memory_value(address, enabled_if, output_value);

        let update_row = self.current_row();

        // Insert new values
        self.add_lookup(Lookup {
            numerator: Self::to_fp(enabled_if.clone()),
            table_id: Self::to_fp(Self::constant(TableID::Memory as u32)),
            value: vec![
                Self::to_fp(value.clone()),
                Self::to_fp(address.clone()),
                Self::to_fp(update_row.clone()),
            ],
        });

        let last_write = self.last_memory_write(&address, enabled_if, output_last_write);
        self.set_last_memory_write(&address, enabled_if, &update_row);

        // Remove old values
        self.add_lookup(Lookup {
            numerator: -Self::to_fp(enabled_if.clone()),
            table_id: Self::to_fp(Self::constant(TableID::Memory as u32)),
            value: vec![
                Self::to_fp(value.clone()),
                Self::to_fp(address.clone()),
                Self::to_fp(last_write.clone()),
            ],
        });

        (value, last_write)
    }

    fn overwrite_memory(
        &mut self,
        address: &Self::Variable,
        value: &Self::Variable,
        enabled_if: &Self::Variable,
        output_last_write: Self::Column,
    ) -> Self::Variable {
        let update_row = self.current_row();

        // Insert new values
        self.add_lookup(Lookup {
            numerator: Self::to_fp(enabled_if.clone()),
            table_id: Self::to_fp(Self::constant(TableID::Memory as u32)),
            value: vec![
                Self::to_fp(value.clone()),
                Self::to_fp(address.clone()),
                Self::to_fp(update_row.clone()),
            ],
        });

        let output_old_value = self.alloc_scratch();
        let old_value = self.get_memory_value(&address, enabled_if, output_old_value);
        self.set_memory_value(&address, enabled_if, &value);

        let last_write = self.last_memory_write(&address, enabled_if, output_last_write);
        self.set_last_memory_write(&address, enabled_if, &update_row);

        // Remove old values
        self.add_lookup(Lookup {
            numerator: -Self::to_fp(enabled_if.clone()),
            table_id: Self::to_fp(Self::constant(TableID::Memory as u32)),
            value: vec![
                Self::to_fp(old_value),
                Self::to_fp(address.clone()),
                Self::to_fp(last_write.clone()),
            ],
        });

        last_write
    }

    fn instruction_part(&self, part: InstructionPart) -> Self::Variable;

    fn immediate(&self) -> Self::Variable {
        self.instruction_part(InstructionPart::RD) * Self::constant(1 << 11)
            + self.instruction_part(InstructionPart::Shamt) * Self::constant(1 << 6)
            + self.instruction_part(InstructionPart::Funct)
    }

    fn add_lookup(&mut self, lookup: Lookup<Self::Fp>);

    fn increment_range_check_counter(&mut self, value: &Self::Variable);

    fn range_check_16(&mut self, value: &Self::Variable) {
        self.increment_range_check_counter(value);
        self.add_lookup(Lookup {
            numerator: -Self::to_fp(Self::constant(1u32)),
            table_id: Self::to_fp(Self::constant(TableID::RangeCheck16 as u32)),
            value: vec![Self::to_fp(value.clone())],
        });
    }

    fn range_check(&mut self, value: &Self::Variable, shift: u32) {
        if shift < 16 {
            let shift_actual = Self::constant(1 << (16 - shift));
            self.range_check_16(value);
            self.range_check_16(&(value.clone() * shift_actual));
        } else {
            panic!("Unexpected shift: {}", shift)
        }
    }

    fn range_check_1(&mut self, value: &Self::Variable);

    fn range_check_2(&mut self, value: &Self::Variable);

    fn decompose(
        &mut self,
        value: &Self::Variable,
        decomposition_little_endian: Vec<u32>,
        outputs: Vec<Self::Column>,
    ) -> Vec<Self::Variable>;

    fn div_rem(
        &mut self,
        numerator: &Self::Variable,
        denominator: &Self::Variable,
        output_div: Self::Column,
        output_rem: Self::Column,
        output_divide_by_zero: Self::Column,
    ) -> (Self::Variable, Self::Variable, Self::Variable);

    fn and_xor(
        &mut self,
        lhs: &Self::Variable,
        rhs: &Self::Variable,
        output_and: Self::Column,
        output_xor: Self::Column,
    ) -> (Self::Variable, Self::Variable);

    fn alloc_scratch(&mut self) -> Self::Column;

    fn fetch_register_checked(&mut self, register_idx: &Self::Variable) -> Self::Variable {
        let output_register = self.alloc_scratch();
        let output_last_write = self.alloc_scratch();
        let (register, last_write) =
            self.fetch_register(register_idx, output_register, output_last_write);
        self.range_check_16(&(self.current_row() - last_write));
        register
    }

    fn overwrite_register_checked(
        &mut self,
        register_idx: &Self::Variable,
        value: &Self::Variable,
    ) {
        let output_last_write = self.alloc_scratch();
        let last_write = self.overwrite_register(register_idx, value, output_last_write);
        self.range_check_16(&(self.current_row() - last_write));
    }

    fn fetch_memory_checked(
        &mut self,
        address: &Self::Variable,
        enabled_if: &Self::Variable,
    ) -> Self::Variable {
        let output_memory = self.alloc_scratch();
        let output_last_write = self.alloc_scratch();
        let (memory, last_write) =
            self.fetch_memory(&address, enabled_if, output_memory, output_last_write);
        self.range_check_16(&(self.current_row() - last_write));
        memory
    }

    fn overwrite_memory_checked(
        &mut self,
        address: &Self::Variable,
        value: &Self::Variable,
        enabled_if: &Self::Variable,
    ) {
        let output_last_write = self.alloc_scratch();
        let last_write = self.overwrite_memory(address, value, enabled_if, output_last_write);
        self.range_check_16(&(self.current_row() - last_write));
    }

    fn decode(instruction: &Self::Variable) -> Option<InstructionSelector>;

    fn assert_(&mut self, value: &Self::Variable);

    fn eq_zero_terms(
        &mut self,
        value: &Self::Variable,
        res_output: Self::Column,
        inv_output: Self::Column,
    ) -> (Self::Variable, Self::Variable);

    fn is_zero(&mut self, value: &Self::Variable) -> Self::Variable {
        let res_output = self.alloc_scratch();
        let inv_output = self.alloc_scratch();
        let (res, inv) = self.eq_zero_terms(value, res_output, inv_output);
        self.assert_(&(inv * value.clone() - (Self::constant(1u32) - res.clone())));
        self.assert_(&(res.clone() * value.clone()));
        res
    }

    fn sign_extend(&mut self, value: &Self::Variable, output: Self::Column) -> Self::Variable;
}

use ark_ff::Zero;
pub fn decode_instruction<Env: InstructionEnvironment>(
    env: &mut Env,
) -> (Option<InstructionSelector>, Env::Variable)
where
    Env::Variable: std::fmt::Debug + Zero,
{
    let memory_addrs: [_; 4] = array::from_fn(|i| {
        if i == 0 {
            env.instruction_pointer()
        } else {
            env.instruction_pointer() + Env::constant(i as u32)
        }
    });
    let memory_accessible = {
        let scratch = env.alloc_scratch();
        env.memory_accessible(
            &(Env::constant(1u32) - env.halted()),
            scratch,
            memory_addrs.iter().collect(),
        )
    };
    let may_read = memory_accessible;
    if !may_read.is_zero() {
        println!("may_read: {:?}", may_read);
    }
    //let may_read = memory_accessible * (Env::constant(1u32) - env.halted());
    let instruction = array::from_fn(|i| env.fetch_memory_checked(&memory_addrs[i], &may_read));

    let instruction = {
        let [i0, i1, i2, i3] = instruction;
        if !may_read.is_zero() {
            println!("instr: {:?} {:?} {:?} {:?}", i0, i1, i2, i3);
        }
        (Env::constant(1u32 << 24) * i0)
            + (Env::constant(1u32 << 16) * i1)
            + (Env::constant(1u32 << 8) * i2)
            + i3
    };

    (Env::decode(&instruction), instruction)
}

pub fn run_instruction<Env: InstructionEnvironment>(
    instr: crate::mips::columns::InstructionSelector,
    env: &mut Env,
) where
    Env::Variable: std::fmt::Debug,
{
    use crate::mips::columns::{
        ITypeInstruction as IT, InstructionSelector::*, JTypeInstruction as JT,
        RTypeInstruction as RT,
    };
    match instr {
        RType(RT::ShiftLeftLogical) => (),
        RType(RT::ShiftRightLogical) => (),
        RType(RT::ShiftRightArithmetic) => (),
        RType(RT::ShiftLeftLogicalVariable) => (),
        RType(RT::ShiftRightLogicalVariable) => (),
        RType(RT::ShiftRightArithmeticVariable) => (),
        RType(RT::JumpRegister) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let register_rs = env.fetch_register_checked(&rs);
            let decomposition = {
                let scratch = (0..3).map(|_| env.alloc_scratch()).collect();
                env.decompose(&register_rs, vec![16, 14, 2], scratch)
            };
            env.range_check_16(&decomposition[0]);
            env.range_check(&decomposition[1], 14);
            env.range_check_2(&decomposition[2]);
            let is_aligned = env.is_zero(&decomposition[2]);
            // TODO: Don't do this
            let should_halt = Env::constant(1) - is_aligned * (Env::constant(1) - env.halted());
            env.set_halted(&should_halt);
            let halted = env.halted();
            env.set_instruction_pointer(
                &(halted.clone() * register_rs
                    + (Env::constant(1) - halted) * env.instruction_pointer()),
            );
            return;
        }
        RType(RT::JumpAndLinkRegister) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let register_rs = env.fetch_register_checked(&rs);
            let rd = env.instruction_part(InstructionPart::RD);
            env.overwrite_register_checked(&rd, &(env.instruction_pointer() + Env::constant(8)));
            let decomposition = {
                let scratch = (0..3).map(|_| env.alloc_scratch()).collect();
                env.decompose(&register_rs, vec![16, 14, 2], scratch)
            };
            env.range_check_16(&decomposition[0]);
            env.range_check(&decomposition[1], 14);
            env.range_check_2(&decomposition[2]);
            let is_aligned = env.is_zero(&decomposition[2]);
            // TODO: Don't do this
            let should_halt = Env::constant(1) - is_aligned * (Env::constant(1) - env.halted());
            env.set_halted(&should_halt);
            let halted = env.halted();
            env.set_instruction_pointer(
                &(halted.clone() * register_rs
                    + (Env::constant(1) - halted) * env.instruction_pointer()),
            );
            return;
        }
        RType(RT::Syscall) => {
            // Treat as an effective halt
            env.set_halted(&Env::constant(1u32));
        }
        RType(RT::MoveFromHi) => {
            let register_hi = env.fetch_register_checked(&Env::hi_register_idx());
            let rd = env.instruction_part(InstructionPart::RD);
            env.overwrite_register_checked(&rd, &register_hi);
        }
        RType(RT::MoveToHi) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let register_rs = env.fetch_register_checked(&rs);
            env.overwrite_register_checked(&Env::hi_register_idx(), &register_rs);
        }
        RType(RT::MoveFromLo) => {
            let register_lo = env.fetch_register_checked(&Env::lo_register_idx());
            let rd = env.instruction_part(InstructionPart::RD);
            env.overwrite_register_checked(&rd, &register_lo);
        }
        RType(RT::MoveToLo) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let register_rs = env.fetch_register_checked(&rs);
            env.overwrite_register_checked(&Env::lo_register_idx(), &register_rs);
        }
        RType(RT::Multiply) => (),
        RType(RT::MultiplyUnsigned) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let rt = env.instruction_part(InstructionPart::RT);
            let register_rs = env.fetch_register_checked(&rs);
            let register_rt = env.fetch_register_checked(&rt);
            let product = register_rs * register_rt;
            let decomposition = {
                let scratch = (0..4).map(|_| env.alloc_scratch()).collect();
                env.decompose(&product, vec![16, 16, 16, 16], scratch)
            };
            env.range_check_16(&decomposition[0]);
            env.range_check_16(&decomposition[1]);
            env.range_check_16(&decomposition[2]);
            env.range_check_16(&decomposition[3]);
            let hi = decomposition[3].clone() * Env::constant(1 << 16) + decomposition[2].clone();
            let lo = decomposition[1].clone() * Env::constant(1 << 16) + decomposition[0].clone();
            env.overwrite_register_checked(&Env::hi_register_idx(), &hi);
            env.overwrite_register_checked(&Env::lo_register_idx(), &lo);
        }
        RType(RT::Div) => (),
        RType(RT::DivUnsigned) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let rt = env.instruction_part(InstructionPart::RT);
            let register_rs = env.fetch_register_checked(&rs);
            let register_rt = env.fetch_register_checked(&rt);
            let (div, rem, divide_by_zero) = {
                let output_div = env.alloc_scratch();
                let output_rem = env.alloc_scratch();
                let output_divide_by_zero = env.alloc_scratch();
                env.div_rem(
                    &register_rs,
                    &register_rt,
                    output_div,
                    output_rem,
                    output_divide_by_zero,
                )
            };
            env.range_check_1(&divide_by_zero);
            let decomposition_div = {
                let scratch = (0..2).map(|_| env.alloc_scratch()).collect();
                env.decompose(&div, vec![16, 16], scratch)
            };
            let decomposition_rem = {
                let scratch = (0..2).map(|_| env.alloc_scratch()).collect();
                env.decompose(&rem, vec![16, 16], scratch)
            };
            env.range_check_16(&decomposition_div[0]);
            env.range_check_16(&decomposition_div[1]);
            env.range_check_16(&decomposition_rem[0]);
            env.range_check_16(&decomposition_rem[1]);
            let hi = decomposition_rem[1].clone() * Env::constant(1 << 16)
                + decomposition_rem[0].clone();
            let lo = decomposition_div[1].clone() * Env::constant(1 << 16)
                + decomposition_div[0].clone();
            env.overwrite_register_checked(&Env::hi_register_idx(), &hi);
            env.overwrite_register_checked(&Env::lo_register_idx(), &lo);
            // TODO: Don't do this
            let should_halt = Env::constant(1)
                - (Env::constant(1) - divide_by_zero) * (Env::constant(1) - env.halted());
            env.set_halted(&should_halt);
        }
        RType(RT::Add) => (),
        RType(RT::AddUnsigned) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let rt = env.instruction_part(InstructionPart::RT);
            let register_rs = env.fetch_register_checked(&rs);
            let register_rt = env.fetch_register_checked(&rt);
            let product = register_rs + register_rt;
            let decomposition = {
                let scratch = (0..3).map(|_| env.alloc_scratch()).collect();
                env.decompose(&product, vec![16, 16, 1], scratch)
            };
            env.range_check_16(&decomposition[0]);
            env.range_check_16(&decomposition[1]);
            env.range_check_1(&decomposition[2]);
            let value =
                decomposition[1].clone() * Env::constant(1 << 16) + decomposition[0].clone();
            let rd = env.instruction_part(InstructionPart::RD);
            env.overwrite_register_checked(&rd, &value);
        }
        RType(RT::Sub) => (),
        RType(RT::SubUnsigned) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let rt = env.instruction_part(InstructionPart::RT);
            let register_rs = env.fetch_register_checked(&rs);
            let register_rt = env.fetch_register_checked(&rt);
            let product = register_rs - register_rt;
            let decomposition = {
                let scratch = (0..3).map(|_| env.alloc_scratch()).collect();
                env.decompose(&product, vec![16, 16, 1], scratch)
            };
            env.range_check_16(&decomposition[0]);
            env.range_check_16(&decomposition[1]);
            env.range_check_1(&decomposition[2]);
            let value =
                decomposition[1].clone() * Env::constant(1 << 16) + decomposition[0].clone();
            let rd = env.instruction_part(InstructionPart::RD);
            env.overwrite_register_checked(&rd, &value);
        }
        RType(RT::And) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let rt = env.instruction_part(InstructionPart::RT);
            let register_rs = env.fetch_register_checked(&rs);
            let register_rt = env.fetch_register_checked(&rt);
            let (and, _xor) = {
                let output_and = env.alloc_scratch();
                let output_xor = env.alloc_scratch();
                env.and_xor(&register_rs, &register_rt, output_and, output_xor)
            };
            let rd = env.instruction_part(InstructionPart::RD);
            env.overwrite_register_checked(&rd, &and);
        }
        RType(RT::Or) => (),
        RType(RT::Xor) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let rt = env.instruction_part(InstructionPart::RT);
            let register_rs = env.fetch_register_checked(&rs);
            let register_rt = env.fetch_register_checked(&rt);
            let (_and, xor) = {
                let output_and = env.alloc_scratch();
                let output_xor = env.alloc_scratch();
                env.and_xor(&register_rs, &register_rt, output_and, output_xor)
            };
            let rd = env.instruction_part(InstructionPart::RD);
            env.overwrite_register_checked(&rd, &xor);
        }
        RType(RT::Nor) => (),
        RType(RT::SetLessThan) => (),
        RType(RT::SetLessThanUnsigned) => (),
        JType(JT::Jump) => return,
        JType(JT::JumpAndLink) => {
            let value = env.instruction_pointer() + Env::constant(8);
            env.overwrite_register_checked(&Env::constant(31), &value);
            return;
        }
        IType(IT::BranchEq) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let register_rs = env.fetch_register_checked(&rs);
            let rt = env.instruction_part(InstructionPart::RT);
            let register_rt = env.fetch_register_checked(&rt);
            let equal = env.is_zero(&(register_rs - register_rt));
            let imm = env.immediate();
            let offset = {
                let offset_output = env.alloc_scratch();
                env.sign_extend(&imm, offset_output)
            };
            let ip = env.instruction_pointer();
            env.set_instruction_pointer(
                &(ip + Env::constant(4) + equal * offset * Env::constant(4)),
            );
            return;
        }
        IType(IT::BranchNeq) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let register_rs = env.fetch_register_checked(&rs);
            let rt = env.instruction_part(InstructionPart::RT);
            let register_rt = env.fetch_register_checked(&rt);
            let equal = env.is_zero(&(register_rs - register_rt));
            let imm = env.immediate();
            let offset = {
                let offset_output = env.alloc_scratch();
                env.sign_extend(&imm, offset_output)
            };
            let ip = env.instruction_pointer();
            println!("imm: {:?}", imm);
            println!("offset: {:?}", offset);
            println!("equal: {:?}", equal);
            env.set_instruction_pointer(
                &(ip + Env::constant(4) + (Env::constant(1) - equal) * offset * Env::constant(4)),
            );
            return;
        }
        IType(IT::BranchLeqZero) => return,
        IType(IT::BranchGtZero) => return,
        IType(IT::AddImmediate) => (),
        IType(IT::AddImmediateUnsigned) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let register_rs = env.fetch_register_checked(&rs);
            let imm = env.immediate();
            let res = register_rs + imm;
            let rt = env.instruction_part(InstructionPart::RT);
            env.overwrite_register_checked(&rt, &res);
        }
        IType(IT::SetLessThanImmediate) => (),
        IType(IT::SetLessThanImmediateUnsigned) => (),
        IType(IT::AndImmediate) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let register_rs = env.fetch_register_checked(&rs);
            let imm = env.immediate();
            let (and, _xor) = {
                let output_and = env.alloc_scratch();
                let output_xor = env.alloc_scratch();
                env.and_xor(&register_rs, &imm, output_and, output_xor)
            };
            let rt = env.instruction_part(InstructionPart::RT);
            env.overwrite_register_checked(&rt, &and);
        }
        IType(IT::OrImmediate) => (),
        IType(IT::XorImmediate) => {
            let rs = env.instruction_part(InstructionPart::RS);
            let register_rs = env.fetch_register_checked(&rs);
            let imm = env.immediate();
            let (_and, xor) = {
                let output_and = env.alloc_scratch();
                let output_xor = env.alloc_scratch();
                env.and_xor(&register_rs, &imm, output_and, output_xor)
            };
            let rt = env.instruction_part(InstructionPart::RT);
            env.overwrite_register_checked(&rt, &xor);
        }
        IType(IT::LoadImmediate) => {
            let rt = env.instruction_part(InstructionPart::RT);
            let imm = env.immediate();
            env.overwrite_register_checked(&rt, &(imm * Env::constant(1u32 << 16)));
        }
        IType(IT::Load8) => (),
        IType(IT::Load16) => (),
        IType(IT::Load32) => (),
        IType(IT::Load8Unsigned) => (),
        IType(IT::Load16Unsigned) => (),
        IType(IT::Store8) => (),
        IType(IT::Store16) => (),
        IType(IT::Store32) => (),
    };
    let ip = env.instruction_pointer();
    env.set_instruction_pointer(&(ip + Env::constant(4) - env.halted() * Env::constant(4)));
}
