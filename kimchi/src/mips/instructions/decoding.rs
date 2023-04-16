use crate::mips::columns::{
    ITypeInstruction, InstructionSelector, JTypeInstruction, RTypeInstruction,
};

pub fn encode_rtype(instr: RTypeInstruction) -> (u32, u32) {
    let funct = match instr {
        RTypeInstruction::ShiftLeftLogical => 0,
        RTypeInstruction::ShiftRightLogical => 2,
        RTypeInstruction::ShiftRightArithmetic => 3,
        RTypeInstruction::ShiftLeftLogicalVariable => 4,
        RTypeInstruction::ShiftRightLogicalVariable => 6,
        RTypeInstruction::ShiftRightArithmeticVariable => 7,
        RTypeInstruction::JumpRegister => 8,
        RTypeInstruction::JumpAndLinkRegister => 9,
        RTypeInstruction::Syscall => 12,
        RTypeInstruction::MoveFromHi => 16,
        RTypeInstruction::MoveToHi => 17,
        RTypeInstruction::MoveFromLo => 18,
        RTypeInstruction::MoveToLo => 19,
        RTypeInstruction::Multiply => 24,
        RTypeInstruction::MultiplyUnsigned => 25,
        RTypeInstruction::Div => 26,
        RTypeInstruction::DivUnsigned => 27,
        RTypeInstruction::Add => 32,
        RTypeInstruction::AddUnsigned => 33,
        RTypeInstruction::Sub => 34,
        RTypeInstruction::SubUnsigned => 35,
        RTypeInstruction::And => 36,
        RTypeInstruction::Or => 37,
        RTypeInstruction::Xor => 38,
        RTypeInstruction::Nor => 39,
        RTypeInstruction::SetLessThan => 42,
        RTypeInstruction::SetLessThanUnsigned => 43,
    };
    (0, funct)
}

pub fn decode_rtype((instr, funct): (u32, u32)) -> Option<RTypeInstruction> {
    if instr != 0 {
        return None;
    }
    let instruction = match funct {
        0 => RTypeInstruction::ShiftLeftLogical,
        2 => RTypeInstruction::ShiftRightLogical,
        3 => RTypeInstruction::ShiftRightArithmetic,
        4 => RTypeInstruction::ShiftLeftLogicalVariable,
        6 => RTypeInstruction::ShiftRightLogicalVariable,
        7 => RTypeInstruction::ShiftRightArithmeticVariable,
        8 => RTypeInstruction::JumpRegister,
        9 => RTypeInstruction::JumpAndLinkRegister,
        12 => RTypeInstruction::Syscall,
        16 => RTypeInstruction::MoveFromHi,
        17 => RTypeInstruction::MoveToHi,
        18 => RTypeInstruction::MoveFromLo,
        19 => RTypeInstruction::MoveToLo,
        24 => RTypeInstruction::Multiply,
        25 => RTypeInstruction::MultiplyUnsigned,
        26 => RTypeInstruction::Div,
        27 => RTypeInstruction::DivUnsigned,
        32 => RTypeInstruction::Add,
        33 => RTypeInstruction::AddUnsigned,
        34 => RTypeInstruction::Sub,
        35 => RTypeInstruction::SubUnsigned,
        36 => RTypeInstruction::And,
        37 => RTypeInstruction::Or,
        38 => RTypeInstruction::Xor,
        39 => RTypeInstruction::Nor,
        42 => RTypeInstruction::SetLessThan,
        43 => RTypeInstruction::SetLessThanUnsigned,
        _ => return None,
    };
    Some(instruction)
}

pub fn encode_jtype(instr: JTypeInstruction) -> u32 {
    match instr {
        JTypeInstruction::Jump => 2,
        JTypeInstruction::JumpAndLink => 3,
    }
}

pub fn decode_jtype(instr: u32) -> Option<JTypeInstruction> {
    match instr {
        2 => Some(JTypeInstruction::Jump),
        3 => Some(JTypeInstruction::JumpAndLink),
        _ => None,
    }
}

pub fn encode_itype(instr: ITypeInstruction) -> u32 {
    match instr {
        ITypeInstruction::BranchEq => 4,
        ITypeInstruction::BranchNeq => 5,
        ITypeInstruction::BranchLeqZero => 6,
        ITypeInstruction::BranchGtZero => 7,
        ITypeInstruction::AddImmediate => 8,
        ITypeInstruction::AddImmediateUnsigned => 9,
        ITypeInstruction::SetLessThanImmediate => 10,
        ITypeInstruction::SetLessThanImmediateUnsigned => 11,
        ITypeInstruction::AndImmediate => 12,
        ITypeInstruction::OrImmediate => 13,
        ITypeInstruction::XorImmediate => 14,
        ITypeInstruction::LoadImmediate => 15,
        ITypeInstruction::Load8 => 32,
        ITypeInstruction::Load16 => 33,
        ITypeInstruction::Load32 => 34,
        ITypeInstruction::Load8Unsigned => 36,
        ITypeInstruction::Load16Unsigned => 37,
        ITypeInstruction::Store8 => 40,
        ITypeInstruction::Store16 => 41,
        ITypeInstruction::Store32 => 43,
    }
}

pub fn decode_itype(instr: u32) -> Option<ITypeInstruction> {
    let instruction = match instr {
        4 => ITypeInstruction::BranchEq,
        5 => ITypeInstruction::BranchNeq,
        6 => ITypeInstruction::BranchLeqZero,
        7 => ITypeInstruction::BranchGtZero,
        8 => ITypeInstruction::AddImmediate,
        9 => ITypeInstruction::AddImmediateUnsigned,
        10 => ITypeInstruction::SetLessThanImmediate,
        11 => ITypeInstruction::SetLessThanImmediateUnsigned,
        12 => ITypeInstruction::AndImmediate,
        13 => ITypeInstruction::OrImmediate,
        14 => ITypeInstruction::XorImmediate,
        15 => ITypeInstruction::LoadImmediate,
        32 => ITypeInstruction::Load8,
        33 => ITypeInstruction::Load16,
        34 => ITypeInstruction::Load32,
        36 => ITypeInstruction::Load8Unsigned,
        37 => ITypeInstruction::Load16Unsigned,
        40 => ITypeInstruction::Store8,
        41 => ITypeInstruction::Store16,
        43 => ITypeInstruction::Store32,
        _ => return None,
    };
    Some(instruction)
}

pub fn encode_selector(instr: InstructionSelector) -> (u32, Option<u32>) {
    match instr {
        InstructionSelector::RType(instr) => {
            let (opcode, funct) = encode_rtype(instr);
            (opcode, Some(funct))
        }
        InstructionSelector::JType(instr) => (encode_jtype(instr), None),
        InstructionSelector::IType(instr) => (encode_itype(instr), None),
    }
}

pub fn decode_selector((instr, funct): (u32, u32)) -> Option<InstructionSelector> {
    if let Some(rtype) = decode_rtype((instr, funct)) {
        return Some(InstructionSelector::RType(rtype));
    }
    if let Some(jtype) = decode_jtype(instr) {
        return Some(InstructionSelector::JType(jtype));
    }
    if let Some(itype) = decode_itype(instr) {
        return Some(InstructionSelector::IType(itype));
    }
    None
}

pub fn decode(instruction: u32) -> Option<InstructionSelector> {
    let instr = instruction >> 26;
    let funct = instruction & ((1 << 6) - 1);
    decode_selector((instr, funct))
}
