// This is specific to ARM64, adapt for other architectures
pub const SVC_OPCODE: [u8; 4] = [0x01, 0x00, 0x00, 0xD4];
pub const SVC_INT_NUMBER: u32 = 2;
pub const INSTRUCTION_SIZE: usize = size_of::<u32>();
pub const ADDRESS_SIZE: usize = size_of::<u64>();

