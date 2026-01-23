use std::{fs, io, path::Path};

use goblin::{
    Object,
    mach::{Mach, MachO},
};
use log::{debug, error, info};
use unicorn_engine::{Arch, Mode, Prot, RegisterARM64};

const STACK_SIZE: u64 = 8 << 20;
const STACK_TOP: u64 = 0x7fff_ffff_ffff;
const STACK_BASE: u64 = STACK_TOP - STACK_SIZE + 1;

pub struct Runner {
    path: String,
}

impl Runner {
    pub fn new(path: String) -> Self {
        Self { path }
    }

    pub fn run(&self) {
        info!("Loading executable: {}", self.path);
        let path = Path::new(&self.path);
        let buffer = fs::read(path).unwrap();
        let object = Object::parse(&buffer).unwrap();
        let mach = extract_mach(&object).unwrap();

        let mut emu = unicorn_engine::Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN)
            .expect("failed to initialize Unicorn instance");

        // Map segments to virtual memory
        mach.segments.iter().for_each(|it| {
            let start_addr = it.vmaddr;
            let vm_size = it.vmsize;
            let prot = map_mach_o_prot(it.initprot);
            println!("Segment: {:#x} {:#x} {:#x}", start_addr, vm_size, prot.0);

            if it.filesize > 0 {
                emu.mem_map(start_addr, vm_size, prot)
                    .expect("failed to map code page");

                let data = &buffer[it.fileoff as usize..(it.fileoff + it.filesize) as usize];
                emu.mem_write(start_addr, data)
                    .expect("failed to write instructions");
                debug!(
                    "Copied {:#x} bytes from {:#x} to {:#x}",
                    data.len(),
                    it.fileoff,
                    start_addr
                );
            }
        });

        // Setup stack
        info!("Stack: Base: {:#x} Size: {:#x}", STACK_BASE, STACK_SIZE);
        emu.mem_map(STACK_BASE as u64, STACK_SIZE, Prot::READ | Prot::WRITE)
            .expect("failed to map stack");
        emu.reg_write(RegisterARM64::SP, STACK_TOP)
            .expect("failed to set sp register");

        let entrypoint_addr = mach.entry;

        // Setup __got and resolve symbols now (they have flags = 6 so its S_NON_LAZY_SYMBOL_POINTERS)
        let got = mach
            .segments
            .iter()
            .flat_map(|it| it.sections().unwrap())
            .find(|(it, _)| return it.name().unwrap() == "__got")
            .unwrap()
            .0;
        println!("__got: {:#x}, size = {:#x}", got.addr, got.size);

        // Dump Indirect symbol table in DysymtabCommand

        // - Look for sections of type S_NON_LAZY_SYMBOL_POINTERS or S_LAZY_SYMBOL_POINTERS
        // For each section:
        // - num_unresolved_symbol_addresses = (section.size / sizeof(u64))
        // For each unresolved symbol address:
        // - symbol_index = indirect_symbol_table[section.reserved1 + i]
        // So that means symbol_index <-> index i of section
        //
        // In this executable:
        // 1 section = __got
        // num_unresolved_symbol_addresses = 16 / 8 = 2
        // Index 0 of __got <-> symbol_index = indirect_symbol_table[2 + 0] = 2 (symbols[2] = _printf)
        // Index 1 of __got <-> symbol_index = indirect_symbol_table[2 + 1] = 3 (symbols[3] = _scanf)
        // __got = 0x100004000
        emu.mem_write(0x100004000, &[0, 0, 0, 0, 0, 0, 0, 0])
            .unwrap(); // _printf trampoline
        emu.mem_write(0x100004008, &[4, 0, 0, 0, 0, 0, 0, 0])
            .unwrap(); // _scanf trampoline

        emu.mem_map(0x00, 4 * 1024, Prot::ALL).unwrap();
        emu.mem_write(0x00, &[0x01, 0x00, 0x00, 0xD4]).unwrap(); // _printf
        emu.mem_write(0x04, &[0x01, 0x00, 0x00, 0xD4]).unwrap(); // _scanf
        emu.mem_write(0x08, &[0x01, 0x00, 0x00, 0xD4]).unwrap(); // program end 
        emu.reg_write(RegisterARM64::LR, 0x08).unwrap();

        emu.add_intr_hook(move |emu, interrupt| {
            if interrupt != 2 {
                return;
            }

            let pc = emu.reg_read(RegisterARM64::PC).unwrap() - 4; // PC is already incremented
            let return_addr = emu.reg_read(RegisterARM64::LR).unwrap();
            if pc == 0x08 {
                emu.emu_stop().unwrap();
                return;
            }
            println!(
                "INTR: {:#x}, PC: {:#x}, Return: {:#x}",
                interrupt, pc, return_addr
            );
            if pc == 0x00 {
                println!("PRINTF");
                let mut addr = emu.reg_read(RegisterARM64::X0).unwrap() as u64;
                let mut buf: Vec<u8> = Vec::new();

                loop {
                    let mut byte = [0u8; 1];
                    emu.mem_read(addr, &mut byte).unwrap();

                    if byte[0] == 0 {
                        break;
                    }

                    buf.push(byte[0]);
                    addr += 1;
                }

                let s = String::from_utf8_lossy(&buf);

                if s.find("%d").is_none() {
                    print!("{}", s);
                } else {
                    let sp = emu.reg_read(RegisterARM64::SP).unwrap();
                    let mut buf = [0u8; 8];

                    emu.mem_read(sp, &mut buf).unwrap();
                    let arg = u64::from_le_bytes(buf);

                    let formatted_str = s.replace("%d", &arg.to_string());
                    print!("{}", formatted_str);
                }
            } else if pc == 0x04 {
                println!("SCANF");

                // Ignore X0, assume it's always "%d %d", args always come from stack
                let sp = emu.reg_read(RegisterARM64::SP).unwrap();

                let mut buf = [0u8; 8];

                emu.mem_read(sp, &mut buf).unwrap();
                let dst1 = u64::from_le_bytes(buf);

                emu.mem_read(sp + 8, &mut buf).unwrap();
                let dst2 = u64::from_le_bytes(buf);

                println!("dst1: {:#x}, dst2: {:#x}", dst1, dst2);
                let mut input = String::new();
                io::stdin().read_line(&mut input).unwrap();

                let mut it = input.split_whitespace();
                let a: i32 = it.next().unwrap().parse().unwrap();
                let b: i32 = it.next().unwrap().parse().unwrap();

                emu.mem_write(dst1, &a.to_le_bytes()).unwrap();
                emu.mem_write(dst2, &b.to_le_bytes()).unwrap();
            } else {
                panic!("Undefined symbol");
            }
            emu.reg_write(RegisterARM64::PC, return_addr).unwrap();
        })
        .unwrap();

        // Run the program
        const PROGRAM_SIZE: u64 = 124;
        emu.emu_start(entrypoint_addr, entrypoint_addr + PROGRAM_SIZE - 1, 0, 0)
            .unwrap();

        info!("Program finished");
    }
}

fn extract_mach<'a, 'b>(object: &'b Object<'a>) -> Option<&'b MachO<'a>> {
    let Object::Mach(mach_container) = object else {
        error!("Not a mach binary");
        return None;
    };

    if let Mach::Binary(mach) = mach_container {
        return Some(mach);
    }

    error!("Not a single-arch mach binary, implement fat binaries");
    None
}

fn map_mach_o_prot(prot: u32) -> Prot {
    let mut result = Prot::NONE;
    if prot & 0x1 != 0 {
        result |= Prot::READ;
    }
    if prot & 0x2 != 0 {
        result |= Prot::WRITE;
    }
    if prot & 0x4 != 0 {
        result |= Prot::EXEC;
    }
    result
}
