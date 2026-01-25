use std::{fs, io, path::Path};

use goblin::{
    Object,
    mach::{
        Mach, MachO,
        constants::{S_LAZY_SYMBOL_POINTERS, S_NON_LAZY_SYMBOL_POINTERS},
        load_command::CommandVariant,
        segment::Section,
    },
};
use log::{debug, error, info, trace};
use unicorn_engine::{Arch, Mode, Prot, RegisterARM64, Unicorn};

const STACK_SIZE: u64 = 8 << 20; // Not growable
const STACK_TOP: u64 = 0x7fff_ffff_ffff;
const STACK_BASE: u64 = STACK_TOP - STACK_SIZE + 1;

const SVC_OPCODE: [u8; 4] = [0x01, 0x00, 0x00, 0xD4];

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

        let mut emu = Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN).unwrap();
        map_segments(mach, &buffer, &mut emu);
        setup_stack(&mut emu);
        let indirect_symbol_table = get_indirect_symbol_table(mach, &buffer);

        // Find unresolved symbols
        let sections_with_unresolved_symbols: Vec<Section> = mach
            .segments
            .iter()
            .flat_map(|it| it.sections().unwrap())
            .filter(|(it, _)| {
                it.flags == S_NON_LAZY_SYMBOL_POINTERS || it.flags == S_LAZY_SYMBOL_POINTERS
            })
            .map(|it| it.0)
            .collect();

        info!("Sections with unresolved symbols:");
        sections_with_unresolved_symbols.iter().for_each(|it| {
            info!(
                "{} at {:#x} num_unresolved_symbol_addresses: {} reserved1: {}",
                it.name().unwrap(),
                it.addr,
                it.size / size_of::<u64>() as u64,
                it.reserved1
            );
        });

        info!("Unresolved symbols:");
        sections_with_unresolved_symbols.iter().for_each(|it| {
            let num_unresolved_symbol_addresses = it.size / size_of::<u64>() as u64;
            for i in 0..num_unresolved_symbol_addresses {
                let symbol_index = indirect_symbol_table[it.reserved1 as usize + i as usize];
                let (symbol_name, _) = mach.symbols().nth(symbol_index as usize).unwrap().unwrap();
                let address = it.addr + i * size_of::<u64>() as u64;
                debug!("Symbol {}, resolution addr: {:#x}", symbol_name, address);
            }
        });

        return; // WIP Uncomment and continue the refactor

        emu.mem_write(0x100004000, &[0, 0, 0, 0, 0, 0, 0, 0])
            .unwrap(); // _printf trampoline
        emu.mem_write(0x100004008, &[4, 0, 0, 0, 0, 0, 0, 0])
            .unwrap(); // _scanf trampoline

        emu.mem_map(0x00, 4 * 1024, Prot::ALL).unwrap();
        emu.mem_write(0x00, &SVC_OPCODE).unwrap(); // _printf
        emu.mem_write(0x04, &SVC_OPCODE).unwrap(); // _scanf
        emu.mem_write(0x08, &SVC_OPCODE).unwrap(); // program end 
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
            trace!(
                "INTR: {:#x}, PC: {:#x}, Return: {:#x}",
                interrupt, pc, return_addr
            );
            // PC -> symbol name
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
        emu.emu_start(mach.entry, STACK_TOP, 0, 0).unwrap();

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

fn map_segments(mach: &MachO<'_>, buffer: &[u8], emu: &mut Unicorn<'_, ()>) {
    mach.segments
        .iter()
        .filter(|it| it.initprot != 0)
        .for_each(|it| {
            let prot = map_mach_o_prot(it.initprot);
            info!(
                "Segment({}): start_addr={:#x} vm_size={:#x} prot={:#b}",
                it.name().unwrap(),
                it.vmaddr,
                it.vmsize,
                prot.0
            );

            emu.mem_map(it.vmaddr, it.vmsize, prot)
                .expect("failed to map code page");

            if it.filesize > 0 {
                let data = &buffer[it.fileoff as usize..(it.fileoff + it.filesize) as usize];
                emu.mem_write(it.vmaddr, data).unwrap();
                info!(
                    "Copied {:#x} bytes from file at {:#x} to {:#x}",
                    data.len(),
                    it.fileoff,
                    it.vmaddr
                );
            }
        });
}

fn get_indirect_symbol_table(mach: &MachO<'_>, buffer: &Vec<u8>) -> Vec<u32> {
    let dysymtab_command_maybe = mach
        .load_commands
        .iter()
        .filter_map(|it| {
            let CommandVariant::Dysymtab(command) = it.command else {
                return None;
            };
            Some(command)
        })
        .next();
    let Some(dysymtab_command) = dysymtab_command_maybe else {
        error!("Dysymtab command not found");
        std::process::exit(1);
    };
    info!(
        "Indirect symbol table: {:#x} Entries: {}",
        dysymtab_command.indirectsymoff, dysymtab_command.nindirectsyms
    );
    let start = dysymtab_command.indirectsymoff as usize;
    let end = start + dysymtab_command.nindirectsyms as usize * size_of::<u32>();

    return buffer[start..end]
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect();
}

fn setup_stack(emu: &mut Unicorn<'_, ()>) {
    info!("Stack: Base: {:#x} Size: {:#x}", STACK_BASE, STACK_SIZE);
    emu.mem_map(STACK_BASE as u64, STACK_SIZE, Prot::READ | Prot::WRITE)
        .unwrap();
    emu.reg_write(RegisterARM64::SP, STACK_TOP).unwrap();
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
