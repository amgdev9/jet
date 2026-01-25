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
use std::{fs, path::Path};
use unicorn_engine::{Arch, Mode, Prot, RegisterARM64, Unicorn};

use crate::{allocator::Allocator, host_dynamic_library::HostDynamicLibrary};

const STACK_SIZE: u64 = 8 << 20; // Not growable
const STACK_TOP: u64 = 0x7fff_ffff_ffff;
const STACK_BASE: u64 = STACK_TOP - STACK_SIZE + 1;

const SVC_OPCODE: [u8; 4] = [0x01, 0x00, 0x00, 0xD4];
const SVC_INT_NUMBER: u32 = 2;
const INSTRUCTION_SIZE: usize = size_of::<u32>();
const ADDRESS_SIZE: usize = size_of::<u64>();

const MAX_HEAP_SIZE: u64 = 2 << 40; // 2TB

pub struct Runner {
    path: String,
    host_dynamic_libraries: Vec<HostDynamicLibrary>,
}

impl Runner {
    pub fn new(path: String, host_dynamic_libraries: Vec<HostDynamicLibrary>) -> Self {
        Self {
            path,
            host_dynamic_libraries,
        }
    }

    pub fn run(&self, args: Vec<String>, env: Vec<String>) {
        info!("Loading executable: {}", self.path);
        let path = Path::new(&self.path);
        let buffer = fs::read(path).unwrap();
        let object = Object::parse(&buffer).unwrap();
        let mach = extract_mach(&object).unwrap();

        let mut emu = Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN).unwrap();
        map_segments(mach, &buffer, &mut emu);
        setup_stack(&mut emu, &args, &env);
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
                "{} at {:#x} num_unresolved_symbol_addresses: {} reserved1: {} flags: {}",
                it.name().unwrap(),
                it.addr,
                it.size / size_of::<u64>() as u64,
                it.reserved1,
                it.flags
            );
        });

        // Initialize allocator
        let heap_start = mach
            .segments
            .iter()
            .map(|it| it.vmaddr + it.vmsize)
            .max()
            .unwrap();
        let mmap_start = heap_start + MAX_HEAP_SIZE;
        let mmap_end = STACK_BASE;
        let mut allocator = Allocator::new(heap_start, mmap_start, mmap_end);
        info!("Program break: {:#x} - {:#x}", heap_start, mmap_start - 1);
        info!("MMAP region: {:#x} - {:#x}", mmap_start, mmap_end);

        // Setup program exit call
        let exit_function = allocator
            .mmap_alloc(&mut emu, size_of::<u32>() as u64)
            .unwrap();
        emu.mem_write(exit_function, &SVC_OPCODE).unwrap();
        emu.reg_write(RegisterARM64::LR, exit_function).unwrap();

        // Load libraries
        let libs: Vec<&str> = mach
            .libs
            .iter()
            .filter(|it| *it != &"self")
            .map(|it| *it)
            .collect();
        info!("Libraries to load: {:#?}", libs);
        let mut libs_baseaddr = vec![];
        libs.iter().for_each(|path| {
            info!("Loading library: {}", path);
            let host_dynamic_library = self
                .host_dynamic_libraries
                .iter()
                .find(|it| it.path == *path);
            let Some(host_dynamic_library) = host_dynamic_library else {
                // TODO Implement loading compiled dynamic libraries
                error!("Library {} not found", path);
                std::process::exit(1);
            };

            let global_variables_size = host_dynamic_library
                .global_variables
                .iter()
                .map(|it| it.data.len())
                .sum::<usize>();
            let functions_size =
                (host_dynamic_library.function_handlers.len() as usize) * INSTRUCTION_SIZE;
            let size = global_variables_size + functions_size;
            if size == 0 {
                return;
            }

            let base_addr = allocator.mmap_alloc(&mut emu, size as u64).unwrap();
            libs_baseaddr.push(base_addr);
            let num_functions = host_dynamic_library.function_handlers.len();

            // Write functions
            for i in 0..num_functions {
                emu.mem_write(base_addr + (i * INSTRUCTION_SIZE) as u64, &SVC_OPCODE)
                    .unwrap();
            }

            // Write global variables
            let mut base_variables = base_addr + (num_functions * INSTRUCTION_SIZE) as u64;
            for it in host_dynamic_library.global_variables.iter() {
                emu.mem_write(base_variables, &it.data).unwrap();
                base_variables += it.data.len() as u64;
            }
        });

        // Resolve undefined symbols
        info!("Resolving undefined symbols...");
        sections_with_unresolved_symbols.iter().for_each(|it| {
            let num_unresolved_symbol_addresses = it.size / size_of::<u64>() as u64;
            for i in 0..num_unresolved_symbol_addresses {
                let symbol_index = indirect_symbol_table[it.reserved1 as usize + i as usize];
                let (symbol_name, _) = mach.symbols().nth(symbol_index as usize).unwrap().unwrap();
                let address = it.addr + i * ADDRESS_SIZE as u64;

                let host_library = self
                    .host_dynamic_libraries
                    .iter()
                    .find(|it| it.function_handlers.iter().any(|it| it.name == symbol_name));
                let Some(host_library) = host_library else {
                    error!("Symbol {} not found", symbol_name);
                    std::process::exit(1);
                };
                let function_index = host_library
                    .function_handlers
                    .iter()
                    .position(|it| it.name == symbol_name)
                    .unwrap();
                let libs_index = libs.iter().position(|it| it == &host_library.path).unwrap();
                let trampoline_address =
                    libs_baseaddr[libs_index] + (function_index * INSTRUCTION_SIZE) as u64;
                emu.mem_write(address, &trampoline_address.to_le_bytes())
                    .unwrap();
                debug!(
                    "Resolved symbol {}, resolution addr: {:#x}, trampoline addr: {:#x}",
                    symbol_name, address, trampoline_address
                );
            }
        });

        emu.add_intr_hook(move |emu, interrupt| {
            if interrupt != SVC_INT_NUMBER {
                return;
            }

            let pc = emu.reg_read(RegisterARM64::PC).unwrap() - INSTRUCTION_SIZE as u64; // PC is already incremented
            let return_addr = emu.reg_read(RegisterARM64::LR).unwrap();
            if pc == exit_function {
                emu.emu_stop().unwrap();
                return;
            }
            trace!(
                "INTR: {:#x}, PC: {:#x}, Return: {:#x}",
                interrupt, pc, return_addr
            );

            // PC -> symbol name
            let lib = libs.iter().enumerate().find(|(index, lib)| {
                let base_addr = libs_baseaddr[*index];
                let host_lib = self
                    .host_dynamic_libraries
                    .iter()
                    .find(|it| it.path == lib.to_string())
                    .unwrap();
                let num_functions = host_lib.function_handlers.len();
                let end_addr = base_addr + (num_functions * INSTRUCTION_SIZE) as u64;
                return pc >= base_addr && pc < end_addr;
            });
            let Some(lib) = lib else {
                panic!("Symbol at PC={:#x} not found", pc);
            };
            let (libs_index, lib) = lib;
            let host_library = self
                .host_dynamic_libraries
                .iter()
                .find(|it| it.path == lib.to_string())
                .unwrap();
            let function_index = (pc - libs_baseaddr[libs_index]) / INSTRUCTION_SIZE as u64;
            let function_name = &host_library.function_handlers[function_index as usize].name;

            let mut processed = false;
            for library in self.host_dynamic_libraries.iter() {
                if let Some(handler) = library
                    .function_handlers
                    .iter()
                    .find(|it| it.name == *function_name)
                {
                    (handler.handler)(emu);
                    processed = true;
                }
            }

            if !processed {
                panic!("Symbol {} not found", function_name);
            }

            emu.reg_write(RegisterARM64::PC, return_addr).unwrap();
        })
        .unwrap();

        info!("Running program at {:#x}...", mach.entry);
        emu.emu_start(mach.entry, STACK_TOP, 0, 0).unwrap();

        info!("Program finished!");
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
    let dysymtab_command = mach
        .load_commands
        .iter()
        .filter_map(|it| {
            let CommandVariant::Dysymtab(command) = it.command else {
                return None;
            };
            Some(command)
        })
        .next();
    let Some(dysymtab_command) = dysymtab_command else {
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

fn setup_stack(emu: &mut Unicorn<'_, ()>, args: &Vec<String>, env: &Vec<String>) {
    info!("Stack: Base: {:#x} Size: {:#x}", STACK_BASE, STACK_SIZE);
    emu.mem_map(STACK_BASE as u64, STACK_SIZE, Prot::READ | Prot::WRITE)
        .unwrap();

    let argc = args.len() as u64;
    emu.reg_write(RegisterARM64::X0, argc).unwrap();

    let argv_ptr_count = args.len() + 1;
    let envp_ptr_count = env.len() + 1;

    let strings_size: usize = args.iter().chain(env.iter()).map(|s| s.len() + 1).sum();

    let ptrs_size = (argv_ptr_count + envp_ptr_count) * std::mem::size_of::<u64>();

    let total_size = strings_size + ptrs_size;

    let sp = STACK_TOP - total_size as u64;
    emu.reg_write(RegisterARM64::SP, sp).unwrap();

    let argv_base = sp;
    let envp_base = argv_base + (argv_ptr_count * 8) as u64;
    let mut str_base = envp_base + (envp_ptr_count * 8) as u64;

    for (i, arg) in args.iter().enumerate() {
        emu.mem_write(argv_base + (i * 8) as u64, &str_base.to_le_bytes())
            .unwrap();
        emu.mem_write(str_base, &[arg.as_bytes(), &[0]].concat())
            .unwrap();
        str_base += (arg.len() + 1) as u64;
    }
    emu.mem_write(argv_base + (args.len() * 8) as u64, &0u64.to_le_bytes())
        .unwrap();

    for (i, var) in env.iter().enumerate() {
        emu.mem_write(envp_base + (i * 8) as u64, &str_base.to_le_bytes())
            .unwrap();
        emu.mem_write(str_base, &[var.as_bytes(), &[0]].concat())
            .unwrap();
        str_base += (var.len() + 1) as u64;
    }
    emu.mem_write(envp_base + (env.len() * 8) as u64, &0u64.to_le_bytes())
        .unwrap();

    emu.reg_write(RegisterARM64::X1, argv_base).unwrap();
    emu.reg_write(RegisterARM64::X2, envp_base).unwrap();
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
