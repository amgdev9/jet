use std::{fs, path::Path};

use goblin::{
    Object,
    mach::{
        Mach, MachO,
        constants::{S_LAZY_SYMBOL_POINTERS, S_NON_LAZY_SYMBOL_POINTERS},
        load_command::{CommandVariant, LoadCommand},
        segment::{Section, Segment},
    },
};
use log::{debug, error, info};
use unicorn_engine::{Prot, Unicorn};

use crate::{
    allocator::Allocator,
    arch::{ADDRESS_SIZE, INSTRUCTION_SIZE, SVC_OPCODE},
    host_dynamic_library::HostDynamicLibrary,
};

pub struct MachOFile {
    pub entrypoint: Option<u64>,
    pub loaded_libs: Vec<LoadedLibrary>,
}

pub struct LoadedLibrary {
    pub base_address: u64,
    pub path: String,
}

impl MachOFile {
    pub fn load(
        path: String,
        emu: &mut Unicorn<'_, ()>,
        allocator: &mut Allocator,
        host_libs: &Vec<HostDynamicLibrary>,
    ) -> Self {
        // Load file
        info!("Loading Mach-O file: {}", path);
        let path = Path::new(&path);
        let buffer = fs::read(path).unwrap();
        let object = Object::parse(&buffer).unwrap();
        let mach = extract_mach(&object).unwrap();

        // Map segments to emulator
        let segments: Vec<&Segment<'_>> =
            mach.segments.iter().filter(|it| it.initprot != 0).collect();
        let start_addr = segments.iter().map(|it| it.vmaddr).min().unwrap();
        let end_addr = segments
            .iter()
            .map(|it| it.vmaddr + it.vmsize)
            .max()
            .unwrap();
        let total_size = end_addr - start_addr;
        let base_address = allocator.alloc_unmapped(total_size).unwrap();
        map_segments(segments, &buffer, emu);

        // Fetch sections with unresolved symbols
        info!("Fetching sections with unresolved symbols...");
        let sections_with_unresolved_symbols: Vec<Section> = mach
            .segments
            .iter()
            .flat_map(|it| it.sections().unwrap())
            .filter(|(it, _)| {
                it.flags == S_NON_LAZY_SYMBOL_POINTERS || it.flags == S_LAZY_SYMBOL_POINTERS
            })
            .map(|it| it.0)
            .inspect(|it| {
                info!(
                    "Section name={} at {:#x} num_unresolved_symbol_addresses={} reserved1={} flags={}",
                    it.name().unwrap(),
                    it.addr,
                    it.size / size_of::<u64>() as u64,
                    it.reserved1,
                    it.flags
                );
            })
            .collect();

        // Load libraries
        let loaded_libs = mach
            .libs
            .iter()
            .filter(|it| *it != &"self")
            .map(|it| *it)
            .inspect(|it| {
                info!("Loading library: {}", it);
            })
            .map(|path| {
                let host_lib = host_libs.iter().find(|it| it.path == *path);
                let Some(host_lib) = host_lib else {
                    // TODO Implement loading compiled dynamic libraries
                    error!("Library {} not found", path);
                    std::process::exit(1);
                };

                let global_variables_size = host_lib
                    .global_variables
                    .iter()
                    .map(|it| it.data.len())
                    .sum::<usize>();
                let functions_size = (host_lib.function_handlers.len() as usize) * INSTRUCTION_SIZE;
                let size = global_variables_size + functions_size;

                let base_addr = allocator
                    .alloc_mapped(emu, size as u64, Prot::ALL) // TODO Optimize permissions
                    .unwrap();
                let num_functions = host_lib.function_handlers.len();

                // Write functions
                for i in 0..num_functions {
                    emu.mem_write(base_addr + (i * INSTRUCTION_SIZE) as u64, &SVC_OPCODE)
                        .unwrap();
                }

                // Write global variables
                let mut base_variables = base_addr + (num_functions * INSTRUCTION_SIZE) as u64;
                for it in host_lib.global_variables.iter() {
                    emu.mem_write(base_variables, &it.data).unwrap();
                    base_variables += it.data.len() as u64;
                }

                return LoadedLibrary {
                    base_address: base_addr,
                    path: path.to_string(),
                };
            })
            .collect::<Vec<LoadedLibrary>>();

        // Resolve undefined symbols
        info!("Resolving undefined symbols...");
        let indirect_symbol_table = get_indirect_symbol_table(&mach.load_commands, &buffer);

        sections_with_unresolved_symbols.iter().for_each(|it| {
            let num_unresolved_symbol_addresses = it.size / size_of::<u64>() as u64;
            for i in 0..num_unresolved_symbol_addresses {
                let symbol_index = indirect_symbol_table[it.reserved1 as usize + i as usize];
                let (symbol_name, _) = mach.symbols().nth(symbol_index as usize).unwrap().unwrap();
                let address = it.addr + i * ADDRESS_SIZE as u64;

                let host_lib = host_libs
                    .iter()
                    .find(|it| it.function_handlers.iter().any(|it| it.name == symbol_name));
                let Some(host_lib) = host_lib else {
                    error!("Symbol {} not found", symbol_name);
                    std::process::exit(1);
                };
                let function_index = host_lib
                    .function_handlers
                    .iter()
                    .position(|it| it.name == symbol_name)
                    .unwrap();
                let loaded_lib = loaded_libs
                    .iter()
                    .find(|it| it.path == host_lib.path)
                    .unwrap();
                let trampoline_address =
                    loaded_lib.base_address + (function_index * INSTRUCTION_SIZE) as u64;
                emu.mem_write(address, &trampoline_address.to_le_bytes())
                    .unwrap();
                debug!(
                    "Resolved symbol name={}, resolution_addr={:#x}, trampoline_addr={:#x}",
                    symbol_name, address, trampoline_address
                );
            }
        });

        // Figure out the entrypoint if file is executable
        let entrypoint = if mach.entry == 0 {
            None
        } else {
            Some(mach.entry + base_address)
        };

        Self {
            entrypoint,
            loaded_libs,
        }
    }

    // TODO Implement drop to free memory from emulator
}

fn extract_mach<'a>(object: &'a Object<'a>) -> Option<&'a MachO<'a>> {
    let Object::Mach(mach_container) = object else {
        error!("Not a mach binary");
        return None;
    };

    if let Mach::Binary(mach) = mach_container {
        return Some(mach);
    }

    todo!("Not a single-arch mach binary, implement fat binaries");
}

fn map_segments(segments: Vec<&Segment<'_>>, buffer: &[u8], emu: &mut Unicorn<'_, ()>) {
    segments.iter().for_each(|it| {
        let prot = map_mach_prot(it.initprot);
        info!(
            "Segment: name={} start_addr={:#x} vm_size={:#x} prot={:#b}",
            it.name().unwrap(),
            it.vmaddr,
            it.vmsize,
            prot.0
        );

        emu.mem_map(it.vmaddr, it.vmsize, prot).unwrap();

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

fn map_mach_prot(prot: u32) -> Prot {
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

fn get_indirect_symbol_table(load_commands: &Vec<LoadCommand>, buffer: &Vec<u8>) -> Vec<u32> {
    let dysymtab_command = load_commands
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
        "Indirect symbol table: addr={:#x} num_entries={}",
        dysymtab_command.indirectsymoff, dysymtab_command.nindirectsyms
    );
    let start = dysymtab_command.indirectsymoff as usize;
    let end = start + dysymtab_command.nindirectsyms as usize * size_of::<u32>();

    return buffer[start..end]
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect();
}
