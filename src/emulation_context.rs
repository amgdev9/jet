use std::sync::{Arc, Mutex, RwLock};

use log::{error, info};
use unicorn_engine::{Arch, HookType, Mode, Prot, RegisterARM64, Unicorn};

use crate::{
    allocator::Allocator,
    arch::{INSTRUCTION_SIZE, SVC_INT_NUMBER},
    host_dynamic_library::HostDynamicLibrary,
    mach::MachOFile,
};

#[derive(Clone)]
pub struct EmulationContext {
    pub host_dynamic_libraries: Arc<Vec<HostDynamicLibrary>>,
    pub macho_files: Arc<RwLock<Vec<MachOFile>>>,
    pub allocator: Arc<Mutex<Allocator>>,
}

impl EmulationContext {
    pub fn new(host_dynamic_libraries: Vec<HostDynamicLibrary>) -> Self {
        Self {
            host_dynamic_libraries: Arc::new(host_dynamic_libraries),
            macho_files: Arc::new(RwLock::new(Vec::new())),
            allocator: Arc::new(Mutex::new(Allocator::new())),
        }
    }

    pub fn new_emulator<'a>(&self) -> Unicorn<'a, ()> {
        let mut emu = Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN).unwrap();

        // Setup stack
        const STACK_SIZE: u64 = 8 << 20; // Fixed size 
        let allocation = self
            .allocator
            .lock()
            .unwrap()
            .simple_alloc(&mut emu, STACK_SIZE, Prot::READ | Prot::WRITE)
            .unwrap();
        let stack_top = allocation.address + allocation.size - 1;
        info!(
            "Stack: Base: {:#x} Size: {:#x} Top: {:#x}",
            allocation.address, STACK_SIZE, stack_top
        );
        emu.reg_write(RegisterARM64::SP, stack_top).unwrap();

        // Setup syscall handler (used to call host functions)
        let self_clone = self.clone();
        emu.add_intr_hook(move |emu, interrupt| {
            if interrupt != SVC_INT_NUMBER {
                return;
            }

            let pc = emu.reg_read(RegisterARM64::PC).unwrap() - INSTRUCTION_SIZE as u64; // PC is already incremented

            // Match PC with function handler from a host library
            for lib in self_clone.macho_files.read().unwrap().iter() {
                let host_lib = self_clone
                    .host_dynamic_libraries
                    .iter()
                    .find(|it| it.path == lib.path);
                let Some(host_lib) = host_lib else {
                    continue;
                };
                for symbol in lib.export_symbols.iter() {
                    let possible_handler = host_lib
                        .function_handlers
                        .iter()
                        .find(|it| it.name == symbol.name)
                        .unwrap();
                    let fun_start = symbol.address;
                    let fun_end = fun_start + (possible_handler.entrypoint().len() as u64);
                    if pc >= fun_start && pc < fun_end {
                        let instruction_offset =
                            ((pc - fun_start) / (INSTRUCTION_SIZE as u64)) as u32;
                        (possible_handler.syscall_handler)(
                            emu,
                            instruction_offset,
                            self_clone.clone(),
                        );
                        return;
                    }
                }
            }

            error!("Symbol at PC={:#x} not found", pc);
            std::process::exit(1);
        })
        .unwrap();

        // Setup page fault handler
        let allocator = self.allocator.clone();
        emu.add_mem_hook(
            HookType::MEM_INVALID,
            0,
            u64::MAX,
            move |emu, _access, addr, _size, _value| {
                allocator.lock().unwrap().page_fault_handler(emu, addr)
            },
        )
        .unwrap();

        emu
    }

    pub fn start_emulator(&self, emu: &mut Unicorn<'_, ()>, entrypoint: u64) {
        emu.emu_start(entrypoint, u64::MAX, 0, 0).unwrap();
        self.allocator.lock().unwrap().garbage_collect_thread(emu);
    }

    pub fn resolve_symbol(&self, name: &str) -> Option<u64> {
        for lib in self.macho_files.read().unwrap().iter() {
            let host_lib = self
                .host_dynamic_libraries
                .iter()
                .find(|it| it.path == lib.path);
            if host_lib.is_none() {
                continue;
            }
            for symbol in lib.export_symbols.iter() {
                if symbol.name == name {
                    return Some(symbol.address);
                }
            }
        }
        None
    }
}
