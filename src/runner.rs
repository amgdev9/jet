use std::{
    cell::RefCell,
    rc::Rc,
    sync::{Arc, Mutex},
};

use log::{error, info};
use unicorn_engine::{Arch, HookType, Mode, Prot, RegisterARM64, Unicorn};

use crate::{
    allocator::Allocator,
    arch::{INSTRUCTION_SIZE, SVC_INT_NUMBER, SVC_OPCODE},
    host_dynamic_library::{FunctionHandler, HostDynamicLibrary},
    mach::MachOFile,
};

const STACK_SIZE: u64 = 8 << 20; // Fixed size 

pub struct Runner {
    host_dynamic_libraries: Rc<Vec<HostDynamicLibrary>>,
    macho_files: Rc<RefCell<Vec<MachOFile>>>,
    allocator: Arc<Mutex<Allocator>>,
    exit_function_address: Rc<RefCell<Option<u64>>>,
}

impl Runner {
    pub fn new(host_dynamic_libraries: Vec<HostDynamicLibrary>) -> Self {
        Self {
            host_dynamic_libraries: Rc::new(host_dynamic_libraries),
            macho_files: Rc::new(RefCell::new(Vec::new())),
            allocator: Arc::new(Mutex::new(Allocator::new())),
            exit_function_address: Rc::new(RefCell::new(None)),
        }
    }

    pub fn run(&mut self, path: String, args: Vec<String>, env: Vec<String>) {
        let mut emu = self.new_emulator();

        // Setup program exit call
        let exit_function_alloc = self
            .allocator
            .lock()
            .unwrap()
            .simple_alloc(&mut emu, INSTRUCTION_SIZE as u64, Prot::READ | Prot::EXEC)
            .unwrap();
        let exit_function = exit_function_alloc.address;
        emu.mem_write(exit_function, &SVC_OPCODE).unwrap();
        emu.reg_write(RegisterARM64::LR, exit_function).unwrap();
        self.exit_function_address
            .borrow_mut()
            .replace(exit_function);

        // Load executable file
        {
            let mut macho_files = self.macho_files.borrow_mut();
            let mut allocator = self.allocator.lock().unwrap(); // TODO Lock on usage inside MachOFile::load_into
            MachOFile::load_into(
                path.clone(),
                &mut emu,
                &mut allocator,
                &self.host_dynamic_libraries,
                &mut macho_files,
            );
        }

        // Figure out entrypoint
        let entrypoint = self
            .macho_files
            .borrow()
            .iter()
            .find(|it| it.path == path)
            .unwrap()
            .entrypoint;
        let Some(entrypoint) = entrypoint else {
            error!("Program is not executable");
            return;
        };

        info!("Running program at {:#x}...", entrypoint);
        push_arguments(&mut emu, &args, &env);  // TODO Move to crt0
        self.start_emulator(&mut emu, entrypoint);

        info!("Program finished!");
    }

    pub fn allocator(&self) -> Arc<Mutex<Allocator>> {
        self.allocator.clone()
    }

    pub fn new_thread(&mut self, entrypoint: u64) {
        let mut emu = self.new_emulator();

        info!("Starting new thread at {:#x}...", entrypoint);
        self.start_emulator(&mut emu, entrypoint);

        info!("Thread finished!");
    }

    fn new_emulator<'a>(&mut self) -> Unicorn<'a, ()> {
        let mut emu = Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN).unwrap();

        // Setup stack
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
        let exit_function_address = self.exit_function_address.clone();
        let macho_files = self.macho_files.clone();
        let host_dynamic_libraries = self.host_dynamic_libraries.clone();
        emu.add_intr_hook(move |emu, interrupt| {
            if interrupt != SVC_INT_NUMBER {
                return;
            }

            let pc = emu.reg_read(RegisterARM64::PC).unwrap() - INSTRUCTION_SIZE as u64; // PC is already incremented

            // Check program exit
            if pc == exit_function_address.borrow().unwrap() {
                emu.emu_stop().unwrap();
                return;
            }

            // Match PC with function handler from a host library
            let mut handler: Option<&FunctionHandler> = None;
            let mut instruction_offset: Option<u32> = None;
            for lib in macho_files.borrow().iter() {
                if handler.is_some() {
                    break;
                }
                let host_lib = host_dynamic_libraries.iter().find(|it| it.path == lib.path);
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
                        instruction_offset =
                            Some(((pc - fun_start) / (INSTRUCTION_SIZE as u64)) as u32);
                        handler = Some(possible_handler);
                        break;
                    }
                }
            }

            let Some(handler) = handler else {
                error!("Symbol at PC={:#x} not found", pc);
                std::process::exit(1);
            };
            (handler.syscall_handler)(emu, instruction_offset.unwrap());
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

    fn start_emulator(&mut self, emu: &mut Unicorn<'_, ()>, entrypoint: u64) {
        emu.emu_start(entrypoint, u64::MAX, 0, 0).unwrap();
        self.allocator.lock().unwrap().garbage_collect_thread(emu);
    }
}

fn push_arguments(emu: &mut Unicorn<'_, ()>, args: &Vec<String>, env: &Vec<String>) {
    let argc = args.len() as u64;
    emu.reg_write(RegisterARM64::X0, argc).unwrap();

    let argv_ptr_count = args.len() + 1;
    let envp_ptr_count = env.len() + 1;

    let strings_size: usize = args.iter().chain(env.iter()).map(|s| s.len() + 1).sum();

    let ptrs_size = (argv_ptr_count + envp_ptr_count) * std::mem::size_of::<u64>();

    let total_size = strings_size + ptrs_size;

    let mut sp = emu.reg_read(RegisterARM64::SP).unwrap();
    sp -= total_size as u64;
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
