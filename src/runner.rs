use log::{error, info};
use unicorn_engine::{Arch, Mode, Prot, RegisterARM64, Unicorn};

use crate::{
    allocator::Allocator,
    arch::{INSTRUCTION_SIZE, SVC_INT_NUMBER, SVC_OPCODE},
    host_dynamic_library::HostDynamicLibrary,
    mach::MachOFile,
};

const STACK_SIZE: u64 = 8 << 20; // Not growable
const STACK_TOP: u64 = 0x7fff_ffff_ffff;
const STACK_BASE: u64 = STACK_TOP - STACK_SIZE + 1;

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
        let mut emu = Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN).unwrap();
        let mut allocator = Allocator::new(0, STACK_BASE);
        setup_stack(&mut emu, &args, &env);

        // Setup program exit call
        let exit_function = allocator
            .alloc_mapped(&mut emu, size_of::<u32>() as u64, Prot::READ | Prot::EXEC)
            .unwrap();
        emu.mem_write(exit_function, &SVC_OPCODE).unwrap();
        emu.reg_write(RegisterARM64::LR, exit_function).unwrap();

        // Load executable file
        let mut macho_files = Vec::new();
        MachOFile::load_into(
            self.path.clone(),
            &mut emu,
            &mut allocator,
            &self.host_dynamic_libraries,
            &mut macho_files,
        );
        let program = macho_files.iter().find(|it| it.path == self.path).unwrap();
        let Some(entrypoint) = program.entrypoint else {
            error!("Program is not executable");
            return;
        };
            
        emu.add_intr_hook(move |emu, interrupt| {
            if interrupt != SVC_INT_NUMBER {
                return;
            }

            let pc = emu.reg_read(RegisterARM64::PC).unwrap() - INSTRUCTION_SIZE as u64; // PC is already incremented
            let return_addr = emu.reg_read(RegisterARM64::LR).unwrap();

            // Check program exit
            if pc == exit_function {
                emu.emu_stop().unwrap();
                return;
            }

            // PC -> symbol name
            let lib = macho_files 
                .iter()
                .find(|lib| {
                    let base_addr = lib.base_address;
                    let host_lib = self
                        .host_dynamic_libraries
                        .iter()
                        .find(|it| it.path == lib.path)
                        .unwrap();
                    let num_functions = host_lib.function_handlers.len();
                    let end_addr = base_addr + (num_functions * INSTRUCTION_SIZE) as u64;
                    return pc >= base_addr && pc < end_addr;
                })
                .expect("Symbol at PC={:#x} not found");
            let host_library = self
                .host_dynamic_libraries
                .iter()
                .find(|it| it.path == lib.path)
                .unwrap();
            let function_index = (pc - lib.base_address) / INSTRUCTION_SIZE as u64;
            let handler = &host_library.function_handlers[function_index as usize];
            (handler.handler)(emu);

            emu.reg_write(RegisterARM64::PC, return_addr).unwrap();
        })
        .unwrap();

        info!("Running program at {:#x}...", entrypoint);
        emu.emu_start(entrypoint, STACK_TOP, 0, 0).unwrap();

        info!("Program finished!");
    }
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
