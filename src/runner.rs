use log::{error, info};
use unicorn_engine::Prot;

use crate::{
    arch::{INSTRUCTION_SIZE, SVC_OPCODE},
    emulation_context::EmulationContext,
    host_dynamic_library::HostDynamicLibrary,
    mach::MachOFile,
    runtime::Runtime,
};

pub struct Runner {
    context: EmulationContext,
}

impl Runner {
    pub fn new(host_dynamic_libraries: Vec<HostDynamicLibrary>) -> Self {
        Self {
            context: EmulationContext::new(host_dynamic_libraries),
        }
    }

    pub fn run(&self, path: String, args: Vec<String>, env: Vec<String>) {
        let ctx = &self.context;
        let mut emu = ctx.new_emulator();

        // Load executable file
        {
            let mut macho_files = ctx.macho_files.write().unwrap();
            MachOFile::load_into(
                path.clone(),
                &mut emu,
                &ctx.allocator,
                &ctx.host_dynamic_libraries,
                &mut macho_files,
            );
        }

        // Figure out entrypoint
        let entrypoint = ctx
            .macho_files
            .read()
            .unwrap()
            .iter()
            .find(|it| it.path == path)
            .unwrap()
            .entrypoint;
        let Some(entrypoint) = entrypoint else {
            error!("Program is not executable");
            return;
        };

        info!("Running program at {:#x}...", entrypoint);

        // Setup runtime
        Runtime::install(&mut emu, &args, &env);
        let exit_function_alloc = ctx
            .allocator
            .lock()
            .unwrap()
            .simple_alloc(&mut emu, INSTRUCTION_SIZE as u64, Prot::READ | Prot::EXEC)
            .unwrap();
        let exit_function = exit_function_alloc.address;
        emu.mem_write(exit_function, &SVC_OPCODE).unwrap();
        ctx.exit_function_address
            .write()
            .unwrap()
            .replace(exit_function);

        ctx.start_emulator(&mut emu, entrypoint);

        info!("Program finished!");
    }
}
