use log::{error, info};
use unicorn_engine::Unicorn;

use crate::{
    emulation_context::EmulationContext, host_dynamic_library::HostDynamicLibrary, mach::MachOFile,
};

type SetupRuntimeFn = fn(&mut Unicorn<'_, ()>, &EmulationContext);

pub struct Runner {
    context: EmulationContext,
    setup_runtime: SetupRuntimeFn,
}

impl Runner {
    /// For setup_runtime function, at least it must set LR so the program knows how to exit
    pub fn new(
        host_dynamic_libraries: Vec<HostDynamicLibrary>,
        setup_runtime: SetupRuntimeFn,
    ) -> Self {
        Self {
            context: EmulationContext::new(host_dynamic_libraries),
            setup_runtime,
        }
    }

    pub fn run(&self, path: String) {
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

        (self.setup_runtime)(&mut emu, ctx);
        ctx.start_emulator(&mut emu, entrypoint);

        info!("Program finished!");
    }
}
