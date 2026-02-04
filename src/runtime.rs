use unicorn_engine::{RegisterARM64, Unicorn};

pub struct Runtime {}

impl Runtime {
    pub fn install(emu: &mut Unicorn<'_, ()>, args: &Vec<String>, env: &Vec<String>) {
        Self::push_arguments(emu, args, env);
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
}
