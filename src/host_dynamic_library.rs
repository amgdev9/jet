use unicorn_engine::Unicorn;

pub struct HostDynamicLibrary {
    pub path: String,
    pub function_handlers: Vec<FunctionHandler>,
    pub global_variables: Vec<GlobalVariable>,
}

pub struct FunctionHandler {
    pub name: String,

    /// Assembly entrypoint for this function
    /// If not provided, it will be just a syscall + ret
    pub entrypoint: Option<Vec<u8>>,

    /// Syscall handler for this function
    /// Second parameter is the offset inside the entrypoint code, measured in instructions
    pub syscall_handler: fn(&mut Unicorn<'_, ()>, u32),
}

impl FunctionHandler {
    pub fn entrypoint(&self) -> &[u8] {
        const DEFAULT_ENTRYPOINT: [u8; 8] = [
            0x01, 0x00, 0x00, 0xD4, // SVC #0
            0xc0, 0x03, 0x5f, 0xd6, // RET
        ];
        return self
            .entrypoint
            .as_ref()
            .map(|it| it.as_slice())
            .unwrap_or(&DEFAULT_ENTRYPOINT);
    }
}

pub struct GlobalVariable {
    pub name: String,
    pub data: Vec<u8>,
}
