use unicorn_engine::Unicorn;

pub struct HostDynamicLibrary {
    pub path: String,
    pub function_handlers: Vec<FunctionHandler>,
    pub global_variables: Vec<GlobalVariable>,
}

pub struct FunctionHandler {
    pub name: String,
    pub handler: fn(&Unicorn<'_, ()>)
}

pub struct GlobalVariable {
    pub name: String,
    pub data: Vec<u8>,
}
