use unicorn_engine::Unicorn;

pub struct HostDynamicLibrary {
    pub path: String,
    pub function_handlers: Vec<FunctionHandler>,
    pub global_variables: Vec<GlobalVariable>,
}

pub struct FunctionHandler {
    pub name: String,

    /// When you need to call back to an emulated function from the handler (e.g. via a function pointer argument), you need to split your handler in multiple parts (continuations) so the program flow stays consistent when mixing jumps between host code and emulated code. If the function does not receive function pointers to call, just keep this field to 1
    /// A typical handler in this case will have this form
    /*
        num_continuations: 2,
        handler: |emu, num_continuation| {
            match num_continuation {
                0 => {
                    // ... handler code ...
                    // When you need to call the function pointer do as follows:
                    // - Push registers to the stack (the ones which will get overwritten for the callback function call) 
                    // - Push LR to the stack
                    // - Set registers for callback function arguments
                    // - Jump to callback function (PC = function pointer)
                    // - Set LR = PC so we return to next continuation block
                }
                1 => {
                    // - Pop LR from the stack
                    // - Pop registers from the stack
                    // ... more code ...
                }
            }
        }
    */
    pub num_continuations: u32,
    pub handler: fn(&mut Unicorn<'_, ()>, u32),
}

pub struct GlobalVariable {
    pub name: String,
    pub data: Vec<u8>,
}
