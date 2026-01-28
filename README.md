# Jet - A multi-architecture Mach-O runner for Linux

This is a PoC of trying to run Mach-O executables for different CPU architectures, using [Unicorn Emulator](https://github.com/unicorn-engine/unicorn) when the CPU architecture does not match the host.

## What's working
- ✅ Running ARM64 Mach-O binaries on x86_64 Linux
- ✅ Provide dynamic libraries which run on the host
- ✅ Load regular dynamic libraries required by the executable (resolved recursively)
    (*) needs polishing when resolving runtime search paths
- ✅ Call from host function to emulated function (via a function pointer), preserving program flow

## What's work in progress
- 🚧 Provide a threading solution using host threads (e.g. instantiating an emulator per thread sharing mapped memory)

## Future goals
- 🎯 Achieve native execution if executable target cpu matches host cpu

## What this crate won't do
- Adhere to any specific ABI, runtime environment or operating system for the execution of Mach-O binaries, although it can be used as a baseline to achieve this.

