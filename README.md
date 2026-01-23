# Jet - A multi-architecture Mach-O runner for Linux

This is a PoC of trying to run Mach-O executables on Linux for different architectures, using [Unicorn Emulator](https://github.com/unicorn-engine/unicorn) when the CPU architecture does not match the host.

For this proof of concept, we will be running ARM64 binaries on x86_64 Linux. This runner does not adhere to any specific ABI and it's up to the user of this crate to implement it.
