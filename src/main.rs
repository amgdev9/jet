use std::env;

use flexi_logger::{Age, Cleanup, Criterion, FileSpec, Logger, Naming};

use crate::runner::Runner;

mod runner;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("Usage: {} <executable>", args[0]);
    }
    let program_path = &args[1];

    Logger::try_with_str("jet=debug")
        .unwrap()
        .log_to_file(
            FileSpec::default()
                .directory("logs")
                .basename("output")
                .suffix("log"),
        )
        .rotate(
            Criterion::Age(Age::Second),
            Naming::Numbers,
            Cleanup::KeepLogFiles(0),
        )
        .start()
        .unwrap();

    let runner = Runner::new(program_path.to_string());
    runner.run();
}
