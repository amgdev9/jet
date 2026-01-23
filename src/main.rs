use simplelog::{Config, LevelFilter, WriteLogger};
use std::fs::File;

use crate::runner::Runner;

mod runner;

fn main() {
    WriteLogger::init(
        LevelFilter::Info,
        Config::default(),
        File::create("jet.log").unwrap(),
    )
    .unwrap();

    let runner = Runner::new("./test".into());
    runner.run();
}
