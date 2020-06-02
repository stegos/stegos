//! A logger that prints all messages with a readable output format.
use colored::*;
use stegos_blockchain::Timestamp;

use log::{Level, Log, Metadata, Record, SetLoggerError};

use std::cell::RefCell;

struct SimpleLogger {
    level: Level,
    init_time: Timestamp,
}

thread_local! {
    pub static MODULE_PREFIX: RefCell<String> = RefCell::new(String::from("TESTING"));
}

impl Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let level_string = {
                match record.level() {
                    Level::Error => record.level().to_string().red(),
                    Level::Warn => record.level().to_string().yellow(),
                    Level::Info => record.level().to_string().cyan(),
                    Level::Debug => record.level().to_string().purple(),
                    Level::Trace => record.level().to_string().normal(),
                }
            };
            let target = if record.target().len() > 0 {
                record.target()
            } else {
                record.module_path().unwrap_or_default()
            };
            let duration = Timestamp::now().duration_since(self.init_time);
            MODULE_PREFIX.with(|prefix| {
                println!(
                    "{}:{}.{:<3} | {:^17} {:<5} [{}] {}",
                    duration.as_secs() / 60,
                    duration.as_secs() % 60,
                    duration.subsec_nanos() / 1000_000,
                    prefix.borrow(),
                    level_string,
                    target,
                    record.args()
                );
            })
        }
    }

    fn flush(&self) {}
}

/// Initializes the global logger with a SimpleLogger instance with
/// `max_log_level` set to a specific log level.
pub fn init_with_level(level: Level) -> Result<(), SetLoggerError> {
    let logger = SimpleLogger {
        level,
        init_time: Timestamp::now(),
    };
    log::set_boxed_logger(Box::new(logger))?;
    log::set_max_level(level.to_level_filter());
    Ok(())
}
