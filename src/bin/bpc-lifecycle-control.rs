#![forbid(unsafe_code)]

use std::path::PathBuf;

use bpc_protocol::control_service::{ControlError, ServiceConfig, migrate, run};

#[tokio::main]
async fn main() {
    let (config_path, migrate_only) = match arguments() {
        Ok(arguments) => arguments,
        Err(error) => fail(error),
    };
    let config = match ServiceConfig::load_from_path(&config_path) {
        Ok(config) => config,
        Err(error) => fail(error),
    };
    if migrate_only {
        match tokio::task::spawn_blocking(move || migrate(&config)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => fail(error),
            Err(_) => fail(ControlError::DatabaseConnection),
        }
    } else if let Err(error) = run(config).await {
        fail(error);
    }
}

fn arguments() -> Result<(PathBuf, bool), ControlError> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let Some(path) = arguments.next() else {
        return Err(ControlError::InvalidArguments);
    };
    let migrate_only = match arguments.next() {
        None => false,
        Some(flag) if flag == "--migrate" && arguments.next().is_none() => true,
        Some(_) => return Err(ControlError::InvalidArguments),
    };
    Ok((PathBuf::from(path), migrate_only))
}

fn fail(error: ControlError) -> ! {
    // `ControlError` is deliberately value-free: never print config values,
    // database URLs, bearer tokens, private keys, or parser/driver errors.
    eprintln!("bpc lifecycle control startup failed: {error}");
    std::process::exit(1);
}
