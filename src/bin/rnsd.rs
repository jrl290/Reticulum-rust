use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use reticulum_rust::reticulum::Reticulum;
use reticulum_rust::version::VERSION;

const RNSD_VERSION: &str = "0.1.0";

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("rnsd-rust {RNSD_VERSION} (reticulum-rust {VERSION})");
        return;
    }

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_usage();
        return;
    }

    // Parse CLI arguments (compatible with Python rnsd)
    let config_dir = arg_value(&args, "--config").map(PathBuf::from);
    let verbose: i32 = args.iter().map(|a| {
        if a == "--verbose" { 1 }
        else if a.starts_with("-") && !a.starts_with("--") {
            a.chars().filter(|&c| c == 'v').count() as i32
        } else { 0 }
    }).sum();
    let quiet: i32 = args.iter().map(|a| {
        if a == "--quiet" { 1 }
        else if a.starts_with("-") && !a.starts_with("--") {
            a.chars().filter(|&c| c == 'q').count() as i32
        } else { 0 }
    }).sum();
    let service = args.iter().any(|a| a == "-s" || a == "--service");

    // Compute effective log level: base LOG_NOTICE (3) + verbose - quiet
    let effective_verbosity = reticulum_rust::LOG_NOTICE + verbose - quiet;
    let loglevel = effective_verbosity.max(reticulum_rust::LOG_CRITICAL);

    // Service mode: log to file instead of stdout
    // Set before init so early messages are captured, and re-applied after
    // in case Reticulum::init() resets log state.
    let service_logfile = if service {
        let log_dir = config_dir
            .clone()
            .unwrap_or_else(default_config_dir);
        let logfile_path = log_dir.join("logfile");
        let path_str = logfile_path.to_string_lossy().to_string();
        reticulum_rust::set_logdest(reticulum_rust::LOG_FILE);
        reticulum_rust::set_logfile(path_str.clone());
        Some(path_str)
    } else {
        None
    };

    reticulum_rust::set_loglevel(loglevel);

    // Install signal handler
    let interrupted = Arc::new(AtomicBool::new(false));
    {
        let flag = Arc::clone(&interrupted);
        if let Err(e) = ctrlc::set_handler(move || {
            flag.store(true, Ordering::Relaxed);
        }) {
            eprintln!("[rnsd] Failed to install signal handler: {e}");
        }
    }

    // Initialize Reticulum
    // Transport mode is controlled by `enable_transport = Yes` in the config file
    reticulum_rust::log(
        format!("Starting rnsd-rust {RNSD_VERSION}"),
        reticulum_rust::LOG_NOTICE,
        false,
        false,
    );

    let init_result = std::panic::catch_unwind(|| {
        Reticulum::init(config_dir, Some(loglevel), None, None, false, None)
    });

    match init_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            eprintln!("[rnsd] Reticulum init failed: {e}");
            std::process::exit(1);
        }
        Err(panic) => {
            let detail = panic
                .downcast_ref::<String>()
                .map(|s| s.as_str())
                .or_else(|| panic.downcast_ref::<&str>().copied())
                .unwrap_or("unknown panic");
            eprintln!("[rnsd] Reticulum init panicked: {detail}");
            std::process::exit(1);
        }
    }

    // Re-apply log settings after init (Reticulum::init may reset loglevel)
    reticulum_rust::set_loglevel(loglevel);
    if let Some(ref path) = service_logfile {
        reticulum_rust::set_logdest(reticulum_rust::LOG_FILE);
        reticulum_rust::set_logfile(path.clone());
    }

    // Check if connected to shared instance (which is probably wrong for rnsd)
    if let Some(instance) = Reticulum::get_instance() {
        if let Ok(ret) = instance.lock() {
            if ret.is_connected_to_shared_instance {
                reticulum_rust::log(
                    format!("Started rnsd-rust {RNSD_VERSION} connected to another shared local instance, this is probably NOT what you want!"),
                    reticulum_rust::LOG_WARNING,
                    false,
                    false,
                );
            } else {
                reticulum_rust::log(
                    format!("Started rnsd-rust {RNSD_VERSION}"),
                    reticulum_rust::LOG_NOTICE,
                    false,
                    false,
                );
            }
        }
    }

    // Main loop: sleep until interrupted
    while !interrupted.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    // Graceful shutdown
    reticulum_rust::log(
        "rnsd-rust shutting down".to_string(),
        reticulum_rust::LOG_NOTICE,
        false,
        false,
    );
    reticulum_rust::reticulum::exit_handler();
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn default_config_dir() -> PathBuf {
    if std::path::Path::new("/etc/reticulum").is_dir()
        && std::path::Path::new("/etc/reticulum/config").is_file()
    {
        return PathBuf::from("/etc/reticulum");
    }
    if let Some(home) = std::env::var_os("HOME") {
        let config_home = PathBuf::from(&home).join(".config/reticulum");
        if config_home.is_dir() && config_home.join("config").is_file() {
            return config_home;
        }
        return PathBuf::from(home).join(".reticulum");
    }
    PathBuf::from("/tmp/reticulum")
}

fn print_usage() {
    println!("rnsd-rust {RNSD_VERSION} — Reticulum Network Stack Daemon (Rust)");
    println!();
    println!("Usage: rnsd [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --config <DIR>  Path to alternative Reticulum config directory");
    println!("  -v, --verbose   Increase verbosity (can be repeated)");
    println!("  -q, --quiet     Decrease verbosity (can be repeated)");
    println!("  -s, --service   Run as a service (log to file instead of stdout)");
    println!("  -V, --version   Print version and exit");
    println!("  -h, --help      Print this help and exit");
    println!();
    println!("Transport mode is controlled by `enable_transport = Yes` in the config file.");
}
