//! Publishes one destination and does nothing else, so every announce it
//! makes is Transport's own: the refresh sweep's, or an interface up-edge's.
//! Staging runs it to see which interface events announce; an AutoInterface
//! peer appearing, flapping or returning must not (PARITY-AUDIT-1.5.2.md B41).
//!
//!   publish_refresh <config_dir> <refresh_secs | none>
//!
//! `none` publishes without a refresh interval, so only up-edges announce it.
//! Prints `DEST <hex>` once the destination is published.

use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use reticulum_rust::destination::{Destination, DestinationType};
use reticulum_rust::identity::Identity;
use reticulum_rust::reticulum::Reticulum;
use reticulum_rust::transport::Transport;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let refresh = match args.get(2).map(String::as_str) {
        Some("none") if args.len() == 3 => None,
        Some(secs) if args.len() == 3 => match secs.parse::<u64>() {
            // A zero period would announce on every sweep.
            Ok(secs) if secs > 0 => Some(Duration::from_secs(secs)),
            _ => usage(),
        },
        _ => usage(),
    };
    Reticulum::init(Some(PathBuf::from(&args[1])), None, None, None, false, None).expect("Reticulum init");

    let destination = Destination::new_inbound(
        Some(Identity::new(true)),
        DestinationType::Single,
        "publish_refresh".to_string(),
        vec!["probe".to_string()],
    )
    .expect("create destination");
    let hash = destination.hash.clone();
    Transport::register_destination(destination);
    Transport::publish_destination(hash.clone(), refresh, None);
    println!("DEST {}", reticulum_rust::hexrep(&hash, false));

    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}

fn usage() -> ! {
    eprintln!("usage: publish_refresh <config_dir> <refresh_secs | none>");
    std::process::exit(2);
}
