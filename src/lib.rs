use chrono::{DateTime, Datelike, Local, TimeZone, Timelike};
use once_cell::sync::Lazy;
use rand::rngs::{OsRng, StdRng};
use rand::{Rng, SeedableRng};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub mod version;

pub mod announce_log;
pub mod app_links;
pub mod buffer;
pub mod channel;
pub mod destination;
pub mod config;
pub mod discovery;
pub mod identity;
pub mod interface_writer;
pub mod interfaces;
pub mod link;
pub mod lxstamper;
pub mod packet;
pub mod send_assertion;
pub mod resolver;
pub mod resource;
pub mod reticulum;
pub mod transport;
pub mod ffi;
pub mod cffi;
pub mod client;

pub const LOG_NONE: i32 = -1;
pub const LOG_CRITICAL: i32 = 0;
pub const LOG_ERROR: i32 = 1;
pub const LOG_WARNING: i32 = 2;
pub const LOG_NOTICE: i32 = 3;
pub const LOG_INFO: i32 = 4;
pub const LOG_VERBOSE: i32 = 5;
pub const LOG_DEBUG: i32 = 6;
pub const LOG_EXTREME: i32 = 7;

pub const LOG_STDOUT: i32 = 0x91;
pub const LOG_FILE: i32 = 0x92;
pub const LOG_CALLBACK: i32 = 0x93;

pub const LOG_MAXSIZE: u64 = 5 * 1024 * 1024;

pub struct LogState {
    pub loglevel: i32,
    pub logfile: Option<String>,
    pub logdest: i32,
    pub logcall: Option<Arc<dyn Fn(String) + Send + Sync>>,
    logtimefmt: String,
    logtimefmt_p: String,
    compact_log_fmt: bool,
    always_override_destination: bool,
}

static LOG_STATE: Lazy<Mutex<LogState>> = Lazy::new(|| {
    Mutex::new(LogState {
        loglevel: LOG_NOTICE,
        logfile: None,
        logdest: LOG_STDOUT,
        logcall: None,
        logtimefmt: "%Y-%m-%d %H:%M:%S".to_string(),
        logtimefmt_p: "%H:%M:%S.%f".to_string(),
        compact_log_fmt: false,
        always_override_destination: false,
    })
});

static LOGGING_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

static INSTANCE_RNG: Lazy<Mutex<StdRng>> = Lazy::new(|| {
    let mut seed = [0u8; 32];
    OsRng.fill(&mut seed);
    Mutex::new(StdRng::from_seed(seed))
});

pub fn loglevelname(level: i32) -> &'static str {
    match level {
        LOG_CRITICAL => "[Critical]",
        LOG_ERROR => "[Error]   ",
        LOG_WARNING => "[Warning] ",
        LOG_NOTICE => "[Notice]  ",
        LOG_INFO => "[Info]    ",
        LOG_VERBOSE => "[Verbose] ",
        LOG_DEBUG => "[Debug]   ",
        LOG_EXTREME => "[Extra]   ",
        _ => "Unknown",
    }
}

pub fn version() -> &'static str {
    version::VERSION
}

pub fn host_os() -> String {
    if cfg!(target_os = "macos") {
        "darwin".to_string()
    } else if cfg!(target_os = "windows") {
        "windows".to_string()
    } else if cfg!(target_os = "android") {
        "android".to_string()
    } else {
        std::env::consts::OS.to_string()
    }
}

fn format_time(dt: DateTime<Local>, fmt: &str) -> String {
    let mut out = String::new();
    let mut chars = fmt.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '%' {
            if let Some(spec) = chars.next() {
                match spec {
                    'Y' => out.push_str(&format!("{:04}", dt.year())),
                    'm' => out.push_str(&format!("{:02}", dt.month())),
                    'd' => out.push_str(&format!("{:02}", dt.day())),
                    'H' => out.push_str(&format!("{:02}", dt.hour())),
                    'M' => out.push_str(&format!("{:02}", dt.minute())),
                    'S' => out.push_str(&format!("{:02}", dt.second())),
                    'f' => out.push_str(&format!("{:06}", dt.timestamp_subsec_micros())),
                    _ => {
                        out.push('%');
                        out.push(spec);
                    }
                }
            } else {
                out.push('%');
            }
        } else {
            out.push(ch);
        }
    }
    out
}

pub fn timestamp_str(time_s: f64) -> String {
    let secs = time_s.floor() as i64;
    let nanos = ((time_s - time_s.floor()) * 1_000_000_000.0) as u32;
    let dt = Local.timestamp_opt(secs, nanos)
        .single()
        .unwrap_or_else(Local::now);
    let fmt = { LOG_STATE.lock().unwrap().logtimefmt.clone() };
    format_time(dt, &fmt)
}

pub fn precise_timestamp_str(_time_s: f64) -> String {
    let dt = Local::now();
    let fmt = { LOG_STATE.lock().unwrap().logtimefmt_p.clone() };
    let rendered = format_time(dt, &fmt);
    if rendered.len() >= 3 {
        rendered[..rendered.len() - 3].to_string()
    } else {
        rendered
    }
}

pub fn log(msg: impl ToString, level: i32, override_destination: bool, pt: bool) {
    let msg = msg.to_string();
    let mut state = LOG_STATE.lock().unwrap();
    if state.loglevel == LOG_NONE {
        return;
    }
    if state.loglevel < level {
        return;
    }

    let now_dt = Local::now();
    let timestamp = if pt {
        let rendered = format_time(now_dt, &state.logtimefmt_p);
        if rendered.len() >= 3 {
            rendered[..rendered.len() - 3].to_string()
        } else {
            rendered
        }
    } else {
        format_time(now_dt, &state.logtimefmt)
    };

    let logstring = if !state.compact_log_fmt {
        format!("[{}] {} {}", timestamp, loglevelname(level), msg)
    } else {
        format!("[{}] {}", timestamp, msg)
    };

    let _lock = LOGGING_LOCK.lock().unwrap();
    if state.logdest == LOG_STDOUT || state.always_override_destination || override_destination {
        println!("{}", logstring);
        return;
    }

    if state.logdest == LOG_FILE {
        if let Some(path) = state.logfile.clone() {
            let write_result = append_log(&path, &logstring);
            if let Err(err) = write_result {
                state.always_override_destination = true;
                drop(state);
                log(
                    format!("Exception occurred while writing log message to log file: {}", err),
                    LOG_CRITICAL,
                    false,
                    false,
                );
                log("Dumping future log events to console!", LOG_CRITICAL, false, false);
                log(msg, level, false, pt);
            }
        }
        return;
    }

    if state.logdest == LOG_CALLBACK {
        if let Some(callback) = state.logcall.clone() {
            let call_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                callback(logstring.clone())
            }));
            if call_result.is_err() {
                state.always_override_destination = true;
                drop(state);
                log("Exception occurred while calling external log handler", LOG_CRITICAL, false, false);
                log("Dumping future log events to console!", LOG_CRITICAL, false, false);
                log(msg, level, false, pt);
            }
        }
    }
}

pub fn set_loglevel(level: i32) {
    let mut state = LOG_STATE.lock().unwrap();
    state.loglevel = level;
}

pub fn set_logdest(dest: i32) {
    let mut state = LOG_STATE.lock().unwrap();
    state.logdest = dest;
}

pub fn set_logfile(path: String) {
    let mut state = LOG_STATE.lock().unwrap();
    state.logfile = Some(path);
}

fn append_log(path: &str, line: &str) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{}", line)?;
    let size = fs::metadata(path)?.len();
    if size > LOG_MAXSIZE {
        let prevfile = format!("{}.1", path);
        if Path::new(&prevfile).is_file() {
            let _ = fs::remove_file(&prevfile);
        }
        let _ = fs::rename(path, &prevfile);
    }
    Ok(())
}

#[allow(dead_code)]
fn now_seconds() -> f64 {
    let since = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::from_secs(0));
    since.as_secs() as f64 + (since.subsec_nanos() as f64 / 1_000_000_000.0)
}

pub fn rand() -> f64 {
    INSTANCE_RNG.lock().unwrap().gen::<f64>()
}

pub fn trace_exception(err: impl std::fmt::Display) {
    log(
        format!("An unhandled exception occurred: {}", err),
        LOG_ERROR,
        false,
        false,
    );
}

pub fn hexrep(data: &[u8], delimit: bool) -> String {
    let delimiter = if delimit { ":" } else { "" };
    data.iter()
        .map(|c| format!("{:02x}", c))
        .collect::<Vec<_>>()
        .join(delimiter)
}

/// Decode a hex string into bytes. Returns `None` if the string has odd length
/// or contains non-hex characters.
pub fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = match bytes[i] {
            b'0'..=b'9' => bytes[i] - b'0',
            b'a'..=b'f' => bytes[i] - b'a' + 10,
            b'A'..=b'F' => bytes[i] - b'A' + 10,
            _ => return None,
        };
        let lo = match bytes[i + 1] {
            b'0'..=b'9' => bytes[i + 1] - b'0',
            b'a'..=b'f' => bytes[i + 1] - b'a' + 10,
            b'A'..=b'F' => bytes[i + 1] - b'A' + 10,
            _ => return None,
        };
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

pub fn prettyhexrep(data: &[u8]) -> String {
    format!("<{}>", hexrep(data, false))
}

pub fn prettyspeed(num: f64, suffix: &str) -> String {
    format!("{}ps", prettysize(num / 8.0, suffix))
}

pub fn prettysize(mut num: f64, suffix: &str) -> String {
    let mut units = vec!["", "K", "M", "G", "T", "P", "E", "Z"];
    let mut last_unit = "Y";

    if suffix == "b" {
        num *= 8.0;
        units = vec!["", "K", "M", "G", "T", "P", "E", "Z"];
        last_unit = "Y";
    }

    for unit in units {
        if num.abs() < 1000.0 {
            if unit.is_empty() {
                return format!("{:.0} {}", num, suffix);
            }
            return format!("{:.2} {}{}", num, unit, suffix);
        }
        num /= 1000.0;
    }

    format!("{:.2}{}{}", num, last_unit, suffix)
}

pub fn prettyfrequency(hz: f64, suffix: &str) -> String {
    let mut num = hz * 1e6;
    let units = vec!["\u{00B5}", "m", "", "K", "M", "G", "T", "P", "E", "Z"];
    let last_unit = "Y";

    for unit in units {
        if num.abs() < 1000.0 {
            if unit.is_empty() {
                return format!("{:.2} {}", num, suffix);
            }
            return format!("{:.2} {}{}", num, unit, suffix);
        }
        num /= 1000.0;
    }

    format!("{:.2}{}{}", num, last_unit, suffix)
}

pub fn prettydistance(m: f64, suffix: &str) -> String {
    let mut num = m * 1e6;
    let units = vec!["\u{00B5}", "m", "c", ""];
    let last_unit = "K";

    for unit in units {
        let mut divisor = 1000.0;
        if unit == "m" {
            divisor = 10.0;
        }
        if unit == "c" {
            divisor = 100.0;
        }

        if num.abs() < divisor {
            if unit.is_empty() {
                return format!("{:.2} {}", num, suffix);
            }
            return format!("{:.2} {}{}", num, unit, suffix);
        }
        num /= divisor;
    }

    format!("{:.2} {}{}", num, last_unit, suffix)
}

pub fn prettytime(mut time_s: f64, verbose: bool, compact: bool) -> String {
    let mut neg = false;
    if time_s < 0.0 {
        time_s = time_s.abs();
        neg = true;
    }

    let days = (time_s / (24.0 * 3600.0)).floor() as i64;
    time_s %= 24.0 * 3600.0;
    let hours = (time_s / 3600.0).floor() as i64;
    time_s %= 3600.0;
    let minutes = (time_s / 60.0).floor() as i64;
    time_s %= 60.0;
    let seconds = if compact { time_s.floor() } else { (time_s * 100.0).round() / 100.0 };

    let ss = if seconds == 1.0 { "" } else { "s" };
    let sm = if minutes == 1 { "" } else { "s" };
    let sh = if hours == 1 { "" } else { "s" };
    let sd = if days == 1 { "" } else { "s" };

    let mut displayed = 0;
    let mut components: Vec<String> = Vec::new();

    if days > 0 && (!compact || displayed < 2) {
        components.push(if verbose {
            format!("{} day{}", days, sd)
        } else {
            format!("{}d", days)
        });
        displayed += 1;
    }

    if hours > 0 && (!compact || displayed < 2) {
        components.push(if verbose {
            format!("{} hour{}", hours, sh)
        } else {
            format!("{}h", hours)
        });
        displayed += 1;
    }

    if minutes > 0 && (!compact || displayed < 2) {
        components.push(if verbose {
            format!("{} minute{}", minutes, sm)
        } else {
            format!("{}m", minutes)
        });
        displayed += 1;
    }

    if seconds > 0.0 && (!compact || displayed < 2) {
        let seconds_str = if seconds.fract() == 0.0 {
            format!("{:.0}", seconds)
        } else {
            let mut s = format!("{:.2}", seconds);
            while s.ends_with('0') {
                s.pop();
            }
            if s.ends_with('.') {
                s.pop();
            }
            s
        };
        components.push(if verbose {
            format!("{} second{}", seconds_str, ss)
        } else {
            format!("{}s", seconds_str)
        });
        displayed += 1;
    }

    if components.is_empty() {
        return "0s".to_string();
    }

    let mut tstr = String::new();
    for (i, c) in components.iter().enumerate() {
        if i == 0 {
            tstr.push_str(c);
        } else if i < components.len() - 1 {
            tstr.push_str(", ");
            tstr.push_str(c);
        } else {
            tstr.push_str(" and ");
            tstr.push_str(c);
        }
    }

    let _ = displayed;
    if neg {
        format!("-{}", tstr)
    } else {
        tstr
    }
}

pub fn prettyshorttime(time_s: f64, verbose: bool, compact: bool) -> String {
    let mut neg = false;
    let mut time_us = time_s * 1e6;
    if time_us < 0.0 {
        time_us = time_us.abs();
        neg = true;
    }

    let seconds = (time_us / 1e6).floor() as i64;
    time_us %= 1e6;
    let milliseconds = (time_us / 1e3).floor() as i64;
    time_us %= 1e3;
    let microseconds = if compact { time_us.floor() } else { (time_us * 100.0).round() / 100.0 };

    let ss = if seconds == 1 { "" } else { "s" };
    let sms = if milliseconds == 1 { "" } else { "s" };
    let sus = if microseconds == 1.0 { "" } else { "s" };

    let mut displayed = 0;
    let mut components: Vec<String> = Vec::new();

    if seconds > 0 && (!compact || displayed < 2) {
        components.push(if verbose {
            format!("{} second{}", seconds, ss)
        } else {
            format!("{}s", seconds)
        });
        displayed += 1;
    }

    if milliseconds > 0 && (!compact || displayed < 2) {
        components.push(if verbose {
            format!("{} millisecond{}", milliseconds, sms)
        } else {
            format!("{}ms", milliseconds)
        });
        displayed += 1;
    }

    if microseconds > 0.0 && (!compact || displayed < 2) {
        let micro_str = if microseconds.fract() == 0.0 {
            // Python oracle keeps one decimal place for whole microsecond
            // values in prettyshorttime, e.g. "234.0µs".
            format!("{:.1}", microseconds)
        } else {
            let mut s = format!("{:.2}", microseconds);
            if s.ends_with('0') {
                s.pop();
            }
            s
        };
        components.push(if verbose {
            format!("{} microsecond{}", micro_str, sus)
        } else {
            format!("{}\u{00B5}s", micro_str)
        });
        displayed += 1;
    }

    if components.is_empty() {
        return "0us".to_string();
    }

    let mut tstr = String::new();
    for (i, c) in components.iter().enumerate() {
        if i == 0 {
            tstr.push_str(c);
        } else if i < components.len() - 1 {
            tstr.push_str(", ");
            tstr.push_str(c);
        } else {
            tstr.push_str(" and ");
            tstr.push_str(c);
        }
    }

    let _ = displayed;
    if neg {
        format!("-{}", tstr)
    } else {
        tstr
    }
}

pub fn phyparams() {
    println!("Required Physical Layer MTU : {} bytes", reticulum::MTU);
    println!("Plaintext Packet MDU        : {} bytes", packet::PLAIN_MDU);
    println!("Encrypted Packet MDU        : {} bytes", packet::ENCRYPTED_MDU);
    println!("Link Curve                  : {}", link::CURVE);
    println!("Link Packet MDU             : {} bytes", link::MDU);
    println!("Link Public Key Size        : {} bits", link::ECPUBSIZE * 8);
    println!("Link Private Key Size       : {} bits", link::KEYSIZE * 8);
}

pub fn panic_exit() -> ! {
    std::process::exit(255)
}

static EXIT_CALLED: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));

pub fn exit(code: i32) -> ! {
    let mut called = EXIT_CALLED.lock().unwrap();
    if !*called {
        *called = true;
        reticulum::exit_handler();
    }
    std::process::exit(code)
}

pub struct Profiler {
    tag: Option<String>,
    super_tag: Option<String>,
    paused: bool,
    pause_time: Duration,
    pause_started: Option<Instant>,
}

struct ThreadCapture {
    current_start: Option<Instant>,
    captures: Vec<f64>,
}

struct TagEntry {
    threads: HashMap<u64, ThreadCapture>,
    super_tag: Option<String>,
}

struct ProfilerState {
    ran: bool,
    tags: HashMap<String, TagEntry>,
    profilers: HashMap<String, Profiler>,
}

static PROFILER_STATE: Lazy<Mutex<ProfilerState>> = Lazy::new(|| {
    Mutex::new(ProfilerState {
        ran: false,
        tags: HashMap::new(),
        profilers: HashMap::new(),
    })
});

impl Profiler {
    pub fn get_profiler(tag: Option<&str>, super_tag: Option<&str>) -> Profiler {
        let mut state = PROFILER_STATE.lock().unwrap();
        if let Some(tag_name) = tag {
            if let Some(existing) = state.profilers.get(tag_name) {
                return existing.clone();
            }
            let profiler = Profiler {
                tag: Some(tag_name.to_string()),
                super_tag: super_tag.map(|s| s.to_string()),
                paused: false,
                pause_time: Duration::from_secs(0),
                pause_started: None,
            };
            state.profilers.insert(tag_name.to_string(), profiler.clone());
            profiler
        } else {
            Profiler {
                tag: None,
                super_tag: super_tag.map(|s| s.to_string()),
                paused: false,
                pause_time: Duration::from_secs(0),
                pause_started: None,
            }
        }
    }

    pub fn guard(&self) -> ProfilerGuard {
        let mut profiler = self.clone();
        profiler.enter();
        ProfilerGuard { profiler }
    }

    pub fn enter(&mut self) {
        if let Some(ref tag) = self.tag {
            self.pause_super();
            let thread_id = current_thread_id_u64();
            let mut state = PROFILER_STATE.lock().unwrap();
            let entry = state.tags.entry(tag.clone()).or_insert(TagEntry {
                threads: HashMap::new(),
                super_tag: self.super_tag.clone(),
            });
            let capture = entry.threads.entry(thread_id).or_insert(ThreadCapture {
                current_start: None,
                captures: Vec::new(),
            });
            capture.current_start = Some(Instant::now());
            self.resume_super();
        }
    }

    pub fn exit(&mut self) {
        if let Some(ref tag) = self.tag {
            self.pause_super();
            let thread_id = current_thread_id_u64();
            let mut state = PROFILER_STATE.lock().unwrap();
            if let Some(entry) = state.tags.get_mut(tag) {
                if let Some(capture) = entry.threads.get_mut(&thread_id) {
                    if let Some(start) = capture.current_start.take() {
                        let elapsed = Instant::now().duration_since(start) - self.pause_time;
                        capture.captures.push(elapsed.as_secs_f64());
                        state.ran = true;
                    }
                }
            }
            self.pause_time = Duration::from_secs(0);
            self.resume_super();
        }
    }

    fn pause_super(&self) {
        if let Some(ref super_tag) = self.super_tag {
            let mut state = PROFILER_STATE.lock().unwrap();
            if let Some(super_profiler) = state.profilers.get_mut(super_tag) {
                super_profiler.pause_internal(None, false);
            }
        }
    }

    fn resume_super(&self) {
        if let Some(ref super_tag) = self.super_tag {
            let mut state = PROFILER_STATE.lock().unwrap();
            if let Some(super_profiler) = state.profilers.get_mut(super_tag) {
                super_profiler.resume_internal(false);
            }
        }
    }

    fn pause_internal(&mut self, pause_started: Option<Instant>, with_super: bool) {
        if !self.paused {
            self.paused = true;
            let started = pause_started.unwrap_or_else(Instant::now);
            self.pause_started = Some(started);
            if with_super {
                self.pause_super();
            }
        }
    }

    fn resume_internal(&mut self, with_super: bool) {
        if self.paused {
            if let Some(start) = self.pause_started.take() {
                self.pause_time += Instant::now().duration_since(start);
            }
            self.paused = false;
            if with_super {
                self.resume_super();
            }
        }
    }

    pub fn pause(&mut self, pause_started: Option<Instant>) {
        self.pause_internal(pause_started, true);
    }

    pub fn resume(&mut self) {
        self.resume_internal(true);
    }

    pub fn ran() -> bool {
        PROFILER_STATE.lock().unwrap().ran
    }

    pub fn results() {
        let state = PROFILER_STATE.lock().unwrap();
        let mut results = HashMap::new();

        for (tag, entry) in state.tags.iter() {
            let mut tag_captures = Vec::new();
            for capture in entry.threads.values() {
                tag_captures.extend(capture.captures.iter().copied());
            }
            if !tag_captures.is_empty() {
                let stats = compute_stats(&tag_captures);
                results.insert(tag.clone(), (entry.super_tag.clone(), stats));
            }
        }

        println!("\nProfiler results:\n");
        for (tag, (super_tag, _stats)) in results.iter() {
            if super_tag.is_none() {
                print_results_recursive(tag, &results, 0);
            }
        }
    }
}

fn current_thread_id_u64() -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    std::thread::current().id().hash(&mut hasher);
    hasher.finish()
}

fn compute_stats(samples: &[f64]) -> Stats {
    let count = samples.len();
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let mean = sorted.iter().sum::<f64>() / count as f64;
    let median = if count % 2 == 0 {
        (sorted[count / 2 - 1] + sorted[count / 2]) / 2.0
    } else {
        sorted[count / 2]
    };

    let stdev = if count > 1 {
        let variance = sorted
            .iter()
            .map(|v| (v - mean) * (v - mean))
            .sum::<f64>()
            / (count as f64 - 1.0);
        Some(variance.sqrt())
    } else {
        None
    };

    Stats {
        count,
        mean,
        median,
        stdev,
    }
}

struct Stats {
    count: usize,
    mean: f64,
    median: f64,
    stdev: Option<f64>,
}

fn print_results_recursive(tag: &str, results: &HashMap<String, (Option<String>, Stats)>, level: usize) {
    print_tag_results(tag, results, level + 1);
    for (tag_name, (super_tag, _)) in results.iter() {
        if super_tag.as_deref() == Some(tag) {
            print_results_recursive(tag_name, results, level + 1);
        }
    }
}

fn print_tag_results(tag: &str, results: &HashMap<String, (Option<String>, Stats)>, level: usize) {
    if let Some((_, stats)) = results.get(tag) {
        let ind = "  ".repeat(level);
        println!("{}{}", ind, tag);
        println!("{}  Samples  : {}", ind, stats.count);
        if let Some(stdev) = stats.stdev {
            println!("{}  Mean     : {}", ind, prettyshorttime(stats.mean, false, false));
            println!("{}  Median   : {}", ind, prettyshorttime(stats.median, false, false));
            println!("{}  St.dev.  : {}", ind, prettyshorttime(stdev, false, false));
        }
        println!("{}  Total    : {}", ind, prettyshorttime(stats.mean * stats.count as f64, false, false));
        println!();
    }
}

pub struct ProfilerGuard {
    profiler: Profiler,
}

impl Drop for ProfilerGuard {
    fn drop(&mut self) {
        self.profiler.exit();
    }
}

impl Clone for Profiler {
    fn clone(&self) -> Self {
        Profiler {
            tag: self.tag.clone(),
            super_tag: self.super_tag.clone(),
            paused: self.paused,
            pause_time: self.pause_time,
            pause_started: self.pause_started,
        }
    }
}

pub fn profile(tag: Option<&str>, super_tag: Option<&str>) -> Profiler {
    Profiler::get_profiler(tag, super_tag)
}
