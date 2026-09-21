use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, Default)]
pub struct ConfigSection {
    items: HashMap<String, String>,
    subsections: HashMap<String, ConfigSection>,
}

impl ConfigSection {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.items.get(key).map(|v| v.as_str())
    }

    pub fn get_section(&self, name: &str) -> Option<&ConfigSection> {
        self.subsections.get(name)
    }

    pub fn subsections(&self) -> &HashMap<String, ConfigSection> {
        &self.subsections
    }

    pub fn items(&self) -> &HashMap<String, String> {
        &self.items
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.get(key).and_then(parse_bool)
    }

    pub fn get_int(&self, key: &str) -> Option<i64> {
        self.get(key).and_then(|v| v.parse::<i64>().ok())
    }

    pub fn get_float(&self, key: &str) -> Option<f64> {
        self.get(key).and_then(|v| v.parse::<f64>().ok())
    }

    pub fn get_list(&self, key: &str) -> Option<Vec<String>> {
        self.get(key).map(parse_list)
    }

    fn insert_item(&mut self, key: String, value: String) {
        self.items.insert(key, value);
    }
}

#[derive(Clone, Debug, Default)]
pub struct Config {
    sections: HashMap<String, ConfigSection>,
    /// Lines that carried a setting but belong to no section, as
    /// `(line number, text)`. They cannot take effect — every reader asks a
    /// named section — so whoever loads the config MUST report them. See
    /// `from_str`.
    discarded: Vec<(usize, String)>,
}

impl Config {
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|err| format!("Failed to read config {}: {}", path.display(), err))?;
        Ok(Self::from_str(&content))
    }

    pub fn from_str(content: &str) -> Self {
        let mut cfg = Config::default();
        let mut current_section: Option<String> = None;
        let mut current_subsection: Option<String> = None;

        for (index, raw_line) in content.lines().enumerate() {
            let line = strip_comment(raw_line).trim().to_string();
            if line.is_empty() {
                continue;
            }

            if line.starts_with("[[") && line.ends_with("]]" ) {
                let name = line.trim_start_matches("[[").trim_end_matches("]]").trim().to_string();
                if let Some(section) = current_section.clone() {
                    cfg.sections
                        .entry(section.clone())
                        .or_default()
                        .subsections
                        .entry(name.clone())
                        .or_default();
                    current_subsection = Some(name);
                } else {
                    cfg.discarded.push((index + 1, line.clone()));
                }
                continue;
            }

            if line.starts_with('[') && line.ends_with(']') {
                let name = line.trim_start_matches('[').trim_end_matches(']').trim().to_string();
                cfg.sections.entry(name.clone()).or_default();
                current_section = Some(name);
                current_subsection = None;
                continue;
            }

            if let Some((key, value)) = split_kv(&line) {
                let key = key.to_string();
                let value = unquote(value.trim());
                if let Some(section_name) = current_section.clone() {
                    let section = cfg.sections.entry(section_name).or_default();
                    if let Some(subsection_name) = current_subsection.clone() {
                        let subsection = section.subsections.entry(subsection_name).or_default();
                        subsection.insert_item(key, value);
                    } else {
                        section.insert_item(key, value);
                    }
                } else {
                    // A setting above the first `[section]`. It used to vanish
                    // here without a word. On the production gateway that was
                    // `enable_transport = Yes` on line 1 of a config with no
                    // `[reticulum]` header: the node ran with transport
                    // DISABLED for its whole life while its config said
                    // otherwise, and a non-reference announce forwarder was
                    // written to make it relay anyway — the symptom patched,
                    // the cause never seen. Silence is forbidden: keep the line
                    // so the loader can say so.
                    cfg.discarded.push((index + 1, line.clone()));
                }
            }
        }

        cfg
    }

    /// Settings that were parsed but can never take effect because they sit
    /// outside every section, as `(line number, text)`.
    pub fn discarded(&self) -> &[(usize, String)] {
        &self.discarded
    }

    pub fn get_section(&self, name: &str) -> Option<&ConfigSection> {
        self.sections.get(name)
    }
}

fn strip_comment(line: &str) -> &str {
    if let Some((prefix, _)) = line.split_once('#') {
        prefix
    } else {
        line
    }
}

fn split_kv(line: &str) -> Option<(&str, &str)> {
    let mut parts = line.splitn(2, '=');
    let key = parts.next()?.trim();
    let value = parts.next()?.trim();
    if key.is_empty() {
        None
    } else {
        Some((key, value))
    }
}

fn unquote(value: &str) -> String {
    let trimmed = value.trim();
    if (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
    {
        trimmed[1..trimmed.len() - 1].to_string()
    } else {
        trimmed.to_string()
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_lowercase().as_str() {
        "true" | "yes" | "1" | "on" => Some(true),
        "false" | "no" | "0" | "off" => Some(false),
        _ => None,
    }
}

fn parse_list(value: &str) -> Vec<String> {
    let raw = value.trim();
    let parts: Vec<String> = if raw.contains(',') {
        raw.split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect()
    } else {
        raw.split_whitespace()
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect()
    };
    parts
}

pub fn default_config_lines() -> Vec<String> {
    DEFAULT_CONFIG.iter().map(|s| s.to_string()).collect()
}

const DEFAULT_CONFIG: &[&str] = &[
    "# This is the default Reticulum config file.",
    "# You should probably edit it to include any additional,",
    "# interfaces and settings you might need.",
    "",
    "# Only the most basic options are included in this default",
    "# configuration. To see a more verbose, and much longer,",
    "# configuration example, you can run the command:",
    "# rnsd --exampleconfig",
    "",
    "",
    "[reticulum]",
    "",
    "# If you enable Transport, your system will route traffic",
    "# for other peers, pass announces and serve path requests.",
    "# This should only be done for systems that are suited to",
    "# act as transport nodes, ie. if they are stationary and",
    "# always-on. This directive is optional and can be removed",
    "# for brevity.",
    "",
    "enable_transport = False",
    "",
    "",
    "# By default, the first program to launch the Reticulum",
    "# Network Stack will create a shared instance, that other",
    "# programs can communicate with. Only the shared instance",
    "# opens all the configured interfaces directly, and other",
    "# local programs communicate with the shared instance over",
    "# a local socket. This is completely transparent to the",
    "# user, and should generally be turned on. This directive",
    "# is optional and can be removed for brevity.",
    "",
    "share_instance = Yes",
    "",
    "",
    "# If you want to run multiple *different* shared instances",
    "# on the same system, you will need to specify different",
    "# instance names for each. On platforms supporting domain",
    "# sockets, this can be done with the instance_name option:",
    "",
    "instance_name = default",
    "",
    "",
    "# Some platforms don't support domain sockets, and if that",
    "# is the case, you can isolate different instances by",
    "# specifying a unique set of ports for each:",
    "",
    "# shared_instance_port = 37428",
    "# instance_control_port = 37429",
    "",
    "",
    "# If you want to explicitly use TCP for shared instance",
    "# communication, instead of domain sockets, this is also",
    "# possible, by using the following option:",
    "",
    "# shared_instance_type = tcp",
    "",
    "",
    "# You can configure whether Reticulum should discover",
    "# available interfaces from other Transport Instances over",
    "# the network. If this option is enabled, Reticulum will",
    "# collect interface information discovered from the network.",
    "",
    "# discover_interfaces = No",
    "",
    "",
    "# You can configure Reticulum to panic and forcibly close",
    "# if an unrecoverable interface error occurs, such as the",
    "# hardware device for an interface disappearing. This is",
    "# an optional directive, and can be left out for brevity.",
    "# This behaviour is disabled by default.",
    "",
    "# panic_on_interface_error = No",
    "",
    "",
    "# If you're connecting to a large external network, you",
    "# can use one or more external blackhole list to block",
    "# spammy and excessive announces onto your network. This",
    "# funtionality is especially useful if you're hosting public",
    "# entrypoints or gateways. The list source below provides a",
    "# functional example, but better, more timely maintained",
    "# lists probably exist in the community.",
    "",
    "# blackhole_sources = 521c87a83afb8f29e4455e77930b973b",
    "",
    "",
    "[logging]",
    "# Valid log levels are 0 through 7:",
    "#   0: Log only critical information",
    "#   1: Log errors and lower log levels",
    "#   2: Log warnings and lower log levels",
    "#   3: Log notices and lower log levels",
    "#   4: Log info and lower (this is the default)",
    "#   5: Verbose logging",
    "#   6: Debug logging",
    "#   7: Extreme logging",
    "",
    "loglevel = 4",
    "",
    "",
    "# The interfaces section defines the physical and virtual",
    "# interfaces Reticulum will use to communicate on. This",
    "# section will contain examples for a variety of interface",
    "# types. You can modify these or use them as a basis for",
    "# your own config, or simply remove the unused ones.",
    "",
    "[interfaces]",
    "",
    "  # This interface enables communication with other",
    "  # link-local Reticulum nodes over UDP. It does not",
    "  # need any functional IP infrastructure like routers",
    "  # or DHCP servers, but will require that at least link-",
    "  # local IPv6 is enabled in your operating system, which",
    "  # should be enabled by default in almost any OS. See",
    "  # the Reticulum Manual for more configuration options.",
    "",
    "  [[Default Interface]]",
    "    type = AutoInterface",
    "    enabled = Yes",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The production gateway's config, as it was: `enable_transport` on line 1
    /// with no `[reticulum]` header above it.
    #[test]
    fn a_setting_above_the_first_section_is_reported_not_swallowed() {
        let cfg = Config::from_str("enable_transport = Yes\n\n[logging]\nloglevel = 3\n\n[interfaces]\n[[RMAP]]\ntype = TCPClientInterface\n");
        assert!(cfg.get_section("reticulum").is_none(), "there is no [reticulum] section to read it from");
        assert_eq!(
            cfg.discarded(),
            &[(1, "enable_transport = Yes".to_string())],
            "a setting that cannot take effect must be surfaced to the loader, never dropped silently"
        );
    }

    #[test]
    fn a_subsection_above_the_first_section_is_reported() {
        let cfg = Config::from_str("[[Orphan]]\ntype = TCPClientInterface\n[interfaces]\n");
        let lines: Vec<usize> = cfg.discarded().iter().map(|(n, _)| *n).collect();
        assert_eq!(lines, vec![1, 2], "the orphan header and the setting under it");
    }

    #[test]
    fn a_well_formed_config_discards_nothing() {
        let cfg = Config::from_str("# comment\n[reticulum]\nenable_transport = Yes\n[interfaces]\n[[RMAP]]\ntype = TCPClientInterface\n");
        assert!(cfg.discarded().is_empty());
        assert_eq!(cfg.get_section("reticulum").and_then(|s| s.get_bool("enable_transport")), Some(true));
    }
}
