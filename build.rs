use chrono::Utc;
use lazy_static::lazy_static;
use regex::Regex;
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;

lazy_static! {
    static ref DESCRIBE_RE: Regex = Regex::new(
        r"v(?P<major>[0-9]+)\.(?P<minor>[0-9]+)-(?P<patch>[0-9]+)-g(?P<commit>[0-9a-f]+)$",
    )
    .expect("regex is valid");
}

struct VersionInfo {
    major: String,
    minor: String,
    patch: String,
    commit: String,
}

impl VersionInfo {
    fn parse(describe: String) -> Result<VersionInfo, failure::Error> {
        let describe = DESCRIBE_RE
            .captures(describe.trim())
            .ok_or_else(|| failure::format_err!("Error parsing git describe."))?;
        let version = VersionInfo {
            major: describe
                .name("major")
                .expect("major version")
                .as_str()
                .to_string(),
            minor: describe
                .name("minor")
                .expect("minor version")
                .as_str()
                .to_string(),
            patch: describe
                .name("patch")
                .expect("patch version")
                .as_str()
                .to_string(),
            commit: describe
                .name("commit")
                .expect("commit version")
                .as_str()
                .to_string(),
        };
        Ok(version)
    }
}

impl Default for VersionInfo {
    fn default() -> Self {
        VersionInfo {
            major: String::from("0"),
            minor: String::from("0"),
            patch: String::from("0"),
            commit: String::from("unknown"),
        }
    }
}

fn parse_cargo_toml() -> Result<VersionInfo, failure::Error> {
    let mut pre_version = env::var("CARGO_PKG_VERSION_PRE")?;
    if pre_version.is_empty() {
        pre_version = "release".to_string();
    }
    Ok(VersionInfo {
        major: env::var("CARGO_PKG_VERSION_MAJOR")?,
        minor: env::var("CARGO_PKG_VERSION_MINOR")?,
        patch: env::var("CARGO_PKG_VERSION_PATCH")?,
        commit: pre_version,
    })
}

fn parse_describe() -> Result<VersionInfo, failure::Error> {
    // Run `git describe --long` and parse the output.
    // v0.1-49-g895818f

    let describe = Command::new("git").args(&["describe", "--long"]).output()?;

    let describe = String::from_utf8_lossy(&describe.stdout).into_owned();
    let version = VersionInfo::parse(describe)?;
    // Stolen from `vergen`:
    // https://github.com/rustyhorde/vergen/blob/master/src/output/envvar.rs
    let git_dir = PathBuf::from(".git");
    assert!(git_dir.is_dir(), ".git/ is directory");
    // Echo the HEAD path
    let git_head_path = git_dir.join("HEAD");
    println!("cargo:rerun-if-changed={}", git_head_path.display());

    // Determine where HEAD points and echo that path also.
    let mut f = File::open(&git_head_path).expect(".git/HEAD is valid");
    let mut git_head_contents = String::new();
    let _ = f
        .read_to_string(&mut git_head_contents)
        .expect("can read .git/HEAD");
    eprintln!("HEAD contents: {}", git_head_contents);
    let ref_vec: Vec<&str> = git_head_contents.split(": ").collect();
    if ref_vec.len() == 2 {
        let current_head_file = ref_vec[1];
        let git_refs_path = PathBuf::from(".git").join(current_head_file);
        println!("cargo:rerun-if-changed={}", git_refs_path.display());
    } else {
        eprintln!("You are most likely in a detached HEAD state");
    }
    Ok(version)
}

fn main() {
    let version = parse_describe()
        .or_else(|_| parse_cargo_toml())
        .unwrap_or(VersionInfo::default());

    println!("cargo:rustc-env=VERSION_MAJOR={}", version.major);
    println!("cargo:rustc-env=VERSION_MINOR={}", version.minor);
    println!("cargo:rustc-env=VERSION_PATCH={}", version.patch);
    println!("cargo:rustc-env=VERSION_COMMIT={}", version.commit);
    println!(
        "cargo:rustc-env=VERSION_DATE={}",
        Utc::now().format("%Y-%m-%d").to_string()
    );
}
