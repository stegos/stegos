use chrono::Utc;
use regex::Regex;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Run `git describe --long` and parse the output.
    // v0.1-49-g895818f
    let describe_re = Regex::new(
        r"v(?P<major>[0-9]+)\.(?P<minor>[0-9]+)-(?P<patch>[0-9]+)-g(?P<commit>[0-9a-f]+)$",
    )
    .expect("regex is valid");
    let describe = Command::new("git")
        .args(&["describe", "--long"])
        .output()
        .expect("git describe works");
    let describe = String::from_utf8_lossy(&describe.stdout).into_owned();
    let describe = describe_re
        .captures(describe.trim())
        .expect("git describe is valid");
    let major = describe.name("major").expect("major version").as_str();
    let minor = describe.name("minor").expect("minor version").as_str();
    let patch = describe.name("patch").expect("patch version").as_str();
    let commit = describe.name("commit").expect("commit version").as_str();
    println!("cargo:rustc-env=VERSION_MAJOR={}", major);
    println!("cargo:rustc-env=VERSION_MINOR={}", minor);
    println!("cargo:rustc-env=VERSION_PATCH={}", patch);
    println!("cargo:rustc-env=VERSION_COMMIT={}", commit);
    println!(
        "cargo:rustc-env=VERSION_DATE={}",
        Utc::now().format("%Y-%m-%d").to_string()
    );

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
}
