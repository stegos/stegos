use std::env;
use stegos_serialization::build_script;

// try find overrided location
fn find_location(lib: &str) -> Option<String> {
    env::var(format!("{}_LIB_DIR", lib.to_uppercase())).ok()
}

fn main() {
    issue_47048_fix::issue_47048_fix();
    // Compile the external code
    let mut conf = cc::Build::new();

    if cfg!(debug_assertions) {
        conf.define("DEBUG", None);
    }

    conf.cpp(true)
        .include("/usr/local/include/flint")
        .include("/usr/local/include")
        .flag_if_supported("-Wno-unused-parameter")
        .file("src/dicemix/solver_flint.cpp")
        .compile("libsolver_flint.a");
    if let Some(flint_path) = find_location("flint") {
        println!("cargo:rustc-link-search={}", flint_path);
    }
    // Tell rustc to link against flint and gmp
    println!("cargo:rustc-link-search=/usr/local/lib");
    println!("cargo:rustc-link-search=/usr/lib64");
    println!("cargo:rustc-link-search=/usr/lib/x86_64-linux-gnu");
    println!("cargo:rustc-link-search=/usr/lib");
    println!("cargo:rustc-link-lib=static=flint");
    println!("cargo:rustc-link-lib=static=gmp");
    println!("cargo:rustc-link-lib=static=mpfr");

    build_script::build_protobuf("protos", "protos", &[]);
}
