use stegos_serialization::build_script;

fn main() {
    // Compile the external code
    let mut conf = cc::Build::new();

    if cfg!(debug_assertions) {
        conf.define("DEBUG", None);
    }

    conf.cpp(true)
        .include("/usr/local/include/flint")
        .file("src/dicemix/solver_flint.cpp")
        .compile("libsolver_flint.a");

    // Tell rustc to link against flint and gmp
    println!("cargo:rustc-link-lib=flint");
    println!("cargo:rustc-link-lib=gmp");
    println!("cargo:rustc-link-lib=mpfr");
    build_script::build_protobuf("protos", "protos", &[]);
}
