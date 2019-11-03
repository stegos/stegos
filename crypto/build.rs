use std::env;
use stegos_serialization::build_script;

fn main() {
    #[cfg(feature = "flint")]
    {
        use std::path::PathBuf;
        issue_47048_fix::issue_47048_fix();
        // Compile the external code
        let mut conf = cc::Build::new();

        if cfg!(debug_assertions) {
            conf.define("DEBUG", None);
        }

        let gmp_mpfr_include_dir = PathBuf::from(var("DEP_GMP_INCLUDE_DIR"));
        let flint_include_dir = PathBuf::from(var("DEP_FLINT_INCLUDE_DIR"));
        let flint_include_dir2 = flint_include_dir.join("flint");
        conf.cpp(true)
            .include(flint_include_dir)
            .include(flint_include_dir2)
            .include(gmp_mpfr_include_dir)
            .flag_if_supported("-Wno-unused-parameter")
            .file("src/dicemix/solver_flint.cpp")
            .compile("libsolver_flint.a");
        println!("cargo:rustc-link-lib=static=gmp");
        println!("cargo:rustc-link-lib=static=mpfr");
        println!("cargo:rustc-link-lib=static=flint");
    }

    build_script::build_protobuf("protos", "protos", &[]);
}

fn var(name: &str) -> String {
    env::var(name)
        .map_err(|_e| format!("Missing {}", name))
        .unwrap()
}
