//
// Copyright (c) 2019 Stegos AG
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use protobuf_codegen_pure::Codegen;
use std::{
    env,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

fn create_protos_path_env(input_dir: &str) {
    let path = env::current_dir()
        .expect("Failed to get current dir.")
        .join(input_dir);

    println!("cargo:protos={}", path.to_str().unwrap());
}

fn get_includes(input_path: &str, libs: &[&str]) -> Vec<String> {
    let mut array = vec![input_path.to_string()];

    for lib in libs {
        let upper_lib = lib.to_uppercase();
        let lib_path = env::var(&format!("DEP_{}_PROTOS", upper_lib))
            .map_err(|e| {
                format!(
                    "Couldn't find lib {}, probably it didn't use stegos_\
                     serialization, or didn't set 'links' variable in Cargo.toml, error = {}",
                    lib, e
                )
            })
            .unwrap();
        array.push(lib_path);
    }
    array
}

fn get_protos(path: &str) -> Vec<PathBuf> {
    let path: &Path = path.as_ref();
    WalkDir::new(path)
        .into_iter()
        .filter_map(|e| {
            let e = e.ok()?;
            if e.path().extension()? == "proto" {
                Some(e.path().into())
            } else {
                None
            }
        })
        .collect()
}

fn generate_mod_rs(out_dir: &str, protos: &[PathBuf]) {
    let content = {
        protos
            .iter()
            .map(|proto| {
                let mod_name = proto
                    .file_stem()
                    .unwrap()
                    .to_str()
                    .expect(".proto file name is not convertible to &str");
                format!("pub mod {};\n", mod_name)
            })
            .collect::<String>()
    };

    let dest_path = PathBuf::from(out_dir).join("mod.rs");
    let mut file = File::create(dest_path).expect("Unable to create output file");
    file.write_all(content.as_bytes())
        .expect("Unable to write data to file");
}

pub fn build_protobuf(input_path: &str, out_prefix: &str, deps: &[&str]) {
    let out_dir =
        PathBuf::from(env::var("OUT_DIR").expect("Unable to get OUT_DIR")).join(out_prefix);

    let out_dir_str = out_dir.to_str().unwrap();

    let mut path: &Path = input_path.as_ref();
    let protos = if path.is_file() {
        let out = vec![path.into()];
        path = path.parent().unwrap();
        out
    } else {
        get_protos(input_path)
    };
    let includes = get_includes(path.to_str().unwrap(), deps);

    // Create folder for output rust modules.

    fs::create_dir_all(&out_dir).unwrap();

    // Create resulting mod.rs file.
    generate_mod_rs(out_dir_str, &protos);

    // Convert PathBufs into str.
    let protos_str = protos
        .iter()
        .map(|p| p.to_str())
        .collect::<Option<Vec<_>>>()
        .unwrap();

    let includes_str: Vec<_> = includes.iter().map(String::as_str).collect();
    // Execute protoc.
    Codegen::new()
        .out_dir(&out_dir_str)
        .includes(&includes_str)
        .inputs(&protos_str)
        .run()
        .expect("protoc");

    // Set cargo to rerun build.rs if proto files was changed.
    println!("cargo:rerun-if-changed={}", input_path);

    // Set enviroment variable for link with dependent crates.
    create_protos_path_env(path.to_str().unwrap());
}
