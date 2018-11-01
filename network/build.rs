extern crate protoc_rust;

use protoc_rust::Customize;

fn main() {
    protoc_rust::run(protoc_rust::Args {
        out_dir: "src/ncp",
        input: &["protos/ncp.proto"],
        includes: &["protos"],
        customize: Customize {
            ..Default::default()
        },
    }).expect("protoc");
}
