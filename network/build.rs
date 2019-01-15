use protobuf_codegen_pure::{Args, Customize};
use std::fs;

fn check_for_regen(src: &str, dst: &str) -> bool {
    let meta_src_result = fs::metadata(src);
    let meta_dst_result = fs::metadata(dst);
    match (meta_src_result, meta_dst_result) {
        (Err(_), _) => true,
        (_, Err(_)) => true,
        (Ok(meta_src), Ok(meta_dst)) => match (meta_src.modified(), meta_dst.modified()) {
            (Err(_), _) => true,
            (_, Err(_)) => true,
            (Ok(time_src), Ok(time_dst)) if time_src > time_dst => true,
            (Ok(_), Ok(_)) => false,
        },
    }
}

fn main() {
    if check_for_regen(
        "protos/heartbeat_proto.proto",
        "src/node/heartbeat/heartbeat_proto.rs",
    ) {
        protobuf_codegen_pure::run(Args {
            out_dir: &"src/node/heartbeat",
            input: &["protos/heartbeat_proto.proto"],
            includes: &["protos"],
            customize: Customize {
                ..Default::default()
            },
        })
        .expect("protoc");
    }

    if check_for_regen("protos/ncp.proto", "src/ncp/ncp.rs") {
        protobuf_codegen_pure::run(Args {
            out_dir: &"src/ncp",
            input: &["protos/ncp.proto"],
            includes: &["protos"],
            customize: Customize {
                ..Default::default()
            },
        })
        .expect("protoc");
    }

    if check_for_regen("protos/unicast.proto", "src/node/broker/unicast.rs") {
        protobuf_codegen_pure::run(Args {
            out_dir: &"src/node/broker",
            input: &["protos/unicast.proto"],
            includes: &["protos"],
            customize: Customize {
                ..Default::default()
            },
        })
        .expect("protoc");
    }
}
