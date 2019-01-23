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
    if check_for_regen("protos/ncp_proto.proto", "src/ncp/ncp_proto.rs") {
        protobuf_codegen_pure::run(Args {
            out_dir: &"src/ncp/",
            input: &["protos/ncp_proto.proto"],
            includes: &["protos"],
            customize: Customize {
                ..Default::default()
            },
        })
        .expect("protoc");
    }

    if check_for_regen(
        "protos/unicast_proto.proto",
        "src/libp2p_network/unicast_proto.rs",
    ) {
        protobuf_codegen_pure::run(Args {
            out_dir: &"src/libp2p_network/",
            input: &["protos/unicast_proto.proto"],
            includes: &["protos"],
            customize: Customize {
                ..Default::default()
            },
        })
        .expect("protoc");
    }
}
