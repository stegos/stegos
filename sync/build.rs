use stegos_serialization::build_script;

fn main() {
    build_script::build_protobuf("protos", "protos", &["stegos_crypto", "stegos_blockchain"])
}
