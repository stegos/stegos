//
// MIT License
//
// Copyright (c) 2018-2019 Stegos AG
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

use stegos_serialization::build_script;

fn main() {
    build_script::build_protobuf("protos/ncp_proto.proto", "ncp_proto", &[]);
    build_script::build_protobuf("protos/unicast_proto.proto", "unicast_proto", &[]);
    build_script::build_protobuf("protos/pubsub_proto.proto", "pubsub", &[]);
    build_script::build_protobuf("protos/gatekeeper_proto.proto", "gatekeeper_proto", &[]);
    build_script::build_protobuf("protos/delivery_proto.proto", "delivery_proto", &[]);
    build_script::build_protobuf("protos/dht.proto", "dht", &[]);
    build_script::build_protobuf("protos/gossipsub.proto", "gossipsub", &[]);
}
