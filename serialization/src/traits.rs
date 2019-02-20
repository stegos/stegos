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

//!
//! Protobuf converting trait.
//!

use failure::Error;
use protobuf::Message as ProtobufMessage;

///
/// `ProtoConvert` is a trait for converting protobuf structure into valid finite rust structure.
/// It will checks that protobuf object contain all needed fields.
/// Additionally it provide a methods to convert valid rust structure into protobuf object.
/// And separate methods to work with buffer.
///
pub trait ProtoConvert: Sized {
    type Proto: ProtobufMessage + Sized;
    /// Converts from rust structure to generated protobuf structure.
    fn into_proto(&self) -> Self::Proto;
    /// Converts from protobuf generated structure to rust structure.
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error>;

    /// Converts from buffer into rust structure.
    fn from_buffer(buffer: &[u8]) -> Result<Self, Error> {
        let proto: Self::Proto = protobuf::parse_from_bytes(buffer)?;
        Self::from_proto(&proto)
    }

    /// Converts rust structure to protobuf serialised buffer
    fn into_buffer(&self) -> Result<Vec<u8>, Error> {
        let proto = self.into_proto();
        let data = proto.write_to_bytes()?;
        Ok(data)
    }
}
