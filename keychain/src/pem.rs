//
// Copyright (c) 2016-2017 Jonathan Creekmore
// Copyright (c) 2018 Stegos AG
//
// Based on https://github.com/jcreekmore/pem-rs
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

//! This crate provides a parser and encoder for PEM-encoded binary data.
//! PEM-encoded binary data is essentially a beginning and matching end
//! tag that encloses base64-encoded binary data (see:
//! https://en.wikipedia.org/wiki/Privacy-enhanced_Electronic_Mail).
//!

#![deny(
    missing_docs,
    missing_debug_implementations,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unstable_features,
    unused_import_braces,
    unused_qualifications
)]

use failure::Fail;
use lazy_static::lazy_static;
use regex::bytes::{Captures, Regex};

/// Erros caused by PEM decoder
#[derive(Debug, Fail)]
pub enum ErrorKind {
    /// Non-UTF8 input
    #[fail(display = "Invalid UTF-8 sequence: {}", _0)]
    NotUtf8(std::str::Utf8Error),
    /// Mising PEM framing
    #[fail(display = "Missing framing")]
    MalformedFraming,
    /// Missing BEGIN tag
    #[fail(display = "Missing BEGIN tag")]
    MissingBeginTag,
    /// Missing END tag
    #[fail(display = "Missing END tag")]
    MissingEndTag,
    /// No data
    #[fail(display = "Missing DATA")]
    MissingData,
    /// Error base64-decoding data
    #[fail(display = "Invalid DATA: {}", _0)]
    InvalidData(base64::DecodeError),
    /// BEGIN/END tags mismatch
    #[fail(display = "mismatching BEGIN:{} and END:{} tags.", _0, _1)]
    MismatchedTags(String, String),
}

const REGEX_STR: &'static str =
    r"(?s)-----BEGIN (?P<begin>.*?)-----\s*(?P<data>.*?)-----END (?P<end>.*?)-----\s*";

lazy_static! {
    static ref ASCII_ARMOR: Regex = Regex::new(REGEX_STR).unwrap();
}

/// A representation of Pem-encoded data
#[derive(PartialEq, Debug)]
pub struct Pem {
    /// The tag extracted from the Pem-encoded data
    pub tag: String,
    /// The binary contents of the Pem-encoded data
    pub contents: Vec<u8>,
}

impl Pem {
    fn new_from_captures(caps: Captures<'_>) -> Result<Pem, ErrorKind> {
        fn as_utf8<'a>(bytes: &'a [u8]) -> Result<&'a str, ErrorKind> {
            std::str::from_utf8(bytes).map_err(|e| ErrorKind::NotUtf8(e).into())
        }

        // Verify that the begin section exists
        let tag = as_utf8(
            caps.name("begin")
                .ok_or_else(|| ErrorKind::MissingBeginTag)?
                .as_bytes(),
        )?;
        if tag.is_empty() {
            return Err(ErrorKind::MissingBeginTag.into());
        }

        // as well as the end section
        let tag_end = as_utf8(
            caps.name("end")
                .ok_or_else(|| ErrorKind::MissingEndTag)?
                .as_bytes(),
        )?;
        if tag_end.is_empty() {
            return Err(ErrorKind::MissingEndTag.into());
        }

        // The beginning and the end sections must match
        if tag != tag_end {
            return Err(ErrorKind::MismatchedTags(tag.into(), tag_end.into()).into());
        }

        // If they did, then we can grab the data section
        let data = as_utf8(
            caps.name("data")
                .ok_or_else(|| ErrorKind::MissingData)?
                .as_bytes(),
        )?;

        // And decode it from Base64 into a vector of u8
        let contents =
            base64::decode_config(&data, base64::MIME).map_err(ErrorKind::InvalidData)?;

        Ok(Pem {
            tag: tag.to_owned(),
            contents,
        })
    }
}

/// Parses a single PEM-encoded data from a data-type that can be dereferenced as a [u8].
///
/// # Example: parse PEM-encoded data from a Vec<u8>
///
/// const SAMPLE: &'static str = "-----BEGIN RSA PRIVATE KEY-----
/// MIIBPQIBAAJBAOsfi5AGYhdRs/x6q5H7kScxA0Kzzqe6WI6gf6+tc6IvKQJo5rQc
/// dWWSQ0nRGt2hOPDO+35NKhQEjBQxPh/v7n0CAwEAAQJBAOGaBAyuw0ICyENy5NsO
/// 2gkT00AWTSzM9Zns0HedY31yEabkuFvrMCHjscEF7u3Y6PB7An3IzooBHchsFDei
/// AAECIQD/JahddzR5K3A6rzTidmAf1PBtqi7296EnWv8WvpfAAQIhAOvowIXZI4Un
/// DXjgZ9ekuUjZN+GUQRAVlkEEohGLVy59AiEA90VtqDdQuWWpvJX0cM08V10tLXrT
/// TTGsEtITid1ogAECIQDAaFl90ZgS5cMrL3wCeatVKzVUmuJmB/VAmlLFFGzK0QIh
/// ANJGc7AFk4fyFD/OezhwGHbWmo/S+bfeAiIh2Ss2FxKJ
/// -----END RSA PRIVATE KEY-----
/// ";
/// let SAMPLE_BYTES: Vec<u8> = SAMPLE.into();
///
///  let pem = parse(SAMPLE_BYTES).unwrap();
///  assert_eq!(pem.tag, "RSA PRIVATE KEY");
///
/// # Example: parse PEM-encoded data from a String
///
/// use pem::parse;
///
/// const SAMPLE: &'static str = "-----BEGIN RSA PRIVATE KEY-----
/// MIIBPQIBAAJBAOsfi5AGYhdRs/x6q5H7kScxA0Kzzqe6WI6gf6+tc6IvKQJo5rQc
/// dWWSQ0nRGt2hOPDO+35NKhQEjBQxPh/v7n0CAwEAAQJBAOGaBAyuw0ICyENy5NsO
/// 2gkT00AWTSzM9Zns0HedY31yEabkuFvrMCHjscEF7u3Y6PB7An3IzooBHchsFDei
/// AAECIQD/JahddzR5K3A6rzTidmAf1PBtqi7296EnWv8WvpfAAQIhAOvowIXZI4Un
/// DXjgZ9ekuUjZN+GUQRAVlkEEohGLVy59AiEA90VtqDdQuWWpvJX0cM08V10tLXrT
/// TTGsEtITid1ogAECIQDAaFl90ZgS5cMrL3wCeatVKzVUmuJmB/VAmlLFFGzK0QIh
/// ANJGc7AFk4fyFD/OezhwGHbWmo/S+bfeAiIh2Ss2FxKJ
/// -----END RSA PRIVATE KEY-----
/// ";
/// let SAMPLE_STRING: String = SAMPLE.into();
///
///  let pem = parse(SAMPLE_STRING).unwrap();
///  assert_eq!(pem.tag, "RSA PRIVATE KEY");
///
pub fn parse<B: AsRef<[u8]>>(input: B) -> Result<Pem, ErrorKind> {
    ASCII_ARMOR
        .captures(&input.as_ref())
        .ok_or_else(|| ErrorKind::MalformedFraming)
        .and_then(Pem::new_from_captures)
}

/// Encode a PEM struct into a PEM-encoded data string
///
/// # Example
///
///  let pem = Pem {
///     tag: String::from("FOO"),
///     contents: vec![1, 2, 3, 4],
///   };
///   encode(&pem);
///
pub fn encode(pem: &Pem) -> String {
    let mut output = String::new();

    let contents;

    if pem.contents.is_empty() {
        contents = String::from("");
    } else {
        contents = base64::encode_config(
            &pem.contents,
            base64::Config::new(
                base64::CharacterSet::Standard,
                true,
                true,
                base64::LineWrap::Wrap(64, base64::LineEnding::LF),
            ),
        );
    }

    output.push_str(&format!("-----BEGIN {}-----\n", pem.tag));
    output.push_str(&format!("{}\n", contents));
    output.push_str(&format!("-----END {}-----\n", pem.tag));

    output
}

#[cfg(test)]
mod test {
    use super::*;

    const SAMPLE: &'static str = "-----BEGIN RSA PRIVATE KEY-----\r
MIIBPQIBAAJBAOsfi5AGYhdRs/x6q5H7kScxA0Kzzqe6WI6gf6+tc6IvKQJo5rQc\r
dWWSQ0nRGt2hOPDO+35NKhQEjBQxPh/v7n0CAwEAAQJBAOGaBAyuw0ICyENy5NsO\r
2gkT00AWTSzM9Zns0HedY31yEabkuFvrMCHjscEF7u3Y6PB7An3IzooBHchsFDei\r
AAECIQD/JahddzR5K3A6rzTidmAf1PBtqi7296EnWv8WvpfAAQIhAOvowIXZI4Un\r
DXjgZ9ekuUjZN+GUQRAVlkEEohGLVy59AiEA90VtqDdQuWWpvJX0cM08V10tLXrT\r
TTGsEtITid1ogAECIQDAaFl90ZgS5cMrL3wCeatVKzVUmuJmB/VAmlLFFGzK0QIh\r
ANJGc7AFk4fyFD/OezhwGHbWmo/S+bfeAiIh2Ss2FxKJ\r
-----END RSA PRIVATE KEY-----\r
\r
-----BEGIN RSA PUBLIC KEY-----\r
MIIBOgIBAAJBAMIeCnn9G/7g2Z6J+qHOE2XCLLuPoh5NHTO2Fm+PbzBvafBo0oYo\r
QVVy7frzxmOqx6iIZBxTyfAQqBPO3Br59BMCAwEAAQJAX+PjHPuxdqiwF6blTkS0\r
RFI1MrnzRbCmOkM6tgVO0cd6r5Z4bDGLusH9yjI9iI84gPRjK0AzymXFmBGuREHI\r
sQIhAPKf4pp+Prvutgq2ayygleZChBr1DC4XnnufBNtaswyvAiEAzNGVKgNvzuhk\r
ijoUXIDruJQEGFGvZTsi1D2RehXiT90CIQC4HOQUYKCydB7oWi1SHDokFW2yFyo6\r
/+lf3fgNjPI6OQIgUPmTFXciXxT1msh3gFLf3qt2Kv8wbr9Ad9SXjULVpGkCIB+g\r
RzHX0lkJl9Stshd/7Gbt65/QYq+v+xvAeT0CoyIg\r
-----END RSA PUBLIC KEY-----\r
";

    #[test]
    fn test_parse_works() {
        let pem = parse(SAMPLE).unwrap();
        assert_eq!(pem.tag, "RSA PRIVATE KEY");
    }

    #[test]
    fn test_parse_invalid_framing() {
        let input = "--BEGIN data-----
        -----END data-----";
        match parse(&input) {
            Err(ErrorKind::MalformedFraming) => assert!(true),
            _ => assert!(false),
        }
    }

    #[test]
    fn test_parse_invalid_begin() {
        let input = "-----BEGIN -----
MIIBOgIBAAJBAMIeCnn9G/7g2Z6J+qHOE2XCLLuPoh5NHTO2Fm+PbzBvafBo0oYo
QVVy7frzxmOqx6iIZBxTyfAQqBPO3Br59BMCAwEAAQJAX+PjHPuxdqiwF6blTkS0
RFI1MrnzRbCmOkM6tgVO0cd6r5Z4bDGLusH9yjI9iI84gPRjK0AzymXFmBGuREHI
sQIhAPKf4pp+Prvutgq2ayygleZChBr1DC4XnnufBNtaswyvAiEAzNGVKgNvzuhk
ijoUXIDruJQEGFGvZTsi1D2RehXiT90CIQC4HOQUYKCydB7oWi1SHDokFW2yFyo6
/+lf3fgNjPI6OQIgUPmTFXciXxT1msh3gFLf3qt2Kv8wbr9Ad9SXjULVpGkCIB+g
RzHX0lkJl9Stshd/7Gbt65/QYq+v+xvAeT0CoyIg
-----END RSA PUBLIC KEY-----";
        match parse(&input) {
            Err(ErrorKind::MissingBeginTag) => assert!(true),
            _ => assert!(false),
        }
    }

    #[test]
    fn test_parse_invalid_end() {
        let input = "-----BEGIN DATA-----
MIIBOgIBAAJBAMIeCnn9G/7g2Z6J+qHOE2XCLLuPoh5NHTO2Fm+PbzBvafBo0oYo
QVVy7frzxmOqx6iIZBxTyfAQqBPO3Br59BMCAwEAAQJAX+PjHPuxdqiwF6blTkS0
RFI1MrnzRbCmOkM6tgVO0cd6r5Z4bDGLusH9yjI9iI84gPRjK0AzymXFmBGuREHI
sQIhAPKf4pp+Prvutgq2ayygleZChBr1DC4XnnufBNtaswyvAiEAzNGVKgNvzuhk
ijoUXIDruJQEGFGvZTsi1D2RehXiT90CIQC4HOQUYKCydB7oWi1SHDokFW2yFyo6
/+lf3fgNjPI6OQIgUPmTFXciXxT1msh3gFLf3qt2Kv8wbr9Ad9SXjULVpGkCIB+g
RzHX0lkJl9Stshd/7Gbt65/QYq+v+xvAeT0CoyIg
-----END -----";
        match parse(&input) {
            Err(ErrorKind::MissingEndTag) => assert!(true),
            _ => assert!(false),
        }
    }

    #[test]
    fn test_parse_invalid_data() {
        let input = "-----BEGIN DATA-----
MIIBOgIBAAJBAMIeCnn9G/7g2Z6J+qHOE2XCLLuPoh5NHTO2Fm+PbzBvafBo0oY?
QVVy7frzxmOqx6iIZBxTyfAQqBPO3Br59BMCAwEAAQJAX+PjHPuxdqiwF6blTkS0
RFI1MrnzRbCmOkM6tgVO0cd6r5Z4bDGLusH9yjI9iI84gPRjK0AzymXFmBGuREHI
sQIhAPKf4pp+Prvutgq2ayygleZChBr1DC4XnnufBNtaswyvAiEAzNGVKgNvzuhk
ijoUXIDruJQEGFGvZTsi1D2RehXiT90CIQC4HOQUYKCydB7oWi1SHDokFW2yFyo6
/+lf3fgNjPI6OQIgUPmTFXciXxT1msh3gFLf3qt2Kv8wbr9Ad9SXjULVpGkCIB+g
RzHX0lkJl9Stshd/7Gbt65/QYq+v+xvAeT0CoyIg
-----END DATA-----";
        match parse(&input) {
            Err(ErrorKind::InvalidData(_)) => assert!(true),
            _ => assert!(false),
        }
    }

    #[test]
    fn test_parse_empty_data() {
        let input = "-----BEGIN DATA-----
-----END DATA-----";
        let pem = parse(&input).unwrap();
        assert_eq!(pem.contents.len(), 0);
    }

    #[test]
    fn test_encode_empty_contents() {
        let pem = Pem {
            tag: String::from("FOO"),
            contents: vec![],
        };
        let encoded = encode(&pem);
        assert!(encoded != "");

        let pem_out = parse(&encoded).unwrap();
        assert_eq!(&pem, &pem_out);
    }

    #[test]
    fn test_encode_contents() {
        let pem = Pem {
            tag: String::from("FOO"),
            contents: vec![1, 2, 3, 4],
        };
        let encoded = encode(&pem);
        assert!(encoded != "");

        let pem_out = parse(&encoded).unwrap();
        assert_eq!(&pem, &pem_out);
    }
}
