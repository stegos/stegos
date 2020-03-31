//! WebSocket API - Server.

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
use super::api::{ApiHandler, RawRequest, RawResponse};
use failure::{bail, Error};
use log::debug;

pub struct Register {
    methods: Vec<Box<dyn ApiHandler>>,
}

impl Register {
    pub fn new() -> Self {
        Register { methods: vec![] }
    }

    pub fn add_api<A: ApiHandler + 'static>(&mut self, handler: A) {
        self.methods.push(Box::new(handler));
    }

    pub async fn try_process(
        &self,
        _method_type: &str,
        req: RawRequest,
    ) -> Result<RawResponse, Error> {
        for api in &self.methods {
            debug!("Trying to parse api request: api_name={}", api.name());
            match api.try_process(req.clone()).await {
                Ok(res) => return Ok(res),
                Err(e) => debug!("Error when parsing request: error={}", e),
            }
        }

        bail!("Failed to parse request, no api responsible for this request was found.");
    }
}
