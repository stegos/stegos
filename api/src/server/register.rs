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
use futures::stream::SelectAll;
use futures::Stream;
use log::{debug, trace};
use std::collections::HashSet;

pub struct Register {
    methods: Vec<Box<dyn ApiHandler>>,
    registred_notifications: HashSet<String>,
    pub notifications: SelectAll<Box<dyn Stream<Item = RawResponse> + Unpin + Send>>,
}

impl Register {
    pub fn new() -> Self {
        Register {
            methods: Vec::new(),
            registred_notifications: HashSet::new(),
            notifications: SelectAll::new(),
        }
    }

    pub fn add_api(&mut self, handler: Box<dyn ApiHandler>) {
        for notification in handler.register_notification() {
            let _ignore_dublicates = self.registred_notifications.insert(notification);
        }
        self.methods.push(handler);
    }

    pub async fn try_process(
        &mut self,
        _method_type: &str,
        req: RawRequest,
    ) -> Result<RawResponse, Error> {
        let notification = req.is_subscribe(&self.registred_notifications);

        for api in &self.methods {
            debug!("Trying to parse api request: api_name={}", api.name());

            match api
                .try_process(req.clone(), &mut self.notifications, notification)
                .await
            {
                Ok(response) => {
                    return Ok(response);
                }
                Err(e) => trace!("Error when parsing request: error={}", e),
            }
        }

        bail!("Failed to parse request, no api responsible for this request was found.");
    }
}
