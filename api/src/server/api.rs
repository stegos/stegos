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
use failure::{bail, Error};

use async_trait::async_trait;

use serde::{de::DeserializeOwned, Serialize};
use serde_json;
use stegos_node::{ChainNotification, Node, NodeRequest, NodeResponse, StatusNotification};

use crate::{Request, RequestKind, ResponseKind};
use std::convert::{TryFrom, TryInto};

#[derive(Clone)]
pub struct RawRequest(pub Request);

impl TryFrom<RawRequest> for NodeRequest {
    type Error = Error;
    fn try_from(request: RawRequest) -> Result<NodeRequest, Self::Error> {
        match request.0.kind {
            RequestKind::NodeRequest(req) => Ok(req),
            _ => bail!("Cannot parse request as node request."),
        }
    }
}

pub struct RawResponse(pub ResponseKind);

impl From<NodeResponse> for RawResponse {
    fn from(response: NodeResponse) -> RawResponse {
        RawResponse(ResponseKind::NodeResponse(response))
    }
}

// Todo: Later replace our requests with json-rpc core, and remove register/apihandler.
#[async_trait]
pub trait ApiHandler: Sync + Send {
    fn name(&self) -> String {
        std::any::type_name::<Self>().to_owned()
    }

    async fn try_process(&self, req: RawRequest) -> Result<RawResponse, Error>;
}

#[async_trait]
impl<T: ApiHandler + Sync> ApiHandler for Option<T> {
    fn name(&self) -> String {
        let val = if self.is_some() { "" } else { "::None" };
        format!("Option<{}>{}", std::any::type_name::<T>(), val)
    }

    async fn try_process(&self, req: RawRequest) -> Result<RawResponse, Error> {
        if let Some(val) = self {
            val.try_process(req).await
        } else {
            bail!("Api not inited.")
        }
    }
}

// Our api implementors.

#[async_trait]
impl ApiHandler for Node {
    async fn try_process(&self, req: RawRequest) -> Result<RawResponse, Error> {
        let request: NodeRequest = req.try_into()?;
        let response = self.request(request).await?;
        Ok(response.into())
    }
}
