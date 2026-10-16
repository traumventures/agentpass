//! Calls to the daemon's JSON API.

use agentpass_protocol::{
    ApiError, EditOp, EditRequest, EditResult, FlowCompletion, FlowInfo, FlowResult, TOKEN_HEADER,
};
use gloo_net::http::{Request, Response};

async fn error_of(resp: Response) -> String {
    match resp.json::<ApiError>().await {
        Ok(e) => e.error,
        Err(_) => format!("agentpass returned HTTP {}", resp.status()),
    }
}

fn network(e: gloo_net::Error) -> String {
    format!("Could not reach the agentpass daemon ({e}). Is it still running?")
}

pub async fn flow_info(token: &str) -> Result<FlowInfo, String> {
    let resp = Request::get("/api/flow")
        .header(TOKEN_HEADER, token)
        .send()
        .await
        .map_err(network)?;
    if !resp.ok() {
        return Err(error_of(resp).await);
    }
    resp.json()
        .await
        .map_err(|e| format!("Unexpected response: {e}"))
}

pub async fn complete(token: &str, body: &FlowCompletion) -> Result<String, String> {
    let resp = Request::post("/api/flow/complete")
        .header(TOKEN_HEADER, token)
        .json(body)
        .map_err(|e| e.to_string())?
        .send()
        .await
        .map_err(network)?;
    if !resp.ok() {
        return Err(error_of(resp).await);
    }
    let result: FlowResult = resp
        .json()
        .await
        .map_err(|e| format!("Unexpected response: {e}"))?;
    Ok(result.message)
}

pub async fn edit(token: &str, ops: Vec<EditOp>) -> Result<EditResult, String> {
    let resp = Request::post("/api/edit")
        .header(TOKEN_HEADER, token)
        .json(&EditRequest { ops })
        .map_err(|e| e.to_string())?
        .send()
        .await
        .map_err(network)?;
    if !resp.ok() {
        return Err(error_of(resp).await);
    }
    resp.json()
        .await
        .map_err(|e| format!("Unexpected response: {e}"))
}
