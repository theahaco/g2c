use serde::Serialize;
use worker::{Request, Response, RouteContext};

use passkey_core::challenge::Challenge;
use passkey_core::contract_id::validate_contract_id;
use passkey_core::rp;
use passkey_core::storage::ChallengeStore;
use passkey_core::webauthn::verify::VerifyRequest;

use crate::kv_store::WorkersKvStore;

const KV_NAMESPACE: &str = "CHALLENGES";

#[derive(Serialize)]
struct ChallengeResponse {
    challenge: String,
    rp_id: String,
    challenge_id: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
}

fn json_response<T: Serialize>(body: &T, status: u16) -> worker::Result<Response> {
    let json = serde_json::to_string(body).map_err(|e| worker::Error::RustError(e.to_string()))?;
    let mut response = Response::ok(json)?;
    response
        .headers_mut()
        .set("Content-Type", "application/json")?;
    if status == 200 {
        Ok(response)
    } else {
        Ok(response.with_status(status))
    }
}

fn error_response(message: &str, status: u16) -> worker::Result<Response> {
    json_response(
        &ErrorResponse {
            error: message.to_string(),
        },
        status,
    )
}

fn get_kv_store(ctx: &RouteContext<()>) -> worker::Result<WorkersKvStore> {
    let kv = ctx.kv(KV_NAMESPACE)?;
    Ok(WorkersKvStore::new(kv))
}

pub fn health(_req: Request, _ctx: RouteContext<()>) -> worker::Result<Response> {
    json_response(
        &HealthResponse {
            status: "ok".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        200,
    )
}

pub async fn create_challenge(_req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let contract_id = match ctx.param("contract_id") {
        Some(id) => id.to_string(),
        None => return error_response("missing contract_id", 400),
    };

    if let Err(e) = validate_contract_id(&contract_id) {
        return error_response(&e.to_string(), 400);
    }

    let store = get_kv_store(&ctx)?;
    let challenge = Challenge::new(&contract_id);
    let key = challenge.storage_key();

    store
        .store_challenge(&key, &challenge)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    json_response(
        &ChallengeResponse {
            challenge: challenge.challenge,
            rp_id: rp::rp_id(&contract_id),
            challenge_id: challenge.challenge_id,
        },
        200,
    )
}

pub async fn verify(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    #[derive(serde::Deserialize)]
    struct VerifyBody {
        challenge_id: String,
        #[serde(flatten)]
        request: VerifyRequest,
    }

    let contract_id = match ctx.param("contract_id") {
        Some(id) => id.to_string(),
        None => return error_response("missing contract_id", 400),
    };

    if let Err(e) = validate_contract_id(&contract_id) {
        return error_response(&e.to_string(), 400);
    }

    // Parse request body
    let body: VerifyBody = match req.json().await {
        Ok(b) => b,
        Err(e) => return error_response(&format!("invalid request body: {e}"), 400),
    };

    let store = get_kv_store(&ctx)?;
    let key = format!("challenge:{}:{}", contract_id, body.challenge_id);

    // Retrieve and consume challenge (one-time use)
    let Some(challenge) = store
        .retrieve_challenge(&key)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?
    else {
        return error_response("challenge not found or already used", 404);
    };

    // Delete immediately (one-time use)
    store
        .delete_challenge(&key)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    // Check expiry (belt-and-suspenders with KV TTL)
    if challenge.is_expired() {
        return error_response("challenge expired", 410);
    }

    // Verify the assertion
    match passkey_core::webauthn::verify::verify_assertion(
        &contract_id,
        &challenge.challenge,
        &body.request,
    ) {
        Ok(result) => json_response(&result, 200),
        Err(e) => error_response(&e.to_string(), 401),
    }
}
