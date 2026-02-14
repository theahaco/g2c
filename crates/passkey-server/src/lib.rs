use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;

use passkey_core::challenge::Challenge;
use passkey_core::contract_id::validate_contract_id;
use passkey_core::rp;
use passkey_core::storage::InMemoryStore;
use passkey_core::webauthn::verify::VerifyRequest;

pub type AppState = Arc<InMemoryStore>;

#[derive(Serialize)]
struct ChallengeResponse {
    challenge: String,
    rp_id: String,
    challenge_id: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
}

#[derive(Deserialize)]
struct VerifyBody {
    challenge_id: String,
    #[serde(flatten)]
    request: VerifyRequest,
}

/// Build the Axum router with all passkey server routes.
pub fn build_router(store: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/auth/challenge/{contract_id}", post(create_challenge))
        .route("/auth/verify/{contract_id}", post(verify_handler))
        .layer(CorsLayer::permissive())
        .with_state(store)
}

async fn health() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

async fn create_challenge(
    State(store): State<AppState>,
    Path(contract_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = validate_contract_id(&contract_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        );
    }

    let challenge = Challenge::new(&contract_id);
    let key = challenge.storage_key();

    if let Err(e) = store.store(&key, &challenge) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        );
    }

    (
        StatusCode::OK,
        Json(serde_json::json!(ChallengeResponse {
            challenge: challenge.challenge,
            rp_id: rp::rp_id(&contract_id),
            challenge_id: challenge.challenge_id,
        })),
    )
}

async fn verify_handler(
    State(store): State<AppState>,
    Path(contract_id): Path<String>,
    Json(body): Json<VerifyBody>,
) -> impl IntoResponse {
    if let Err(e) = validate_contract_id(&contract_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        );
    }

    let key = format!("challenge:{}:{}", contract_id, body.challenge_id);

    // Retrieve and consume challenge (sync methods for Send compatibility)
    let challenge = match store.retrieve(&key) {
        Ok(Some(c)) => c,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "challenge not found or already used" })),
            );
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            );
        }
    };

    // Delete immediately (one-time use)
    let _ = store.delete(&key);

    // Check expiry
    if challenge.is_expired() {
        return (
            StatusCode::GONE,
            Json(serde_json::json!({ "error": "challenge expired" })),
        );
    }

    // Verify the assertion
    match passkey_core::webauthn::verify::verify_assertion(
        &contract_id,
        &challenge.challenge,
        &body.request,
    ) {
        Ok(result) => (StatusCode::OK, Json(serde_json::json!(result))),
        Err(e) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": e.to_string() })),
        ),
    }
}
