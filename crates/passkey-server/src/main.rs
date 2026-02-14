use std::sync::Arc;

use passkey_core::storage::InMemoryStore;
use passkey_server::{build_router, AppState};

#[tokio::main]
async fn main() {
    let store: AppState = Arc::new(InMemoryStore::new());
    let app = build_router(store);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8787").await.unwrap();
    println!("Passkey server listening on http://localhost:8787");
    axum::serve(listener, app).await.unwrap();
}
