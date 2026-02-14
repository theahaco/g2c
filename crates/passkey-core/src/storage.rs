use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::challenge::Challenge;
use crate::error::Error;

/// Trait for storing and retrieving WebAuthn challenges.
///
/// Uses `?Send` bound for wasm compatibility (single-threaded executor).
#[async_trait(?Send)]
pub trait ChallengeStore {
    /// Store a challenge with the given key.
    async fn store_challenge(&self, key: &str, challenge: &Challenge) -> Result<(), Error>;

    /// Retrieve a challenge by key, returning None if not found.
    async fn retrieve_challenge(&self, key: &str) -> Result<Option<Challenge>, Error>;

    /// Delete a challenge by key (for one-time use consumption).
    async fn delete_challenge(&self, key: &str) -> Result<(), Error>;
}

/// In-memory challenge store for testing and local development.
pub struct InMemoryStore {
    data: Mutex<HashMap<String, String>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            data: Mutex::new(HashMap::new()),
        }
    }

    /// Synchronous store — usable from Send contexts (e.g. Axum).
    pub fn store(&self, key: &str, challenge: &Challenge) -> Result<(), Error> {
        let json = serde_json::to_string(challenge).map_err(|e| Error::Storage(e.to_string()))?;
        self.data
            .lock()
            .map_err(|e| Error::Storage(e.to_string()))?
            .insert(key.to_string(), json);
        Ok(())
    }

    /// Synchronous retrieve.
    pub fn retrieve(&self, key: &str) -> Result<Option<Challenge>, Error> {
        let guard = self
            .data
            .lock()
            .map_err(|e| Error::Storage(e.to_string()))?;
        match guard.get(key) {
            Some(json) => {
                let challenge: Challenge =
                    serde_json::from_str(json).map_err(|e| Error::Storage(e.to_string()))?;
                Ok(Some(challenge))
            }
            None => Ok(None),
        }
    }

    /// Synchronous delete.
    pub fn delete(&self, key: &str) -> Result<(), Error> {
        self.data
            .lock()
            .map_err(|e| Error::Storage(e.to_string()))?
            .remove(key);
        Ok(())
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait(?Send)]
impl ChallengeStore for InMemoryStore {
    async fn store_challenge(&self, key: &str, challenge: &Challenge) -> Result<(), Error> {
        self.store(key, challenge)
    }

    async fn retrieve_challenge(&self, key: &str) -> Result<Option<Challenge>, Error> {
        self.retrieve(key)
    }

    async fn delete_challenge(&self, key: &str) -> Result<(), Error> {
        self.delete(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn store_and_retrieve() {
        let store = InMemoryStore::new();
        let challenge = Challenge::new("CABC123");
        let key = challenge.storage_key();

        store.store_challenge(&key, &challenge).await.unwrap();

        let retrieved = store.retrieve_challenge(&key).await.unwrap().unwrap();
        assert_eq!(retrieved.challenge, challenge.challenge);
        assert_eq!(retrieved.contract_id, challenge.contract_id);
    }

    #[tokio::test]
    async fn retrieve_nonexistent_returns_none() {
        let store = InMemoryStore::new();
        let result = store.retrieve_challenge("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn delete_removes_challenge() {
        let store = InMemoryStore::new();
        let challenge = Challenge::new("CABC123");
        let key = challenge.storage_key();

        store.store_challenge(&key, &challenge).await.unwrap();
        store.delete_challenge(&key).await.unwrap();

        let result = store.retrieve_challenge(&key).await.unwrap();
        assert!(result.is_none());
    }
}
