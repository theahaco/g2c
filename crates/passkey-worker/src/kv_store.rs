use async_trait::async_trait;
use worker::kv::KvStore;

use passkey_core::challenge::Challenge;
use passkey_core::error::Error;
use passkey_core::storage::ChallengeStore;

/// Workers KV-backed challenge store with built-in TTL.
pub struct WorkersKvStore {
    kv: KvStore,
}

impl WorkersKvStore {
    pub fn new(kv: KvStore) -> Self {
        Self { kv }
    }
}

#[async_trait(?Send)]
impl ChallengeStore for WorkersKvStore {
    async fn store_challenge(&self, key: &str, challenge: &Challenge) -> Result<(), Error> {
        let json = serde_json::to_string(challenge).map_err(|e| Error::Storage(e.to_string()))?;
        self.kv
            .put(key, json)
            .map_err(|e| Error::Storage(e.to_string()))?
            .expiration_ttl(300) // 5 minutes
            .execute()
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;
        Ok(())
    }

    async fn retrieve_challenge(&self, key: &str) -> Result<Option<Challenge>, Error> {
        let value = self
            .kv
            .get(key)
            .text()
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;

        match value {
            Some(json) => {
                let challenge: Challenge =
                    serde_json::from_str(&json).map_err(|e| Error::Storage(e.to_string()))?;
                Ok(Some(challenge))
            }
            None => Ok(None),
        }
    }

    async fn delete_challenge(&self, key: &str) -> Result<(), Error> {
        self.kv
            .delete(key)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;
        Ok(())
    }
}
