use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::hash::{Hash, Hasher};
use std::sync::OnceLock;

use cedar_policy::EntityUid;

use crate::error::PolicyError;

/// Lazily caches the validated Cedar identity for immutable identity fields.
///
/// The cache is deliberately excluded from equality and hashing: whether a UID
/// has already been requested is an implementation detail, not part of the
/// value represented by the containing public type.
#[derive(Default)]
pub(super) struct EntityUidCache(OnceLock<EntityUid>);

impl EntityUidCache {
    pub(super) fn get_or_build(
        &self,
        build: impl FnOnce() -> Result<EntityUid, PolicyError>,
    ) -> Result<EntityUid, PolicyError> {
        if let Some(uid) = self.0.get() {
            return Ok(uid.clone());
        }

        let uid = build()?;
        if self.0.set(uid.clone()).is_ok() {
            return Ok(uid);
        }

        // Another thread populated the cache while this thread validated the
        // same immutable fields.
        Ok(self
            .0
            .get()
            .expect("OnceLock must contain a value after a failed set")
            .clone())
    }
}

impl Clone for EntityUidCache {
    fn clone(&self) -> Self {
        let cloned = Self::default();
        if let Some(uid) = self.0.get() {
            let _ = cloned.0.set(uid.clone());
        }
        cloned
    }
}

impl Debug for EntityUidCache {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("EntityUidCache")
    }
}

impl PartialEq for EntityUidCache {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for EntityUidCache {}

impl Hash for EntityUidCache {
    fn hash<H: Hasher>(&self, _state: &mut H) {}
}
