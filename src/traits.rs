use std::collections::{HashMap, HashSet};

use cedar_policy::{Context, Entity, EntityUid, RestrictedExpression};

use crate::error::PolicyError;

/// Anything that can become a Cedar‐typed atom, e.g. `User::"alice"`,
/// `Action::"foo"`, `Group::"devs"`.
pub trait CedarAtom {
    /// The Cedar typename (“User”, “Action”, “Group”, etc)
    fn cedar_type() -> &'static str;

    /// Build a Cedar parent list for this atom, default is no parents
    fn cedar_parents(&self) -> HashSet<EntityUid> {
        // Default: no parent type
        HashSet::new()
    }

    /// Build an entity for this Cedar atom, e.g. `User::"alice"` or `Host::"flappa.example.com"`
    fn cedar_entity(&self) -> Result<Entity, PolicyError> {
        let entity_uid = self.cedar_entity_uid()?;
        let attrs = self.cedar_attr()?;
        Ok(Entity::new(entity_uid, attrs, self.cedar_parents())?)
    }

    /// Build the attributes for this Cedar atom
    fn cedar_attr(&self) -> Result<HashMap<String, RestrictedExpression>, PolicyError> {
        let res: HashMap<String, RestrictedExpression> = HashMap::new();
        Ok(res)
    }

    /// Build an EntityUid for atomic principal / action / resource slots
    fn cedar_entity_uid(&self) -> Result<EntityUid, PolicyError> {
        self.cedar_id()
            .parse::<EntityUid>()
            .map_err(|e| PolicyError::ParseError(e.to_string()))
    }

    /// Build the context for this Cedar atom, empty by default
    fn cedar_ctx(&self) -> Result<Context, PolicyError> {
        Ok(Context::empty())
    }

    /// The ID string, fully qualified (e.g. User::"alice” or DNS::Action::"create_host”)
    fn cedar_id(&self) -> String;
}
