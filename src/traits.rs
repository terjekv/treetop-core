use std::collections::HashMap;

use cedar_policy::{EntityUid, RestrictedExpression};

use crate::error::PolicyError;

/// Anything that can become a Cedar‐typed atom, e.g. `User::"alice"`,
/// `Action::"foo"`, `Group::"devs"`.
///
/// Types implementing this trait can produce their Cedar identity (`cedar_id`)
/// and attributes for internal request preparation.
pub(crate) trait CedarAtom {
    /// The Cedar typename (“User”, “Action”, “Group”, etc)
    fn cedar_type() -> &'static str;

    /// Build the attributes for this Cedar atom.
    fn cedar_attr(&self) -> Result<HashMap<String, RestrictedExpression>, PolicyError> {
        let res: HashMap<String, RestrictedExpression> = HashMap::new();
        Ok(res)
    }

    /// Build an EntityUid for atomic principal / action / resource slots.
    fn cedar_entity_uid(&self) -> Result<EntityUid, PolicyError> {
        self.cedar_id()
            .parse::<EntityUid>()
            .map_err(|e| PolicyError::ParseError(e.to_string()))
    }

    /// The ID string, fully qualified (e.g. `User::"alice"` or `DNS::Action::"create_host"`).
    fn cedar_id(&self) -> String;
}
