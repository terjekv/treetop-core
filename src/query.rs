use std::collections::HashSet;

use cedar_policy::EntityUid;

use crate::error::PolicyError;
use crate::traits::CedarAtom;
use crate::types::{Action, Principal, Resource, group_entity_uid, user_entity_uid};

#[derive(Debug)]
pub(crate) struct PrincipalQuery {
    pub(crate) uid: EntityUid,
    pub(crate) type_name: String,
    pub(crate) parents: HashSet<EntityUid>,
}

impl PrincipalQuery {
    pub(crate) fn for_user(
        user: &str,
        groups: &[&str],
        namespace: &[&str],
    ) -> Result<Self, PolicyError> {
        let uid = user_entity_uid(user, namespace)?;

        let mut parents = HashSet::with_capacity(groups.len());
        for group in groups {
            parents.insert(group_entity_uid(group, namespace)?);
        }

        Ok(Self {
            type_name: entity_type_name_from_uid(&uid),
            uid,
            parents,
        })
    }

    pub(crate) fn for_group(group: &str, namespace: &[&str]) -> Result<Self, PolicyError> {
        let uid = group_entity_uid(group, namespace)?;
        let mut parents = HashSet::new();
        // Cedar `in` includes equality for entities.
        parents.insert(uid.clone());

        Ok(Self {
            type_name: entity_type_name_from_uid(&uid),
            uid,
            parents,
        })
    }

    pub(crate) fn from_principal(principal: &Principal) -> Result<Self, PolicyError> {
        let uid = principal.cedar_entity_uid()?;
        let type_name = entity_type_name_from_uid(&uid);

        let parents = match principal {
            Principal::User(user) => {
                let mut parents = HashSet::with_capacity(user.groups().len());
                for group in user.groups() {
                    parents.insert(group.cedar_entity_uid()?);
                }
                parents
            }
            Principal::Group(_) => {
                let mut parents = HashSet::new();
                // Cedar `in` includes equality for entities.
                parents.insert(uid.clone());
                parents
            }
        };

        Ok(Self {
            uid,
            type_name,
            parents,
        })
    }
}

#[derive(Debug)]
pub(crate) struct ResourceQuery {
    pub(crate) uid: EntityUid,
    pub(crate) type_name: String,
}

impl ResourceQuery {
    pub(crate) fn from_resource(resource: &Resource) -> Result<Self, PolicyError> {
        let uid = resource.cedar_entity_uid()?;
        Ok(Self {
            uid,
            type_name: resource.kind().to_string(),
        })
    }
}

#[derive(Debug)]
pub(crate) struct ActionQuery {
    pub(crate) uid: EntityUid,
}

impl ActionQuery {
    pub(crate) fn from_action(action: &Action) -> Result<Self, PolicyError> {
        Ok(Self {
            uid: action.cedar_entity_uid()?,
        })
    }
}

fn entity_type_name_from_uid(uid: &EntityUid) -> String {
    uid.type_name().to_string()
}
