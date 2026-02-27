use cedar_policy::{ActionConstraint, Effect, PrincipalConstraint, ResourceConstraint};

use crate::query::{ActionQuery, PrincipalQuery, ResourceQuery};
use crate::types::{PolicyEffectFilter, PolicyMatchReason};

pub(crate) fn principal_match_reason(
    constraint: PrincipalConstraint,
    principal: &PrincipalQuery,
) -> Option<PolicyMatchReason> {
    match constraint {
        PrincipalConstraint::Eq(uid) if uid == principal.uid => {
            Some(PolicyMatchReason::PrincipalEq)
        }
        PrincipalConstraint::In(uid)
            if uid == principal.uid || principal.parents.contains(&uid) =>
        {
            Some(PolicyMatchReason::PrincipalIn)
        }
        PrincipalConstraint::Any => Some(PolicyMatchReason::PrincipalAny),
        PrincipalConstraint::Is(entity_type) if entity_type.to_string() == principal.type_name => {
            Some(PolicyMatchReason::PrincipalIs)
        }
        PrincipalConstraint::IsIn(entity_type, parent)
            if entity_type.to_string() == principal.type_name
                && (parent == principal.uid || principal.parents.contains(&parent)) =>
        {
            Some(PolicyMatchReason::PrincipalIsIn)
        }
        _ => None,
    }
}

pub(crate) fn resource_match_reason(
    constraint: ResourceConstraint,
    resource: Option<&ResourceQuery>,
) -> Option<Option<PolicyMatchReason>> {
    let Some(resource) = resource else {
        return Some(None);
    };

    match constraint {
        ResourceConstraint::Eq(uid) if uid == resource.uid => {
            Some(Some(PolicyMatchReason::ResourceEq))
        }
        ResourceConstraint::In(uid) if uid == resource.uid => {
            Some(Some(PolicyMatchReason::ResourceIn))
        }
        ResourceConstraint::Any => Some(Some(PolicyMatchReason::ResourceAny)),
        ResourceConstraint::Is(entity_type) if entity_type.to_string() == resource.type_name => {
            Some(Some(PolicyMatchReason::ResourceIs))
        }
        ResourceConstraint::IsIn(entity_type, parent)
            if entity_type.to_string() == resource.type_name && parent == resource.uid =>
        {
            Some(Some(PolicyMatchReason::ResourceIsIn))
        }
        _ => None,
    }
}

pub(crate) fn action_match_reason(
    constraint: ActionConstraint,
    action: Option<&ActionQuery>,
) -> Option<Option<PolicyMatchReason>> {
    let Some(action) = action else {
        return Some(None);
    };

    match constraint {
        ActionConstraint::Eq(uid) if uid == action.uid => Some(Some(PolicyMatchReason::ActionEq)),
        ActionConstraint::In(uids) if uids.contains(&action.uid) => {
            Some(Some(PolicyMatchReason::ActionIn))
        }
        ActionConstraint::Any => Some(Some(PolicyMatchReason::ActionAny)),
        _ => None,
    }
}

pub(crate) fn matches_effect(effect: Effect, filter: PolicyEffectFilter) -> bool {
    match filter {
        PolicyEffectFilter::Any => true,
        PolicyEffectFilter::Permit => effect == Effect::Permit,
        PolicyEffectFilter::Forbid => effect == Effect::Forbid,
    }
}
