use cedar_policy::{
    ContextCreationError, EntityAttrEvaluationError, ParseErrors, RequestValidationError,
};
use cedar_policy_core::entities::err::EntitiesError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, Serialize, Deserialize)]
pub enum PolicyError {
    #[error("failed to lock policy set for read/write: {0}")]
    LockError(String),

    #[error("failed to parse policy: {0}")]
    ParseError(String),

    #[error("evaluation error: {0}")]
    EvalError(String),

    #[error("request validation error: {0}")]
    RequestValidationError(String),

    #[error("Context creation error: {0}")]
    ContextError(String),

    #[error("Entity error: {0}")]
    EntityError(String),

    #[error("Poisoned lock error: {0}")]
    PoisonedLockError(String),

    #[error("QualifiedId error: {0}")]
    QualifiedIdError(String),

    #[error("Invalid format: {0}")]
    InvalidFormat(String),
}

impl From<RequestValidationError> for PolicyError {
    fn from(err: cedar_policy::RequestValidationError) -> Self {
        PolicyError::EvalError(err.to_string())
    }
}

impl From<ParseErrors> for PolicyError {
    fn from(err: ParseErrors) -> Self {
        PolicyError::ParseError(err.to_string())
    }
}

impl From<ContextCreationError> for PolicyError {
    fn from(err: ContextCreationError) -> Self {
        PolicyError::ContextError(err.to_string())
    }
}

impl From<EntityAttrEvaluationError> for PolicyError {
    fn from(err: EntityAttrEvaluationError) -> Self {
        PolicyError::EvalError(err.to_string())
    }
}

impl From<EntitiesError> for PolicyError {
    fn from(err: EntitiesError) -> Self {
        PolicyError::EntityError(err.to_string())
    }
}

impl From<std::sync::PoisonError<std::sync::RwLockReadGuard<'_, cedar_policy::PolicySet>>>
    for PolicyError
{
    fn from(
        err: std::sync::PoisonError<std::sync::RwLockReadGuard<'_, cedar_policy::PolicySet>>,
    ) -> Self {
        PolicyError::PoisonedLockError(err.to_string())
    }
}
