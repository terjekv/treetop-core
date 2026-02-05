use cedar_policy::{
    Authorizer, Entities, Entity, Policy, PolicyId, PolicySet, Request as CedarRequest,
};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime};
use std::vec;

use crate::labels::LabelRegistry;
use crate::policy_match::{matches_effect, principal_match_reason, resource_match_reason};
use crate::query::{PrincipalQuery, ResourceQuery};
use crate::timers::PhaseTimer;
use crate::traits::CedarAtom;
use crate::types::{
    Decision, FromDecisionWithPolicy, PermitPolicies, PermitPolicy, PolicyEffectFilter,
    PolicyMatchReason, PolicyVersion, Request, Resource, UserPolicies,
};
use crate::{Groups, Principal};
use crate::{error::PolicyError, loader};
use arc_swap::ArcSwap;

use sha2::{Digest, Sha256};
use tracing::debug;
#[cfg(feature = "observability")]
use tracing::info_span;

#[cfg(feature = "observability")]
use crate::metrics::{
    EvaluationPhases, EvaluationStats, record_evaluation, record_evaluation_phases, record_reload,
};

/// Static cached Authorizer instance (stateless, reusable across evaluations).
fn get_authorizer() -> &'static Authorizer {
    static AUTHORIZER: OnceLock<Authorizer> = OnceLock::new();
    AUTHORIZER.get_or_init(Authorizer::new)
}

/// Aggregates timing information for all evaluation phases.
#[derive(Debug)]
struct EvalTimers {
    /// Total elapsed time from start of evaluation
    total_start: Instant,
    /// Time spent applying labels
    labels: Duration,
    /// Time spent constructing Cedar request
    construct_req: Duration,
    /// Time spent building Cedar entities
    entities: Duration,
    /// Time spent resolving groups
    groups: Duration,
    /// Time spent performing authorization
    authz: Duration,
}

impl EvalTimers {
    fn start() -> Self {
        Self {
            total_start: Instant::now(),
            labels: Duration::ZERO,
            construct_req: Duration::ZERO,
            entities: Duration::ZERO,
            groups: Duration::ZERO,
            authz: Duration::ZERO,
        }
    }

    fn total_elapsed(&self) -> Duration {
        self.total_start.elapsed()
    }
}

/// Result of preparing a request for authorization: Cedar request, entities, snapshot, and phase timings.
struct PreparedRequest {
    cedar_req: CedarRequest,
    entities: Entities,
    snapshot: Snapshot,
    timers: EvalTimers,
}

/// Immutable snapshot of a compiled policy set, along with metadata.
#[derive(Debug)]
struct PolicySnapshot {
    set: PolicySet,
    version: PolicyVersion,
    permit_policies: HashMap<PolicyId, PermitPolicy>,
}

/// Convenience alias for a shared policy snapshot.
type Snapshot = Arc<PolicySnapshot>;

impl PolicySnapshot {
    fn from_policy_text(policy_text: &str) -> Result<Self, PolicyError> {
        let set = loader::compile_policy(policy_text)?;
        let permit_policies = loader::precompute_permit_policies(&set);

        let mut hasher = Sha256::new();
        hasher.update(policy_text.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        Ok(PolicySnapshot {
            set,
            version: PolicyVersion {
                hash,
                loaded_at: humantime::format_rfc3339(SystemTime::now()).to_string(),
            },
            permit_policies,
        })
    }

    fn policy_set(&self) -> &PolicySet {
        &self.set
    }

    fn version(&self) -> PolicyVersion {
        self.version.clone()
    }
}

/// Extract all permit policies from the Cedar authorization result.
fn extract_permit_policies(
    snapshot: &PolicySnapshot,
    result: &cedar_policy::Response,
) -> PermitPolicies {
    if result.decision() != cedar_policy::Decision::Allow {
        return PermitPolicies::empty();
    }

    result
        .diagnostics()
        .reason()
        .filter_map(|reason| snapshot.permit_policies.get(reason))
        .cloned()
        .collect()
}

/// Iterate over groups from a request principal.
fn request_groups(request: &Request) -> Option<&Groups> {
    match &request.principal {
        Principal::User(user) => Some(user.groups()),
        Principal::Group(_) => None,
    }
}

/// Apply label augmentations to a resource.
fn apply_labels(
    registry: &Option<Arc<LabelRegistry>>,
    resource: &mut crate::types::Resource,
    timers: &mut EvalTimers,
) {
    let _timer = PhaseTimer::new(&mut timers.labels);
    #[cfg(feature = "observability")]
    let _label_span = info_span!("apply_labels").entered();
    if let Some(registry) = registry {
        registry.apply(resource);
    }
}

/// Build a Cedar request from the authorization request and resource.
/// UIDs should be pre-converted to avoid redundant conversions.
fn build_cedar_req(
    principal_uid: &cedar_policy::EntityUid,
    action_uid: &cedar_policy::EntityUid,
    resource_uid: &cedar_policy::EntityUid,
    context: &cedar_policy::Context,
    timers: &mut EvalTimers,
) -> Result<CedarRequest, PolicyError> {
    let _timer = PhaseTimer::new(&mut timers.construct_req);
    #[cfg(feature = "observability")]
    let _req_span = info_span!("construct_cedar_req").entered();

    Ok(CedarRequest::new(
        principal_uid.clone(),
        action_uid.clone(),
        resource_uid.clone(),
        context.clone(),
        None,
    )?)
}

/// Build Cedar entities for the principal, resource, and groups.
/// UIDs should be pre-converted to avoid redundant conversions.
fn build_entities(
    principal_uid: &cedar_policy::EntityUid,
    resource_uid: &cedar_policy::EntityUid,
    resource: &crate::types::Resource,
    groups: Option<&Groups>,
    timers: &mut EvalTimers,
) -> Result<Entities, PolicyError> {
    let schema: Option<&cedar_policy::Schema> = None;

    // Time and measure entity construction
    let entities = {
        let _timer = PhaseTimer::new(&mut timers.entities);
        #[cfg(feature = "observability")]
        let _entity_span = info_span!("construct_entities").entered();

        // Collect group UIDs with pre-allocation to avoid over-allocations
        let group_uids = {
            let _timer = PhaseTimer::new(&mut timers.groups);
            #[cfg(feature = "observability")]
            let _groups_span = info_span!("resolve_groups").entered();

            match groups {
                Some(groups_slice) => {
                    let mut uids = Vec::with_capacity(groups_slice.len());
                    for g in groups_slice {
                        uids.push(g.cedar_entity_uid()?);
                    }
                    uids.into_iter().collect::<HashSet<_>>()
                }
                None => HashSet::new(),
            }
        };

        // Construct resource entity
        let resource_attrs = resource.cedar_attr()?;
        let resource_entity =
            cedar_policy::Entity::new(resource_uid.clone(), resource_attrs, Default::default())?;

        // Construct principal entity with groups as parents
        let principal_entity =
            Entity::new(principal_uid.clone(), HashMap::new(), group_uids.clone())?;

        // Construct group entities
        let group_entities: Vec<Entity> = group_uids.into_iter().map(Entity::with_uid).collect();

        // Combine all entities (use manual resource_entity to include attributes)
        Entities::empty()
            .add_entities(vec![principal_entity, resource_entity], schema)?
            .add_entities(group_entities, schema)?
    };

    debug!(
        event = "Request",
        phase = "Entities",
        time = timers.entities.as_micros(),
        entities = entities
            .iter()
            .map(|e| format!("[{e}]"))
            .collect::<Vec<_>>()
            .join(", ")
            .replace('\n', "")
    );

    Ok(entities)
}

/// The main engine handle. Thread-safe and cheaply cloneable.
///
/// Cloning is cheap (just increments Arc refcounts), but for multithreaded
/// applications, wrapping in `Arc<PolicyEngine>` and using `Arc::clone()`
/// is more idiomatic and makes ownership clearer.
///
/// For single-threaded use or when passing the engine to a single thread,
/// you can simply clone it directly.
#[derive(Clone)]
pub struct PolicyEngine {
    /// Shared pointer to an `ArcSwap` holding the current `Snapshot`.
    inner: Arc<ArcSwap<Snapshot>>,
    /// Optional label registry for augmenting resources with derived attributes.
    label_registry: Option<Arc<LabelRegistry>>,
}

impl From<PolicyEngine> for PolicyVersion {
    fn from(engine: PolicyEngine) -> Self {
        engine.current_version()
    }
}

impl From<&PolicyEngine> for PolicyVersion {
    fn from(engine: &PolicyEngine) -> Self {
        engine.current_version()
    }
}

impl PolicyEngine {
    pub fn new_from_str(policy_text: &str) -> Result<Self, PolicyError> {
        let snapshot: Snapshot = Arc::new(PolicySnapshot::from_policy_text(policy_text)?);
        Ok(PolicyEngine {
            inner: Arc::new(ArcSwap::from(Arc::new(snapshot))),
            label_registry: None,
        })
    }

    /// Create a new policy engine with a label registry.
    ///
    /// This is a convenience method that combines `new_from_str` and `with_label_registry`.
    pub fn with_label_registry(mut self, registry: LabelRegistry) -> Self {
        self.label_registry = Some(Arc::new(registry));
        self
    }

    /// Set or replace the label registry for this engine.
    ///
    /// This allows updating the labelers after the engine has been created.
    pub fn set_label_registry(&mut self, registry: LabelRegistry) {
        self.label_registry = Some(Arc::new(registry));
    }

    /// Get a reference to the label registry, if one is configured.
    pub fn label_registry(&self) -> Option<&LabelRegistry> {
        self.label_registry.as_deref()
    }

    pub fn reload_from_str(&self, policy_text: &str) -> Result<(), PolicyError> {
        let new_snapshot: Snapshot = Arc::new(PolicySnapshot::from_policy_text(policy_text)?);
        self.inner.store(Arc::new(new_snapshot));
        // Track reloads for metrics (no-op if feature disabled or no sink configured)
        #[cfg(feature = "observability")]
        record_reload();
        Ok(())
    }

    /// Get the current snapshot using a short-lived read lock, then drop the lock.
    fn current_snapshot(&self) -> Snapshot {
        // `load_full` returns `Arc<Arc<PolicySnapshot>>`; deref one level.
        let outer = self.inner.load_full();
        Arc::clone(&outer)
    }

    /// Get the current policy version.
    ///
    /// The `hash` is computed from the policy text, and `loaded_at` reflects
    /// when this snapshot was installed.
    pub fn current_version(&self) -> PolicyVersion {
        self.current_snapshot().version()
    }

    /// Prepare a request for authorization: accumulate labels, build Cedar entities, resolve groups.
    ///
    /// This separates request preparation from the authorization decision, making both
    /// more testable and the main hot path more readable.
    fn prepare(&self, request: &Request) -> Result<PreparedRequest, PolicyError> {
        let snapshot = self.current_snapshot();
        let mut timers = EvalTimers::start();

        let groups = request_groups(request);

        debug!(
            event = "Request",
            phase = "Evaluation",
            principal = request.principal.to_string(),
            action = request.action.to_string(),
            resource = request.resource.to_string(),
            groups = %groups.map(ToString::to_string).unwrap_or_else(|| "[]".into())
        );

        // Convert UIDs once to avoid redundant conversions (on original resource)
        let principal_uid = request.principal.cedar_entity_uid()?;
        let action_uid = request.action.cedar_entity_uid()?;
        let resource_uid_original = request.resource.cedar_entity_uid()?;
        let context_original = request.resource.cedar_ctx()?;

        // Only clone and apply labels if a label registry is configured
        // We need to keep the potentially-modified resource for building entities
        let (resource_uid, context, resource_for_entities) = if self.label_registry.is_some() {
            let mut resource = request.resource.clone();
            apply_labels(&self.label_registry, &mut resource, &mut timers);

            debug!(
                event = "Request",
                phase = "LabelsApplied",
                time = timers.labels.as_micros(),
                resource_attrs = ?resource.attrs()
            );

            let uid = resource.cedar_entity_uid()?;
            let ctx = resource.cedar_ctx()?;
            (uid, ctx, resource)
        } else {
            debug!(
                event = "Request",
                phase = "LabelsApplied",
                time = timers.labels.as_micros()
            );

            (
                resource_uid_original,
                context_original,
                request.resource.clone(),
            )
        };

        debug!(
            event = "Request",
            phase = "Parsed",
            principal = principal_uid.to_string(),
            action = action_uid.to_string(),
            resource = resource_uid.to_string(),
            context = context.to_string(),
            groups = %groups.map(ToString::to_string).unwrap_or_else(|| "[]".into()),
            attrs = ?resource_for_entities.cedar_attr()
        );

        // Build Cedar request with pre-converted UIDs
        let cedar_req = build_cedar_req(
            &principal_uid,
            &action_uid,
            &resource_uid,
            &context,
            &mut timers,
        )?;

        // Build entities with pre-converted UIDs and potentially-modified resource
        let entities = build_entities(
            &principal_uid,
            &resource_uid,
            &resource_for_entities,
            groups,
            &mut timers,
        )?;

        debug!(
            event = "Request",
            phase = "GroupsResolved",
            time = timers.groups.as_micros(),
        );

        Ok(PreparedRequest {
            cedar_req,
            entities,
            snapshot,
            timers,
        })
    }

    /// Evaluate a policy request against the currently loaded policy set.
    ///
    /// This method performs a complete Cedar policy evaluation:
    /// 1. Applies any registered labelers to augment resource attributes
    /// 2. Constructs Cedar entities for the principal (including groups), action, and resource
    /// 3. Executes the Cedar authorization decision
    /// 4. Returns either `Allow` (with the matching policy) or `Deny`, both including version metadata
    ///
    /// # Arguments
    ///
    /// * `request` - The authorization request containing the principal, action, and resource
    ///
    /// # Returns
    ///
    /// * `Ok(Decision::Allow)` - If at least one permit policy matches and no forbid policies match
    /// * `Ok(Decision::Deny)` - If no permit policies match or if a forbid policy matches
    /// * `Err(PolicyError)` - If there's an error constructing entities, parsing the request, or during evaluation
    ///
    /// # Examples
    ///
    /// ```rust
    /// use treetop_core::{PolicyEngine, Request, Principal, User, Action, Resource, Decision};
    ///
    /// let policies = r#"
    ///     permit (
    ///         principal == User::"alice",
    ///         action == Action::"read",
    ///         resource == Document::"doc1"
    ///     );
    /// "#;
    ///
    /// let engine = PolicyEngine::new_from_str(policies).unwrap();
    ///
    /// let request = Request {
    ///     principal: Principal::User(User::new("alice", None, None)),
    ///     action: Action::new("read", None),
    ///     resource: Resource::new("Document", "doc1"),
    /// };
    ///
    /// let decision = engine.evaluate(&request).unwrap();
    /// assert!(matches!(decision, Decision::Allow { .. }));
    ///
    /// // Access version information
    /// if let Decision::Allow { version, .. } = decision {
    ///     println!("Allowed by policy version: {}", version.hash);
    /// }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and lock-free. Multiple threads can evaluate requests
    /// concurrently without blocking each other.
    #[cfg_attr(
        feature = "observability",
        tracing::instrument(
            name = "policy_evaluation",
            skip_all,
            fields(
                principal = %request.principal,
                action = %request.action,
                resource = %request.resource
            )
        )
    )]
    pub fn evaluate(&self, request: &Request) -> Result<Decision, PolicyError> {
        // Prepare the request: apply labels, build entities, resolve groups
        let mut prepared = self.prepare(request)?;

        // Perform authorization with RAII timing (using cached Authorizer)
        let result = {
            let _timer = PhaseTimer::new(&mut prepared.timers.authz);
            #[cfg(feature = "observability")]
            let _authz_span = info_span!("authorize").entered();
            get_authorizer().is_authorized(
                &prepared.cedar_req,
                &prepared.snapshot.set,
                &prepared.entities,
            )
        };

        debug!(
            event = "Request",
            phase = "Authorized",
            time = prepared.timers.authz.as_micros(),
            decision = ?result.decision(),
        );

        let version = prepared.snapshot.version();
        debug!(
            event = "Request",
            phase = "Result",
            time = prepared.timers.total_elapsed().as_micros(),
            result = ?result.decision(),
            policy_hash = %version.hash,
            policy_loaded_at = %version.loaded_at,
        );

        // Extract all permit policies from the authorization result
        let permit_policies = extract_permit_policies(&prepared.snapshot, &result);

        // Record metrics (no-op when no sink is configured or feature disabled)
        #[cfg(feature = "observability")]
        {
            let dur = prepared.timers.total_elapsed();
            let allowed = result.decision() == cedar_policy::Decision::Allow;
            let principal_id = request.principal.to_string();
            let action_id = request.action.to_string();

            let matched_policies = permit_policies.ids();

            let stats = EvaluationStats {
                duration: dur,
                allowed,
                principal_id,
                action_id,
                matched_policies,
            };

            let phases = EvaluationPhases {
                apply_labels_ms: prepared.timers.labels.as_secs_f64() * 1000.0,
                construct_entities_ms: prepared.timers.entities.as_secs_f64() * 1000.0,
                resolve_groups_ms: prepared.timers.groups.as_secs_f64() * 1000.0,
                authorize_ms: prepared.timers.authz.as_secs_f64() * 1000.0,
                total_ms: stats.duration.as_secs_f64() * 1000.0,
            };

            record_evaluation(&stats);
            record_evaluation_phases(&stats, &phases);
        }

        Ok(Decision::from_decision_with_policy(
            result.decision(),
            permit_policies,
            version,
        ))
    }

    /// List all policies applicable to a user.
    ///
    /// This mirrors [`PolicyEngine::evaluate`] input shape for principal identity:
    /// user id + groups + shared namespace.
    ///
    /// Matching includes all Cedar principal-constraint forms:
    /// - `principal == User::"..."`
    /// - `principal in Group::"..."`
    /// - `principal`
    /// - `principal is User`
    /// - `principal is User in Group::"..."`
    ///
    /// Resource constraints are not applied in this method. To additionally
    /// filter by policy resource constraints, use
    /// [`PolicyEngine::list_policies_for_user_with_resource`].
    ///
    /// Output is deterministic: policies are sorted by Cedar policy ID.
    /// Each returned policy includes match reasons via `UserPolicies::matches()`.
    ///
    /// # Arguments
    ///
    /// * `user` - User ID
    /// * `groups` - Group IDs the user belongs to
    /// * `namespace` - Optional shared namespace path for both user and groups
    ///
    /// # Returns
    ///
    /// * `Ok(UserPolicies)` - Matching policies and match metadata
    /// * `Err(PolicyError)` - If entity UID construction fails
    ///
    /// # Examples
    ///
    /// ```rust
    /// use treetop_core::PolicyEngine;
    ///
    /// let policies = r#"
    ///     permit (principal == User::"alice", action, resource);
    ///     permit (principal in Group::"admins", action, resource);
    /// "#;
    ///
    /// let engine = PolicyEngine::new_from_str(policies).unwrap();
    /// let user_policies = engine.list_policies_for_user("alice", &["admins"], &[]).unwrap();
    ///
    /// assert_eq!(user_policies.policies().len(), 2);
    /// assert!(!user_policies.matches().is_empty());
    /// ```
    pub fn list_policies_for_user(
        &self,
        user: &str,
        groups: &[&str],
        namespace: &[&str],
    ) -> Result<UserPolicies, PolicyError> {
        self.list_policies_for_user_with_resource_and_effect(
            user,
            groups,
            namespace,
            None,
            PolicyEffectFilter::Any,
        )
    }

    /// List all policies applicable to a concrete request.
    ///
    /// This mirrors [`PolicyEngine::evaluate`] by accepting `&Request` and uses:
    /// - the request principal (including user group membership, if any)
    /// - the request resource
    ///
    /// Effect filter defaults to `Any`; to filter by permit/forbid, use
    /// [`PolicyEngine::list_policies_with_effect`].
    pub fn list_policies(&self, request: &Request) -> Result<UserPolicies, PolicyError> {
        self.list_policies_with_effect(request, PolicyEffectFilter::Any)
    }

    /// List all policies applicable to a concrete request, with effect filtering.
    pub fn list_policies_with_effect(
        &self,
        request: &Request,
        effect_filter: PolicyEffectFilter,
    ) -> Result<UserPolicies, PolicyError> {
        let principal = PrincipalQuery::from_principal(&request.principal)?;
        self.list_policies_dispatch(
            &request.principal.to_string(),
            &principal,
            Some(&request.resource),
            effect_filter,
        )
    }

    /// List all policies applicable to a user, optionally filtering by resource constraints.
    ///
    /// This variant applies both principal and resource constraints:
    /// - principal constraints as described in [`PolicyEngine::list_policies_for_user`]
    /// - resource constraints (`==`, `in`, `is`, `is in`, `any`) when `resource` is provided
    ///
    /// When `resource` is `None`, behavior is equivalent to
    /// [`PolicyEngine::list_policies_for_user`].
    ///
    /// Returned `UserPolicies` includes match reasons for principal and, when
    /// applicable, resource matches.
    pub fn list_policies_for_user_with_resource(
        &self,
        user: &str,
        groups: &[&str],
        namespace: &[&str],
        resource: Option<&Resource>,
    ) -> Result<UserPolicies, PolicyError> {
        self.list_policies_for_user_with_resource_and_effect(
            user,
            groups,
            namespace,
            resource,
            PolicyEffectFilter::Any,
        )
    }

    /// List all policies applicable to a user with optional resource and effect filtering.
    pub fn list_policies_for_user_with_resource_and_effect(
        &self,
        user: &str,
        groups: &[&str],
        namespace: &[&str],
        resource: Option<&Resource>,
        effect_filter: PolicyEffectFilter,
    ) -> Result<UserPolicies, PolicyError> {
        let principal = PrincipalQuery::for_user(user, groups, namespace)?;
        self.list_policies_dispatch(user, &principal, resource, effect_filter)
    }

    /// List all policies applicable to a group principal.
    ///
    /// Useful when callers model group identities directly as principals
    /// (mirroring `Principal::Group` in [`PolicyEngine::evaluate`]).
    ///
    /// Resource constraints are not applied in this method. To also filter by
    /// resource constraints, use
    /// [`PolicyEngine::list_policies_for_group_with_resource`].
    pub fn list_policies_for_group(
        &self,
        group: &str,
        namespace: &[&str],
    ) -> Result<UserPolicies, PolicyError> {
        self.list_policies_for_group_with_resource_and_effect(
            group,
            namespace,
            None,
            PolicyEffectFilter::Any,
        )
    }

    /// List all policies applicable to a group principal, optionally filtering by resource constraints.
    ///
    /// This applies principal constraints for a group principal and, when
    /// `resource` is provided, resource constraints as well.
    pub fn list_policies_for_group_with_resource(
        &self,
        group: &str,
        namespace: &[&str],
        resource: Option<&Resource>,
    ) -> Result<UserPolicies, PolicyError> {
        self.list_policies_for_group_with_resource_and_effect(
            group,
            namespace,
            resource,
            PolicyEffectFilter::Any,
        )
    }

    /// List all policies applicable to a group principal with optional resource and effect filtering.
    pub fn list_policies_for_group_with_resource_and_effect(
        &self,
        group: &str,
        namespace: &[&str],
        resource: Option<&Resource>,
        effect_filter: PolicyEffectFilter,
    ) -> Result<UserPolicies, PolicyError> {
        let principal = PrincipalQuery::for_group(group, namespace)?;
        self.list_policies_dispatch(group, &principal, resource, effect_filter)
    }

    fn list_policies_dispatch(
        &self,
        principal_id: &str,
        principal: &PrincipalQuery,
        resource: Option<&Resource>,
        effect_filter: PolicyEffectFilter,
    ) -> Result<UserPolicies, PolicyError> {
        let snapshot = self.current_snapshot();
        let policies = snapshot.set.policies();
        let resource_query = match resource {
            Some(resource) => Some(ResourceQuery::from_resource(resource)?),
            None => None,
        };
        let mut matching_policies: Vec<(Policy, Vec<PolicyMatchReason>)> = Vec::new();

        for policy in policies {
            if !matches_effect(policy.effect(), effect_filter) {
                continue;
            }

            let Some(principal_reason) =
                principal_match_reason(policy.principal_constraint(), principal)
            else {
                continue;
            };

            let Some(resource_reason) =
                resource_match_reason(policy.resource_constraint(), resource_query.as_ref())
            else {
                continue;
            };

            let mut reasons = vec![principal_reason];
            if let Some(resource_reason) = resource_reason {
                reasons.push(resource_reason);
            }

            matching_policies.push((policy.clone(), reasons));
        }

        Ok(UserPolicies::new_with_matches(
            principal_id,
            matching_policies,
        ))
    }

    pub fn policies(&self) -> Result<Vec<Policy>, PolicyError> {
        let snapshot = self.current_snapshot();
        Ok(snapshot.policy_set().policies().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::labels::{LabelRegistryBuilder, RegexLabeler};
    use crate::snapshot_decision;
    use crate::types::AttrValue;
    use crate::types::{Decision::Allow, Decision::Deny, Group, Resource};
    use crate::{Action, PolicyEffectFilter, PolicyMatchReason, User};
    use cedar_policy::EntityUid;
    use regex::Regex;
    use yare::parameterized;

    const TEST_POLICY: &str = r#"
permit (
    principal == User::"alice",
    action in [Action::"view", Action::"edit", Action::"delete"],
    resource == Photo::"VacationPhoto94.jpg"
);

permit (
    principal == User::"bob",
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
);
"#;

    const TEST_POLICY_WITHOUT_BOB: &str = r#"
permit (
    principal == User::"alice",
    action in [Action::"view", Action::"edit", Action::"delete"],
    resource == Photo::"VacationPhoto94.jpg"
);
"#;

    const TEST_POLICY_WITH_CONTEXT: &str = r#"
permit (
    principal == User::"alice",
    action == Action::"create_host",
    resource is Host
) when {
    resource.name like "web*" &&
    resource.ip.isInRange(ip("192.0.1.0/24"))
};

permit (
    principal == User::"bob",
    action == Action::"create_host",
    resource is Host
) when {
    resource.name like "bob*" &&
    resource.ip.isInRange(ip("192.0.0.0/24"))
};
"#;

    const TEST_PERMISSION_POLICY: &str = r#"
permit (
    principal == User::"alice",
    action in [Action::"view", Action::"edit", Action::"delete"],
    resource == Photo::"VacationPhoto94.jpg"
);

permit (
    principal == User::"alice",
    action == Action::"create_host",
    resource is Host
);

permit (
    principal == User::"bob",
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
);
"#;

    const TEST_POLICY_WITH_FORBID: &str = r#"
permit (
    principal == User::"alice",
    action in [Action::"view", Action::"edit", Action::"delete"],
    resource == Photo::"VacationPhoto94.jpg"
);
forbid (
    principal == User::"alice",
    action == Action::"edit",
    resource == Photo::"VacationPhoto94.jpg"
);
forbid (
    principal,
    action == Action::"delete",
    resource == Photo::"VacationPhoto94.jpg"
);
"#;

    const TEST_POLICY_WITH_HOST_PATTERNS: &str = r#"
permit (
    principal == User::"alice",
    action == Action::"create_host",
    resource is Host
) when {
    resource.nameLabels.contains("example_domain")
};

permit (
    principal == User::"bob",
    action == Action::"create_host",
    resource is Host
) when {
    resource.nameLabels.contains("valid_web_name") &&
    resource.nameLabels.contains("example_domain")
};
"#;

    const TEST_POLICY_ACTION_ONLY_HERE: &str = r#"
permit (
    principal == User::"alice",
    action == Action::"only_here",
    resource
);
"#;

    const TEST_POLICY_GENERIC_RESOURCE: &str = r#"
permit (
    principal == User::"alice",
    action == Action::"assign_gateway",
    resource is Gateway
) when {
    resource.id == "mygateway"
};
"#;

    const TEST_POLICY_WITH_GROUPS: &str = r#"
permit (
    principal in Group::"admins",
    action in [Action::"delete", Action::"view"],
    resource is Photo
);

permit (
    principal in Group::"users",
    action == Action::"view",
    resource is Photo
);
"#;

    const TEST_POLICY_BY_ID: &str = r#"
@id("id_of_policy")
permit (
    principal == User::"alice",
    action, 
    resource
);
"#;

    const TEST_POLICY_WITH_NAMESPACES: &str = r#"
permit (
    principal == Database::User::"alice",
    action in [Database::Action::"create_table", Database::Action::"view_table"],
    resource is Database::Table
);

permit (
    principal in Database::Group::"dbusers",
    action == Database::Action::"view_table",
    resource is Database::Table
);

permit (
    principal in Furniture::Group::"carpenters",
    action == Furniture::Action::"create_table",
    resource is Furniture::Table
);
"#;

    const TEST_POLICY_WITH_IP: &str = r#"
permit (
    principal == User::"alice",
    action == Action::"create_host",
    resource is Host
) when {
    resource.ip.isInRange(ip("192.168.0.0/24"))
};
"#;

    const TEST_POLICY_WITH_IS_AND_ISIN: &str = r#"
permit (
    principal is User,
    action == Action::"read",
    resource
);

permit (
    principal is User in Group::"admins",
    action == Action::"write",
    resource
);

permit (
    principal is Group,
    action == Action::"group_read",
    resource
);

permit (
    principal is Group in Group::"admins",
    action == Action::"group_write",
    resource
);
"#;

    const TEST_POLICY_WITH_RESOURCE_CONSTRAINTS: &str = r#"
permit (
    principal,
    action == Action::"view",
    resource is Photo
);
permit (
    principal,
    action == Action::"edit",
    resource == Photo::"vacation.jpg"
);
permit (
    principal,
    action == Action::"create",
    resource is Host
);
"#;

    #[parameterized(
        alice_edit_allow = { "alice", "edit", "VacationPhoto94.jpg" },
        alice_view_allow = { "alice", "view", "VacationPhoto94.jpg" },
        alice_delete_allow = { "alice", "delete", "VacationPhoto94.jpg" },
        alice_view_deny_wrong_photo = { "alice", "view", "wrongphoto.jpg" },
        bob_view_allow = { "bob", "view", "VacationPhoto94.jpg" },
        bob_edit_deny = { "bob", "edit", "VacationPhoto94.jpg", },
        bob_view_deny_wrong_photo = { "bob", "edit", "wrongphoto.jpg", },
        charlie_view_deny = { "charlie", "view", "VacationPhoto94.jpg", },
    )]
    fn test_evaluate_requests(user: &str, action: &str, resource: &str) {
        let engine = PolicyEngine::new_from_str(TEST_POLICY).unwrap();

        // Convert the resource to the appropriate type
        let resource = Resource::new("Photo", resource.to_string())
            .with_attr("name", AttrValue::String(resource.to_string()));

        let request = Request {
            principal: Principal::User(User::new(user, None, None)),
            action: Action::new(action, None),
            resource,
        };
        let decision = engine.evaluate(&request).unwrap();
        snapshot_decision!(decision);
    }

    #[parameterized(
        alice_create_host_allow = { "alice", "create_host", "web-01.example.com", "192.0.1.1" }, 
        bob_create_host_allow = { "bob", "create_host", "bob-01.example.com", "192.0.0.1" }, 
        alice_create_host_wrong_net_deny = { "alice", "create_host", "web-99.example.com", "192.0.2.1" },
        alice_create_host_wrong_name_deny = { "alice", "create_host", "abc.example.com", "192.0.1.2" },
    )]
    fn test_create_host_requests(user: &str, action: &str, host_name: &str, ip: &str) {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_CONTEXT).unwrap();

        let request = Request {
            principal: Principal::User(User::new(user, None, None)),
            action: Action::new(action, None),
            resource: Resource::new("Host", host_name)
                .with_attr("name", AttrValue::String(host_name.into()))
                .with_attr("ip", AttrValue::Ip(ip.into())),
        };
        let decision = engine.evaluate(&request).unwrap();
        snapshot_decision!(decision);
    }

    #[test]
    fn test_reload_policy() {
        let engine = PolicyEngine::new_from_str(TEST_POLICY).unwrap();
        let request = Request {
            principal: Principal::User(User::new("bob", None, None)),
            action: Action::new("view", None),
            resource: Resource::from_str("Photo::VacationPhoto94.jpg").unwrap(),
        };

        assert!(matches!(engine.evaluate(&request).unwrap(), Allow { .. }));

        engine.reload_from_str(TEST_POLICY_WITHOUT_BOB).unwrap();
        assert!(matches!(engine.evaluate(&request).unwrap(), Deny { .. }));
    }

    #[parameterized(
        alice_permissions = { "alice", vec![], 2, vec!["create_host", "delete", "edit", "view"] },
        bob_permissions = { "bob", vec![], 1, vec!["view"] },
        charlie_permissions = { "charlie", vec![], 0, vec![] },
    )]
    fn test_list_permissions(
        user: &str,
        groups: Vec<String>,
        expected_policies: usize,
        expected_actions: Vec<&str>,
    ) {
        let engine = PolicyEngine::new_from_str(TEST_PERMISSION_POLICY).unwrap();

        let group_strs: Vec<&str> = groups.iter().map(|s| s.as_str()).collect();
        let user_policies = engine
            .list_policies_for_user(user, &group_strs, &[])
            .expect("Failed to list permissions");
        assert_eq!(user_policies.policies().len(), expected_policies);

        // Fetch the actions by name, this list is automatically sorted
        let actions = user_policies.actions_by_name();

        assert_eq!(actions.len(), expected_actions.len());

        for (i, action) in expected_actions.iter().enumerate() {
            let padded_action = format!("Action::\"{}\"", action);
            assert_eq!(padded_action, actions[i].to_string(),);
        }
    }

    // So, the arrays in the serialized output are not guaranteed to be in the same order,
    // even with sort-maps set to true for insta. As such, we end up needing to do this
    // rather manually.
    #[test]
    fn test_serialize_user_permissions() {
        let combined = TEST_PERMISSION_POLICY.to_string() + TEST_POLICY_WITH_CONTEXT;
        let engine = PolicyEngine::new_from_str(&combined).unwrap();

        let perms = engine.list_policies_for_user("alice", &[], &[]).unwrap();

        let expected_serialized = r#"{"user":"alice","policies":[{"effect":"permit","principal":{"op":"==","entity":{"type":"User","id":"alice"}},"action":{"op":"in","entities":[{"type":"Action","id":"view"},{"type":"Action","id":"edit"},{"type":"Action","id":"delete"}]},"resource":{"op":"==","entity":{"type":"Photo","id":"VacationPhoto94.jpg"}},"conditions":[]},{"effect":"permit","principal":{"op":"==","entity":{"type":"User","id":"alice"}},"action":{"op":"==","entity":{"type":"Action","id":"create_host"}},"resource":{"op":"is","entity_type":"Host"},"conditions":[]},{"effect":"permit","principal":{"op":"==","entity":{"type":"User","id":"alice"}},"action":{"op":"==","entity":{"type":"Action","id":"create_host"}},"resource":{"op":"is","entity_type":"Host"},"conditions":[{"kind":"when","body":{"&&":{"left":{"like":{"left":{".":{"left":{"Var":"resource"},"attr":"name"}},"pattern":[{"Literal":"w"},{"Literal":"e"},{"Literal":"b"},"Wildcard"]}},"right":{"isInRange":[{".":{"left":{"Var":"resource"},"attr":"ip"}},{"ip":[{"Value":"192.0.1.0/24"}]}]}}}}]}]}"#;

        let actual: serde_json::Value = serde_json::to_value(&perms).unwrap();
        let expected: serde_json::Value = serde_json::from_str(expected_serialized).unwrap();

        assert_eq!(actual["user"], expected["user"]);

        let act_arr = actual["policies"].as_array().unwrap();
        let exp_arr = expected["policies"].as_array().unwrap();
        assert_eq!(act_arr.len(), exp_arr.len(), "wrong number of policies");

        for exp in exp_arr {
            assert!(
                act_arr.iter().any(|act| act == exp),
                "expected policy not found: {:#}",
                exp
            );
        }
    }

    #[parameterized(
        admins_can_view_delete = { "admin_user", vec!["admins".to_string()], 1, vec!["delete", "view"] },
        users_can_only_view = { "regular_user", vec!["users".to_string()], 1, vec!["view"] },
        both_groups = { "super_user", vec!["admins".to_string(), "users".to_string()], 2, vec!["delete", "view", "view"] },
        no_groups = { "bob", vec![], 0, vec![] },
    )]
    fn test_list_policies_with_groups(
        user: &str,
        groups: Vec<String>,
        expected_policies: usize,
        expected_actions: Vec<&str>,
    ) {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_GROUPS).unwrap();

        let group_strs: Vec<&str> = groups.iter().map(|s| s.as_str()).collect();
        let user_policies = engine
            .list_policies_for_user(user, &group_strs, &[])
            .expect("Failed to list policies");
        assert_eq!(
            user_policies.policies().len(),
            expected_policies,
            "Expected {} policies but got {}",
            expected_policies,
            user_policies.policies().len()
        );

        let actions = user_policies.actions_by_name();
        assert_eq!(
            actions.len(),
            expected_actions.len(),
            "Expected {} actions but got {}",
            expected_actions.len(),
            actions.len()
        );

        for (i, action) in expected_actions.iter().enumerate() {
            let padded_action = format!("Action::\"{}\"", action);
            assert_eq!(padded_action, actions[i].to_string());
        }
    }

    #[test]
    fn test_list_policies_with_namespaces() {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_NAMESPACES).unwrap();

        // Test Database::User::"alice" with Database::Group::"dbusers"
        let user_policies = engine
            .list_policies_for_user("alice", &["dbusers"], &["Database"])
            .expect("Failed to list policies");

        // Should match both:
        // 1. principal == Database::User::"alice" (direct match)
        // 2. principal in Database::Group::"dbusers" (group membership)
        assert_eq!(user_policies.policies().len(), 2);
    }

    #[test]
    fn test_list_policies_with_multiple_namespaces() {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_NAMESPACES).unwrap();

        // Test Furniture::Group::"carpenters"
        let user_policies = engine
            .list_policies_for_user("carpenter_user", &["carpenters"], &["Furniture"])
            .expect("Failed to list policies");

        // Should match principal in Furniture::Group::"carpenters"
        assert_eq!(user_policies.policies().len(), 1);
    }

    #[test]
    fn test_list_policies_unconstrained_principal() {
        let policy_with_unconstrained_principal = r#"
permit (
    principal,
    action == Action::"view",
    resource
);
"#;
        let engine = PolicyEngine::new_from_str(policy_with_unconstrained_principal).unwrap();

        let user_policies = engine
            .list_policies_for_user("anyone", &[], &[])
            .expect("Failed to list policies");

        // The policy has unconstrained principal, so it should match any user
        assert_eq!(user_policies.policies().len(), 1);
    }

    #[test]
    fn test_list_policies_no_matching_policies() {
        let engine = PolicyEngine::new_from_str(TEST_POLICY).unwrap();

        let user_policies = engine
            .list_policies_for_user("charlie", &[], &[])
            .expect("Failed to list policies");

        // charlie is not mentioned in the policies
        assert_eq!(user_policies.policies().len(), 0);
    }

    #[test]
    fn test_list_policies_basic() {
        // Basic list_policies_for_user usage
        let engine = PolicyEngine::new_from_str(TEST_PERMISSION_POLICY).unwrap();

        let user_policies = engine
            .list_policies_for_user("alice", &[], &[])
            .expect("Failed to list permissions");

        // Should have 2 policies for alice (one with exact match, one with generic action)
        assert_eq!(user_policies.policies().len(), 2);
    }

    #[test]
    fn test_list_policies_with_is_and_isin() {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_IS_AND_ISIN).unwrap();

        let user_policies = engine
            .list_policies_for_user("alice", &["admins"], &[])
            .expect("Failed to list permissions");

        assert_eq!(user_policies.policies().len(), 2);

        let mut has_principal_is = false;
        let mut has_principal_is_in = false;
        for policy_match in user_policies.matches() {
            has_principal_is |= policy_match
                .reasons
                .contains(&PolicyMatchReason::PrincipalIs);
            has_principal_is_in |= policy_match
                .reasons
                .contains(&PolicyMatchReason::PrincipalIsIn);
        }

        assert!(has_principal_is);
        assert!(has_principal_is_in);
    }

    #[test]
    fn test_list_policies_for_group_with_is_and_isin() {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_IS_AND_ISIN).unwrap();

        let group_policies = engine
            .list_policies_for_group("admins", &[])
            .expect("Failed to list group policies");

        assert_eq!(group_policies.policies().len(), 2);

        let reasons = group_policies
            .matches()
            .iter()
            .flat_map(|m| m.reasons.iter().cloned())
            .collect::<Vec<_>>();
        assert!(reasons.contains(&PolicyMatchReason::PrincipalIs));
        assert!(reasons.contains(&PolicyMatchReason::PrincipalIsIn));
    }

    #[test]
    fn test_list_policies_with_optional_resource_constraints() {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_RESOURCE_CONSTRAINTS).unwrap();

        let without_resource = engine
            .list_policies_for_user("alice", &[], &[])
            .expect("Failed listing policies");
        assert_eq!(without_resource.policies().len(), 3);

        let photo = Resource::new("Photo", "vacation.jpg");
        let with_photo = engine
            .list_policies_for_user_with_resource("alice", &[], &[], Some(&photo))
            .expect("Failed listing policies with resource");
        assert_eq!(with_photo.policies().len(), 2);

        let host = Resource::new("Host", "web-01");
        let with_host = engine
            .list_policies_for_user_with_resource("alice", &[], &[], Some(&host))
            .expect("Failed listing policies with host resource");
        assert_eq!(with_host.policies().len(), 1);

        let reasons = with_photo
            .matches()
            .iter()
            .flat_map(|m| m.reasons.iter().cloned())
            .collect::<Vec<_>>();
        assert!(reasons.contains(&PolicyMatchReason::ResourceIs));
        assert!(reasons.contains(&PolicyMatchReason::ResourceEq));
    }

    #[test]
    fn test_group_membership_is_evaluated_per_request_and_per_listing_call() {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_GROUPS).unwrap();

        // Same user, no groups: should not match group-based policies.
        let no_group_request = Request {
            principal: Principal::User(User::new("alice", None, None)),
            action: Action::new("view", None),
            resource: Resource::new("Photo", "photo.jpg"),
        };
        assert!(matches!(
            engine.evaluate(&no_group_request).unwrap(),
            Deny { .. }
        ));

        // Same user, with users group: now group policy should match.
        let users_group_request = Request {
            principal: Principal::User(User::new("alice", Some(vec!["users".into()]), None)),
            action: Action::new("view", None),
            resource: Resource::new("Photo", "photo.jpg"),
        };
        assert!(matches!(
            engine.evaluate(&users_group_request).unwrap(),
            Allow { .. }
        ));

        // Same engine + same user id for listing, but different group input:
        // group membership is taken from call input, not cached globally.
        let listed_without_groups = engine.list_policies_for_user("alice", &[], &[]).unwrap();
        let listed_with_users = engine
            .list_policies_for_user("alice", &["users"], &[])
            .unwrap();

        assert_eq!(listed_without_groups.policies().len(), 0);
        assert_eq!(listed_with_users.policies().len(), 1);
        assert!(
            listed_with_users
                .matches()
                .iter()
                .any(|m| m.reasons.contains(&PolicyMatchReason::PrincipalIn))
        );
    }

    #[test]
    fn test_list_policies_mirrors_evaluate_input_shape() {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_GROUPS).unwrap();
        let request = Request {
            principal: Principal::User(User::new("alice", Some(vec!["admins".into()]), None)),
            action: Action::new("view", None),
            resource: Resource::new("Photo", "photo.jpg"),
        };

        let listed = engine.list_policies(&request).unwrap();
        assert_eq!(listed.policies().len(), 1);
        assert!(
            listed
                .matches()
                .iter()
                .all(|m| m.reasons.contains(&PolicyMatchReason::PrincipalIn))
        );
        assert!(
            listed
                .matches()
                .iter()
                .all(|m| m.reasons.contains(&PolicyMatchReason::ResourceIs))
        );
    }

    #[test]
    fn test_list_policies_output_is_deterministic() {
        let engine = PolicyEngine::new_from_str(TEST_PERMISSION_POLICY).unwrap();
        let first = engine.list_policies_for_user("alice", &[], &[]).unwrap();
        let second = engine.list_policies_for_user("alice", &[], &[]).unwrap();

        let first_ids = first
            .matches()
            .iter()
            .map(|m| m.cedar_id.clone())
            .collect::<Vec<_>>();
        let second_ids = second
            .matches()
            .iter()
            .map(|m| m.cedar_id.clone())
            .collect::<Vec<_>>();

        assert_eq!(first_ids, second_ids);
    }

    #[test]
    fn test_list_policies_effect_filter_defaults_to_any_and_can_filter() {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_FORBID).unwrap();
        let resource = Resource::new("Photo", "VacationPhoto94.jpg");

        // Default API includes both permit and forbid (Any).
        let default_any = engine
            .list_policies_for_user_with_resource("alice", &[], &[], Some(&resource))
            .unwrap();
        assert_eq!(default_any.policies().len(), 3);

        let permit_only = engine
            .list_policies_for_user_with_resource_and_effect(
                "alice",
                &[],
                &[],
                Some(&resource),
                PolicyEffectFilter::Permit,
            )
            .unwrap();
        assert_eq!(permit_only.policies().len(), 1);
        assert!(
            permit_only
                .policies()
                .iter()
                .all(|policy| policy.effect() == cedar_policy::Effect::Permit)
        );

        let forbid_only = engine
            .list_policies_for_user_with_resource_and_effect(
                "alice",
                &[],
                &[],
                Some(&resource),
                PolicyEffectFilter::Forbid,
            )
            .unwrap();
        assert_eq!(forbid_only.policies().len(), 2);
        assert!(
            forbid_only
                .policies()
                .iter()
                .all(|policy| policy.effect() == cedar_policy::Effect::Forbid)
        );
    }

    #[test]
    fn test_list_policies_with_effect_consistent_with_evaluate_on_forbid_deny() {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_FORBID).unwrap();
        let request = Request {
            principal: Principal::User(User::new("alice", None, None)),
            action: Action::new("edit", None),
            resource: Resource::new("Photo", "VacationPhoto94.jpg"),
        };

        let decision = engine.evaluate(&request).unwrap();
        assert!(matches!(decision, Deny { .. }));

        let any = engine.list_policies(&request).unwrap();
        let permit = engine
            .list_policies_with_effect(&request, PolicyEffectFilter::Permit)
            .unwrap();
        let forbid = engine
            .list_policies_with_effect(&request, PolicyEffectFilter::Forbid)
            .unwrap();

        // Listing is currently principal+resource scoped (not action scoped),
        // so both forbid policies match this request shape.
        assert_eq!(any.policies().len(), 3);
        assert_eq!(permit.policies().len(), 1);
        assert_eq!(forbid.policies().len(), 2);
    }

    #[test]
    fn test_list_policies_for_group_with_effect_filter() {
        let policy = r#"
permit (
    principal in Group::"admins",
    action == Action::"view",
    resource is Photo
);
forbid (
    principal in Group::"admins",
    action == Action::"delete",
    resource is Photo
);
"#;
        let engine = PolicyEngine::new_from_str(policy).unwrap();
        let resource = Resource::new("Photo", "photo.jpg");

        let any = engine
            .list_policies_for_group_with_resource("admins", &[], Some(&resource))
            .unwrap();
        let permit = engine
            .list_policies_for_group_with_resource_and_effect(
                "admins",
                &[],
                Some(&resource),
                PolicyEffectFilter::Permit,
            )
            .unwrap();
        let forbid = engine
            .list_policies_for_group_with_resource_and_effect(
                "admins",
                &[],
                Some(&resource),
                PolicyEffectFilter::Forbid,
            )
            .unwrap();

        assert_eq!(any.policies().len(), 2);
        assert_eq!(permit.policies().len(), 1);
        assert_eq!(forbid.policies().len(), 1);
    }

    #[test]
    fn test_list_policies_request_with_deep_namespace() {
        let policy = r#"
permit (
    principal in A::B::C::Group::"admins",
    action == A::B::C::Action::"view",
    resource is A::B::C::Photo
);
"#;
        let engine = PolicyEngine::new_from_str(policy).unwrap();
        let request = Request {
            principal: Principal::User(User::new(
                "alice",
                Some(vec!["admins".into()]),
                Some(vec!["A".into(), "B".into(), "C".into()]),
            )),
            action: Action::new("view", Some(vec!["A".into(), "B".into(), "C".into()])),
            resource: Resource::new("A::B::C::Photo", "holiday-1"),
        };

        assert!(matches!(engine.evaluate(&request).unwrap(), Allow { .. }));
        let listed = engine.list_policies(&request).unwrap();
        assert_eq!(listed.policies().len(), 1);
    }

    #[test]
    fn test_list_policies_mixed_effect_order_is_deterministic() {
        let policy = r#"
@id("p3")
permit (principal == User::"alice", action == Action::"read", resource == Photo::"p");
@id("f1")
forbid (principal == User::"alice", action == Action::"read", resource == Photo::"p");
@id("p2")
permit (principal == User::"alice", action == Action::"read", resource == Photo::"p");
"#;
        let engine = PolicyEngine::new_from_str(policy).unwrap();
        let request = Request {
            principal: Principal::User(User::new("alice", None, None)),
            action: Action::new("read", None),
            resource: Resource::new("Photo", "p"),
        };

        let first = engine.list_policies(&request).unwrap();
        let second = engine.list_policies(&request).unwrap();

        let first_ids = first
            .matches()
            .iter()
            .map(|m| m.cedar_id.clone())
            .collect::<Vec<_>>();
        let second_ids = second
            .matches()
            .iter()
            .map(|m| m.cedar_id.clone())
            .collect::<Vec<_>>();

        let mut sorted = first_ids.clone();
        sorted.sort();
        assert_eq!(first_ids, second_ids);
        assert_eq!(first_ids, sorted);
    }

    #[test]
    fn test_list_policies_for_user_with_groups_and_namespace() {
        // Test that the API supports groups and namespaces
        let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_NAMESPACES).unwrap();

        let user_policies = engine
            .list_policies_for_user("alice", &["dbusers"], &["Database"])
            .expect("Failed to list permissions");

        // Should match both the direct user constraint and the group constraint
        assert_eq!(user_policies.policies().len(), 2);
    }

    #[parameterized(
        alice_view_allow = { "alice", "view", "VacationPhoto94.jpg" },
        alice_edit_deny_explicit = { "alice", "edit", "VacationPhoto94.jpg" },
        alice_delete_forbid_any = { "alice", "delete", "VacationPhoto94.jpg" },
    )]
    fn test_policy_with_forbid(user: &str, action: &str, resource: &str) {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_FORBID).unwrap();

        // Convert the resource to the appropriate type
        let resource = Resource::new("Photo", resource.to_string())
            .with_attr("name", AttrValue::String(resource.to_string()));

        let request = Request {
            principal: Principal::User(User::new(user, None, None)),
            action: Action::new(action, None),
            resource,
        };
        let decision = engine.evaluate(&request).unwrap();
        snapshot_decision!(decision);
    }

    #[parameterized(
        alice_web_and_example_allow = { "alice", "web-01.example.com" },
        alice_no_web_allow = { "alice", "flappa.example.com" },
        alice_only_example_allow = { "alice", "whatever.example.com" },
        alice_no_example_deny = { "alice", "web.examples.com" },
        bob_web_and_example_allow = { "bob", "web-01.example.com" },
        bob_host_pattern_no_web_deny = { "bob", "somehost.example.com" },
        bob_host_pattern_no_example_deny = { "bob", "example.com" },

    )]
    fn test_policy_with_host_patterns(username: &str, host_name: &str) {
        let patterns = vec![
            ("valid_web_name".to_string(), Regex::new(r"^web.*").unwrap()),
            (
                "example_domain".to_string(),
                Regex::new(r"example\.com$").unwrap(),
            ),
        ];
        let labeler =
            RegexLabeler::new("Host", "name", "nameLabels", patterns.into_iter().collect());

        let label_registry = LabelRegistryBuilder::new()
            .add_labeler(Arc::new(labeler))
            .build();

        let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_HOST_PATTERNS)
            .unwrap()
            .with_label_registry(label_registry);

        let request = Request {
            principal: Principal::User(User::new(username, None, None)),
            action: Action::new("create_host", None),
            resource: Resource::new("Host", host_name.to_string())
                .with_attr("name", AttrValue::String(host_name.into()))
                .with_attr("ip", AttrValue::Ip("10.0.0.1".into())),
        };

        let decision = engine.evaluate(&request).unwrap();
        snapshot_decision!(decision);
    }

    #[parameterized(
        alice_allow = {"alice" },
        bob_deny = {"bob" }
    )]
    fn test_only_here_policy(username: &str) {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_ACTION_ONLY_HERE).unwrap();
        let request = Request {
            principal: Principal::User(User::new(username, None, None)),
            action: Action::new("only_here", None),
            resource: Resource::new("Photo", "irrelevant_photo.jpg")
                .with_attr("name", AttrValue::String("irrelevant.example.com".into()))
                .with_attr("ip", AttrValue::Ip("10.0.0.1".into())),
        };

        let decision = engine.evaluate(&request).unwrap();
        snapshot_decision!(decision);
    }

    #[parameterized(
        alice_assign_gateway_allow = { "alice", "assign_gateway", "mygateway" },
        bob_assign_gateway_deny = { "bob", "assign_gateway", "mygateway" },
        alice_assign_gateway_wrong_id_deny = { "alice", "assign_gateway", "wronggateway" },
    )]
    fn test_generic_policies(user: &str, action: &str, resource_id: &str) {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_GENERIC_RESOURCE).unwrap();
        let request = Request {
            principal: Principal::User(User::new(user, None, None)),
            action: Action::new(action, None),
            resource: Resource::new("Gateway", resource_id.to_string()),
        };
        let decision = engine.evaluate(&request).unwrap();
        snapshot_decision!(decision);
    }

    #[parameterized(
        alice_delete_allow = { "alice", "admins", "delete" },
        alice_view_allow = { "alice", "admins", "view" },
        bob_delete_deny = { "bob", "users", "delete" },
        bob_view_allow = { "bob", "users", "view" },
    )]
    fn test_policy_with_groups(user: &str, group: &str, action: &str) {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_GROUPS).unwrap();

        // Convert the resource to the appropriate type
        let resource = Resource::new("Photo", "photo.jpg".to_string());

        let request = Request {
            principal: Principal::User(User::new(user, Some(vec![group.to_string()]), None)),
            action: Action::new(action, None),
            resource,
        };
        let decision = engine.evaluate(&request).unwrap();
        snapshot_decision!(decision);
    }

    #[parameterized(
        admins_delete_allow = { "admins", "delete" },
        admins_view_allow = { "admins", "view" },
        users_view_allow = { "users", "view" },
        users_delete_deny = { "users", "delete" },
    )]
    fn test_group_direct_access(group: &str, action: &str) {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_GROUPS).unwrap();

        // Convert the resource to the appropriate type
        let resource = Resource::new("Photo", "photo.jpg".to_string());

        let request = Request {
            principal: Principal::Group(Group::new(group, None)),
            action: Action::new(action, None),
            resource,
        };

        let decision = engine.evaluate(&request).unwrap();
        snapshot_decision!(decision);
    }

    #[test]
    fn test_policy_by_id() {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_BY_ID).unwrap();
        let request = Request {
            principal: Principal::User(User::new("alice", Some(vec!["admins".to_string()]), None)),
            action: Action::new("view", None),
            resource: Resource::new("Photo", "VacationPhoto94.jpg".to_string()),
        };
        let decision = engine.evaluate(&request).unwrap();
        snapshot_decision!(decision);
    }

    #[parameterized(
        alice_namespace_database_create_allow = { "alice", "create_table", "dbusers", "Database" },
        bob_namespace_database_create_deny = { "bob", "create_table", "dbusers", "Database" },
        bob_namespace_database_view_allow = { "bob", "view_table", "dbusers", "Database" },
        bob_namespace_furniture_allow = { "bob", "create_table", "carpenters", "Furniture" },
        alice_namespace_furniture_deny = { "alice", "create_table", "spectators", "Furniture" },

    )]
    fn test_namespaces(user: &str, action: &str, group: &str, namespace: &str) {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_NAMESPACES).unwrap();
        let request = Request {
            principal: Principal::User(User::new(
                user,
                Some(vec![group.to_string()]),
                Some(vec![namespace.to_string()]),
            )),
            action: Action::new(action, Some(vec![namespace.to_string()])),
            resource: Resource::new(format!("{}::{}", namespace, "Table"), "mytable".to_string()),
        };

        let decision = engine.evaluate(&request).unwrap();
        snapshot_decision!(decision);
    }

    #[parameterized(
        alice_ip_allow_1 = { "192.168.0.1" },
        alice_ip_allow_255 = { "192.168.0.255" },
        alice_ip_deny_wrong_net = { "10.0.0.1" },
        alice_ip_allow_same_network = { "192.168.0.0/24" }, // The same network is OK
        alice_ip_deny_largernetwork = { "192.168.0.0/23" }, // A larger network is NOT OK
        alice_ip_allow_subnet_of_network = { "192.168.0.0/25" } // A smaller subnet is OK


    )]
    fn test_ip_functionality(ip: &str) {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_IP).unwrap();
        let request = Request {
            principal: Principal::User(User::new("alice", None, None)),
            action: Action::new("create_host", None),
            resource: Resource::new("Host", "host.example.com".to_string())
                .with_attr("ip", AttrValue::Ip(ip.to_string())),
        };

        let decision = engine.evaluate(&request).unwrap();
        snapshot_decision!(decision);
    }

    #[parameterized(
        alice_ip_err_not_ip = { "not.an.ip.address" },
        alice_ip_err_empty = { "" },
    )]
    fn test_ip_functionality_errors(ip: &str) {
        let engine = PolicyEngine::new_from_str(TEST_POLICY_WITH_IP).unwrap();
        let request = Request {
            principal: Principal::User(User::new("alice", None, None)),
            action: Action::new("create_host", None),
            resource: Resource::new("Host", "host.example.com".to_string())
                .with_attr("ip", AttrValue::Ip(ip.to_string())),
        };

        assert!(engine.evaluate(&request).is_err());
    }

    #[test]
    fn test_current_version_hash() {
        let engine = PolicyEngine::new_from_str(TEST_POLICY).unwrap();
        let version = engine.current_version();

        let expected_hash = format!("{:x}", Sha256::digest(TEST_POLICY.as_bytes()));
        assert_eq!(version.hash, expected_hash);
    }

    #[test]
    fn test_policysnapshot_policies() {
        let engine = PolicyEngine::new_from_str(TEST_POLICY).unwrap();
        let snapshot = engine.current_snapshot();
        let policies = snapshot.policy_set();
        assert_eq!(policies.policies().count(), 2);
    }

    #[test]
    fn test_concurrent_evaluation() {
        use std::sync::Arc;
        use std::thread;

        let policies = r#"
            permit (
                principal == User::"alice",
                action == Action::"read",
                resource == Document::"doc1"
            );
        "#;

        let engine = Arc::new(PolicyEngine::new_from_str(policies).unwrap());
        let mut handles = vec![];

        // Spawn 10 threads, each doing 100 evaluations
        for i in 0..10 {
            let engine_clone = Arc::clone(&engine);
            let handle = thread::spawn(move || {
                for _ in 0..100 {
                    let request = Request {
                        principal: Principal::User(User::new("alice", None, None)),
                        action: Action::new("read", None),
                        resource: Resource::new("Document", format!("doc{}", i % 5)),
                    };
                    let decision = engine_clone.evaluate(&request);
                    assert!(decision.is_ok());
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_policy_reload_during_evaluation() {
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let initial_policy = r#"
            permit (
                principal == User::"alice",
                action == Action::"read",
                resource == Document::"doc1"
            );
        "#;

        let updated_policy = r#"
            permit (
                principal == User::"bob",
                action == Action::"write",
                resource == Document::"doc2"
            );
        "#;

        let engine = Arc::new(PolicyEngine::new_from_str(initial_policy).unwrap());
        let engine_eval = Arc::clone(&engine);
        let engine_reload = Arc::clone(&engine);

        // Thread 1: Continuously evaluate
        let eval_handle = thread::spawn(move || {
            for _ in 0..100 {
                let request = Request {
                    principal: Principal::User(User::new("alice", None, None)),
                    action: Action::new("read", None),
                    resource: Resource::new("Document", "doc1"),
                };
                let _ = engine_eval.evaluate(&request);
                thread::sleep(Duration::from_micros(10));
            }
        });

        // Thread 2: Reload policy multiple times
        let reload_handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(5));
            for _ in 0..10 {
                let _ = engine_reload.reload_from_str(updated_policy);
                thread::sleep(Duration::from_millis(10));
            }
        });

        eval_handle.join().unwrap();
        reload_handle.join().unwrap();
    }

    #[test]
    fn test_concurrent_label_registry_access() {
        use std::thread;

        let patterns = vec![("test_label".to_string(), Regex::new(r"test").unwrap())];
        let labeler = RegexLabeler::new("Host", "name", "nameLabels", patterns);

        let label_registry = Arc::new(
            LabelRegistryBuilder::new()
                .add_labeler(Arc::new(labeler))
                .build(),
        );

        let mut handles = vec![];

        // Multiple threads applying labels
        for i in 0..5 {
            let registry = Arc::clone(&label_registry);
            let handle = thread::spawn(move || {
                let mut resource = Resource::new("Host", format!("test-{}", i))
                    .with_attr("name", AttrValue::String(format!("test-{}", i)));

                registry.apply(&mut resource);

                // Verify labels were applied
                if let Some(AttrValue::Set(labels)) = resource.attrs().get("nameLabels") {
                    assert!(!labels.is_empty());
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_error_context_on_invalid_entity() {
        let policies = r#"
            permit (
                principal == User::"alice",
                action == Action::"read",
                resource == Document::"doc1"
            );
        "#;

        let _ = PolicyEngine::new_from_str(policies).unwrap();

        // Create request with malformed principal
        let result = "Invalid::Entity::Structure".parse::<EntityUid>();
        assert!(result.is_err());
    }

    #[test]
    fn test_error_context_on_malformed_policy() {
        let malformed_policy = r#"
            permit (
                principal == User::"alice"
                // Missing comma and rest of policy
        "#;

        let result = PolicyEngine::new_from_str(malformed_policy);
        assert!(result.is_err());

        if let Err(PolicyError::ParseError(msg)) = result {
            assert!(msg.contains("parse") || msg.contains("expected"));
        } else {
            panic!("Expected ParseError");
        }
    }

    #[test]
    fn test_empty_policy_text() {
        let result = PolicyEngine::new_from_str("");
        assert!(result.is_ok());

        let engine = result.unwrap();
        let request = Request {
            principal: Principal::User(User::new("alice", None, None)),
            action: Action::new("read", None),
            resource: Resource::new("Document", "doc1"),
        };

        let decision = engine.evaluate(&request).unwrap();
        assert!(matches!(decision, Decision::Deny { .. }));
    }

    #[test]
    fn test_whitespace_only_policy() {
        let result = PolicyEngine::new_from_str("   \n\t  \n  ");
        assert!(result.is_ok());
    }

    #[test]
    fn test_label_registry_initialization() {
        let patterns1 = vec![("label1".to_string(), Regex::new(r"test1").unwrap())];
        let labeler1 = RegexLabeler::new("Host", "name", "nameLabels", patterns1);

        let label_registry = LabelRegistryBuilder::new()
            .add_labeler(Arc::new(labeler1))
            .build();

        let mut resource = Resource::new("Host", "test1-host")
            .with_attr("name", AttrValue::String("test1-host".into()));

        label_registry.apply(&mut resource);

        if let Some(AttrValue::Set(labels)) = resource.attrs().get("nameLabels") {
            assert_eq!(labels.len(), 1);
        }
    }

    #[test]
    fn test_apply_labels_with_no_labelers() {
        // Test that an empty registry doesn't panic
        let label_registry = LabelRegistryBuilder::new().build();

        let mut resource = Resource::new("Host", "test-host")
            .with_attr("name", AttrValue::String("test-host".into()));

        // Should not panic with no labelers
        label_registry.apply(&mut resource);

        // Verify no labels were added
        assert!(resource.attrs().get("nameLabels").is_none());
    }

    #[test]
    fn test_label_registry_replacement() {
        let patterns1 = vec![("old_label".to_string(), Regex::new(r"old").unwrap())];
        let labeler1 = RegexLabeler::new("Host", "name", "nameLabels", patterns1);

        let label_registry = LabelRegistryBuilder::new()
            .add_labeler(Arc::new(labeler1))
            .build();

        let patterns2 = vec![("new_label".to_string(), Regex::new(r"new").unwrap())];
        let labeler2 = RegexLabeler::new("Host", "name", "nameLabels", patterns2);

        // Replace labelers via reload
        label_registry.reload(vec![Arc::new(labeler2)]);

        let mut resource = Resource::new("Host", "new-host")
            .with_attr("name", AttrValue::String("new-host".into()));

        label_registry.apply(&mut resource);

        if let Some(AttrValue::Set(labels)) = resource.attrs().get("nameLabels") {
            // Should have new_label, not old_label
            let has_new = labels.iter().any(|l| {
                if let AttrValue::String(s) = l {
                    s == "new_label"
                } else {
                    false
                }
            });
            assert!(has_new);
        }
    }

    #[test]
    fn test_large_policy_set() {
        // Generate 100 policies
        let mut policies = String::new();
        for i in 0..100 {
            policies.push_str(&format!(
                r#"
                permit (
                    principal == User::"user{}",
                    action == Action::"read",
                    resource == Document::"doc{}"
                );
                "#,
                i, i
            ));
        }

        let engine = PolicyEngine::new_from_str(&policies).unwrap();

        // Test evaluation still works
        let request = Request {
            principal: Principal::User(User::new("user50", None, None)),
            action: Action::new("read", None),
            resource: Resource::new("Document", "doc50"),
        };

        let decision = engine.evaluate(&request).unwrap();
        assert!(matches!(decision, Decision::Allow { .. }));
    }

    #[test]
    fn test_deeply_nested_namespaces() {
        let policies = r#"
            permit (
                principal == A::B::C::D::E::User::"alice",
                action == A::B::C::D::E::Action::"read",
                resource == A::B::C::D::E::Document::"doc1"
            );
        "#;

        let engine = PolicyEngine::new_from_str(policies).unwrap();

        let request = Request {
            principal: Principal::User(User::new(
                "alice",
                None,
                Some(vec![
                    "A".into(),
                    "B".into(),
                    "C".into(),
                    "D".into(),
                    "E".into(),
                ]),
            )),
            action: Action::new(
                "read",
                Some(vec![
                    "A".into(),
                    "B".into(),
                    "C".into(),
                    "D".into(),
                    "E".into(),
                ]),
            ),
            resource: Resource::new("A::B::C::D::E::Document", "doc1"),
        };

        let decision = engine.evaluate(&request).unwrap();
        assert!(matches!(decision, Decision::Allow { .. }));
    }

    #[test]
    fn test_resource_with_many_attributes() {
        let policies = r#"
            permit (
                principal == User::"alice",
                action == Action::"read",
                resource is Document
            );
        "#;

        let engine = PolicyEngine::new_from_str(policies).unwrap();

        // Create resource with 50 attributes
        let mut resource = Resource::new("Document", "doc1");
        for i in 0..50 {
            resource = resource.with_attr(
                format!("attr{}", i),
                AttrValue::String(format!("value{}", i)),
            );
        }

        let request = Request {
            principal: Principal::User(User::new("alice", None, None)),
            action: Action::new("read", None),
            resource,
        };

        let decision = engine.evaluate(&request).unwrap();
        assert!(matches!(decision, Decision::Allow { .. }));
    }

    #[test]
    fn test_user_with_many_groups() {
        let policies = r#"
            permit (
                principal in Group::"group25",
                action == Action::"read",
                resource == Document::"doc1"
            );
        "#;

        let engine = PolicyEngine::new_from_str(policies).unwrap();

        // Create user in 50 groups
        let groups: Vec<String> = (0..50).map(|i| format!("group{}", i)).collect();

        let request = Request {
            principal: Principal::User(User::new("alice", Some(groups), None)),
            action: Action::new("read", None),
            resource: Resource::new("Document", "doc1"),
        };

        let decision = engine.evaluate(&request).unwrap();
        assert!(matches!(decision, Decision::Allow { .. }));
    }

    #[test]
    fn test_policy_version_changes_on_reload() {
        let policy1 = r#"
            permit (
                principal == User::"alice",
                action == Action::"read",
                resource == Document::"doc1"
            );
        "#;

        let policy2 = r#"
            permit (
                principal == User::"bob",
                action == Action::"write",
                resource == Document::"doc2"
            );
        "#;

        let engine = PolicyEngine::new_from_str(policy1).unwrap();
        let version1 = engine.current_version();

        engine.reload_from_str(policy2).unwrap();
        let version2 = engine.current_version();

        assert_ne!(version1.hash, version2.hash);
        assert_ne!(version1.loaded_at, version2.loaded_at);
    }

    #[test]
    fn test_decision_includes_correct_version() {
        let policies = r#"
            permit (
                principal == User::"alice",
                action == Action::"read",
                resource == Document::"doc1"
            );
        "#;

        let engine = PolicyEngine::new_from_str(policies).unwrap();
        let engine_version = engine.current_version();

        let request = Request {
            principal: Principal::User(User::new("alice", None, None)),
            action: Action::new("read", None),
            resource: Resource::new("Document", "doc1"),
        };

        let decision = engine.evaluate(&request).unwrap();

        match decision {
            Decision::Allow { version, .. } => {
                assert_eq!(version.hash, engine_version.hash);
            }
            Decision::Deny { .. } => panic!("Expected Allow"),
        }
    }

    #[test]
    fn test_multiple_snapshots_share_data() {
        let policies = r#"
            permit (
                principal == User::"alice",
                action == Action::"read",
                resource == Document::"doc1"
            );
        "#;

        let engine1 = PolicyEngine::new_from_str(policies).unwrap();
        let engine2 = engine1.clone();

        let version1 = engine1.current_version();
        let version2 = engine2.current_version();

        // Both clones should share the same snapshot
        assert_eq!(version1.hash, version2.hash);
        assert_eq!(version1.loaded_at, version2.loaded_at);
    }

    #[test]
    fn test_snapshot_immutable_after_reload() {
        let policy1 = r#"
            permit (
                principal == User::"alice",
                action == Action::"read",
                resource == Document::"doc1"
            );
        "#;

        let policy2 = r#"
            permit (
                principal == User::"bob",
                action == Action::"write",
                resource == Document::"doc2"
            );
        "#;

        let engine = PolicyEngine::new_from_str(policy1).unwrap();
        let snapshot1 = engine.current_snapshot();
        let version1 = snapshot1.version();

        engine.reload_from_str(policy2).unwrap();

        // Old snapshot should still have old version
        let still_version1 = snapshot1.version();
        assert_eq!(version1.hash, still_version1.hash);

        // New snapshot should have new version
        let snapshot2 = engine.current_snapshot();
        let version2 = snapshot2.version();
        assert_ne!(version1.hash, version2.hash);
    }

    #[test]
    fn test_multiple_policies_captured() {
        // Test that when multiple policies match, all are captured in the Decision
        let policies = r#"
            permit (
                principal,
                action == Action::"read",
                resource == Document::"public"
            );
            
            permit (
                principal == User::"alice",
                action,
                resource
            );
        "#;

        let engine = PolicyEngine::new_from_str(policies).unwrap();

        // Alice reading public document should match both policies
        let request = Request {
            principal: Principal::User(User::new("alice", None, None)),
            action: Action::new("read", None),
            resource: Resource::new("Document", "public"),
        };

        let decision = engine.evaluate(&request).unwrap();

        match decision {
            Decision::Allow { policies, .. } => {
                assert_eq!(
                    policies.len(),
                    2,
                    "Should have captured both matching policies"
                );
                // Both policy0 and policy1 should be present
                let policy_ids: Vec<_> = policies.iter().map(|p| p.cedar_id.as_str()).collect();
                assert!(policy_ids.contains(&"policy0"), "Should contain policy0");
                assert!(policy_ids.contains(&"policy1"), "Should contain policy1");
            }
            Decision::Deny { .. } => panic!("Expected Allow decision"),
        }
    }
}
