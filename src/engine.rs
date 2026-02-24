use cedar_policy::{
    Authorizer, Entities, Entity, Policy, PolicyId, PolicySet, Request as CedarRequest, Schema,
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
    schema: Option<Arc<Schema>>,
}

/// Convenience alias for a shared policy snapshot.
type Snapshot = Arc<PolicySnapshot>;

impl PolicySnapshot {
    fn from_policy_text(policy_text: &str) -> Result<Self, PolicyError> {
        Self::from_policy_text_with_schema(policy_text, None)
    }

    fn from_policy_text_with_schema(
        policy_text: &str,
        schema: Option<Arc<Schema>>,
    ) -> Result<Self, PolicyError> {
        let set = match schema.as_deref() {
            Some(schema) => loader::compile_policy_with_schema(policy_text, schema)?,
            None => loader::compile_policy(policy_text)?,
        };
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
            schema,
        })
    }

    fn policy_set(&self) -> &PolicySet {
        &self.set
    }

    fn version(&self) -> PolicyVersion {
        self.version.clone()
    }

    fn schema(&self) -> Option<&Schema> {
        self.schema.as_deref()
    }
}

/// Extract all permit policies from the Cedar authorization result.
#[inline]
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
#[inline]
fn request_groups(request: &Request) -> Option<&Groups> {
    match &request.principal {
        Principal::User(user) => Some(user.groups()),
        Principal::Group(_) => None,
    }
}

/// Apply label augmentations to a resource.
#[inline]
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
#[inline]
fn build_cedar_req(
    principal_uid: &cedar_policy::EntityUid,
    action_uid: &cedar_policy::EntityUid,
    resource_uid: &cedar_policy::EntityUid,
    context: &cedar_policy::Context,
    schema: Option<&Schema>,
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
        schema,
    )?)
}

/// Build Cedar entities for the principal, resource, and groups.
/// UIDs should be pre-converted to avoid redundant conversions.
#[inline]
fn build_entities(
    principal_uid: &cedar_policy::EntityUid,
    resource_uid: &cedar_policy::EntityUid,
    resource: &crate::types::Resource,
    groups: Option<&Groups>,
    schema: Option<&Schema>,
    timers: &mut EvalTimers,
) -> Result<Entities, PolicyError> {
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

        // Construct group entities and batch all entities into a single call
        let mut all_entities = vec![principal_entity, resource_entity];
        all_entities.extend(group_uids.into_iter().map(Entity::with_uid));

        // Combine all entities in a single call to reduce overhead
        Entities::empty().add_entities(all_entities, schema)?
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

    /// Create a new policy engine with schema-based policy and request validation.
    pub fn new_from_str_with_schema(
        policy_text: &str,
        schema: Schema,
    ) -> Result<Self, PolicyError> {
        let snapshot: Snapshot = Arc::new(PolicySnapshot::from_policy_text_with_schema(
            policy_text,
            Some(Arc::new(schema)),
        )?);
        Ok(PolicyEngine {
            inner: Arc::new(ArcSwap::from(Arc::new(snapshot))),
            label_registry: None,
        })
    }

    /// Create a new policy engine from policy text and Cedar schema text.
    pub fn new_from_str_with_cedarschema(
        policy_text: &str,
        schema_text: &str,
    ) -> Result<Self, PolicyError> {
        let schema: Schema = schema_text
            .parse()
            .map_err(|e| PolicyError::ParseError(format!("failed to parse Cedar schema: {e}")))?;
        Self::new_from_str_with_schema(policy_text, schema)
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
        let current_snapshot = self.current_snapshot();
        let had_schema = current_snapshot.schema.is_some();
        let schema = current_snapshot.schema.clone();
        let new_snapshot: Snapshot = Arc::new(PolicySnapshot::from_policy_text_with_schema(
            policy_text,
            schema,
        )?);
        self.inner.store(Arc::new(new_snapshot));
        debug!(
            event = "PolicyReload",
            schema_enabled = had_schema,
            schema_reloaded = false
        );
        // Track reloads for metrics (no-op if feature disabled or no sink configured)
        #[cfg(feature = "observability")]
        record_reload();
        Ok(())
    }

    /// Reload policies and replace the engine schema at the same time.
    pub fn reload_from_str_with_schema(
        &self,
        policy_text: &str,
        schema: Schema,
    ) -> Result<(), PolicyError> {
        let had_schema = self.current_snapshot().schema.is_some();
        let new_snapshot: Snapshot = Arc::new(PolicySnapshot::from_policy_text_with_schema(
            policy_text,
            Some(Arc::new(schema)),
        )?);
        self.inner.store(Arc::new(new_snapshot));
        debug!(
            event = "PolicyReload",
            schema_enabled = true,
            schema_reloaded = true,
            schema_previously_enabled = had_schema
        );
        // Track reloads for metrics (no-op if feature disabled or no sink configured)
        #[cfg(feature = "observability")]
        record_reload();
        Ok(())
    }

    /// Reload policies and replace the engine schema from Cedar schema text.
    pub fn reload_from_str_with_cedarschema(
        &self,
        policy_text: &str,
        schema_text: &str,
    ) -> Result<(), PolicyError> {
        let schema: Schema = schema_text
            .parse()
            .map_err(|e| PolicyError::ParseError(format!("failed to parse Cedar schema: {e}")))?;
        self.reload_from_str_with_schema(policy_text, schema)
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
        let schema = snapshot.schema();
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
            schema,
            &mut timers,
        )?;

        // Build entities with pre-converted UIDs and potentially-modified resource
        let entities = build_entities(
            &principal_uid,
            &resource_uid,
            &resource_for_entities,
            groups,
            schema,
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
mod tests;
