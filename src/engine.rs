use cedar_policy::{
    Authorizer, Entities, Entity, EntityUid, Policy, PolicySet, PrincipalConstraint,
    Request as CedarRequest,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Instant, SystemTime};
use std::vec;

use crate::labels::LabelRegistry;
use crate::traits::CedarAtom;
use crate::types::{
    Decision, FromDecisionWithPolicy, PermitPolicy, PolicyVersion, Request, UserPolicies,
};
use crate::{Groups, Principal};
use crate::{error::PolicyError, loader};
use arc_swap::ArcSwap;

use sha2::{Digest, Sha256};
#[cfg(feature = "observability")]
use tracing::info_span;
use tracing::{debug, info, warn};

#[cfg(feature = "observability")]
use crate::metrics::{
    EvaluationPhases, EvaluationStats, record_evaluation, record_evaluation_phases, record_reload,
};

/// Immutable snapshot of a compiled policy set, along with metadata.
#[derive(Debug)]
struct PolicySnapshot {
    set: PolicySet,
    version: PolicyVersion,
}

/// Convenience alias for a shared policy snapshot.
type Snapshot = Arc<PolicySnapshot>;

impl PolicySnapshot {
    fn from_policy_text(policy_text: &str) -> Result<Self, PolicyError> {
        let set = loader::compile_policy(policy_text)?;

        let mut hasher = Sha256::new();
        hasher.update(policy_text.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        Ok(PolicySnapshot {
            set,
            version: PolicyVersion {
                hash,
                loaded_at: humantime::format_rfc3339(SystemTime::now()).to_string(),
            },
        })
    }

    fn policy_set(&self) -> &PolicySet {
        &self.set
    }

    fn version(&self) -> PolicyVersion {
        self.version.clone()
    }
}

/// Immutable snapshot of engine state: policies and label registry frozen together.
///
/// This guarantees consistent evaluation semantics across a batch of requests.
/// All requests evaluated against the same `EngineSnapshot` see the exact same
/// policy version and labeling rules.
///
/// The snapshot captures the actual labeler list at the moment of creation,
/// not just a pointer to the registry. This ensures true immutability even if
/// the engine's label registry is later modified via `reload()`.
#[derive(Clone)]
pub struct EngineSnapshot {
    snapshot: Snapshot,
    labelers: Option<Arc<Vec<Arc<dyn crate::labels::Labeler>>>>,
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
    ///
    /// # Thread Safety
    ///
    /// This method requires `&mut self` and is **not thread-safe** for concurrent updates.
    /// It's intended for single-threaded setup/configuration before sharing the engine.
    ///
    /// For runtime label updates in a multithreaded context, use
    /// [`LabelRegistry::reload()`](crate::labels::LabelRegistry::reload) on the
    /// registry itself, which atomically swaps labelers using `Arc` and ensures
    /// thread-safe updates. Note that `reload()` only affects new snapshots;
    /// existing snapshots remain frozen with their original labelers.
    ///
    /// # Example
    ///
    /// ```rust
    /// use treetop_core::{PolicyEngine, LabelRegistryBuilder};
    ///
    /// let mut engine = PolicyEngine::new_from_str("permit(principal,action,resource);").unwrap();
    ///
    /// // Setup during initialization (single-threaded)
    /// let registry = LabelRegistryBuilder::new().build();
    /// engine.set_label_registry(registry);
    /// ```
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

    /// Capture an immutable snapshot of the engine's current state.
    ///
    /// The snapshot freezes both policies and label registry, guaranteeing
    /// consistent evaluation semantics for batch processing.
    ///
    /// # Immutability Guarantee
    ///
    /// The snapshot captures the actual labeler list at the moment of creation,
    /// not just a reference to the mutable `LabelRegistry`. This means:
    ///
    /// - If you call [`LabelRegistry::reload()`](crate::labels::LabelRegistry::reload)
    ///   after creating a snapshot, the snapshot continues using its original labelers
    /// - Multiple snapshots can coexist with different labeler sets
    /// - Snapshots are truly immutable and safe to share across threads
    ///
    /// # Example
    /// ```rust,no_run
    /// # use treetop_core::{PolicyEngine, Request};
    /// # let engine = PolicyEngine::new_from_str("permit(principal,action,resource);").unwrap();
    /// # let requests: Vec<Request> = vec![];
    /// let snapshot = engine.snapshot();
    /// let results: Vec<_> = requests
    ///     .iter()
    ///     .map(|req| snapshot.evaluate(req))
    ///     .collect();
    /// // All evaluations used the same policy version and labels
    /// ```
    pub fn snapshot(&self) -> EngineSnapshot {
        EngineSnapshot {
            snapshot: self.current_snapshot(),
            labelers: self
                .label_registry
                .as_ref()
                .map(|reg| reg.snapshot_labelers()),
        }
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
    pub fn evaluate(&self, request: &Request) -> Result<Decision, PolicyError> {
        self.snapshot().evaluate(request)
    }

    /// List all policies that may apply to a given user (optionally namespaced).
    ///
    /// This is useful for diagnostics and tooling that want to show or export
    /// effective policies for a principal. It matches `principal == User::..`
    /// and `principal == Any` constraints.
    pub fn list_policies_for_user(
        &self,
        user: &str,
        namespace: Vec<String>,
    ) -> Result<UserPolicies, PolicyError> {
        let snapshot = self.current_snapshot();
        let policies = snapshot.set.policies();

        // Join the user and then namespace into a ::-separated string
        let user_with_namespace = if namespace.is_empty() {
            format!("User::\"{user}\"")
        } else {
            format!("User::\"{}\"::{}", namespace.join("::"), user)
        };

        let uid: EntityUid = user_with_namespace.parse()?;

        let mut matching_policies: Vec<Policy> = Vec::new();

        for policy in policies {
            // Check if the policy applies to the user
            let pc = policy.principal_constraint();
            if pc == PrincipalConstraint::Eq(uid.clone()) || pc == PrincipalConstraint::Any {
                matching_policies.push(policy.clone());
            }
        }

        Ok(UserPolicies::new(user, &matching_policies))
    }

    pub fn policies(&self) -> Result<Vec<Policy>, PolicyError> {
        let snapshot = self.current_snapshot();
        Ok(snapshot.policy_set().policies().cloned().collect())
    }
}

impl EngineSnapshot {
    /// Evaluate a request against this immutable snapshot.
    ///
    /// Uses the policies and label registry frozen at snapshot creation time,
    /// guaranteeing consistent results across a batch of evaluations.
    pub fn evaluate(&self, request: &Request) -> Result<Decision, PolicyError> {
        // Top-level span for OpenTelemetry integration (only when observability feature enabled)
        #[cfg(feature = "observability")]
        let span = info_span!(
            "policy_evaluation",
            principal = %request.principal,
            action = %request.action,
            resource = %request.resource,
        );
        #[cfg(feature = "observability")]
        let _guard = span.enter();

        let schema: Option<&cedar_policy::Schema> = None;

        let groups = match &request.principal {
            Principal::User(user) => user.groups().clone(),
            Principal::Group(_) => Groups::default(),
        };

        let now = Instant::now();
        let snapshot = &self.snapshot;
        let version = snapshot.version();

        debug!(
            event = "Request",
            phase = "Evaluation",
            principal = request.principal.to_string(),
            action = request.action.to_string(),
            resource = request.resource.to_string(),
            groups = groups.to_string()
        );

        // resource is &request.resource; take a working copy so we can mutate attrs with labels
        let mut resource_dyn = request.resource.clone();

        // Apply labels from the frozen labeler list
        let labels_start = Instant::now();
        {
            #[cfg(feature = "observability")]
            let _label_span = info_span!("apply_labels").entered();

            if let Some(labelers) = &self.labelers {
                let kind_owned = resource_dyn.kind().to_owned();
                for labeler in labelers.iter() {
                    if labeler.applies_to(&kind_owned) {
                        labeler.apply(&mut resource_dyn);
                    }
                }
            }
        }
        let labels_duration = labels_start.elapsed();
        debug!(
            event = "Request",
            phase = "LabelsApplied",
            time = labels_duration.as_micros(),
            resource_attrs = ?resource_dyn.attrs()
        );

        // Build resource entity from the (now augmented) attrs

        // 1. Turn your Atom types into EntityUids (the "P, A, R" in PARC)
        let entities_start = Instant::now();
        #[cfg(feature = "observability")]
        let _entity_span = info_span!("construct_entities").entered();
        let principal: EntityUid = request.principal.cedar_entity_uid()?;
        let action: EntityUid = request.action.cedar_entity_uid()?;
        let resource: EntityUid = resource_dyn.cedar_entity_uid()?;
        let resource_attrs = resource_dyn.cedar_attr()?;

        // 2. Build a Context from the labeled resource (in case context depends on derived attrs)
        let context = resource_dyn.cedar_ctx()?;

        debug!(
            event = "Request",
            phase = "Parsed",
            principal = principal.to_string(),
            action = action.to_string(),
            resource = resource.to_string(),
            context = context.to_string(),
            groups = groups.to_string(),
            attrs = ?resource_attrs
        );

        #[cfg(feature = "observability")]
        drop(_entity_span);

        let entities_duration = entities_start.elapsed();

        // 3. Create the Cedar request
        let cedar_req = CedarRequest::new(principal.clone(), action, resource, context, None)?;

        // 4. Create Entities for the request
        #[cfg(feature = "observability")]
        let _groups_span = info_span!("resolve_groups").entered();
        let groups_start = Instant::now();
        // 4a. Create EntityUids for each group
        let mut group_uids = HashSet::new();
        for group in groups.clone() {
            let g = group.cedar_entity_uid()?;
            group_uids.insert(g);
        }
        #[cfg(feature = "observability")]
        drop(_groups_span);
        let groups_duration = groups_start.elapsed();

        debug!(
            event = "Request",
            phase = "GroupsResolved",
            time = groups_duration.as_micros(),
            group_uids = ?group_uids
        );

        // 4b. Create an Entity for the principal, with the EntityUid of those groups as parents
        let principal_entity = Entity::new(principal.clone(), HashMap::new(), group_uids.clone())?;

        // 4c. Create Entities for each group out of the EntityUids we created in 4a
        let group_entities: Vec<Entity> = group_uids.into_iter().map(Entity::with_uid).collect();

        // 5. Create the complete Entities collection, including the resource, principal, and groups
        let entities = Entities::empty()
            .add_entities(vec![resource_dyn.cedar_entity()?, principal_entity], schema)?
            .add_entities(group_entities, schema)?;

        debug!(
            event = "Request",
            phase = "Entities",
            time = entities_duration.as_micros(),
            entities = entities
                .iter()
                .map(|e| format!("[{e}]"))
                .collect::<Vec<_>>()
                .join(", ")
                .replace('\n', "")
        );

        // 6. Run the authorizer against the current immutable snapshot
        #[cfg(feature = "observability")]
        let _authz_span = info_span!("authorize").entered();
        let authz_start = Instant::now();
        let result = Authorizer::new().is_authorized(&cedar_req, &snapshot.set, &entities);
        #[cfg(feature = "observability")]
        drop(_authz_span);
        let authz_duration = authz_start.elapsed();

        debug!(
            event = "Request",
            phase = "Authorized",
            time = authz_duration.as_micros(),
            decision = ?result.decision(),
        );

        debug!(
            event = "Request",
            phase = "Result",
            time = now.elapsed().as_micros(),
            result = ?result.decision(),
            policy_hash = %version.hash,
            policy_loaded_at = %version.loaded_at,
        );
        let mut permit_policy = PermitPolicy::default();

        if result.decision() == cedar_policy::Decision::Allow {
            let reasons = result.diagnostics().reason();
            for reason in reasons {
                let policy = snapshot.set.policy(reason);
                if let Some(policy) = policy {
                    permit_policy.literal = policy.to_string().clone();
                    permit_policy.json = policy.to_json().unwrap_or_default();
                    info!(
                        event = "Request",
                        phase = "Policy",
                        reason = reason.to_string(),
                        policy = permit_policy.literal
                    );
                } else {
                    warn!(
                        event = "Request",
                        phase = "Policy",
                        reason = reason.to_string()
                    );
                }
            }
        }

        // Record metrics (no-op when no sink is configured, or when feature is disabled)
        #[cfg(feature = "observability")]
        {
            let dur = now.elapsed();
            let allowed = result.decision() == cedar_policy::Decision::Allow;
            let principal_id = request.principal.to_string();
            let action_id = request.action.to_string();
            let stats = EvaluationStats {
                duration: dur,
                allowed,
                principal_id,
                action_id,
            };

            // Also record detailed phase timings
            let phases = EvaluationPhases {
                apply_labels_ms: labels_duration.as_secs_f64() * 1000.0,
                construct_entities_ms: entities_duration.as_secs_f64() * 1000.0,
                resolve_groups_ms: groups_duration.as_secs_f64() * 1000.0,
                authorize_ms: authz_duration.as_secs_f64() * 1000.0,
                total_ms: stats.duration.as_secs_f64() * 1000.0,
            };

            record_evaluation(&stats);
            record_evaluation_phases(&stats, &phases);
        }

        Ok(Decision::from_decision_with_policy(
            result.decision(),
            permit_policy,
            version,
        ))
    }

    /// List all policies that may apply to a given user (optionally namespaced).
    ///
    /// This is useful for diagnostics and tooling that want to show or export
    /// effective policies for a principal. It matches `principal == User::..`
    /// and `principal == Any` constraints.
    pub fn list_policies_for_user(
        &self,
        user: &str,
        namespace: Vec<String>,
    ) -> Result<UserPolicies, PolicyError> {
        let policies = self.snapshot.set.policies();

        let user_with_namespace = if namespace.is_empty() {
            format!("User::\"{user}\"")
        } else {
            format!("User::\"{}\"::{}", namespace.join("::"), user)
        };

        let uid: EntityUid = user_with_namespace.parse()?;

        let mut matching_policies: Vec<Policy> = Vec::new();

        for policy in policies {
            let pc = policy.principal_constraint();
            if pc == PrincipalConstraint::Eq(uid.clone()) || pc == PrincipalConstraint::Any {
                matching_policies.push(policy.clone());
            }
        }

        Ok(UserPolicies::new(user, &matching_policies))
    }

    pub fn policies(&self) -> Result<Vec<Policy>, PolicyError> {
        Ok(self.snapshot.policy_set().policies().cloned().collect())
    }

    /// Policy version for this snapshot.
    pub fn version(&self) -> PolicyVersion {
        self.snapshot.version()
    }

    /// Access the policy set for inspection or diagnostics.
    pub fn policy_set(&self) -> &PolicySet {
        self.snapshot.policy_set()
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
    use crate::{Action, User};
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
        namespaces: Vec<String>,
        expected_policies: usize,
        expected_actions: Vec<&str>,
    ) {
        let engine = PolicyEngine::new_from_str(TEST_PERMISSION_POLICY).unwrap();
        let user_policies = engine
            .list_policies_for_user(user, namespaces)
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
        let perms = engine.list_policies_for_user("alice", vec![]).unwrap();

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
    fn test_snapshot_without_labels_remains_independent() {
        // Policy that uses labels
        let policies = r#"
            permit (
                principal == User::"alice",
                action == Action::"read",
                resource is Host
            ) when {
                resource.tags.contains("allowed")
            };
        "#;

        // Engine starts without any label registry
        let engine = PolicyEngine::new_from_str(policies).unwrap();
        let snapshot1 = engine.snapshot();

        // Add a label registry to the engine
        let patterns = vec![("allowed".to_string(), Regex::new(r".*").unwrap())];
        let labeler = RegexLabeler::new("Host", "name", "tags", patterns);
        let label_registry = LabelRegistryBuilder::new()
            .add_labeler(Arc::new(labeler))
            .build();
        let engine = engine.with_label_registry(label_registry);

        let request = Request {
            principal: Principal::User(User::new("alice", None, None)),
            action: Action::new("read", None),
            resource: Resource::new("Host", "any-host")
                .with_attr("name", AttrValue::String("any-host".into())),
        };

        // Snapshot without labels should deny
        let snapshot_decision = snapshot1.evaluate(&request).unwrap();
        assert!(
            matches!(snapshot_decision, Decision::Deny { .. }),
            "Snapshot without labels should deny"
        );

        // Engine with labels should allow
        let engine_decision = engine.evaluate(&request).unwrap();
        assert!(
            matches!(engine_decision, Decision::Allow { .. }),
            "Engine with labels should allow"
        );

        // New snapshot should also allow
        let snapshot2 = engine.snapshot();
        let snapshot2_decision = snapshot2.evaluate(&request).unwrap();
        assert!(
            matches!(snapshot2_decision, Decision::Allow { .. }),
            "New snapshot with labels should allow"
        );
    }

    #[test]
    fn test_snapshot_truly_frozen_despite_registry_reload() {
        // This test verifies that EngineSnapshot captures the actual labeler list,
        // not just a pointer to the mutable LabelRegistry. When the registry is
        // reloaded, old snapshots should continue using their original labelers.

        let policies = r#"
            permit (
                principal == User::"alice",
                action == Action::"access",
                resource is Host
            ) when {
                resource.tags.contains("v1")
            };
        "#;

        // Create initial label registry that tags everything with "v1"
        let patterns1 = vec![("v1".to_string(), Regex::new(r".*").unwrap())];
        let labeler1 = RegexLabeler::new("Host", "name", "tags", patterns1);
        let label_registry = LabelRegistryBuilder::new()
            .add_labeler(Arc::new(labeler1))
            .build();

        let engine = PolicyEngine::new_from_str(policies)
            .unwrap()
            .with_label_registry(label_registry);

        // Take snapshot with v1 labelers
        let snapshot1 = engine.snapshot();

        // Reload the label registry with different tags ("v2" instead of "v1")
        let patterns2 = vec![("v2".to_string(), Regex::new(r".*").unwrap())];
        let labeler2 = RegexLabeler::new("Host", "name", "tags", patterns2);
        if let Some(registry) = engine.label_registry() {
            registry.reload(vec![Arc::new(labeler2)]);
        }

        let request = Request {
            principal: Principal::User(User::new("alice", None, None)),
            action: Action::new("access", None),
            resource: Resource::new("Host", "test-host")
                .with_attr("name", AttrValue::String("test-host".into())),
        };

        // Snapshot1 should still use OLD labelers (v1) - should allow
        let snapshot1_decision = snapshot1.evaluate(&request).unwrap();
        assert!(
            matches!(snapshot1_decision, Decision::Allow { .. }),
            "Snapshot should use frozen v1 labelers, allowing access"
        );

        // Engine should use NEW labelers (v2) - should deny since policy expects "v1"
        let engine_decision = engine.evaluate(&request).unwrap();
        assert!(
            matches!(engine_decision, Decision::Deny { .. }),
            "Engine should use reloaded v2 labelers, denying access"
        );

        // New snapshot should capture current (v2) labelers - should also deny
        let snapshot2 = engine.snapshot();
        let snapshot2_decision = snapshot2.evaluate(&request).unwrap();
        assert!(
            matches!(snapshot2_decision, Decision::Deny { .. }),
            "New snapshot should use v2 labelers, denying access"
        );

        // Verify snapshot1 STILL uses v1 after all this
        let snapshot1_decision_again = snapshot1.evaluate(&request).unwrap();
        assert!(
            matches!(snapshot1_decision_again, Decision::Allow { .. }),
            "Snapshot1 should remain truly frozen with v1 labelers"
        );
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
}
