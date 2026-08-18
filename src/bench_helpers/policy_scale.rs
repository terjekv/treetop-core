//! Deterministic large-policy fixtures shared by Treetop benchmark suites.
//!
//! This module is available only through the non-default `bench-internal`
//! feature. It is intended for tests and benchmarks in this crate and in
//! downstream Treetop components, not for production policy generation.

use std::env;
use std::fmt::Write;

use crate::{Action, AttrValue, Principal, Request, Resource, User};

/// Version of the generated corpus and its target request semantics.
///
/// Benchmark reports should record this value. Increment it when policy shape,
/// schema shape, or one of the target requests changes in a way that makes
/// results incomparable with earlier runs.
pub const CORPUS_VERSION: u32 = 1;

/// Policy count used by pull-request correctness coverage.
pub const PR_SCALE_POLICY_COUNT: usize = 10_000;

/// Default policy count for large scheduled and local measurements.
pub const LARGE_SCALE_POLICY_COUNT: usize = 100_000;

/// Environment variable read by [`configured_policy_count`].
pub const POLICY_COUNT_ENV: &str = "TREETOP_SCALE_POLICY_COUNT";

/// Principal ID used by the target scale requests.
pub const TARGET_USER: &str = "scale_target";

/// Resource ID used by the target scale requests.
pub const TARGET_DOCUMENT: &str = "scale_document";

/// Group ID used by [`group_request`].
pub const REVIEWERS_GROUP: &str = "scale_reviewers";

const SPECIAL_POLICY_COUNT: usize = 4;
const NOISE_ACTION_COUNT: usize = 16;

/// A deterministic Cedar policy corpus and its matching strict schema.
///
/// Generation `0` is the initial snapshot. A different generation changes the
/// IDs of noise principals and policies while preserving the four target
/// request outcomes, making it suitable for atomic-reload measurements.
#[derive(Debug)]
pub struct ScaleCorpus {
    /// Complete Cedar policy text.
    pub policy_text: String,
    /// Cedar schema text that strictly validates `policy_text`.
    pub schema_text: String,
    /// Exact number of policies in `policy_text`.
    pub policy_count: usize,
    /// Generation supplied to [`Self::new`].
    pub generation: usize,
}

impl ScaleCorpus {
    /// Generate a corpus with an exact policy count.
    ///
    /// # Panics
    ///
    /// Panics when `policy_count` is less than four because the shared scenario
    /// requires one allow, one permit overridden by a forbid, and one group
    /// policy before filling the remainder with noise policies.
    pub fn new(policy_count: usize, generation: usize) -> Self {
        assert!(
            policy_count >= SPECIAL_POLICY_COUNT,
            "scale corpus requires at least {SPECIAL_POLICY_COUNT} policies"
        );

        let mut policy_text = String::with_capacity(policy_count.saturating_mul(180));
        policy_text.push_str(
            r#"@id("scale.target.read")
permit (
    principal == User::"scale_target",
    action == Action::"read",
    resource == Document::"scale_document"
) when {
    resource.classification == "public"
};
@id("scale.target.delete_permit")
permit (
    principal == User::"scale_target",
    action == Action::"delete",
    resource == Document::"scale_document"
);
@id("scale.target.delete_forbid")
forbid (
    principal == User::"scale_target",
    action == Action::"delete",
    resource == Document::"scale_document"
);
@id("scale.reviewers.review")
permit (
    principal in Group::"scale_reviewers",
    action == Action::"review",
    resource is Document
);
"#,
        );

        for index in SPECIAL_POLICY_COUNT..policy_count {
            write_noise_policy(&mut policy_text, index, generation);
        }

        Self {
            policy_text,
            schema_text: build_schema_text(),
            policy_count,
            generation,
        }
    }
}

/// Read the selected policy count, defaulting to 100,000.
///
/// # Panics
///
/// Panics when [`POLICY_COUNT_ENV`] is not a positive integer.
pub fn configured_policy_count() -> usize {
    match env::var(POLICY_COUNT_ENV) {
        Ok(raw) => {
            let policy_count = raw.parse::<usize>().unwrap_or_else(|error| {
                panic!("{POLICY_COUNT_ENV} must be a positive integer, got {raw:?}: {error}")
            });
            assert!(policy_count > 0, "{POLICY_COUNT_ENV} must be positive");
            policy_count
        }
        Err(env::VarError::NotPresent) => LARGE_SCALE_POLICY_COUNT,
        Err(error) => panic!("failed to read {POLICY_COUNT_ENV}: {error}"),
    }
}

/// Request allowed by the exact-principal target policy.
pub fn allow_request() -> Request {
    request(None, "read")
}

/// Request denied because a matching forbid overrides a matching permit.
pub fn forbid_request() -> Request {
    request(None, "delete")
}

/// Request allowed through the shared reviewers group.
pub fn group_request() -> Request {
    request(Some(vec![REVIEWERS_GROUP.to_string()]), "review")
}

/// Request that matches no target or generated noise policy.
pub fn no_match_request() -> Request {
    request(None, "noise_00")
}

fn request(groups: Option<Vec<String>>, action: &str) -> Request {
    Request {
        principal: Principal::User(User::new(TARGET_USER, groups, None)),
        action: Action::new(action, None),
        resource: Resource::new("Document", TARGET_DOCUMENT)
            .with_attr("classification", AttrValue::String("public".to_string())),
    }
}

fn write_noise_policy(policy_text: &mut String, index: usize, generation: usize) {
    let effect = if index.is_multiple_of(10) {
        "forbid"
    } else {
        "permit"
    };
    let action = index % NOISE_ACTION_COUNT;
    let resource = index % 2_048;

    writeln!(policy_text, "@id(\"scale.g{generation}.{effect}.{index}\")")
        .expect("writing to a String cannot fail");
    writeln!(policy_text, "{effect} (").expect("writing to a String cannot fail");

    if index.is_multiple_of(13) {
        writeln!(
            policy_text,
            "    principal in Group::\"noise_group_{:02}\",",
            index % 64
        )
        .expect("writing to a String cannot fail");
    } else {
        writeln!(
            policy_text,
            "    principal == User::\"noise_g{generation}_{index}\","
        )
        .expect("writing to a String cannot fail");
    }

    writeln!(policy_text, "    action == Action::\"noise_{action:02}\",")
        .expect("writing to a String cannot fail");

    if index.is_multiple_of(7) {
        writeln!(policy_text, "    resource is Document").expect("writing to a String cannot fail");
        writeln!(policy_text, ") when {{").expect("writing to a String cannot fail");
        writeln!(policy_text, "    resource.classification == \"public\"")
            .expect("writing to a String cannot fail");
        writeln!(policy_text, "}};").expect("writing to a String cannot fail");
    } else {
        writeln!(
            policy_text,
            "    resource == Document::\"noise_document_{resource}\""
        )
        .expect("writing to a String cannot fail");
        writeln!(policy_text, ");").expect("writing to a String cannot fail");
    }
}

fn build_schema_text() -> String {
    let mut schema_text = String::from(
        r#"entity User in [Group];
entity Group;
entity Document {
    id: String,
    classification: String
};
action "read" appliesTo {
    principal: [User],
    resource: [Document]
};
action "delete" appliesTo {
    principal: [User],
    resource: [Document]
};
action "review" appliesTo {
    principal: [User],
    resource: [Document]
};
"#,
    );

    for action in 0..NOISE_ACTION_COUNT {
        writeln!(
            schema_text,
            r#"action "noise_{action:02}" appliesTo {{
    principal: [User],
    resource: [Document]
}};"#
        )
        .expect("writing to a String cannot fail");
    }

    schema_text
}
