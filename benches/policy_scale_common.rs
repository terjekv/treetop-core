use std::env;
use std::fmt::Write;

pub const PR_SCALE_POLICY_COUNT: usize = 10_000;
pub const LARGE_SCALE_POLICY_COUNT: usize = 100_000;
pub const POLICY_COUNT_ENV: &str = "TREETOP_SCALE_POLICY_COUNT";
pub const TARGET_USER: &str = "scale_target";
pub const TARGET_DOCUMENT: &str = "scale_document";
pub const REVIEWERS_GROUP: &str = "scale_reviewers";

const SPECIAL_POLICY_COUNT: usize = 4;
const NOISE_ACTION_COUNT: usize = 16;

pub struct ScaleCorpus {
    pub policy_text: String,
    pub schema_text: String,
    pub policy_count: usize,
}

impl ScaleCorpus {
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
        }
    }
}

pub fn configured_policy_count() -> usize {
    match env::var(POLICY_COUNT_ENV) {
        Ok(raw) => raw.parse::<usize>().unwrap_or_else(|error| {
            panic!("{POLICY_COUNT_ENV} must be a positive integer, got {raw:?}: {error}")
        }),
        Err(env::VarError::NotPresent) => LARGE_SCALE_POLICY_COUNT,
        Err(error) => panic!("failed to read {POLICY_COUNT_ENV}: {error}"),
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
