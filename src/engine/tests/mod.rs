use std::str::FromStr;

use super::*;
use crate::labels::{LabelRegistryBuilder, RegexLabeler};
use crate::snapshot_decision;
use crate::types::AttrValue;
use crate::types::{Decision::Allow, Decision::Deny, Group, Resource};
use crate::{Action, PolicyEffectFilter, PolicyMatchReason, User};
use cedar_policy::{EntityUid, Schema};
use regex::Regex;
use yare::parameterized;

mod reload;
mod schema;

macro_rules! snapshot_decision_engine {
    ($decision:expr) => {{
        let mut settings = insta::Settings::clone_current();
        settings.set_snapshot_path("../../snapshots");
        settings.bind(|| {
            snapshot_decision!($decision);
        });
    }};
}

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

const TEST_SCHEMA: &str = r#"
entity User;
entity Group;
entity Document {
    id: String,
    sensitivity: Long
};

action "read" appliesTo {
    principal: [User],
    resource: [Document],
};
"#;

const TEST_SCHEMA_POLICY: &str = r#"
permit (
    principal == User::"alice",
    action == Action::"read",
    resource is Document
);
"#;

const TEST_SCHEMA_WRITE: &str = r#"
entity User;
entity Group;
entity Document {
    id: String,
    sensitivity: Long
};

action "write" appliesTo {
    principal: [User],
    resource: [Document],
};
"#;

const TEST_SCHEMA_POLICY_WRITE: &str = r#"
permit (
    principal == User::"alice",
    action == Action::"write",
    resource is Document
);
"#;

#[derive(Clone)]
struct SharedLogBuffer(Arc<std::sync::Mutex<Vec<u8>>>);

struct SharedLogWriter(Arc<std::sync::Mutex<Vec<u8>>>);

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedLogBuffer {
    type Writer = SharedLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SharedLogWriter(Arc::clone(&self.0))
    }
}

impl std::io::Write for SharedLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn engine_from_policy(policy_text: &str) -> PolicyEngine {
    PolicyEngine::new_from_str(policy_text).expect("policy should load")
}

fn schema_engine_from_policy(policy_text: &str, schema_text: &str) -> PolicyEngine {
    PolicyEngine::new_from_str_with_cedarschema(policy_text, schema_text)
        .expect("schema + policy should load")
}

fn user_request(user: &str, action: &str, resource: Resource) -> Request {
    Request {
        principal: Principal::User(User::new(user, None, None)),
        action: Action::new(action, None),
        resource,
    }
}

fn group_request(group: &str, action: &str, resource: Resource) -> Request {
    Request {
        principal: Principal::Group(Group::new(group, None)),
        action: Action::new(action, None),
        resource,
    }
}

fn document_with_sensitivity(id: &str, sensitivity: i64) -> Resource {
    Resource::new("Document", id).with_attr("sensitivity", AttrValue::Long(sensitivity))
}

fn assert_allow(decision: &Decision) {
    assert!(matches!(decision, Decision::Allow { .. }));
}

fn assert_deny(decision: &Decision) {
    assert!(matches!(decision, Decision::Deny { .. }));
}

include!("core.rs");
include!("evaluate.rs");
include!("listing.rs");
