#![allow(dead_code)]

use regex::Regex;
use std::sync::Arc;
use treetop_core::{
    Action, AttrValue, LabelRegistryBuilder, PolicyEngine, Principal, RegexLabeler, Request,
    Resource, User,
};

#[derive(Debug, Clone, Copy)]
pub struct ScenarioSpec {
    pub name: &'static str,
    pub noise_policies: usize,
    pub groups: usize,
    pub labelers: usize,
    pub deny: bool,
    pub namespace_depth: usize,
}

pub struct Scenario {
    pub name: &'static str,
    pub engine: PolicyEngine,
    pub request: Request,
}

fn namespaced_ref(segments: &[String], type_name: &str, id: &str) -> String {
    if segments.is_empty() {
        format!(r#"{type_name}::"{id}""#)
    } else {
        format!(r#"{}::{type_name}::"{id}""#, segments.join("::"))
    }
}

fn build_policy_text(spec: ScenarioSpec) -> String {
    let namespace: Vec<String> = (0..spec.namespace_depth)
        .map(|idx| format!("Ns{idx}"))
        .collect();

    let allow_action = namespaced_ref(&namespace, "Action", "view_host");
    let target_user = namespaced_ref(&namespace, "User", "target");

    let mut text = String::new();

    // Primary allow rule to keep a stable match path for "allow" scenarios.
    text.push_str(&format!(
        "permit (principal == {target_user}, action == {allow_action}, resource is Host);\n"
    ));

    // Force group-parent checks when groups are part of the scenario.
    if spec.groups > 0 {
        let first_group = namespaced_ref(&namespace, "Group", "group_0");
        text.push_str(&format!(
            "permit (principal in {first_group}, action == {allow_action}, resource is Host);\n"
        ));
    }

    // Add non-matching noise policies to stress policy set scanning.
    for idx in 0..spec.noise_policies {
        let user = namespaced_ref(&namespace, "User", &format!("noise_user_{idx}"));
        let action = namespaced_ref(&namespace, "Action", &format!("noise_action_{idx}"));
        text.push_str(&format!(
            "permit (principal == {user}, action == {action}, resource is Host);\n"
        ));
    }

    text
}

fn build_registry(labelers: usize) -> Option<treetop_core::LabelRegistry> {
    if labelers == 0 {
        return None;
    }

    let mut builder = LabelRegistryBuilder::new();

    for idx in 0..labelers {
        let re1 = Regex::new(r"example\.com$").expect("benchmark regex must compile");
        let re2 = Regex::new(r"^web-").expect("benchmark regex must compile");
        let labeler = RegexLabeler::new(
            "Host",
            "name",
            format!("name_labels_{idx}"),
            vec![
                (format!("domain_match_{idx}"), re1),
                (format!("web_prefix_{idx}"), re2),
            ],
        );

        builder = builder.add_labeler(Arc::new(labeler));
    }

    Some(builder.build())
}

pub fn build_scenario(spec: ScenarioSpec) -> Scenario {
    let namespace: Vec<String> = (0..spec.namespace_depth)
        .map(|idx| format!("Ns{idx}"))
        .collect();

    let policy_text = build_policy_text(spec);
    let mut engine = PolicyEngine::new_from_str(&policy_text).expect("benchmark policy must compile");

    if let Some(registry) = build_registry(spec.labelers) {
        engine = engine.with_label_registry(registry);
    }

    let groups = if spec.groups == 0 {
        None
    } else {
        Some((0..spec.groups).map(|idx| format!("group_{idx}")).collect())
    };

    let action_name = if spec.deny {
        "delete_host"
    } else {
        "view_host"
    };

    let request = Request {
        principal: Principal::User(User::new(
            "target",
            groups,
            if namespace.is_empty() {
                None
            } else {
                Some(namespace.clone())
            },
        )),
        action: Action::new(
            action_name,
            if namespace.is_empty() {
                None
            } else {
                Some(namespace.clone())
            },
        ),
        resource: Resource::new("Host", "web-01.example.com")
            .with_attr("name", AttrValue::String("web-01.example.com".to_string()))
            .with_attr("ip", AttrValue::Ip("10.0.0.42".to_string()))
            .with_attr("env", AttrValue::String("prod".to_string())),
    };

    Scenario {
        name: spec.name,
        engine,
        request,
    }
}

pub fn wide_matrix_specs() -> Vec<ScenarioSpec> {
    vec![
        ScenarioSpec {
            name: "s_small_allow",
            noise_policies: 8,
            groups: 0,
            labelers: 0,
            deny: false,
            namespace_depth: 0,
        },
        ScenarioSpec {
            name: "s_small_deny",
            noise_policies: 8,
            groups: 0,
            labelers: 0,
            deny: true,
            namespace_depth: 0,
        },
        ScenarioSpec {
            name: "m_medium_allow",
            noise_policies: 80,
            groups: 0,
            labelers: 0,
            deny: false,
            namespace_depth: 0,
        },
        ScenarioSpec {
            name: "l_large_allow",
            noise_policies: 400,
            groups: 0,
            labelers: 0,
            deny: false,
            namespace_depth: 0,
        },
        ScenarioSpec {
            name: "m_groups_10",
            noise_policies: 80,
            groups: 10,
            labelers: 0,
            deny: false,
            namespace_depth: 0,
        },
        ScenarioSpec {
            name: "m_groups_40",
            noise_policies: 80,
            groups: 40,
            labelers: 0,
            deny: false,
            namespace_depth: 0,
        },
        ScenarioSpec {
            name: "m_labels_5",
            noise_policies: 80,
            groups: 0,
            labelers: 5,
            deny: false,
            namespace_depth: 0,
        },
        ScenarioSpec {
            name: "m_labels_20",
            noise_policies: 80,
            groups: 0,
            labelers: 20,
            deny: false,
            namespace_depth: 0,
        },
        ScenarioSpec {
            name: "m_labels_20_groups_20",
            noise_policies: 80,
            groups: 20,
            labelers: 20,
            deny: false,
            namespace_depth: 0,
        },
        ScenarioSpec {
            name: "l_labels_20_groups_40",
            noise_policies: 400,
            groups: 40,
            labelers: 20,
            deny: false,
            namespace_depth: 0,
        },
        ScenarioSpec {
            name: "m_namespaced_depth_2",
            noise_policies: 80,
            groups: 10,
            labelers: 5,
            deny: false,
            namespace_depth: 2,
        },
        ScenarioSpec {
            name: "m_namespaced_depth_4_deny",
            noise_policies: 80,
            groups: 10,
            labelers: 5,
            deny: true,
            namespace_depth: 4,
        },
    ]
}

pub fn iai_matrix_specs() -> Vec<ScenarioSpec> {
    vec![
        ScenarioSpec {
            name: "iai_small_allow",
            noise_policies: 8,
            groups: 0,
            labelers: 0,
            deny: false,
            namespace_depth: 0,
        },
        ScenarioSpec {
            name: "iai_small_deny",
            noise_policies: 8,
            groups: 0,
            labelers: 0,
            deny: true,
            namespace_depth: 0,
        },
        ScenarioSpec {
            name: "iai_medium",
            noise_policies: 80,
            groups: 0,
            labelers: 0,
            deny: false,
            namespace_depth: 0,
        },
        ScenarioSpec {
            name: "iai_large",
            noise_policies: 400,
            groups: 0,
            labelers: 0,
            deny: false,
            namespace_depth: 0,
        },
        ScenarioSpec {
            name: "iai_groups_40",
            noise_policies: 80,
            groups: 40,
            labelers: 0,
            deny: false,
            namespace_depth: 0,
        },
        ScenarioSpec {
            name: "iai_labels_20",
            noise_policies: 80,
            groups: 0,
            labelers: 20,
            deny: false,
            namespace_depth: 0,
        },
        ScenarioSpec {
            name: "iai_labels_20_groups_20",
            noise_policies: 80,
            groups: 20,
            labelers: 20,
            deny: false,
            namespace_depth: 0,
        },
        ScenarioSpec {
            name: "iai_namespaced_depth_4_deny",
            noise_policies: 80,
            groups: 10,
            labelers: 5,
            deny: true,
            namespace_depth: 4,
        },
    ]
}
