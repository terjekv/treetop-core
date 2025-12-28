//! Example: OpenTelemetry distributed tracing integration.
//!
//! This demonstrates how to integrate treetop-core with OpenTelemetry for
//! distributed tracing. The PolicyEngine automatically emits structured tracing
//! spans when the observability feature is enabled, which can be captured by
//! OpenTelemetry and exported to backends like Jaeger, Tempo, or Zipkin.
//!
//! Prerequisites:
//! ```bash
//! # Start Jaeger in Docker (or use another OTLP-compatible backend)
//! docker run -d --name jaeger \
//!   -p 16686:16686 \
//!   -p 4317:4317 \
//!   jaegertracing/all-in-one:latest
//! ```
//!
//! To run:
//! ```bash
//! cargo run --example opentelemetry_tracing --features observability
//! ```
//!
//! Then view traces at: http://localhost:16686

use std::error::Error;
use treetop_core::{Action, PolicyEngine, Principal, Request, Resource, User};

// For this example, we'll use a simple console exporter instead of requiring
// external OTLP dependencies. In production, you'd use opentelemetry-otlp.
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const DNS_POLICY: &str = r#"
permit (
    principal in Group::"admins",
    action in [Action::"view_host", Action::"edit_host", Action::"delete_host"],
    resource is Host
);

permit (
    principal in Group::"users",
    action == Action::"view_host",
    resource is Host
);

forbid (
    principal == User::"bob",
    action == Action::"delete_host",
    resource is Host
);
"#;

fn main() -> Result<(), Box<dyn Error>> {
    // Initialize tracing subscriber with console output
    // In production, replace this with OpenTelemetry OTLP exporter:
    //
    // use opentelemetry::global;
    // use opentelemetry_otlp::WithExportConfig;
    // use opentelemetry_sdk::trace::TracerProvider;
    // use tracing_opentelemetry::OpenTelemetryLayer;
    //
    // let tracer = opentelemetry_otlp::new_pipeline()
    //     .tracing()
    //     .with_exporter(
    //         opentelemetry_otlp::new_exporter()
    //             .tonic()
    //             .with_endpoint("http://localhost:4317")
    //     )
    //     .install_batch(opentelemetry_sdk::runtime::Tokio)?;
    //
    // let telemetry = OpenTelemetryLayer::new(tracer);
    // tracing_subscriber::registry()
    //     .with(telemetry)
    //     .with(tracing_subscriber::fmt::layer())
    //     .init();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_level(true)
                .with_line_number(true),
        )
        .with(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("treetop_core=debug".parse()?),
        )
        .init();

    println!("=== OpenTelemetry Tracing Example ===\n");
    println!("Initializing policy engine with DNS policy...");

    let engine = PolicyEngine::new_from_str(DNS_POLICY)?;

    println!("\n--- Tracing Spans Emitted by PolicyEngine ---");
    println!("The following spans are automatically created for each evaluation:");
    println!("  1. policy_evaluation (top-level)");
    println!("  2. ├─ apply_labels (if label registry configured)");
    println!("  3. ├─ construct_entities");
    println!("  4. ├─ resolve_groups");
    println!("  5. └─ authorize\n");

    println!("Running evaluations with different principals...\n");

    // Test 1: Admin user - should allow all actions
    let alice_request = Request {
        principal: Principal::User(User::new("alice", Some(vec!["admins".to_string()]), None)),
        action: Action::new("delete_host", None),
        resource: Resource::new("Host", "web-01.example.com"),
    };

    println!("1. Evaluating: alice (admin) deleting host");
    let decision = engine.evaluate(&alice_request)?;
    println!("   Result: {:?}\n", decision);

    // Test 2: Regular user - should allow view only
    let charlie_request = Request {
        principal: Principal::User(User::new("charlie", Some(vec!["users".to_string()]), None)),
        action: Action::new("view_host", None),
        resource: Resource::new("Host", "web-01.example.com"),
    };

    println!("2. Evaluating: charlie (user) viewing host");
    let decision = engine.evaluate(&charlie_request)?;
    println!("   Result: {:?}\n", decision);

    // Test 3: Explicit forbid - bob cannot delete
    let bob_request = Request {
        principal: Principal::User(User::new(
            "bob",
            Some(vec!["admins".to_string()]), // Even though bob is admin
            None,
        )),
        action: Action::new("delete_host", None),
        resource: Resource::new("Host", "web-01.example.com"),
    };

    println!("3. Evaluating: bob (admin but forbidden) deleting host");
    let decision = engine.evaluate(&bob_request)?;
    println!("   Result: {:?}\n", decision);

    // Test 4: Charlie trying to delete - should deny
    let charlie_delete_request = Request {
        principal: Principal::User(User::new("charlie", Some(vec!["users".to_string()]), None)),
        action: Action::new("delete_host", None),
        resource: Resource::new("Host", "web-01.example.com"),
    };

    println!("4. Evaluating: charlie (user) deleting host");
    let decision = engine.evaluate(&charlie_delete_request)?;
    println!("   Result: {:?}\n", decision);

    println!("\n=== Trace Context ===");
    println!("Each evaluation above generated a trace with nested spans.");
    println!("In the console output above, look for spans like:");
    println!("  - policy_evaluation: Shows the overall request context");
    println!("  - construct_entities: Shows entity creation timing");
    println!("  - resolve_groups: Shows group membership resolution");
    println!("  - authorize: Shows Cedar engine execution");
    println!("\nWith OpenTelemetry + Jaeger:");
    println!("  - View the service graph at http://localhost:16686");
    println!("  - Search for traces by 'treetop_core' service");
    println!("  - See latency breakdown across evaluation phases");
    println!("  - Correlate policy decisions with distributed traces");

    println!("\n=== Integration Guide ===");
    println!("To use with real OpenTelemetry exporters:");
    println!("  1. Add dependencies:");
    println!("     opentelemetry");
    println!("     opentelemetry-otlp");
    println!("     opentelemetry-sdk");
    println!("     tracing-opentelemetry");
    println!("  2. Replace the subscriber setup (see comments in main())");
    println!("  3. Traces will be exported to your OTLP endpoint");

    Ok(())
}
