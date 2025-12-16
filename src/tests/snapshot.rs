/// Helper macro to snapshot a decision with timestamp redaction.
/// This keeps test snapshots stable by masking the time-varying `loaded_at` field.
#[macro_export]
macro_rules! snapshot_decision {
    ($decision:expr) => {{
        let mut settings = insta::Settings::clone_current();
        settings.add_redaction(".**.loaded_at", "[timestamp]");
        settings.bind(|| {
            insta::assert_json_snapshot!($decision);
        });
    }};
}
