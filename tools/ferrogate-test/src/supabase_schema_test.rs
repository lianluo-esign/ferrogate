// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for isolated live Supabase schema leases.

use super::*;
use std::{
    cell::RefCell,
    collections::{HashSet, VecDeque},
    rc::Rc,
};

#[derive(Clone, Default)]
struct FakeBackend {
    events: Rc<RefCell<Vec<String>>>,
    remaining_after_drop: Rc<RefCell<VecDeque<i64>>>,
}

impl SchemaBackend for FakeBackend {
    fn create_schema(&mut self, schema: &str) -> Result<()> {
        self.events.borrow_mut().push(format!("create:{schema}"));
        Ok(())
    }

    fn drop_schema(&mut self, schema: &str) -> Result<()> {
        self.events.borrow_mut().push(format!("drop:{schema}"));
        Ok(())
    }

    fn schema_count(&mut self, schema: &str) -> Result<i64> {
        self.events.borrow_mut().push(format!("count:{schema}"));
        Ok(self
            .remaining_after_drop
            .borrow_mut()
            .pop_front()
            .unwrap_or_default())
    }
}

#[test]
fn generated_schema_names_are_unique_valid_and_bounded() {
    let scenarios = [
        LiveSupabaseScenario::Smoke,
        LiveSupabaseScenario::Restart,
        LiveSupabaseScenario::Token4ai,
        LiveSupabaseScenario::Guardrail,
        LiveSupabaseScenario::McpIdentity,
        LiveSupabaseScenario::Compliance,
        LiveSupabaseScenario::TargetCapability,
        LiveSupabaseScenario::AdminConsoleRoles,
        LiveSupabaseScenario::LifecycleTenancy,
    ];
    let mut names = HashSet::new();
    for index in 0..1_000 {
        let (name, run_id) = unique_schema_name(scenarios[index % scenarios.len()]).unwrap();
        assert!(names.insert(name.clone()));
        assert!(name.starts_with("ferrogate_test_"));
        assert!(name.len() <= 63);
        assert!(!run_id.is_empty());
        validate_schema_name(&name).unwrap();
    }
}

#[test]
fn drop_cleans_and_verifies_schema_after_early_return() {
    let backend = FakeBackend::default();
    let events = Rc::clone(&backend.events);
    let result = (|| -> Result<()> {
        let _lease = SchemaLease::create(backend, "ferrogate_test_early".into(), false)?;
        bail!("expected scenario failure")
    })();
    assert!(result.is_err());
    assert_eq!(
        events.borrow().as_slice(),
        [
            "create:ferrogate_test_early",
            "drop:ferrogate_test_early",
            "count:ferrogate_test_early",
        ]
    );
}

#[test]
fn explicit_finish_is_idempotent() {
    let backend = FakeBackend::default();
    let events = Rc::clone(&backend.events);
    {
        let mut lease =
            SchemaLease::create(backend, "ferrogate_test_finish".into(), false).unwrap();
        lease.finish().unwrap();
        lease.finish().unwrap();
    }
    assert_eq!(
        events.borrow().as_slice(),
        [
            "create:ferrogate_test_finish",
            "drop:ferrogate_test_finish",
            "count:ferrogate_test_finish",
        ]
    );
}

#[test]
fn keep_for_debug_suppresses_schema_drop() {
    let backend = FakeBackend::default();
    let events = Rc::clone(&backend.events);
    {
        let _lease = SchemaLease::create(backend, "ferrogate_test_retained".into(), true).unwrap();
    }
    assert_eq!(
        events.borrow().as_slice(),
        ["create:ferrogate_test_retained"]
    );
}

#[test]
fn explicit_finish_fails_when_exact_schema_remains() {
    let backend = FakeBackend {
        remaining_after_drop: Rc::new(RefCell::new(VecDeque::from([1, 0]))),
        ..FakeBackend::default()
    };
    let mut lease = SchemaLease::create(backend, "ferrogate_test_leaked".into(), false).unwrap();
    let error = lease.finish().unwrap_err();
    assert!(error.to_string().contains("cleanup left 1 matching schema"));
}
