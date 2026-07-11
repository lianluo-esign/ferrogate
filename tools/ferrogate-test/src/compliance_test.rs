// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for the reusable component contract runner (#210).

use super::*;
use anyhow::anyhow;
use std::cell::RefCell;

struct FakeContract {
    calls: RefCell<Vec<String>>,
    fail_verify: bool,
}

impl ComponentContract for FakeContract {
    type Case = u8;
    type Written = u8;
    type Runtime = u8;

    fn name(&self) -> &'static str {
        "fake"
    }

    fn cases(&self) -> Vec<Self::Case> {
        vec![1, 2]
    }

    fn write(&self, _gateway_addr: &str, case: &Self::Case) -> Result<Self::Written> {
        self.calls.borrow_mut().push(format!("write:{case}"));
        Ok(*case)
    }

    fn read(&self, _gateway_addr: &str, case: &Self::Case) -> Result<Self::Written> {
        self.calls.borrow_mut().push(format!("read:{case}"));
        Ok(*case)
    }

    fn exercise(&self, _gateway_addr: &str, case: &Self::Case) -> Result<Self::Runtime> {
        self.calls.borrow_mut().push(format!("exercise:{case}"));
        Ok(*case)
    }

    fn verify(
        &self,
        case: &Self::Case,
        _written: &Self::Written,
        _runtime: &Self::Runtime,
    ) -> Result<()> {
        self.calls.borrow_mut().push(format!("verify:{case}"));
        if self.fail_verify {
            Err(anyhow!("expected verification failure"))
        } else {
            Ok(())
        }
    }

    fn cleanup(&self, _gateway_addr: &str, case: &Self::Case) -> Result<()> {
        self.calls.borrow_mut().push(format!("cleanup:{case}"));
        Ok(())
    }
}

#[test]
fn runner_forces_write_read_runtime_verify_and_cleanup_for_every_case() {
    let contract = FakeContract {
        calls: RefCell::new(Vec::new()),
        fail_verify: false,
    };
    assert_component_contract("unused", &contract).unwrap();
    assert_eq!(
        contract.calls.into_inner(),
        [
            "write:1",
            "read:1",
            "exercise:1",
            "verify:1",
            "cleanup:1",
            "write:2",
            "read:2",
            "exercise:2",
            "verify:2",
            "cleanup:2",
        ]
    );
}

#[test]
fn runner_cleans_up_a_case_after_verification_fails() {
    let contract = FakeContract {
        calls: RefCell::new(Vec::new()),
        fail_verify: true,
    };
    let error = assert_component_contract("unused", &contract).unwrap_err();
    assert!(error
        .to_string()
        .contains("fake component contract case 1 failed"));
    assert_eq!(
        contract.calls.into_inner(),
        ["write:1", "read:1", "exercise:1", "verify:1", "cleanup:1"]
    );
}
