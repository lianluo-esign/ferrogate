// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Opt-in Wasmtime sandbox boundary for future agent execution.

use std::{
    error::Error,
    fmt,
    time::{Duration, Instant},
};

use wasmtime::{Caller, Config as WasmtimeConfig, Engine, Linker, Module, Store};

const DEFAULT_MAX_FUEL: u64 = 1_000_000;

/// Deny-by-default sandbox limits for one untrusted WASM invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmSandboxConfig {
    pub max_fuel: u64,
    pub timeout: Option<Duration>,
}

impl Default for WasmSandboxConfig {
    fn default() -> Self {
        Self {
            max_fuel: DEFAULT_MAX_FUEL,
            timeout: Some(Duration::from_secs(30)),
        }
    }
}

impl WasmSandboxConfig {
    pub fn validate(&self) -> Result<(), WasmSandboxError> {
        if self.max_fuel == 0 {
            return Err(WasmSandboxError::InvalidConfig(
                "max_fuel must be greater than zero".to_string(),
            ));
        }
        if self.timeout == Some(Duration::ZERO) {
            return Err(WasmSandboxError::InvalidConfig(
                "timeout must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }
}

/// Minimal sandbox executor. It intentionally does not register WASI or any
/// host imports; future host ABI calls must be added explicitly.
#[derive(Debug, Clone)]
pub struct WasmSandboxExecutor {
    config: WasmSandboxConfig,
}

impl WasmSandboxExecutor {
    pub fn new(config: WasmSandboxConfig) -> Result<Self, WasmSandboxError> {
        config.validate()?;
        Ok(Self { config })
    }

    pub fn execute_export_i32(
        &self,
        module_bytes: &[u8],
        export_name: &str,
    ) -> Result<WasmRunOutcome, WasmSandboxError> {
        self.execute_export_i32_inner::<NoopHostAbi>(module_bytes, export_name, None)
            .map(|(outcome, _)| outcome)
    }

    pub fn execute_export_i32_with_host<H>(
        &self,
        module_bytes: &[u8],
        export_name: &str,
        host: H,
    ) -> Result<WasmHostRunOutcome<H>, WasmSandboxError>
    where
        H: WasmHostAbi + 'static,
    {
        let (outcome, host) =
            self.execute_export_i32_inner(module_bytes, export_name, Some(host))?;
        Ok(WasmHostRunOutcome {
            outcome,
            host: host.expect("host ABI state should be returned after opt-in execution"),
        })
    }

    fn execute_export_i32_inner<H>(
        &self,
        module_bytes: &[u8],
        export_name: &str,
        host: Option<H>,
    ) -> Result<(WasmRunOutcome, Option<H>), WasmSandboxError>
    where
        H: WasmHostAbi + 'static,
    {
        if export_name.trim().is_empty() {
            return Err(WasmSandboxError::InvalidConfig(
                "export_name must not be empty".to_string(),
            ));
        }

        let mut engine_config = WasmtimeConfig::new();
        engine_config.consume_fuel(true);
        #[cfg(target_has_atomic = "64")]
        engine_config.epoch_interruption(self.config.timeout.is_some());

        let engine = Engine::new(&engine_config).map_err(WasmSandboxError::engine)?;
        let module = Module::new(&engine, module_bytes).map_err(WasmSandboxError::compile)?;
        validate_imports(&module, host.is_some())?;

        let mut store = Store::new(&engine, WasmStoreState { host });
        store
            .set_fuel(self.config.max_fuel)
            .map_err(WasmSandboxError::engine)?;
        #[cfg(target_has_atomic = "64")]
        if let Some(timeout) = self.config.timeout {
            store.set_epoch_deadline(1);
            store.epoch_deadline_trap();
            let timer_engine = engine.clone();
            std::thread::spawn(move || {
                std::thread::sleep(timeout);
                timer_engine.increment_epoch();
            });
        }

        let mut linker = Linker::new(&engine);
        register_host_abi(&mut linker)?;
        let start = Instant::now();
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(WasmSandboxError::instantiate)?;
        let function = instance
            .get_typed_func::<(), i32>(&mut store, export_name)
            .map_err(|error| WasmSandboxError::MissingExport(error.to_string()))?;
        let result = function
            .call(&mut store, ())
            .map_err(WasmSandboxError::trap)?;
        let fuel_remaining = store.get_fuel().map_err(WasmSandboxError::engine)?;

        let host = store.into_data().host;
        Ok((
            WasmRunOutcome {
                export_name: export_name.to_string(),
                result,
                fuel_remaining,
                elapsed: start.elapsed(),
            },
            host,
        ))
    }
}

/// Minimal opt-in host ABI for sandboxed agent modules.
///
/// The ABI intentionally uses integer handles only. The gateway side remains
/// responsible for mapping handles to bounded state entries, audit records, and
/// governed tool dispatch requests.
pub trait WasmHostAbi {
    fn log(&mut self, code: i32);
    fn state_get(&mut self, key: i32) -> i32;
    fn state_set(&mut self, key: i32, value: i32) -> i32;
    fn tool_dispatch(&mut self, tool_handle: i32) -> i32;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmHostRunOutcome<H> {
    pub outcome: WasmRunOutcome,
    pub host: H,
}

struct NoopHostAbi;

impl WasmHostAbi for NoopHostAbi {
    fn log(&mut self, _code: i32) {}

    fn state_get(&mut self, _key: i32) -> i32 {
        0
    }

    fn state_set(&mut self, _key: i32, _value: i32) -> i32 {
        0
    }

    fn tool_dispatch(&mut self, _tool_handle: i32) -> i32 {
        0
    }
}

struct WasmStoreState<H> {
    host: Option<H>,
}

fn validate_imports(module: &Module, host_enabled: bool) -> Result<(), WasmSandboxError> {
    for import in module.imports() {
        let module_name = import.module();
        let name = import.name();
        if !host_enabled
            || module_name != "ferrogate"
            || !matches!(name, "log" | "state_get" | "state_set" | "tool_dispatch")
        {
            return Err(WasmSandboxError::HostImportDenied);
        }
    }
    Ok(())
}

fn register_host_abi<H>(linker: &mut Linker<WasmStoreState<H>>) -> Result<(), WasmSandboxError>
where
    H: WasmHostAbi + 'static,
{
    linker
        .func_wrap(
            "ferrogate",
            "log",
            |mut caller: Caller<'_, WasmStoreState<H>>, code: i32| {
                if let Some(host) = caller.data_mut().host.as_mut() {
                    host.log(code);
                }
            },
        )
        .map_err(WasmSandboxError::engine)?;
    linker
        .func_wrap(
            "ferrogate",
            "state_get",
            |mut caller: Caller<'_, WasmStoreState<H>>, key: i32| -> i32 {
                caller
                    .data_mut()
                    .host
                    .as_mut()
                    .map(|host| host.state_get(key))
                    .unwrap_or_default()
            },
        )
        .map_err(WasmSandboxError::engine)?;
    linker
        .func_wrap(
            "ferrogate",
            "state_set",
            |mut caller: Caller<'_, WasmStoreState<H>>, key: i32, value: i32| -> i32 {
                caller
                    .data_mut()
                    .host
                    .as_mut()
                    .map(|host| host.state_set(key, value))
                    .unwrap_or_default()
            },
        )
        .map_err(WasmSandboxError::engine)?;
    linker
        .func_wrap(
            "ferrogate",
            "tool_dispatch",
            |mut caller: Caller<'_, WasmStoreState<H>>, tool_handle: i32| -> i32 {
                caller
                    .data_mut()
                    .host
                    .as_mut()
                    .map(|host| host.tool_dispatch(tool_handle))
                    .unwrap_or_default()
            },
        )
        .map_err(WasmSandboxError::engine)?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmRunOutcome {
    pub export_name: String,
    pub result: i32,
    pub fuel_remaining: u64,
    pub elapsed: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WasmSandboxError {
    InvalidConfig(String),
    Compile(String),
    Engine(String),
    HostImportDenied,
    MissingExport(String),
    Instantiate(String),
    FuelExhausted(String),
    TimedOut(String),
    Trap(String),
}

impl WasmSandboxError {
    fn compile(error: wasmtime::Error) -> Self {
        Self::Compile(error.to_string())
    }

    fn engine(error: wasmtime::Error) -> Self {
        Self::Engine(error.to_string())
    }

    fn instantiate(error: wasmtime::Error) -> Self {
        Self::Instantiate(error.to_string())
    }

    fn trap(error: wasmtime::Error) -> Self {
        let message = format!("{error:#}");
        let debug = format!("{error:?}");
        let lower = format!("{message}\n{debug}").to_ascii_lowercase();
        if lower.contains("fuel") {
            Self::FuelExhausted(message)
        } else if lower.contains("epoch") || lower.contains("interrupt") {
            Self::TimedOut(message)
        } else {
            Self::Trap(message)
        }
    }
}

impl fmt::Display for WasmSandboxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(formatter, "invalid sandbox config: {message}"),
            Self::Compile(message) => write!(formatter, "failed to compile wasm module: {message}"),
            Self::Engine(message) => write!(formatter, "wasmtime engine error: {message}"),
            Self::HostImportDenied => {
                write!(
                    formatter,
                    "wasm module imports host capabilities that are not registered"
                )
            }
            Self::MissingExport(message) => write!(formatter, "missing wasm export: {message}"),
            Self::Instantiate(message) => {
                write!(formatter, "failed to instantiate wasm module: {message}")
            }
            Self::FuelExhausted(message) => write!(formatter, "wasm fuel exhausted: {message}"),
            Self::TimedOut(message) => write!(formatter, "wasm execution timed out: {message}"),
            Self::Trap(message) => write!(formatter, "wasm trap: {message}"),
        }
    }
}

impl Error for WasmSandboxError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn compile_wat(source: &str) -> Vec<u8> {
        wat::parse_str(source).expect("test wat compiles")
    }

    #[test]
    fn executes_export_with_fuel_budget() {
        let module = compile_wat(
            r#"
            (module
              (func (export "run") (result i32)
                i32.const 42))
            "#,
        );
        let executor = WasmSandboxExecutor::new(WasmSandboxConfig {
            max_fuel: 10_000,
            timeout: None,
        })
        .unwrap();

        let outcome = executor.execute_export_i32(&module, "run").unwrap();

        assert_eq!(outcome.export_name, "run");
        assert_eq!(outcome.result, 42);
        assert!(outcome.fuel_remaining < 10_000);
    }

    #[test]
    fn denies_host_imports_by_default() {
        let module = compile_wat(
            r#"
            (module
              (import "ferrogate" "log" (func $log (param i32)))
              (func (export "run") (result i32)
                i32.const 1
                call $log
                i32.const 1))
            "#,
        );
        let executor = WasmSandboxExecutor::new(WasmSandboxConfig::default()).unwrap();

        let error = executor.execute_export_i32(&module, "run").unwrap_err();

        assert_eq!(error, WasmSandboxError::HostImportDenied);
    }

    #[test]
    fn executes_explicit_host_abi_when_opted_in() {
        let module = compile_wat(
            r#"
            (module
              (import "ferrogate" "log" (func $log (param i32)))
              (import "ferrogate" "state_get" (func $state_get (param i32) (result i32)))
              (import "ferrogate" "state_set" (func $state_set (param i32 i32) (result i32)))
              (import "ferrogate" "tool_dispatch" (func $tool_dispatch (param i32) (result i32)))
              (func (export "run") (result i32)
                i32.const 7
                call $log
                i32.const 3
                i32.const 11
                call $state_set
                drop
                i32.const 3
                call $state_get
                i32.const 5
                call $tool_dispatch
                i32.add))
            "#,
        );
        let executor = WasmSandboxExecutor::new(WasmSandboxConfig {
            max_fuel: 10_000,
            timeout: None,
        })
        .unwrap();
        let host = CapturingHostAbi::default();

        let run = executor
            .execute_export_i32_with_host(&module, "run", host)
            .unwrap();
        let host = run.host;

        assert_eq!(run.outcome.result, 27);
        assert_eq!(host.logs, vec![7]);
        assert_eq!(host.state_sets, vec![(3, 11)]);
        assert_eq!(host.state_gets, vec![3]);
        assert_eq!(host.tool_dispatches, vec![5]);
    }

    #[test]
    fn rejects_unknown_host_abi_even_when_host_is_present() {
        let module = compile_wat(
            r#"
            (module
              (import "ferrogate" "network_open" (func $network_open (param i32) (result i32)))
              (func (export "run") (result i32)
                i32.const 1
                call $network_open))
            "#,
        );
        let executor = WasmSandboxExecutor::new(WasmSandboxConfig::default()).unwrap();
        let host = CapturingHostAbi::default();

        let error = executor
            .execute_export_i32_with_host(&module, "run", host)
            .unwrap_err();

        assert_eq!(error, WasmSandboxError::HostImportDenied);
    }

    #[test]
    fn stops_when_fuel_is_exhausted() {
        let module = compile_wat(
            r#"
            (module
              (func (export "run") (result i32)
                (loop
                  br 0)
                i32.const 1))
            "#,
        );
        let executor = WasmSandboxExecutor::new(WasmSandboxConfig {
            max_fuel: 1_000,
            timeout: None,
        })
        .unwrap();

        let error = executor.execute_export_i32(&module, "run").unwrap_err();

        assert!(matches!(error, WasmSandboxError::FuelExhausted(_)));
    }

    #[cfg(target_has_atomic = "64")]
    #[test]
    fn stops_when_timeout_epoch_expires() {
        let module = compile_wat(
            r#"
            (module
              (func (export "run") (result i32)
                (loop
                  br 0)
                i32.const 1))
            "#,
        );
        let executor = WasmSandboxExecutor::new(WasmSandboxConfig {
            max_fuel: 1_000_000_000,
            timeout: Some(Duration::from_millis(1)),
        })
        .unwrap();

        let error = executor.execute_export_i32(&module, "run").unwrap_err();

        assert!(matches!(error, WasmSandboxError::TimedOut(_)));
    }

    #[test]
    fn rejects_zero_fuel() {
        let error = WasmSandboxExecutor::new(WasmSandboxConfig {
            max_fuel: 0,
            timeout: None,
        })
        .unwrap_err();

        assert!(matches!(error, WasmSandboxError::InvalidConfig(_)));
    }

    #[derive(Debug, Default)]
    struct CapturingHostAbi {
        logs: Vec<i32>,
        state_gets: Vec<i32>,
        state_sets: Vec<(i32, i32)>,
        tool_dispatches: Vec<i32>,
    }

    impl WasmHostAbi for CapturingHostAbi {
        fn log(&mut self, code: i32) {
            self.logs.push(code);
        }

        fn state_get(&mut self, key: i32) -> i32 {
            self.state_gets.push(key);
            self.state_sets
                .iter()
                .rev()
                .find_map(|(stored_key, value)| (*stored_key == key).then_some(*value))
                .unwrap_or_default()
        }

        fn state_set(&mut self, key: i32, value: i32) -> i32 {
            self.state_sets.push((key, value));
            0
        }

        fn tool_dispatch(&mut self, tool_handle: i32) -> i32 {
            self.tool_dispatches.push(tool_handle);
            tool_handle + 11
        }
    }
}
