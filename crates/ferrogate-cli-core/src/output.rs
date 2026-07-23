// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Output rendering: stable machine JSON and human tables (issue #360).
//!
//! The contract is: **stdout carries data, stderr carries diagnostics**. This
//! module renders the *data* into a string; where that string is written is
//! the command layer's job, but it must always be stdout. Progress, warnings,
//! and human hints go to stderr and are never mixed into the rendered payload
//! so `--output json` stays pipe-safe.

use serde::Serialize;

use crate::error::{CliError, CliResult};

/// Selected output format. `Table` is the human default; `Json` is the stable
/// machine contract.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable aligned columns.
    #[default]
    Table,
    /// Stable, pretty-printed JSON. Field order follows the serialized type.
    Json,
}

impl OutputFormat {
    /// Parse a `--output` flag value. Kept here (rather than as a clap
    /// `ValueEnum` derive) so the accepted spellings are one stable list the
    /// whole CLI shares.
    pub fn parse(value: &str) -> CliResult<OutputFormat> {
        match value.trim().to_ascii_lowercase().as_str() {
            "table" | "text" => Ok(OutputFormat::Table),
            "json" => Ok(OutputFormat::Json),
            other => Err(CliError::usage(format!(
                "unknown output format '{other}'; expected one of: table, json"
            ))),
        }
    }

    /// The canonical spelling, for round-tripping and help text.
    pub fn as_str(self) -> &'static str {
        match self {
            OutputFormat::Table => "table",
            OutputFormat::Json => "json",
        }
    }
}

/// A tabular view: header columns plus rows of equal length. The renderer
/// treats this as the neutral shape every resource command can project into
/// for `--output table`, keeping column logic in the command module rather
/// than the transport or renderer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

impl Table {
    /// Build a table, validating that every row matches the header width so a
    /// ragged projection fails loudly instead of rendering misaligned.
    pub fn new(headers: Vec<String>, rows: Vec<Vec<String>>) -> CliResult<Table> {
        let width = headers.len();
        for (index, row) in rows.iter().enumerate() {
            if row.len() != width {
                return Err(CliError::usage(format!(
                    "table row {index} has {} columns but the header has {width}",
                    row.len()
                )));
            }
        }
        Ok(Table { headers, rows })
    }

    /// Render aligned columns padded to the widest cell in each column.
    pub fn render(&self) -> String {
        let mut widths: Vec<usize> = self.headers.iter().map(|header| header.len()).collect();
        for row in &self.rows {
            for (index, cell) in row.iter().enumerate() {
                widths[index] = widths[index].max(cell.len());
            }
        }
        let mut out = String::new();
        push_row(&mut out, &self.headers, &widths);
        for row in &self.rows {
            push_row(&mut out, row, &widths);
        }
        // Trim the trailing newline so the caller controls final spacing.
        if out.ends_with('\n') {
            out.pop();
        }
        out
    }
}

fn push_row(out: &mut String, cells: &[String], widths: &[usize]) {
    for (index, cell) in cells.iter().enumerate() {
        if index > 0 {
            out.push_str("  ");
        }
        out.push_str(cell);
        // Pad every column except the last so trailing whitespace stays out
        // of the rendered line.
        if index + 1 < cells.len() {
            for _ in cell.len()..widths[index] {
                out.push(' ');
            }
        }
    }
    out.push('\n');
}

/// Render a serializable value as stable JSON (pretty-printed).
pub fn render_json<T: Serialize>(value: &T) -> CliResult<String> {
    serde_json::to_string_pretty(value)
        .map_err(|error| CliError::transport(format!("failed to encode JSON output: {error}")))
}

#[cfg(test)]
#[path = "output_test.rs"]
mod output_test;
