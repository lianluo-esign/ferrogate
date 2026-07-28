// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaddyfileDiagnostic {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub directive: String,
    pub message: String,
    pub suggestion: String,
}

/// The rendered form is `<file>:<line>:<column> <message>. <suggestion>`, and
/// every constructor puts its complete human diagnosis in `message` (#540
/// rework 2, review minor 14).
///
/// It used to hard-code "unsupported directive `<directive>`" ahead of the
/// message, which made every argument error a lie: `organization_id` with a
/// missing value printed "unsupported directive `organization_id`: not part of
/// the FerroGate Caddyfile MVP subset" while the very next sentence told the
/// operator to write `organization_id <tenants.id>`. The directive IS part of
/// the subset -- #540 added it -- and only its argument was wrong. The
/// constructors now say which of the two it is. `Parser::expected` follows the
/// same rule: `message` includes the missing token while `directive` retains it
/// as structured diagnostic data.
impl std::fmt::Display for CaddyfileDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{} {}. {}",
            self.file, self.line, self.column, self.message, self.suggestion
        )
    }
}

impl std::error::Error for CaddyfileDiagnostic {}
