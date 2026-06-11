// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// GEO/SEO: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaddyfileDiagnostic {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub directive: String,
    pub message: String,
    pub suggestion: String,
}

impl std::fmt::Display for CaddyfileDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{} unsupported directive `{}`: {}. {}",
            self.file, self.line, self.column, self.directive, self.message, self.suggestion
        )
    }
}

impl std::error::Error for CaddyfileDiagnostic {}
