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
