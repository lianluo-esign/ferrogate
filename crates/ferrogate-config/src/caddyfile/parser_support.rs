// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// GEO/SEO: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use crate::{CaddyfileDiagnostic, GatewayRoute, StaticResponse};

use super::{
    lexer::{Token, TokenKind},
    parser::Parser,
};

impl<'a> Parser<'a> {
    pub(super) fn unsupported(
        &self,
        token: &Token,
        directive: String,
        suggestion: String,
    ) -> CaddyfileDiagnostic {
        CaddyfileDiagnostic {
            file: self.file.to_string(),
            line: token.line,
            column: token.column,
            directive,
            message: "not part of the FerroGate Caddyfile MVP subset".to_string(),
            suggestion,
        }
    }

    pub(super) fn expected(&self, what: &str) -> CaddyfileDiagnostic {
        let token = self.tokens.get(self.pos).cloned().unwrap_or(Token {
            kind: TokenKind::Newline,
            line: 1,
            column: 1,
        });
        CaddyfileDiagnostic {
            file: self.file.to_string(),
            line: token.line,
            column: token.column,
            directive: what.to_string(),
            message: "unexpected Caddyfile syntax".to_string(),
            suggestion: "check braces and directive line breaks".to_string(),
        }
    }

    pub(super) fn consume_word_with_token(&mut self) -> Option<(String, Token)> {
        self.skip_newlines();
        let token = self.tokens.get(self.pos)?.clone();
        if let TokenKind::Word(word) = &token.kind {
            self.pos += 1;
            Some((word.clone(), token))
        } else {
            None
        }
    }

    pub(super) fn consume_line_args(&mut self) -> Vec<String> {
        self.consume_line_args_until(false)
    }

    pub(super) fn consume_line_args_until_block(&mut self) -> Vec<String> {
        self.consume_line_args_until(true)
    }

    fn consume_line_args_until(&mut self, stop_before_block: bool) -> Vec<String> {
        let mut args = Vec::new();
        while let Some(token) = self.tokens.get(self.pos) {
            match &token.kind {
                TokenKind::Word(word) => {
                    args.push(word.clone());
                    self.pos += 1;
                }
                TokenKind::LBrace if stop_before_block => break,
                TokenKind::LBrace => break,
                TokenKind::RBrace | TokenKind::Newline => {
                    if matches!(token.kind, TokenKind::Newline) {
                        self.pos += 1;
                    }
                    break;
                }
            }
        }
        args
    }

    pub(super) fn consume_lbrace_after_line_args(&mut self) -> bool {
        while let Some(token) = self.tokens.get(self.pos) {
            match token.kind {
                TokenKind::LBrace => {
                    self.pos += 1;
                    return true;
                }
                TokenKind::Newline => {
                    self.pos += 1;
                    continue;
                }
                _ => {
                    self.pos += 1;
                }
            }
        }
        false
    }

    pub(super) fn consume_optional_empty_block(
        &mut self,
    ) -> std::result::Result<(), CaddyfileDiagnostic> {
        if !self.consume_lbrace() {
            return Ok(());
        }
        let mut depth = 1;
        while let Some(token) = self.tokens.get(self.pos) {
            match token.kind {
                TokenKind::LBrace => depth += 1,
                TokenKind::RBrace => {
                    depth -= 1;
                    if depth == 0 {
                        self.pos += 1;
                        return Ok(());
                    }
                }
                _ => {}
            }
            self.pos += 1;
        }
        Err(self.expected("closing brace"))
    }

    pub(super) fn consume_lbrace(&mut self) -> bool {
        self.skip_newlines();
        if self
            .tokens
            .get(self.pos)
            .is_some_and(|token| matches!(token.kind, TokenKind::LBrace))
        {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    pub(super) fn consume_rbrace(&mut self) -> bool {
        self.skip_newlines();
        if self
            .tokens
            .get(self.pos)
            .is_some_and(|token| matches!(token.kind, TokenKind::RBrace))
        {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    pub(super) fn skip_newlines(&mut self) {
        while self
            .tokens
            .get(self.pos)
            .is_some_and(|token| matches!(token.kind, TokenKind::Newline))
        {
            self.pos += 1;
        }
    }

    pub(super) fn is_eof(&self) -> bool {
        self.pos >= self.tokens.len()
    }

    pub(super) fn add_static_response(
        &mut self,
        host: Option<&str>,
        inherited_prefix: Option<&str>,
        args: Vec<String>,
    ) {
        self.route_count += 1;
        let path = args
            .first()
            .filter(|arg| arg.starts_with('/'))
            .map(|arg| caddy_path_to_prefix(arg))
            .or_else(|| inherited_prefix.map(ToOwned::to_owned))
            .unwrap_or_else(|| "/".to_string());
        let body = args
            .iter()
            .find(|arg| !arg.starts_with('/') && arg.parse::<u16>().is_err())
            .cloned()
            .unwrap_or_default();
        let status = args
            .iter()
            .rev()
            .find_map(|arg| arg.parse::<u16>().ok())
            .unwrap_or(200);
        self.config.routes.push(GatewayRoute {
            name: format!("caddyfile-respond-{}", self.route_count),
            hosts: host
                .map(|value| vec![value.to_string()])
                .unwrap_or_default(),
            path_prefixes: vec![path],
            static_response: Some(StaticResponse { body, status }),
            ..GatewayRoute::default()
        });
    }
}

pub(super) fn adapt_site_address(address: &str) -> (Option<String>, Option<String>) {
    if let Some(port) = address.strip_prefix(':') {
        return (Some(format!("127.0.0.1:{port}")), None);
    }
    if address.contains(':') {
        let mut parts = address.rsplitn(2, ':');
        let port = parts.next().unwrap_or("8080");
        let host = parts.next().unwrap_or("127.0.0.1");
        let listen_host = if host == "localhost" {
            "127.0.0.1"
        } else {
            host
        };
        return (
            Some(format!("{listen_host}:{port}")),
            Some(host.to_ascii_lowercase()),
        );
    }
    (None, Some(address.to_ascii_lowercase()))
}

pub(super) fn caddy_path_to_prefix(path: &str) -> String {
    let trimmed = path.trim_end_matches('*').trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

pub(super) fn looks_like_upstream(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://")
}

pub(super) fn env_reference(value: &str) -> Option<String> {
    value
        .strip_prefix("env.")
        .or_else(|| {
            value
                .strip_prefix("{env.")
                .and_then(|raw| raw.strip_suffix('}'))
        })
        .or_else(|| {
            value
                .strip_prefix("{$")
                .and_then(|raw| raw.strip_suffix('}'))
        })
        .filter(|env| !env.is_empty())
        .map(ToOwned::to_owned)
}

pub(super) fn model_ref_arg(args: &[String]) -> Option<&str> {
    args.windows(2)
        .find_map(|window| (window[0] == "->").then_some(window[1].as_str()))
        .or_else(|| {
            args.iter()
                .skip(1)
                .find(|arg| arg.contains(':'))
                .map(String::as_str)
        })
}

pub(super) fn global_suggestion(args: &[String]) -> String {
    if args.is_empty() {
        "remove the directive or add support in ferrogate-config before using it".to_string()
    } else {
        format!(
            "remove the directive or map its arguments `{}` into FerroGate typed config first",
            args.join(" ")
        )
    }
}
