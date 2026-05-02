use crate::{
    CaddyfileDiagnostic, GatewayConfig, GatewayHeader, GatewayLog, GatewayRoute, GatewayUpstream,
};

use super::lexer::{lex, Token};
use super::parser_support::{
    adapt_site_address, caddy_path_to_prefix, global_suggestion, looks_like_upstream,
};

pub fn parse_caddyfile(
    raw: &str,
    file: &str,
) -> std::result::Result<GatewayConfig, CaddyfileDiagnostic> {
    Parser::new(raw, file).parse()
}

pub(super) struct Parser<'a> {
    pub(super) file: &'a str,
    pub(super) tokens: Vec<Token>,
    pub(super) pos: usize,
    pub(super) config: GatewayConfig,
    pub(super) upstream_count: usize,
    pub(super) route_count: usize,
}

impl<'a> Parser<'a> {
    fn new(raw: &str, file: &'a str) -> Self {
        Self {
            file,
            tokens: lex(raw),
            pos: 0,
            config: GatewayConfig {
                listen: "127.0.0.1:8080".to_string(),
                ..GatewayConfig::default()
            },
            upstream_count: 0,
            route_count: 0,
        }
    }

    fn parse(mut self) -> std::result::Result<GatewayConfig, CaddyfileDiagnostic> {
        self.skip_newlines();
        while !self.is_eof() {
            if self.consume_lbrace() {
                self.parse_global_options()?;
            } else {
                self.parse_site_block()?;
            }
            self.skip_newlines();
        }
        Ok(self.config)
    }

    fn parse_global_options(&mut self) -> std::result::Result<(), CaddyfileDiagnostic> {
        loop {
            self.skip_newlines();
            if self.consume_rbrace() {
                return Ok(());
            }
            let Some((directive, token)) = self.consume_word_with_token() else {
                return Ok(());
            };
            let args = self.consume_line_args();
            match directive.as_str() {
                "admin" => {
                    if let Some(address) = args.first() {
                        self.config.admin = Some(address.clone());
                    }
                }
                "debug" | "log" => {}
                _ => return Err(self.unsupported(&token, directive, global_suggestion(&args))),
            }
        }
    }

    fn parse_site_block(&mut self) -> std::result::Result<(), CaddyfileDiagnostic> {
        let (address, token) = self
            .consume_word_with_token()
            .ok_or_else(|| self.expected("site address"))?;
        if !self.consume_lbrace_after_line_args() {
            return Err(self.unsupported(
                &token,
                address,
                "expected a Caddyfile site block like `:8080 { ... }`".to_string(),
            ));
        }

        let (listen, host) = adapt_site_address(&address);
        if let Some(listen) = listen {
            self.config.listen = listen;
        }

        loop {
            self.skip_newlines();
            if self.consume_rbrace() {
                return Ok(());
            }
            self.parse_site_directive(host.as_deref(), None)?;
        }
    }

    fn parse_site_directive(
        &mut self,
        host: Option<&str>,
        inherited_prefix: Option<&str>,
    ) -> std::result::Result<(), CaddyfileDiagnostic> {
        let Some((directive, token)) = self.consume_word_with_token() else {
            return Ok(());
        };
        let args = self.consume_line_args_until_block();
        match directive.as_str() {
            "log" => {
                self.config.logs.push(GatewayLog { route: None });
                self.consume_optional_empty_block()?;
                Ok(())
            }
            "route" | "handle" | "handle_path" => {
                let prefix = args
                    .first()
                    .filter(|arg| arg.starts_with('/'))
                    .map(|arg| caddy_path_to_prefix(arg));
                if !self.consume_lbrace() {
                    return Ok(());
                }
                loop {
                    self.skip_newlines();
                    if self.consume_rbrace() {
                        return Ok(());
                    }
                    self.parse_site_directive(host, prefix.as_deref().or(inherited_prefix))?;
                }
            }
            "reverse_proxy" => self.parse_reverse_proxy(host, inherited_prefix, args),
            "respond" => {
                self.add_static_response(host, inherited_prefix, args);
                Ok(())
            }
            "header" | "rewrite" | "uri" | "redir" | "encode" | "tls" => {
                self.consume_optional_empty_block()?;
                Ok(())
            }
            directive if directive.starts_with('@') => {
                if args.first().is_some_and(|arg| {
                    matches!(arg.as_str(), "path" | "host" | "method" | "header" | "query")
                }) {
                    return Ok(());
                }
                self.consume_optional_empty_block()?;
                Ok(())
            }
            _ => Err(self.unsupported(
                &token,
                directive,
                "supported MVP directives are site blocks, matchers, reverse_proxy, route, handle, handle_path, header, rewrite, uri, respond, redir, encode, tls, and log".to_string(),
            )),
        }
    }

    fn parse_reverse_proxy(
        &mut self,
        host: Option<&str>,
        inherited_prefix: Option<&str>,
        args: Vec<String>,
    ) -> std::result::Result<(), CaddyfileDiagnostic> {
        let upstream_urls = args
            .iter()
            .filter(|arg| looks_like_upstream(arg))
            .cloned()
            .collect::<Vec<_>>();
        let Some(upstream_url) = upstream_urls.first().cloned() else {
            return Ok(());
        };
        self.upstream_count += 1;
        let upstream_name = format!("caddyfile-upstream-{}", self.upstream_count);
        self.config.upstreams.push(GatewayUpstream {
            name: upstream_name.clone(),
            url: upstream_url,
            urls: upstream_urls.into_iter().skip(1).collect(),
        });

        let mut request_headers = Vec::new();
        let mut response_headers = Vec::new();
        if self.consume_lbrace() {
            loop {
                self.skip_newlines();
                if self.consume_rbrace() {
                    break;
                }
                let Some((directive, token)) = self.consume_word_with_token() else {
                    break;
                };
                let args = self.consume_line_args();
                match directive.as_str() {
                    "header_up" => {
                        if args.len() >= 2 {
                            request_headers.push(GatewayHeader {
                                name: args[0].clone(),
                                value: args[1..].join(" "),
                            });
                        }
                    }
                    "header_down" => {
                        if args.len() >= 2 {
                            response_headers.push(GatewayHeader {
                                name: args[0].clone(),
                                value: args[1..].join(" "),
                            });
                        }
                    }
                    "lb_policy" | "health_uri" | "health_interval" | "transport" => {}
                    _ => return Err(self.unsupported(&token, directive, "inside reverse_proxy blocks, FerroGate MVP supports header_up plus basic load-balancing and health-check declarations as typed config placeholders".to_string())),
                }
            }
        }

        self.route_count += 1;
        let prefix = inherited_prefix.unwrap_or("/");
        self.config.routes.push(GatewayRoute {
            name: format!("caddyfile-route-{}", self.route_count),
            upstream: Some(upstream_name),
            hosts: host
                .map(|value| vec![value.to_string()])
                .unwrap_or_default(),
            path_prefixes: vec![prefix.to_string()],
            request_headers,
            response_headers,
            ..GatewayRoute::default()
        });
        Ok(())
    }
}
