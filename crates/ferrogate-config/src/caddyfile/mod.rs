mod lexer;
mod parser;
mod parser_support;

#[cfg(test)]
mod parser_tests;

pub use parser::parse_caddyfile;
