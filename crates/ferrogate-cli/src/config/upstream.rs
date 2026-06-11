// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use super::Upstream;

impl Upstream {
    pub(crate) fn endpoint_urls(&self) -> Vec<&str> {
        let mut endpoints = Vec::new();
        if let Some(url) = self.url.as_deref().filter(|url| !url.trim().is_empty()) {
            endpoints.push(url);
        }
        endpoints.extend(
            self.urls
                .iter()
                .map(String::as_str)
                .filter(|url| !url.trim().is_empty()),
        );
        endpoints
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_urls_preserve_primary_then_pool_order() {
        let upstream = Upstream {
            name: "pool".to_string(),
            url: Some("http://127.0.0.1:9001".to_string()),
            urls: vec![
                "".to_string(),
                "http://127.0.0.1:9002".to_string(),
                "   ".to_string(),
            ],
            enabled: true,
        };

        assert_eq!(
            upstream.endpoint_urls(),
            vec!["http://127.0.0.1:9001", "http://127.0.0.1:9002"]
        );
    }
}
