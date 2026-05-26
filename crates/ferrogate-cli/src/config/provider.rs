use super::Provider;

impl Provider {
    pub(crate) fn api_key_value(&self) -> Option<String> {
        let env_name = self.api_key_env.as_deref()?;
        std::env::var(env_name)
            .ok()
            .filter(|value| !value.trim().is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_api_key_reads_non_empty_environment_value() {
        std::env::set_var("FERROGATE_PROVIDER_TEST_KEY", "provider-secret");
        let provider = Provider {
            name: "openai".into(),
            kind: "openai".into(),
            base_url: "https://api.openai.example/v1".into(),
            api_key_env: Some("FERROGATE_PROVIDER_TEST_KEY".into()),
            openrouter_http_referer: None,
            openrouter_x_title: None,
            enabled: true,
        };

        assert_eq!(provider.api_key_value().as_deref(), Some("provider-secret"));
    }

    #[test]
    fn provider_api_key_ignores_missing_or_empty_environment_value() {
        std::env::set_var("FERROGATE_PROVIDER_EMPTY_KEY", "");
        let provider = Provider {
            name: "openai".into(),
            kind: "openai".into(),
            base_url: "https://api.openai.example/v1".into(),
            api_key_env: Some("FERROGATE_PROVIDER_EMPTY_KEY".into()),
            openrouter_http_referer: None,
            openrouter_x_title: None,
            enabled: true,
        };

        assert_eq!(provider.api_key_value(), None);
    }
}
