use super::Config;

pub(crate) fn config_snapshot_id(config: &Config) -> String {
    let bytes = serde_json::to_vec(config).expect("config serialization should not fail");
    format!("{:016x}", fnv1a64(&bytes))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_id_is_stable_for_same_config() {
        let config = Config::default();

        assert_eq!(config_snapshot_id(&config), config_snapshot_id(&config));
    }

    #[test]
    fn snapshot_id_changes_when_config_changes() {
        let first = Config::default();
        let second = Config {
            listen: "127.0.0.1:9090".to_string(),
            ..Config::default()
        };

        assert_ne!(config_snapshot_id(&first), config_snapshot_id(&second));
    }
}
