// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-13
// description: Public canonical provider adapter-family registry contract (#214).

use ferrogate_providers::{ProviderAdapterRegistry, SUPPORTED_PROVIDER_ADAPTER_FAMILIES};

#[test]
fn every_declared_family_and_alias_resolves_to_its_canonical_adapter() {
    let registry = ProviderAdapterRegistry::default();

    for family in SUPPORTED_PROVIDER_ADAPTER_FAMILIES {
        for kind in std::iter::once(family.canonical_kind).chain(family.aliases.iter().copied()) {
            let adapter = registry.adapter_for(kind).unwrap_or_else(|error| {
                panic!("declared adapter kind {kind} did not resolve: {error}")
            });
            assert_eq!(adapter.kind(), family.canonical_kind);
        }
    }
}

#[test]
fn canonical_family_names_are_unique() {
    let mut names = SUPPORTED_PROVIDER_ADAPTER_FAMILIES
        .iter()
        .map(|family| family.canonical_kind)
        .collect::<Vec<_>>();
    names.sort_unstable();
    names.dedup();

    assert_eq!(names.len(), SUPPORTED_PROVIDER_ADAPTER_FAMILIES.len());
}
