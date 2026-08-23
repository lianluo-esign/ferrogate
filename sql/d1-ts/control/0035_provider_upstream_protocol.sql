-- OpenAI-compatible relays do not all expose both inference surfaces. Keep the
-- adapter family (`kind`) separate from the concrete upstream endpoint so one
-- provider can explicitly route Chat clients through the Responses API.
ALTER TABLE platform_provider_channels ADD COLUMN upstream_protocol TEXT;

