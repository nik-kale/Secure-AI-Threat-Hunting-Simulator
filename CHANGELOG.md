# Changelog

## Unreleased

### Fixed

- Analysis reports: the JSON and Markdown reporters the pipeline imports now
  exist, so `analysis_engine` imports again; reports cover every suspicious
  session (not only the first) and are written even when nothing is
  suspicious.
- Telemetry mixing `Z` and `+00:00` timestamps no longer crashes correlation;
  generated telemetry uses one timestamp format and is written in time order.
- `threat-analyze analyze` no longer fails with an unexpected keyword
  argument, and shows each session's ID, risk score and principals.
- `python -m generator.attack_traces.<scenario>.generator` writes to
  `./output/<scenario>/` instead of inside the package.
- ML: the anomaly detector can be fitted with scikit-learn installed;
  failure statuses from the telemetry schema (`failure`, `error`, `denied`)
  are recognised; features are reproducible across processes; behavioural
  baselines compute typical hours, training period and confidence correctly.
- API: failed authentication returns 401 instead of 500; `/analyze/upload`
  returns suspicious sessions instead of failing validation; `/analyze/data`
  and the `/detection/*` routes accept the documented JSON bodies and return
  counts.
- SIEM exporter accepts SIEM type names as strings.
- Packaging: `config.py` is included in installs, and `sqlalchemy[asyncio]`
  brings in greenlet, without which database persistence was disabled.
- Docker: the API image installs libmagic and includes `config.py` and the
  Sigma rules; the dashboard production build compiles.

### Security

- Sigma rule conditions are parsed instead of passed to `eval()`, closing
  remote code execution through `/detection/test-rule`; wildcard patterns are
  regex-escaped.
- `X-Forwarded-For` / `X-Real-IP` are honoured only from `TRUSTED_PROXIES`,
  so clients can no longer dodge or trigger the API-key lockout by spoofing
  their address; API keys are compared in constant time.
- Scenario and rule names must be plain identifiers; `DELETE
  /scenarios/%2E%2E` previously deleted every scenario.
- The HTML report escapes telemetry values.
- The Redis cache no longer unpickles stored values.

### Changed

- New setting `TRUSTED_PROXIES` (comma-separated reverse-proxy IPs).
