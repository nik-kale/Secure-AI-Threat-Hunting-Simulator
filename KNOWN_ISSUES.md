# Known Issues

## Scenarios

All six AWS attack scenarios generate telemetry and are exercised in CI:
`iam_priv_escalation`, `container_escape`, `cred_stuffing`,
`lateral_movement`, `data_exfiltration` and `supply_chain`.

## Open Issues

- The template-based correlation flags no suspicious session for the
  `container_escape` and `cred_stuffing` scenarios at the default risk
  threshold (0.5); their reports list zero suspicious sessions.
- The SOC dashboard's API client calls routes the server does not expose
  (`POST /scenarios/{name}/generate`, `POST /scenarios/{name}/analyze`) and
  expects IOC objects where the API returns strings.
- Database persistence (`_save_to_database`) reads keys the pipeline does not
  produce, so saved sessions and IOCs are mostly empty.

## Priority Fixes

### Medium Priority
- [ ] Implement full UI components (currently skeleton only)
- [ ] Expand test coverage from about 40% to 50%+
- [ ] Enable LLM integration in threat narrative generation
- [ ] Enable threat intelligence enrichment for IOCs

### Low Priority
- [ ] Add more attack scenarios (DDoS, ransomware, insider threat)
- [ ] Implement Kubernetes deployment configs
- [ ] Add multi-cloud support (Azure, GCP)

## Workaround

To use the simulator immediately:
1. Use any of the scenarios
2. Run via CLI: `python -m generator.attack_traces.iam_priv_escalation.generator`
   (writes `./output/iam_priv_escalation/telemetry.jsonl`)
3. Analyze results: `python -m cli.analyze analyze ./output/iam_priv_escalation/telemetry.jsonl`

## Contributing

If you'd like to help fix these issues:
1. Fork the repository
2. Pick one of the open issues above
3. Submit a pull request

Last Updated: 2026-10-15
