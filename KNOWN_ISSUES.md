# Known Issues

## Working Scenarios ✓

The following attack scenarios are fully functional and tested:

1. **IAM Privilege Escalation** (`iam_priv_escalation`) - 31 events
   - PassRole exploitation via Lambda
   - Status: ✅ WORKING

2. **Container Escape** (`container_escape`) - 33 events
   - Container breakout with cryptominer deployment
   - Status: ✅ WORKING

3. **Credential Stuffing** (`cred_stuffing`) - 105 events
   - Distributed botnet credential stuffing attack
   - Status: ✅ WORKING

## Scenarios Requiring Fixes ⚠️

The following scenarios were auto-generated but require additional implementation:

4. **Lateral Movement** (`lateral_movement`)
   - Issue: Missing `create_sts_event()` and `create_database_event()` methods in TelemetrySynthesizer
   - Fix Required: Add missing telemetry synthesizer methods
   - Status: ⚠️ NEEDS FIX

5. **Data Exfiltration** (`data_exfiltration`)
   - Issue: Not yet tested, may have similar missing method issues
   - Status: ⚠️ NEEDS TESTING

6. **Supply Chain Attack** (`supply_chain`)
   - Issue: Not yet tested, may have similar missing method issues
   - Status: ⚠️ NEEDS TESTING

## Priority Fixes

### High Priority
- [ ] Add `create_database_event()` method to TelemetrySynthesizer for RDS/DynamoDB events
- [ ] Test and fix data_exfiltration scenario
- [ ] Test and fix supply_chain scenario

### Medium Priority
- [ ] Implement full UI components (currently skeleton only)
- [ ] Expand test coverage from <10% to 50%+
- [ ] Enable LLM integration in threat narrative generation
- [ ] Enable threat intelligence enrichment for IOCs

### Low Priority
- [ ] Add more attack scenarios (DDoS, ransomware, insider threat)
- [ ] Implement Kubernetes deployment configs
- [ ] Add multi-cloud support (Azure, GCP)

## Workaround

To use the simulator immediately:
1. Use any of the 3 working scenarios
2. Run via CLI: `python -m generator.attack_traces.iam_priv_escalation.generator`
3. Analyze results: `python -m cli.analyze analyze ./path/to/telemetry.jsonl`

## Contributing

If you'd like to help fix these issues:
1. Fork the repository
2. Fix one of the scenarios in `generator/attack_traces/`
3. Add the missing methods to `generator/telemetry_synthesizer.py`
4. Submit a pull request

Last Updated: 2025-11-16
