# Contributing to AI Threat Hunting Simulator

Thank you for your interest in contributing to the AI Threat Hunting Simulator! This document provides guidelines and instructions for contributing.

## Code of Conduct

This project is intended for educational and research purposes. All contributors are expected to:

- Be respectful and professional
- Focus on improving security education and detection capabilities
- Never use this project for malicious purposes
- Keep all generated data synthetic and safe

## How to Contribute

### Reporting Issues

- Check existing issues before creating a new one
- Provide clear reproduction steps
- Include relevant system information (OS, Python version, etc.)
- Use issue templates when available

### Suggesting Features

- Explain the use case clearly
- Describe expected behavior
- Consider whether it fits the project's educational mission

### Submitting Code

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/my-new-feature`
3. **Make your changes** following the coding standards below
4. **Write tests** for new functionality
5. **Run the test suite**: `pytest`
6. **Update documentation** as needed
7. **Commit with clear messages**: `git commit -m "Add: description of feature"`
8. **Push to your fork**: `git push origin feature/my-new-feature`
9. **Submit a pull request**

## Development Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/ai-threat-hunting-simulator.git
cd ai-threat-hunting-simulator

# Run setup script
./scripts/dev_setup.sh

# Activate virtual environment
source venv/bin/activate

# Run tests
pytest

# Run a scenario to verify
python cli/run_scenario.py --scenario iam_priv_escalation --output ./output/test
```

## Coding Standards

### Python Code

- Follow PEP 8 style guide
- Use type hints for all functions
- Write docstrings for classes and public methods
- Keep functions focused and under 50 lines when possible
- Use meaningful variable names

**Example:**

```python
def correlate_events(
    events: List[NormalizedEvent],
    time_window: timedelta
) -> List[CorrelationSession]:
    """
    Correlate events into sessions based on time proximity.

    Args:
        events: List of normalized events
        time_window: Maximum time between correlated events

    Returns:
        List of correlation sessions
    """
    # Implementation
    pass
```

### TypeScript/React Code

- Use functional components with hooks
- Follow Airbnb JavaScript Style Guide
- Use TypeScript for type safety
- Keep components under 200 lines
- Extract reusable logic into custom hooks

### Documentation

- Update README.md for user-facing changes
- Add/update docstrings for code changes
- Create/update docs/ files for architectural changes
- Include examples for new features

## Adding New Attack Scenarios

To add a new attack scenario:

1. **Create scenario directory**:
   ```
   generator/attack_traces/my_scenario/
   ├── README.md          # Scenario description
   └── generator.py       # Generation logic
   ```

2. **Implement generator function**:
   ```python
   def generate_my_scenario(
       output_dir: Path,
       account_id: str = "123456789012",
       region: str = "us-east-1",
       duration_hours: float = 1.0,
       add_noise: bool = True
   ) -> Dict[str, Any]:
       # Generate events
       # Return metadata
       pass
   ```

3. **Register in CLI**:
   Update `cli/run_scenario.py` to include your scenario

4. **Document the scenario**:
   Add details to `docs/threat_scenarios.md`

5. **Add tests**:
   Create test cases in `tests/`

## Testing Guidelines

### Writing Tests

- Test each module independently (unit tests)
- Test integration between components (integration tests)
- Ensure scenarios generate valid telemetry
- Verify analysis pipeline produces expected outputs

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_telemetry_synthesizer.py

# Run with coverage
pytest --cov=analysis_engine --cov=generator
```

## Documentation Contributions

Documentation is crucial for this educational project:

- **Code comments**: Explain why, not what
- **Docstrings**: Describe purpose, parameters, return values
- **README updates**: Keep user-facing docs current
- **Architecture docs**: Document design decisions
- **Examples**: Provide clear usage examples

## Pull Request Guidelines

### PR Title Format

```
[Type] Brief description

Types: Add, Fix, Update, Remove, Refactor, Docs
```

**Examples:**
- `[Add] Container persistence scenario`
- `[Fix] Correlation time window calculation`
- `[Update] MITRE ATT&CK technique mappings`
- `[Docs] Improve quickstart guide`

### PR Description

Include:
- **What**: What changes were made
- **Why**: Motivation for the changes
- **How**: High-level implementation approach
- **Testing**: How you tested the changes
- **Screenshots**: For UI changes

### Review Process

- Maintainers will review PRs within 5 business days
- Address review feedback promptly
- Keep PRs focused and reasonably sized
- Be open to discussion and iteration

## Areas for Contribution

We especially welcome contributions in:

### High Priority

- Additional attack scenarios (lateral movement, data exfiltration, etc.)
- Enhanced UI components for the SOC dashboard
- Integration with real threat intelligence feeds
- Performance optimizations for large datasets

### Medium Priority

- Additional cloud services (Azure, GCP telemetry)
- Real LLM integration (OpenAI, Anthropic, etc.)
- Advanced correlation algorithms
- Export formats (STIX, MISP, etc.)

### Lower Priority

- Additional visualization options
- Alternative deployment methods
- Internationalization
- Dark/light theme toggle

## Questions?

- Open a GitHub issue with the "question" label
- Check existing documentation in `docs/`
- Review closed issues for similar questions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping improve security education and threat hunting capabilities!
