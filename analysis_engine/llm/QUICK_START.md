# LLM Integration - Quick Start Guide

## Installation (2 minutes)

### Step 1: Install Dependencies
```bash
pip install openai>=1.3.0 anthropic>=0.7.0
```

### Step 2: Set API Key
```bash
# Choose one:
export OPENAI_API_KEY="sk-..."           # For OpenAI GPT-4
export ANTHROPIC_API_KEY="sk-ant-..."   # For Anthropic Claude
```

## Usage (3 examples)

### Example 1: Basic Usage (Recommended)
```python
from analysis_engine.llm import get_llm_provider
from analysis_engine.agents import ThreatNarrativeAgent

# Initialize LLM
llm = get_llm_provider("openai")  # or "anthropic"

# Create agent with LLM
agent = ThreatNarrativeAgent(llm_provider=llm)

# Use normally
narrative = agent.generate_narrative(session, kill_chain, mitre, iocs)
```

### Example 2: All Agents
```python
from analysis_engine.llm import get_llm_provider
from analysis_engine.agents import (
    ThreatNarrativeAgent,
    IocExtractorAgent,
    ResponsePlannerAgent
)

# Initialize once
llm = get_llm_provider("openai")

# Create all agents with LLM
narrative_agent = ThreatNarrativeAgent(llm_provider=llm)
ioc_agent = IocExtractorAgent(llm_provider=llm)
response_agent = ResponsePlannerAgent(llm_provider=llm)
```

### Example 3: Without LLM (Templates)
```python
from analysis_engine.agents import ThreatNarrativeAgent

# No LLM provider = automatic template-based mode
agent = ThreatNarrativeAgent()

# Works identically, uses templates instead of LLM
narrative = agent.generate_narrative(session, kill_chain, mitre, iocs)
```

## Key Points

✅ **Works immediately** - No code changes needed, just add API key
✅ **Automatic fallback** - Falls back to templates if LLM fails
✅ **Backward compatible** - All existing code continues to work
✅ **Optional** - LLM is completely optional, templates work great too

## Choose Your Model

```python
# OpenAI GPT-4 (default, most popular)
llm = get_llm_provider("openai")

# Anthropic Claude (excellent reasoning)
llm = get_llm_provider("anthropic")

# Specific model
llm = get_llm_provider("openai", model="gpt-4-turbo-preview")
llm = get_llm_provider("anthropic", model="claude-3-5-sonnet-20241022")
```

## Test It Works

```bash
python3 analysis_engine/llm/example_usage.py
```

Should see:
```
✓ Initialized OpenAI provider
✓ Created agents with LLM support
```

## What You Get

With LLM enabled, you get:
- **Richer narratives** - Context-aware, detailed threat stories
- **Better IOC extraction** - Understands context, not just patterns
- **Smarter response plans** - Tailored to specific attack patterns
- **MITRE mapping** - Enhanced technique identification

## Cost

Typical costs per incident:
- **Detailed mode**: $0.05-0.15 per incident
- **Quick mode**: $0.02-0.05 per incident

For 100 incidents/day: ~$150-450/month

## Troubleshooting

### "ImportError: No module named 'openai'"
```bash
pip install openai anthropic
```

### "API key not found"
```bash
export OPENAI_API_KEY="sk-your-key-here"
```

### "LLM not being used"
Check agent logs:
```python
agent = ThreatNarrativeAgent(llm_provider=llm)
print(agent.use_llm)  # Should be True
```

## More Information

- **Full documentation**: `analysis_engine/llm/README.md`
- **Examples**: `analysis_engine/llm/example_usage.py`
- **Integration guide**: `LLM_INTEGRATION_GUIDE.md`

## That's It!

You're ready to use LLM-powered threat analysis. Start with Example 1 above and you'll be generating AI-enhanced threat reports in minutes.
