# LLM Integration for AI Threat Hunting Simulator

This module provides comprehensive LLM (Large Language Model) integration for AI-powered threat analysis, enabling enhanced narrative generation, IOC extraction, and response planning.

## Features

- **Multi-Provider Support**: OpenAI (GPT-4) and Anthropic (Claude) providers
- **Graceful Fallback**: Automatic fallback to template-based analysis if LLM is unavailable
- **Async Operations**: Full async/await support for efficient API calls
- **Optimized Prompts**: Pre-built, domain-specific prompts for threat hunting
- **Error Handling**: Robust error handling with automatic retries

## Installation

### 1. Install LLM Dependencies

Edit `requirements.txt` and uncomment the LLM packages:

```bash
# Uncomment these lines in requirements.txt
openai>=1.3.0
anthropic>=0.7.0
```

Then install:

```bash
pip install -r requirements.txt
```

### 2. Set Up API Keys

Set environment variables for your chosen provider(s):

```bash
# For OpenAI
export OPENAI_API_KEY="sk-..."

# For Anthropic
export ANTHROPIC_API_KEY="sk-ant-..."
```

## Quick Start

### Basic Usage with OpenAI

```python
from analysis_engine.llm import get_llm_provider
from analysis_engine.agents import (
    ThreatNarrativeAgent,
    IocExtractorAgent,
    ResponsePlannerAgent
)

# Initialize LLM provider
llm_provider = get_llm_provider("openai")  # or "anthropic"

# Create agents with LLM support
narrative_agent = ThreatNarrativeAgent(llm_provider=llm_provider)
ioc_agent = IocExtractorAgent(llm_provider=llm_provider)
response_agent = ResponsePlannerAgent(llm_provider=llm_provider)

# Use agents normally - they'll automatically use LLM when available
narrative = narrative_agent.generate_narrative(
    session, kill_chain_data, mitre_data, ioc_data
)
```

### Using Anthropic Claude

```python
from analysis_engine.llm import get_llm_provider

# Initialize with Claude
llm_provider = get_llm_provider(
    provider_type="anthropic",
    model="claude-3-5-sonnet-20241022"  # Optional: specify model
)

# Use with agents as above
```

### Without LLM (Template-Based)

If LLM packages are not installed or API keys are not set, agents automatically fall back to template-based analysis:

```python
# Create agents without LLM provider
narrative_agent = ThreatNarrativeAgent()  # Uses templates
ioc_agent = IocExtractorAgent()  # Uses templates
response_agent = ResponsePlannerAgent()  # Uses templates
```

## Advanced Usage

### Custom Model Selection

```python
from analysis_engine.llm import get_llm_provider

# Use specific GPT-4 model
openai_provider = get_llm_provider(
    provider_type="openai",
    model="gpt-4-turbo-preview"
)

# Use specific Claude model
anthropic_provider = get_llm_provider(
    provider_type="anthropic",
    model="claude-3-opus-20240229"
)
```

### Disable LLM for Specific Agent

```python
# Create agent with LLM provider but disable it
agent = ThreatNarrativeAgent(
    llm_provider=llm_provider,
    use_llm=False  # Forces template-based generation
)
```

### Direct LLM Provider Usage

```python
from analysis_engine.llm import OpenAIProvider, get_prompt

# Initialize provider directly
provider = OpenAIProvider(api_key="sk-...")

# Get optimized prompt
prompt = get_prompt("narrative", mode="detailed")

# Use provider methods directly
narrative = await provider.generate_narrative(
    session_data=session_data,
    kill_chain_data=kill_chain_data,
    mitre_data=mitre_data,
    ioc_data=ioc_data,
    prompt_template=prompt
)
```

### Using Quick Prompts for Faster Analysis

```python
from analysis_engine.llm import get_prompt

# Use quick mode for faster analysis (shorter, more concise)
quick_prompt = get_prompt("narrative", mode="quick")
detailed_prompt = get_prompt("narrative", mode="detailed")
```

## Available Prompts

The module includes optimized prompts for various analysis tasks:

### 1. Threat Narrative Generation
```python
from analysis_engine.llm import get_prompt

# Get narrative prompt
prompt = get_prompt("narrative", mode="detailed")  # or "quick"
```

### 2. IOC Extraction
```python
# Get IOC extraction prompt
prompt = get_prompt("ioc_extraction", mode="detailed")  # or "quick"
```

### 3. Response Planning
```python
# Get response planning prompt
prompt = get_prompt("response_planning", mode="detailed")  # or "quick"
```

### 4. MITRE Technique Identification
```python
# Get MITRE identification prompt
prompt = get_prompt("mitre_identification", mode="detailed")
```

## Pipeline Integration

### Updating the Analysis Pipeline

To use LLM in the main analysis pipeline, update `analysis_engine/pipeline.py`:

```python
from analysis_engine.llm import get_llm_provider

class ThreatAnalysisPipeline:
    def __init__(self, use_llm=True, llm_provider_type="openai"):
        # Initialize LLM provider if enabled
        self.llm_provider = None
        if use_llm:
            try:
                self.llm_provider = get_llm_provider(llm_provider_type)
                logger.info(f"LLM provider initialized: {llm_provider_type}")
            except Exception as e:
                logger.warning(f"Failed to initialize LLM: {e}. Using template-based analysis.")

        # Initialize agents with LLM support
        self.narrative_agent = ThreatNarrativeAgent(llm_provider=self.llm_provider)
        self.ioc_agent = IocExtractorAgent(llm_provider=self.llm_provider)
        self.response_agent = ResponsePlannerAgent(llm_provider=self.llm_provider)
```

## Configuration Examples

### Environment Variables (.env file)

```bash
# OpenAI Configuration
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4-turbo-preview

# Anthropic Configuration
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-3-5-sonnet-20241022

# LLM Settings
USE_LLM=true
LLM_PROVIDER=openai  # or anthropic
```

### Python Configuration

```python
import os
from analysis_engine.llm import get_llm_provider

# Load from environment
provider_type = os.getenv("LLM_PROVIDER", "openai")
model = os.getenv(f"{provider_type.upper()}_MODEL")

llm_provider = get_llm_provider(
    provider_type=provider_type,
    model=model
)
```

## Error Handling

The LLM integration includes comprehensive error handling:

```python
# Automatic retry with exponential backoff
# Falls back to template-based analysis on failure
# Logs all errors for debugging

try:
    narrative = narrative_agent.generate_narrative(...)
except Exception as e:
    # Even if this fails, you still get template-based results
    logger.error(f"Analysis failed: {e}")
```

## Performance Considerations

### Token Limits

LLM providers automatically limit event samples to avoid token limits:
- Narrative generation: Up to 100 events
- IOC extraction: Up to 100 events
- MITRE identification: Up to 50 events

### Async Operations

All LLM operations are async for better performance:

```python
import asyncio

# Use async context when calling directly
async def analyze_threat():
    narrative = await provider.generate_narrative(...)
    return narrative

# Or use the synchronous wrapper in agents
narrative = narrative_agent.generate_narrative(...)  # Handles async internally
```

### Cost Optimization

To minimize API costs:
1. Use "quick" mode prompts for faster, cheaper analysis
2. Set `use_llm=False` for batch processing of low-priority incidents
3. Use template-based analysis for known attack patterns
4. Consider caching LLM responses for similar incidents

## Supported Models

### OpenAI
- `gpt-4-turbo-preview` (default)
- `gpt-4`
- `gpt-3.5-turbo` (faster, cheaper)

### Anthropic
- `claude-3-5-sonnet-20241022` (default, best balance)
- `claude-3-opus-20240229` (highest capability)
- `claude-3-sonnet-20240229` (balanced)
- `claude-3-haiku-20240307` (fastest, cheapest)

## Troubleshooting

### LLM Not Being Used

1. Check API key is set:
   ```python
   import os
   print(os.getenv("OPENAI_API_KEY"))  # Should not be None
   ```

2. Check packages are installed:
   ```python
   import openai  # Should not raise ImportError
   ```

3. Check agent initialization:
   ```python
   agent = ThreatNarrativeAgent(llm_provider=llm_provider)
   print(agent.use_llm)  # Should be True
   ```

### API Errors

If you see API errors:
- Check your API key is valid and has credits
- Verify network connectivity
- Check rate limits on your API account
- Review logs for detailed error messages

### Import Errors

If you see import errors:
```bash
pip install openai>=1.3.0 anthropic>=0.7.0
```

## Best Practices

1. **Use LLM for Complex Incidents**: Reserve LLM analysis for high-severity or complex incidents
2. **Template-Based for Batch Processing**: Use template-based for routine/batch analysis
3. **Combine Both**: Use template-based for structure, LLM for narrative enhancement
4. **Monitor Costs**: Track API usage and costs, especially in production
5. **Test Fallback**: Regularly test that template-based fallback works
6. **Validate Results**: Always validate LLM-generated results, especially for critical decisions

## Examples

See the `examples/` directory for complete examples:
- `examples/llm_basic_usage.py` - Basic LLM integration
- `examples/llm_advanced.py` - Advanced features and customization
- `examples/llm_comparison.py` - Compare template vs LLM results

## API Reference

### LLMProvider (Abstract Base Class)

```python
class LLMProvider(ABC):
    async def generate_narrative(...) -> Dict[str, Any]
    async def extract_iocs(...) -> Dict[str, Any]
    async def plan_response(...) -> Dict[str, Any]
    async def identify_mitre_techniques(...) -> List[str]
```

### get_llm_provider()

```python
def get_llm_provider(
    provider_type: str = "openai",
    api_key: Optional[str] = None,
    model: Optional[str] = None
) -> LLMProvider
```

### get_prompt()

```python
def get_prompt(
    prompt_type: str,  # "narrative", "ioc_extraction", "response_planning", "mitre_identification"
    mode: str = "detailed"  # "detailed" or "quick"
) -> str
```

## License

Part of the Secure AI Threat Hunting Simulator project.
