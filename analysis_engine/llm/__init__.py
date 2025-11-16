"""
LLM integration module for AI-powered threat analysis.

This module provides LLM providers and optimized prompts for enhancing
threat hunting analysis with AI capabilities.

Usage:
    from analysis_engine.llm import get_llm_provider, get_prompt

    # Initialize provider
    provider = get_llm_provider("openai", api_key="sk-...")

    # Get prompt template
    prompt = get_prompt("narrative", mode="detailed")

    # Use with agent
    narrative = await provider.generate_narrative(...)
"""

from analysis_engine.llm.providers import (
    LLMProvider,
    OpenAIProvider,
    AnthropicProvider,
    get_llm_provider,
)

from analysis_engine.llm.prompts import (
    get_prompt,
    PROMPTS,
    THREAT_NARRATIVE_PROMPT,
    IOC_EXTRACTION_PROMPT,
    RESPONSE_PLANNING_PROMPT,
    MITRE_IDENTIFICATION_PROMPT,
)

__all__ = [
    # Provider classes
    "LLMProvider",
    "OpenAIProvider",
    "AnthropicProvider",
    "get_llm_provider",
    # Prompt functions and templates
    "get_prompt",
    "PROMPTS",
    "THREAT_NARRATIVE_PROMPT",
    "IOC_EXTRACTION_PROMPT",
    "RESPONSE_PLANNING_PROMPT",
    "MITRE_IDENTIFICATION_PROMPT",
]

__version__ = "1.0.0"
