"""
Example usage of LLM integration for threat analysis.

This example demonstrates how to use LLM providers with the threat hunting agents.
"""

import asyncio
import os
from typing import Optional

from analysis_engine.llm import get_llm_provider, get_prompt
from analysis_engine.agents import (
    ThreatNarrativeAgent,
    IocExtractorAgent,
    ResponsePlannerAgent
)


# Example 1: Basic usage with OpenAI
def example_basic_openai():
    """Basic example using OpenAI GPT-4."""
    print("=== Example 1: Basic OpenAI Usage ===\n")

    # Initialize provider (will use OPENAI_API_KEY from environment)
    try:
        llm_provider = get_llm_provider("openai")
        print(f"✓ Initialized OpenAI provider")

        # Create agents with LLM support
        narrative_agent = ThreatNarrativeAgent(llm_provider=llm_provider)
        ioc_agent = IocExtractorAgent(llm_provider=llm_provider)
        response_agent = ResponsePlannerAgent(llm_provider=llm_provider)

        print(f"✓ Created agents with LLM support")
        print(f"  - Narrative agent using LLM: {narrative_agent.use_llm}")
        print(f"  - IOC agent using LLM: {ioc_agent.use_llm}")
        print(f"  - Response agent using LLM: {response_agent.use_llm}")

    except Exception as e:
        print(f"✗ Failed to initialize OpenAI: {e}")
        print("  Make sure OPENAI_API_KEY is set in your environment")


# Example 2: Using Anthropic Claude
def example_anthropic():
    """Example using Anthropic Claude."""
    print("\n=== Example 2: Anthropic Claude Usage ===\n")

    try:
        # Initialize with specific model
        llm_provider = get_llm_provider(
            provider_type="anthropic",
            model="claude-3-5-sonnet-20241022"
        )
        print(f"✓ Initialized Anthropic provider with Claude 3.5 Sonnet")

        # Create agents
        narrative_agent = ThreatNarrativeAgent(llm_provider=llm_provider)
        print(f"✓ Created narrative agent")

    except Exception as e:
        print(f"✗ Failed to initialize Anthropic: {e}")
        print("  Make sure ANTHROPIC_API_KEY is set in your environment")


# Example 3: Template-based fallback
def example_template_fallback():
    """Example showing template-based fallback when LLM is unavailable."""
    print("\n=== Example 3: Template-Based Fallback ===\n")

    # Create agents without LLM provider
    narrative_agent = ThreatNarrativeAgent()
    ioc_agent = IocExtractorAgent()
    response_agent = ResponsePlannerAgent()

    print(f"✓ Created agents without LLM")
    print(f"  - Narrative agent using LLM: {narrative_agent.use_llm}")
    print(f"  - IOC agent using LLM: {ioc_agent.use_llm}")
    print(f"  - Response agent using LLM: {response_agent.use_llm}")
    print(f"  All agents will use template-based analysis")


# Example 4: Selective LLM usage
def example_selective_llm():
    """Example showing how to selectively use LLM for some agents."""
    print("\n=== Example 4: Selective LLM Usage ===\n")

    try:
        llm_provider = get_llm_provider("openai")

        # Use LLM for narrative (most benefit)
        narrative_agent = ThreatNarrativeAgent(llm_provider=llm_provider, use_llm=True)

        # Use template for IOC extraction (fast and reliable)
        ioc_agent = IocExtractorAgent(llm_provider=llm_provider, use_llm=False)

        # Use LLM for response planning (high value)
        response_agent = ResponsePlannerAgent(llm_provider=llm_provider, use_llm=True)

        print(f"✓ Created agents with selective LLM usage")
        print(f"  - Narrative agent: LLM enabled")
        print(f"  - IOC agent: LLM disabled (using templates)")
        print(f"  - Response agent: LLM enabled")

    except Exception as e:
        print(f"✗ Failed: {e}")


# Example 5: Direct provider usage
async def example_direct_provider():
    """Example using LLM provider directly."""
    print("\n=== Example 5: Direct Provider Usage ===\n")

    try:
        from analysis_engine.llm import OpenAIProvider

        provider = OpenAIProvider()

        # Sample data (normally from actual analysis)
        session_data = {
            "session_id": "test-session",
            "duration_seconds": 300,
            "num_events": 25,
            "risk_score": 0.85,
            "start_time": "2024-01-01T10:00:00Z",
            "end_time": "2024-01-01T10:05:00Z"
        }

        kill_chain_data = {
            "num_stages": 4,
            "stages": {
                "reconnaissance": {"num_events": 5},
                "exploitation": {"num_events": 8},
                "installation": {"num_events": 7},
                "actions_on_objectives": {"num_events": 5}
            }
        }

        mitre_data = {
            "num_techniques": 3,
            "technique_ids": ["T1078.004", "T1548.005", "T1110.004"],
            "tactics": ["Initial Access", "Privilege Escalation", "Credential Access"]
        }

        ioc_data = {
            "iocs": {
                "ip_addresses": ["203.0.113.42"],
                "principals": ["compromised-user@example.com"],
                "resources": ["arn:aws:iam::123456789012:role/AdminRole"]
            }
        }

        # Get prompt
        prompt = get_prompt("narrative", mode="quick")

        print("✓ Calling LLM provider directly...")
        # Note: This would make an actual API call
        # narrative = await provider.generate_narrative(
        #     session_data=session_data,
        #     kill_chain_data=kill_chain_data,
        #     mitre_data=mitre_data,
        #     ioc_data=ioc_data,
        #     prompt_template=prompt
        # )
        print("  (API call skipped in example)")

    except Exception as e:
        print(f"✗ Failed: {e}")


# Example 6: Comparing prompt modes
def example_prompt_modes():
    """Example showing different prompt modes."""
    print("\n=== Example 6: Prompt Modes ===\n")

    from analysis_engine.llm import get_prompt

    # Get detailed prompt (comprehensive analysis)
    detailed_prompt = get_prompt("narrative", mode="detailed")
    print(f"✓ Detailed prompt length: {len(detailed_prompt)} characters")
    print(f"  Use for: Critical incidents, executive reports")

    # Get quick prompt (faster, more concise)
    quick_prompt = get_prompt("narrative", mode="quick")
    print(f"✓ Quick prompt length: {len(quick_prompt)} characters")
    print(f"  Use for: Routine analysis, batch processing")

    # All available prompt types
    prompt_types = ["narrative", "ioc_extraction", "response_planning", "mitre_identification"]
    print(f"\n✓ Available prompt types:")
    for ptype in prompt_types:
        prompt = get_prompt(ptype)
        print(f"  - {ptype}: {len(prompt)} characters")


# Example 7: Configuration from environment
def example_env_config():
    """Example showing configuration from environment variables."""
    print("\n=== Example 7: Environment Configuration ===\n")

    # Check environment variables
    openai_key = os.getenv("OPENAI_API_KEY")
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")

    print("Environment configuration:")
    print(f"  OPENAI_API_KEY: {'✓ Set' if openai_key else '✗ Not set'}")
    print(f"  ANTHROPIC_API_KEY: {'✓ Set' if anthropic_key else '✗ Not set'}")

    # Get provider type from environment
    provider_type = os.getenv("LLM_PROVIDER", "openai")
    print(f"  LLM_PROVIDER: {provider_type}")

    # Try to initialize based on environment
    if openai_key or anthropic_key:
        try:
            provider = get_llm_provider(provider_type)
            print(f"\n✓ Successfully initialized {provider_type} provider")
        except Exception as e:
            print(f"\n✗ Failed to initialize provider: {e}")
    else:
        print(f"\n⚠ No API keys found. Set OPENAI_API_KEY or ANTHROPIC_API_KEY")


# Example 8: Complete workflow
def example_complete_workflow():
    """Example showing complete analysis workflow with LLM."""
    print("\n=== Example 8: Complete Workflow ===\n")

    try:
        # Initialize provider
        llm_provider = get_llm_provider("openai")
        print("1. ✓ Initialized LLM provider")

        # Create all agents
        narrative_agent = ThreatNarrativeAgent(llm_provider=llm_provider)
        ioc_agent = IocExtractorAgent(llm_provider=llm_provider)
        response_agent = ResponsePlannerAgent(llm_provider=llm_provider)
        print("2. ✓ Created analysis agents")

        # In a real workflow, you would:
        # 3. Load and parse events
        # 4. Run correlation analysis
        # 5. Extract IOCs (with LLM)
        # 6. Map to MITRE ATT&CK
        # 7. Generate narrative (with LLM)
        # 8. Create response plan (with LLM)
        # 9. Generate reports

        print("3. ℹ In production, would process events and generate analysis")
        print("4. ℹ Results would include LLM-enhanced narratives and insights")

    except Exception as e:
        print(f"✗ Workflow failed: {e}")


def main():
    """Run all examples."""
    print("╔════════════════════════════════════════════════════════╗")
    print("║  LLM Integration Examples - Threat Hunting Simulator  ║")
    print("╚════════════════════════════════════════════════════════╝")

    # Run synchronous examples
    example_basic_openai()
    example_anthropic()
    example_template_fallback()
    example_selective_llm()
    example_prompt_modes()
    example_env_config()
    example_complete_workflow()

    # Run async example
    print("\n" + "="*60)
    asyncio.run(example_direct_provider())

    print("\n" + "="*60)
    print("\n✓ All examples completed!")
    print("\nNext steps:")
    print("  1. Set your API key: export OPENAI_API_KEY='sk-...'")
    print("  2. Install dependencies: pip install openai anthropic")
    print("  3. Run the analysis pipeline with LLM enabled")
    print("  4. Review the generated narratives and insights")


if __name__ == "__main__":
    main()
