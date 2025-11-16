"""
LLM provider implementations for AI-powered threat analysis.
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
import logging
import os
import asyncio
from datetime import datetime

logger = logging.getLogger(__name__)


class LLMProvider(ABC):
    """
    Abstract base class for LLM providers.

    All LLM providers must implement these methods for threat hunting analysis.
    """

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        """
        Initialize LLM provider.

        Args:
            api_key: API key for the provider (if None, will try to get from env)
            model: Model name to use (if None, will use provider default)
        """
        self.api_key = api_key
        self.model = model
        self.max_retries = 3
        self.timeout = 60

    @abstractmethod
    async def generate_narrative(
        self,
        session_data: Dict[str, Any],
        kill_chain_data: Dict[str, Any],
        mitre_data: Dict[str, Any],
        ioc_data: Dict[str, Any],
        prompt_template: str
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive threat narrative.

        Args:
            session_data: Correlation session data
            kill_chain_data: Kill chain mapping results
            mitre_data: MITRE ATT&CK mapping results
            ioc_data: IOC extraction results
            prompt_template: The prompt template to use

        Returns:
            Structured narrative with executive summary, timeline, etc.
        """
        pass

    @abstractmethod
    async def extract_iocs(
        self,
        events: List[Dict[str, Any]],
        prompt_template: str
    ) -> Dict[str, Any]:
        """
        Extract indicators of compromise from events.

        Args:
            events: List of normalized events
            prompt_template: The prompt template to use

        Returns:
            Structured IOC data with categorization
        """
        pass

    @abstractmethod
    async def plan_response(
        self,
        session_data: Dict[str, Any],
        mitre_data: Dict[str, Any],
        ioc_data: Dict[str, Any],
        narrative_data: Dict[str, Any],
        prompt_template: str
    ) -> Dict[str, Any]:
        """
        Generate an incident response plan.

        Args:
            session_data: Correlation session data
            mitre_data: MITRE ATT&CK mapping
            ioc_data: IOC extraction results
            narrative_data: Threat narrative
            prompt_template: The prompt template to use

        Returns:
            Structured response plan with immediate actions, containment, etc.
        """
        pass

    @abstractmethod
    async def identify_mitre_techniques(
        self,
        events: List[Dict[str, Any]],
        prompt_template: str
    ) -> List[str]:
        """
        Identify MITRE ATT&CK techniques from events.

        Args:
            events: List of normalized events
            prompt_template: The prompt template to use

        Returns:
            List of MITRE technique IDs
        """
        pass

    async def _call_with_retry(self, func, *args, **kwargs):
        """Call function with retry logic."""
        last_error = None

        for attempt in range(self.max_retries):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                last_error = e
                logger.warning(
                    f"LLM call failed (attempt {attempt + 1}/{self.max_retries}): {e}"
                )
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff

        raise last_error


class OpenAIProvider(LLMProvider):
    """
    OpenAI GPT-4 provider for threat analysis.
    """

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        """
        Initialize OpenAI provider.

        Args:
            api_key: OpenAI API key (defaults to OPENAI_API_KEY env var)
            model: Model name (defaults to gpt-4-turbo-preview)
        """
        super().__init__(api_key, model)
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = model or "gpt-4-turbo-preview"

        if not self.api_key:
            raise ValueError(
                "OpenAI API key not provided. "
                "Set OPENAI_API_KEY environment variable or pass api_key parameter."
            )

        try:
            import openai
            self.client = openai.AsyncOpenAI(api_key=self.api_key)
        except ImportError:
            raise ImportError(
                "openai package not installed. Install with: pip install openai>=1.3.0"
            )

    async def generate_narrative(
        self,
        session_data: Dict[str, Any],
        kill_chain_data: Dict[str, Any],
        mitre_data: Dict[str, Any],
        ioc_data: Dict[str, Any],
        prompt_template: str
    ) -> Dict[str, Any]:
        """Generate threat narrative using GPT-4."""
        async def _call():
            # Format the prompt with data
            formatted_prompt = prompt_template.format(
                session_data=self._format_session_data(session_data),
                kill_chain_data=self._format_data(kill_chain_data),
                mitre_data=self._format_data(mitre_data),
                ioc_data=self._format_data(ioc_data)
            )

            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert cybersecurity analyst specializing in cloud security and threat hunting."
                    },
                    {
                        "role": "user",
                        "content": formatted_prompt
                    }
                ],
                temperature=0.3,  # Lower temperature for more consistent output
                max_tokens=2000,
                timeout=self.timeout
            )

            narrative_text = response.choices[0].message.content

            # Parse the narrative into structured format
            return self._parse_narrative(narrative_text)

        return await self._call_with_retry(_call)

    async def extract_iocs(
        self,
        events: List[Dict[str, Any]],
        prompt_template: str
    ) -> Dict[str, Any]:
        """Extract IOCs using GPT-4."""
        async def _call():
            # Limit events to avoid token limits
            sample_events = events[:100] if len(events) > 100 else events

            formatted_prompt = prompt_template.format(
                events=self._format_events(sample_events),
                total_events=len(events)
            )

            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert in cybersecurity forensics and IOC identification."
                    },
                    {
                        "role": "user",
                        "content": formatted_prompt
                    }
                ],
                temperature=0.2,
                max_tokens=1500,
                timeout=self.timeout
            )

            ioc_text = response.choices[0].message.content
            return self._parse_iocs(ioc_text)

        return await self._call_with_retry(_call)

    async def plan_response(
        self,
        session_data: Dict[str, Any],
        mitre_data: Dict[str, Any],
        ioc_data: Dict[str, Any],
        narrative_data: Dict[str, Any],
        prompt_template: str
    ) -> Dict[str, Any]:
        """Generate response plan using GPT-4."""
        async def _call():
            formatted_prompt = prompt_template.format(
                session_data=self._format_session_data(session_data),
                mitre_data=self._format_data(mitre_data),
                ioc_data=self._format_data(ioc_data),
                narrative_summary=narrative_data.get("executive_summary", "")
            )

            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert incident responder specializing in cloud security incidents."
                    },
                    {
                        "role": "user",
                        "content": formatted_prompt
                    }
                ],
                temperature=0.3,
                max_tokens=2000,
                timeout=self.timeout
            )

            plan_text = response.choices[0].message.content
            return self._parse_response_plan(plan_text)

        return await self._call_with_retry(_call)

    async def identify_mitre_techniques(
        self,
        events: List[Dict[str, Any]],
        prompt_template: str
    ) -> List[str]:
        """Identify MITRE techniques using GPT-4."""
        async def _call():
            sample_events = events[:50] if len(events) > 50 else events

            formatted_prompt = prompt_template.format(
                events=self._format_events(sample_events)
            )

            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert in MITRE ATT&CK framework and threat classification."
                    },
                    {
                        "role": "user",
                        "content": formatted_prompt
                    }
                ],
                temperature=0.1,
                max_tokens=500,
                timeout=self.timeout
            )

            techniques_text = response.choices[0].message.content
            return self._parse_mitre_techniques(techniques_text)

        return await self._call_with_retry(_call)

    def _format_session_data(self, session_data: Dict[str, Any]) -> str:
        """Format session data for prompt."""
        return f"""
Session ID: {session_data.get('session_id', 'N/A')}
Duration: {session_data.get('duration_seconds', 0) / 60:.1f} minutes
Total Events: {session_data.get('num_events', 0)}
Risk Score: {session_data.get('risk_score', 0):.2%}
Time Range: {session_data.get('start_time', 'N/A')} to {session_data.get('end_time', 'N/A')}
"""

    def _format_data(self, data: Dict[str, Any]) -> str:
        """Format dictionary data for prompt."""
        import json
        return json.dumps(data, indent=2, default=str)

    def _format_events(self, events: List[Dict[str, Any]]) -> str:
        """Format events for prompt."""
        formatted = []
        for i, event in enumerate(events, 1):
            formatted.append(f"""
Event {i}:
  - Time: {event.get('timestamp', 'N/A')}
  - Type: {event.get('event_type', 'N/A')}
  - Principal: {event.get('principal', 'N/A')}
  - Action: {event.get('action', 'N/A')}
  - Resource: {event.get('resource', 'N/A')}
  - Status: {event.get('status', 'N/A')}
  - Source IP: {event.get('source_ip', 'N/A')}
""")
        return "\n".join(formatted)

    def _parse_narrative(self, text: str) -> Dict[str, Any]:
        """Parse narrative text into structured format."""
        # Simple parsing - in production, could use more sophisticated parsing
        sections = {
            "executive_summary": "",
            "attack_timeline": "",
            "detailed_analysis": "",
            "impact_assessment": "",
            "recommended_actions": []
        }

        # Try to extract sections
        if "Executive Summary" in text or "EXECUTIVE SUMMARY" in text:
            sections["executive_summary"] = text
        else:
            sections["executive_summary"] = text

        sections["raw_narrative"] = text
        return sections

    def _parse_iocs(self, text: str) -> Dict[str, Any]:
        """Parse IOC text into structured format."""
        return {
            "iocs": {},
            "raw_analysis": text,
            "llm_generated": True
        }

    def _parse_response_plan(self, text: str) -> Dict[str, Any]:
        """Parse response plan text into structured format."""
        return {
            "immediate_actions": [],
            "containment": [],
            "eradication": [],
            "recovery": [],
            "lessons_learned": [],
            "raw_plan": text,
            "llm_generated": True
        }

    def _parse_mitre_techniques(self, text: str) -> List[str]:
        """Extract MITRE technique IDs from text."""
        import re
        # Find all T#### patterns
        techniques = re.findall(r'T\d{4}(?:\.\d{3})?', text)
        return list(set(techniques))  # Deduplicate


class AnthropicProvider(LLMProvider):
    """
    Anthropic Claude provider for threat analysis.
    """

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        """
        Initialize Anthropic provider.

        Args:
            api_key: Anthropic API key (defaults to ANTHROPIC_API_KEY env var)
            model: Model name (defaults to claude-3-opus-20240229)
        """
        super().__init__(api_key, model)
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.model = model or "claude-3-5-sonnet-20241022"

        if not self.api_key:
            raise ValueError(
                "Anthropic API key not provided. "
                "Set ANTHROPIC_API_KEY environment variable or pass api_key parameter."
            )

        try:
            import anthropic
            self.client = anthropic.AsyncAnthropic(api_key=self.api_key)
        except ImportError:
            raise ImportError(
                "anthropic package not installed. Install with: pip install anthropic>=0.7.0"
            )

    async def generate_narrative(
        self,
        session_data: Dict[str, Any],
        kill_chain_data: Dict[str, Any],
        mitre_data: Dict[str, Any],
        ioc_data: Dict[str, Any],
        prompt_template: str
    ) -> Dict[str, Any]:
        """Generate threat narrative using Claude."""
        async def _call():
            formatted_prompt = prompt_template.format(
                session_data=self._format_session_data(session_data),
                kill_chain_data=self._format_data(kill_chain_data),
                mitre_data=self._format_data(mitre_data),
                ioc_data=self._format_data(ioc_data)
            )

            response = await self.client.messages.create(
                model=self.model,
                max_tokens=4000,
                temperature=0.3,
                system="You are an expert cybersecurity analyst specializing in cloud security and threat hunting. Provide detailed, actionable analysis.",
                messages=[
                    {
                        "role": "user",
                        "content": formatted_prompt
                    }
                ],
                timeout=self.timeout
            )

            narrative_text = response.content[0].text
            return self._parse_narrative(narrative_text)

        return await self._call_with_retry(_call)

    async def extract_iocs(
        self,
        events: List[Dict[str, Any]],
        prompt_template: str
    ) -> Dict[str, Any]:
        """Extract IOCs using Claude."""
        async def _call():
            sample_events = events[:100] if len(events) > 100 else events

            formatted_prompt = prompt_template.format(
                events=self._format_events(sample_events),
                total_events=len(events)
            )

            response = await self.client.messages.create(
                model=self.model,
                max_tokens=3000,
                temperature=0.2,
                system="You are an expert in cybersecurity forensics and IOC identification. Extract and categorize all indicators of compromise.",
                messages=[
                    {
                        "role": "user",
                        "content": formatted_prompt
                    }
                ],
                timeout=self.timeout
            )

            ioc_text = response.content[0].text
            return self._parse_iocs(ioc_text)

        return await self._call_with_retry(_call)

    async def plan_response(
        self,
        session_data: Dict[str, Any],
        mitre_data: Dict[str, Any],
        ioc_data: Dict[str, Any],
        narrative_data: Dict[str, Any],
        prompt_template: str
    ) -> Dict[str, Any]:
        """Generate response plan using Claude."""
        async def _call():
            formatted_prompt = prompt_template.format(
                session_data=self._format_session_data(session_data),
                mitre_data=self._format_data(mitre_data),
                ioc_data=self._format_data(ioc_data),
                narrative_summary=narrative_data.get("executive_summary", "")
            )

            response = await self.client.messages.create(
                model=self.model,
                max_tokens=4000,
                temperature=0.3,
                system="You are an expert incident responder specializing in cloud security incidents. Provide detailed, actionable response plans.",
                messages=[
                    {
                        "role": "user",
                        "content": formatted_prompt
                    }
                ],
                timeout=self.timeout
            )

            plan_text = response.content[0].text
            return self._parse_response_plan(plan_text)

        return await self._call_with_retry(_call)

    async def identify_mitre_techniques(
        self,
        events: List[Dict[str, Any]],
        prompt_template: str
    ) -> List[str]:
        """Identify MITRE techniques using Claude."""
        async def _call():
            sample_events = events[:50] if len(events) > 50 else events

            formatted_prompt = prompt_template.format(
                events=self._format_events(sample_events)
            )

            response = await self.client.messages.create(
                model=self.model,
                max_tokens=1000,
                temperature=0.1,
                system="You are an expert in MITRE ATT&CK framework and threat classification. Identify relevant technique IDs.",
                messages=[
                    {
                        "role": "user",
                        "content": formatted_prompt
                    }
                ],
                timeout=self.timeout
            )

            techniques_text = response.content[0].text
            return self._parse_mitre_techniques(techniques_text)

        return await self._call_with_retry(_call)

    def _format_session_data(self, session_data: Dict[str, Any]) -> str:
        """Format session data for prompt."""
        return f"""
Session ID: {session_data.get('session_id', 'N/A')}
Duration: {session_data.get('duration_seconds', 0) / 60:.1f} minutes
Total Events: {session_data.get('num_events', 0)}
Risk Score: {session_data.get('risk_score', 0):.2%}
Time Range: {session_data.get('start_time', 'N/A')} to {session_data.get('end_time', 'N/A')}
"""

    def _format_data(self, data: Dict[str, Any]) -> str:
        """Format dictionary data for prompt."""
        import json
        return json.dumps(data, indent=2, default=str)

    def _format_events(self, events: List[Dict[str, Any]]) -> str:
        """Format events for prompt."""
        formatted = []
        for i, event in enumerate(events, 1):
            formatted.append(f"""
Event {i}:
  - Time: {event.get('timestamp', 'N/A')}
  - Type: {event.get('event_type', 'N/A')}
  - Principal: {event.get('principal', 'N/A')}
  - Action: {event.get('action', 'N/A')}
  - Resource: {event.get('resource', 'N/A')}
  - Status: {event.get('status', 'N/A')}
  - Source IP: {event.get('source_ip', 'N/A')}
""")
        return "\n".join(formatted)

    def _parse_narrative(self, text: str) -> Dict[str, Any]:
        """Parse narrative text into structured format."""
        sections = {
            "executive_summary": "",
            "attack_timeline": "",
            "detailed_analysis": "",
            "impact_assessment": "",
            "recommended_actions": []
        }

        if "Executive Summary" in text or "EXECUTIVE SUMMARY" in text:
            sections["executive_summary"] = text
        else:
            sections["executive_summary"] = text

        sections["raw_narrative"] = text
        return sections

    def _parse_iocs(self, text: str) -> Dict[str, Any]:
        """Parse IOC text into structured format."""
        return {
            "iocs": {},
            "raw_analysis": text,
            "llm_generated": True
        }

    def _parse_response_plan(self, text: str) -> Dict[str, Any]:
        """Parse response plan text into structured format."""
        return {
            "immediate_actions": [],
            "containment": [],
            "eradication": [],
            "recovery": [],
            "lessons_learned": [],
            "raw_plan": text,
            "llm_generated": True
        }

    def _parse_mitre_techniques(self, text: str) -> List[str]:
        """Extract MITRE technique IDs from text."""
        import re
        techniques = re.findall(r'T\d{4}(?:\.\d{3})?', text)
        return list(set(techniques))


def get_llm_provider(
    provider_type: str = "openai",
    api_key: Optional[str] = None,
    model: Optional[str] = None
) -> LLMProvider:
    """
    Factory function to get an LLM provider instance.

    Args:
        provider_type: Type of provider ('openai' or 'anthropic')
        api_key: API key (if None, will try to get from environment)
        model: Model name (if None, will use provider default)

    Returns:
        Configured LLM provider instance

    Raises:
        ValueError: If provider_type is not supported
    """
    providers = {
        "openai": OpenAIProvider,
        "anthropic": AnthropicProvider,
    }

    provider_class = providers.get(provider_type.lower())

    if not provider_class:
        raise ValueError(
            f"Unknown provider type: {provider_type}. "
            f"Supported providers: {', '.join(providers.keys())}"
        )

    logger.info(f"Initializing {provider_type} provider with model {model or 'default'}")

    try:
        return provider_class(api_key=api_key, model=model)
    except Exception as e:
        logger.error(f"Failed to initialize {provider_type} provider: {e}")
        raise
