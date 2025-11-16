"""
IOC enrichment engine with batch processing and parallel API calls.

Coordinates threat intelligence enrichment across multiple providers.
"""
import logging
import asyncio
from typing import Dict, List, Any, Optional, Set
from datetime import datetime

from analysis_engine.threat_intel.providers import (
    ThreatIntelProvider,
    AbuseIPDBProvider,
    VirusTotalProvider,
    MockThreatIntelProvider
)
from analysis_engine.threat_intel.cache import CacheManager

logger = logging.getLogger(__name__)


class IOCEnricher:
    """
    IOC enrichment engine.

    Enriches indicators of compromise with threat intelligence data
    from multiple providers using batch processing and parallel API calls.
    """

    def __init__(
        self,
        providers: Optional[List[ThreatIntelProvider]] = None,
        cache_manager: Optional[CacheManager] = None,
        max_concurrent_requests: int = 10,
        batch_size: int = 50
    ):
        """
        Initialize the IOC enricher.

        Args:
            providers: List of threat intel providers to use
            cache_manager: Cache manager for storing results
            max_concurrent_requests: Maximum concurrent API requests
            batch_size: Maximum IOCs to process in one batch
        """
        self.providers = providers or []
        self.cache_manager = cache_manager
        self.max_concurrent_requests = max_concurrent_requests
        self.batch_size = batch_size

        logger.info(
            f"IOCEnricher initialized with {len(self.providers)} providers, "
            f"max_concurrent={max_concurrent_requests}, batch_size={batch_size}"
        )

    def add_provider(self, provider: ThreatIntelProvider):
        """
        Add a threat intelligence provider.

        Args:
            provider: Provider to add
        """
        self.providers.append(provider)
        logger.info(f"Added provider: {provider.__class__.__name__}")

    async def enrich_ioc(
        self,
        ioc_type: str,
        ioc_value: str,
        providers: Optional[List[ThreatIntelProvider]] = None
    ) -> Dict[str, Any]:
        """
        Enrich a single IOC with threat intelligence.

        Args:
            ioc_type: Type of IOC (ip, domain, hash)
            ioc_value: IOC value
            providers: Optional list of specific providers to use

        Returns:
            Enrichment data from all providers
        """
        providers_to_use = providers or self.providers

        if not providers_to_use:
            logger.warning("No providers configured for enrichment")
            return {
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
                "enrichments": [],
                "error": "No providers configured"
            }

        # Create tasks for each provider
        tasks = []
        for provider in providers_to_use:
            if ioc_type == "ip":
                tasks.append(self._safe_check(provider.check_ip, ioc_value, provider))
            elif ioc_type == "domain":
                tasks.append(self._safe_check(provider.check_domain, ioc_value, provider))
            elif ioc_type == "hash":
                tasks.append(self._safe_check(provider.check_file_hash, ioc_value, provider))
            else:
                logger.warning(f"Unknown IOC type: {ioc_type}")

        # Execute all provider checks in parallel
        enrichments = await asyncio.gather(*tasks)

        # Aggregate results
        result = {
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "enrichments": [e for e in enrichments if e is not None],
            "enriched_at": datetime.utcnow().isoformat(),
            "providers_queried": len(enrichments)
        }

        # Add aggregated threat assessment
        result["threat_assessment"] = self._aggregate_threat_assessment(enrichments)

        return result

    async def _safe_check(self, check_func, ioc_value: str, provider: ThreatIntelProvider) -> Optional[Dict[str, Any]]:
        """
        Safely execute a provider check with error handling.

        Args:
            check_func: Provider check function
            ioc_value: IOC value
            provider: Provider instance

        Returns:
            Enrichment data or None on error
        """
        try:
            return await check_func(ioc_value)
        except Exception as e:
            logger.error(f"Error checking {ioc_value} with {provider.__class__.__name__}: {e}")
            return {
                "provider": provider.__class__.__name__,
                "error": str(e),
                "ioc_value": ioc_value,
                "timestamp": datetime.utcnow().isoformat()
            }

    async def enrich_iocs_batch(
        self,
        iocs: Dict[str, List[str]],
        providers: Optional[List[ThreatIntelProvider]] = None
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Enrich multiple IOCs in batch with rate limiting.

        Args:
            iocs: Dictionary of IOC types to lists of values
            providers: Optional list of specific providers to use

        Returns:
            Dictionary of enriched IOCs by type
        """
        enriched_iocs = {}

        # Process each IOC type
        for ioc_type, ioc_values in iocs.items():
            if not ioc_values:
                continue

            logger.info(f"Enriching {len(ioc_values)} {ioc_type} IOCs")

            # Deduplicate IOC values
            unique_iocs = list(set(ioc_values))

            # Process in batches to avoid overwhelming APIs
            enriched_batch = []
            for i in range(0, len(unique_iocs), self.batch_size):
                batch = unique_iocs[i:i + self.batch_size]

                # Create semaphore for concurrency control
                semaphore = asyncio.Semaphore(self.max_concurrent_requests)

                async def enrich_with_semaphore(ioc_value):
                    async with semaphore:
                        return await self.enrich_ioc(ioc_type, ioc_value, providers)

                # Process batch in parallel with concurrency limit
                batch_results = await asyncio.gather(
                    *[enrich_with_semaphore(ioc) for ioc in batch]
                )

                enriched_batch.extend(batch_results)

                logger.info(f"Processed batch {i // self.batch_size + 1} of {ioc_type} IOCs")

            enriched_iocs[ioc_type] = enriched_batch

        return enriched_iocs

    async def enrich_ioc_report(
        self,
        ioc_report: Dict[str, Any],
        providers: Optional[List[ThreatIntelProvider]] = None
    ) -> Dict[str, Any]:
        """
        Enrich an IOC report (from IOC extractor) with threat intelligence.

        Args:
            ioc_report: IOC report dictionary
            providers: Optional list of specific providers to use

        Returns:
            Enhanced IOC report with threat intelligence
        """
        start_time = datetime.utcnow()

        # Extract IOCs from report
        iocs = ioc_report.get("iocs", {})

        # Map IOC types to standard types
        ioc_mapping = {
            "ip_addresses": "ip",
            "domains": "domain",
            # file hashes would go here if we had them
        }

        # Prepare IOCs for enrichment
        iocs_to_enrich = {}
        for report_type, standard_type in ioc_mapping.items():
            if report_type in iocs and iocs[report_type]:
                iocs_to_enrich[standard_type] = iocs[report_type]

        # Enrich IOCs
        enriched = await self.enrich_iocs_batch(iocs_to_enrich, providers)

        # Add enrichment data to report
        enhanced_report = {
            **ioc_report,
            "threat_intelligence": enriched,
            "enrichment_metadata": {
                "enriched_at": datetime.utcnow().isoformat(),
                "providers_used": [p.__class__.__name__ for p in (providers or self.providers)],
                "total_enriched": sum(len(iocs) for iocs in enriched.values()),
                "processing_time_seconds": (datetime.utcnow() - start_time).total_seconds()
            }
        }

        # Add high-level threat summary
        enhanced_report["threat_summary"] = self._generate_threat_summary(enriched)

        logger.info(
            f"Enriched IOC report with {sum(len(iocs) for iocs in enriched.values())} IOCs "
            f"in {(datetime.utcnow() - start_time).total_seconds():.2f}s"
        )

        return enhanced_report

    def _aggregate_threat_assessment(self, enrichments: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Aggregate threat assessment from multiple providers.

        Args:
            enrichments: List of enrichment results

        Returns:
            Aggregated threat assessment
        """
        if not enrichments:
            return {"overall_threat_level": "unknown", "is_malicious": False}

        # Count threat levels
        threat_levels = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }

        malicious_count = 0
        total_count = 0

        for enrichment in enrichments:
            if enrichment and not enrichment.get("error"):
                total_count += 1

                threat_level = enrichment.get("threat_level", "low")
                if threat_level in threat_levels:
                    threat_levels[threat_level] += 1

                if enrichment.get("is_malicious"):
                    malicious_count += 1

        # Determine overall threat level
        if threat_levels["critical"] > 0:
            overall_level = "critical"
        elif threat_levels["high"] > 0:
            overall_level = "high"
        elif threat_levels["medium"] > 0:
            overall_level = "medium"
        else:
            overall_level = "low"

        return {
            "overall_threat_level": overall_level,
            "is_malicious": malicious_count > 0,
            "malicious_sources": malicious_count,
            "total_sources": total_count,
            "threat_level_breakdown": threat_levels,
            "confidence": malicious_count / total_count if total_count > 0 else 0
        }

    def _generate_threat_summary(self, enriched_iocs: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """
        Generate high-level threat summary from enriched IOCs.

        Args:
            enriched_iocs: Enriched IOCs by type

        Returns:
            Threat summary
        """
        total_iocs = 0
        malicious_iocs = 0
        threat_level_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for ioc_type, iocs in enriched_iocs.items():
            for ioc in iocs:
                total_iocs += 1
                assessment = ioc.get("threat_assessment", {})

                if assessment.get("is_malicious"):
                    malicious_iocs += 1

                threat_level = assessment.get("overall_threat_level", "low")
                if threat_level in threat_level_counts:
                    threat_level_counts[threat_level] += 1

        # Determine overall risk
        if threat_level_counts["critical"] > 0:
            overall_risk = "critical"
        elif threat_level_counts["high"] > 0:
            overall_risk = "high"
        elif threat_level_counts["medium"] > 0:
            overall_risk = "medium"
        else:
            overall_risk = "low"

        return {
            "total_iocs_enriched": total_iocs,
            "malicious_iocs": malicious_iocs,
            "clean_iocs": total_iocs - malicious_iocs,
            "malicious_percentage": (malicious_iocs / total_iocs * 100) if total_iocs > 0 else 0,
            "threat_level_distribution": threat_level_counts,
            "overall_risk_level": overall_risk,
            "requires_immediate_attention": overall_risk in ["critical", "high"] and malicious_iocs > 0
        }

    def get_cache_stats(self) -> Optional[Dict[str, Any]]:
        """
        Get cache statistics.

        Returns:
            Cache stats or None if no cache manager
        """
        if self.cache_manager:
            return self.cache_manager.get_stats()
        return None

    def clear_cache(self) -> Optional[int]:
        """
        Clear the cache.

        Returns:
            Number of entries cleared or None if no cache manager
        """
        if self.cache_manager:
            return self.cache_manager.clear()
        return None


def create_enricher_from_config(config) -> IOCEnricher:
    """
    Create an IOC enricher from application configuration.

    Args:
        config: Application settings object

    Returns:
        Configured IOCEnricher instance
    """
    # Initialize cache manager
    cache_manager = CacheManager(
        cache_dir="./data/threat_intel_cache",
        default_ttl=config.threat_intel_cache_ttl
    )

    # Initialize providers
    providers = []

    # Add AbuseIPDB if configured
    if config.abuseipdb_api_key:
        providers.append(
            AbuseIPDBProvider(
                api_key=config.abuseipdb_api_key,
                cache_manager=cache_manager,
                cache_ttl=config.threat_intel_cache_ttl
            )
        )
        logger.info("AbuseIPDB provider configured")

    # Add VirusTotal if configured
    if config.virustotal_api_key:
        providers.append(
            VirusTotalProvider(
                api_key=config.virustotal_api_key,
                cache_manager=cache_manager,
                cache_ttl=config.threat_intel_cache_ttl
            )
        )
        logger.info("VirusTotal provider configured")

    # Add mock provider if no real providers configured (for testing)
    if not providers:
        logger.warning("No threat intel API keys configured, using mock provider")
        providers.append(
            MockThreatIntelProvider(
                cache_manager=cache_manager,
                cache_ttl=config.threat_intel_cache_ttl
            )
        )

    # Create enricher
    enricher = IOCEnricher(
        providers=providers,
        cache_manager=cache_manager,
        max_concurrent_requests=10,
        batch_size=50
    )

    return enricher
