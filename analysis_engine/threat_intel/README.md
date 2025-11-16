# Threat Intelligence Integration

This module provides threat intelligence enrichment capabilities for the AI Threat Hunting Simulator. It supports multiple threat intelligence providers with caching, rate limiting, and parallel processing.

## Features

- **Multiple Providers**: Support for AbuseIPDB, VirusTotal, and custom providers
- **Intelligent Caching**: File-based cache with TTL to reduce API calls
- **Rate Limiting**: Built-in rate limiting to respect provider limits
- **Batch Processing**: Efficient batch processing of multiple IOCs
- **Parallel API Calls**: Concurrent requests with configurable limits
- **Error Handling**: Graceful error handling and fallback mechanisms
- **Mock Provider**: Testing without real API keys

## Architecture

```
threat_intel/
├── cache.py          # File-based cache with TTL support
├── providers.py      # Threat intelligence providers
├── enricher.py       # IOC enrichment engine
├── example_usage.py  # Usage examples
└── README.md         # This file
```

## Components

### CacheManager (`cache.py`)

Simple file-based cache with TTL support:

```python
from analysis_engine.threat_intel import CacheManager

cache = CacheManager(
    cache_dir="./data/threat_intel_cache",
    default_ttl=3600  # 1 hour
)

# Store a value
cache.set("key", {"data": "value"}, ttl=1800)

# Retrieve a value
value = cache.get("key")

# Invalidate a key
cache.invalidate("key")

# Get statistics
stats = cache.get_stats()
```

### Providers (`providers.py`)

#### Base Class

All providers inherit from `ThreatIntelProvider`:

```python
class ThreatIntelProvider(ABC):
    async def check_ip(self, ip_address: str) -> Dict[str, Any]
    async def check_domain(self, domain: str) -> Dict[str, Any]
    async def check_file_hash(self, file_hash: str) -> Dict[str, Any]
```

#### AbuseIPDB Provider

IP reputation checking:

```python
from analysis_engine.threat_intel import AbuseIPDBProvider

provider = AbuseIPDBProvider(
    api_key="your-api-key",
    cache_manager=cache,
    cache_ttl=3600
)

result = await provider.check_ip("8.8.8.8")
# Returns: abuse_confidence_score, is_malicious, threat_level, etc.
```

**Rate Limits**: 10 calls/minute (free tier)

#### VirusTotal Provider

Domain and file hash checking:

```python
from analysis_engine.threat_intel import VirusTotalProvider

provider = VirusTotalProvider(
    api_key="your-api-key",
    cache_manager=cache,
    cache_ttl=3600
)

# Check domain
domain_result = await provider.check_domain("example.com")

# Check file hash
hash_result = await provider.check_file_hash("d41d8cd98f00b204e9800998ecf8427e")
```

**Rate Limits**: 4 requests/minute (free tier)

#### Mock Provider

For testing without API keys:

```python
from analysis_engine.threat_intel import MockThreatIntelProvider

provider = MockThreatIntelProvider(cache_manager=cache)

# Returns simulated data based on patterns
result = await provider.check_ip("192.168.1.100")
```

### IOC Enricher (`enricher.py`)

Coordinates enrichment across multiple providers:

```python
from analysis_engine.threat_intel import IOCEnricher

enricher = IOCEnricher(
    providers=[abuseipdb, virustotal],
    cache_manager=cache,
    max_concurrent_requests=10,
    batch_size=50
)

# Enrich single IOC
result = await enricher.enrich_ioc("ip", "8.8.8.8")

# Enrich multiple IOCs in batch
iocs = {
    "ip": ["8.8.8.8", "1.1.1.1"],
    "domain": ["example.com", "test.com"]
}
results = await enricher.enrich_iocs_batch(iocs)

# Enrich IOC report
ioc_report = {...}  # From IOC extractor
enriched = await enricher.enrich_ioc_report(ioc_report)
```

## Configuration

### Environment Variables

Add to your `.env` file:

```bash
# Enable threat intelligence
ENABLE_THREAT_INTEL=true

# API Keys
ABUSEIPDB_API_KEY=your-abuseipdb-api-key
VIRUSTOTAL_API_KEY=your-virustotal-api-key

# Cache settings
THREAT_INTEL_CACHE_TTL=3600  # 1 hour in seconds
```

### Config-Based Setup

```python
from analysis_engine.threat_intel import create_enricher_from_config
from config import get_settings

settings = get_settings()
enricher = create_enricher_from_config(settings)
```

## Integration with IOC Extractor

The IOC extractor agent can automatically enrich extracted IOCs:

```python
from analysis_engine.agents.ioc_extractor_agent import IocExtractorAgent
from analysis_engine.threat_intel import create_enricher_from_config
from config import get_settings

# Setup
settings = get_settings()
enricher = create_enricher_from_config(settings)

# Create IOC extractor with enrichment
ioc_extractor = IocExtractorAgent(
    llm_provider=None,
    use_llm=False,
    threat_intel_enricher=enricher,
    enable_enrichment=True
)

# Extract and enrich IOCs
ioc_report = ioc_extractor.extract_from_session(session)

# Report now includes threat_intelligence and threat_summary sections
```

## API Keys

### AbuseIPDB

1. Sign up at https://www.abuseipdb.com/
2. Get your API key from the dashboard
3. Free tier: 1,000 checks/day, 10 requests/minute

### VirusTotal

1. Sign up at https://www.virustotal.com/
2. Get your API key from your profile
3. Free tier: 500 requests/day, 4 requests/minute

## Response Format

### Enriched IOC

```json
{
  "ioc_type": "ip",
  "ioc_value": "8.8.8.8",
  "enrichments": [
    {
      "provider": "AbuseIPDB",
      "abuse_confidence_score": 0,
      "is_malicious": false,
      "threat_level": "low",
      "country_code": "US",
      "isp": "Google LLC",
      "total_reports": 0
    }
  ],
  "threat_assessment": {
    "overall_threat_level": "low",
    "is_malicious": false,
    "malicious_sources": 0,
    "total_sources": 1,
    "confidence": 0.0
  }
}
```

### Enriched IOC Report

```json
{
  "iocs": {
    "ip_addresses": ["8.8.8.8", "1.1.1.1"],
    "domains": ["example.com"]
  },
  "threat_intelligence": {
    "ip": [...],
    "domain": [...]
  },
  "threat_summary": {
    "total_iocs_enriched": 3,
    "malicious_iocs": 1,
    "clean_iocs": 2,
    "malicious_percentage": 33.33,
    "threat_level_distribution": {
      "critical": 1,
      "high": 0,
      "medium": 0,
      "low": 2
    },
    "overall_risk_level": "critical",
    "requires_immediate_attention": true
  },
  "enrichment_metadata": {
    "enriched_at": "2025-11-16T12:00:00Z",
    "providers_used": ["AbuseIPDB", "VirusTotal"],
    "total_enriched": 3,
    "processing_time_seconds": 1.23
  }
}
```

## Usage Examples

Run the example script:

```bash
python -m analysis_engine.threat_intel.example_usage
```

This demonstrates:
1. Basic provider usage
2. Real provider usage (with API keys)
3. IOC enrichment
4. IOC report enrichment
5. Config-based setup
6. Integration with IOC extractor

## Error Handling

The module handles various error scenarios:

- **Invalid API Keys**: Returns error in response
- **Rate Limiting**: Automatically waits and retries
- **Network Errors**: Graceful failure with error details
- **Invalid IOCs**: Returns error response
- **Provider Unavailable**: Continues with other providers

## Performance Considerations

### Caching

- Default TTL: 1 hour (configurable)
- Reduces API calls by up to 90%
- File-based storage (JSON)
- Automatic cleanup of expired entries

### Rate Limiting

- Built-in rate limiters per provider
- Respects free tier limits
- Automatic backoff on 429 errors

### Parallel Processing

- Configurable concurrent requests (default: 10)
- Batch processing support (default: 50 IOCs/batch)
- Async/await for efficiency

### Benchmarks

| Operation | Time | Notes |
|-----------|------|-------|
| Single IOC (cached) | <10ms | Cache hit |
| Single IOC (uncached) | 200-500ms | API call |
| Batch 50 IPs (uncached) | 5-15s | Parallel processing |
| Batch 50 IPs (cached) | <100ms | All cache hits |

## Best Practices

1. **Always use caching** to reduce API calls and costs
2. **Configure rate limits** appropriately for your tier
3. **Use batch processing** for multiple IOCs
4. **Monitor cache stats** regularly
5. **Handle errors gracefully** - enrichment is optional
6. **Use mock provider** for development and testing
7. **Clean up expired cache** periodically

## Troubleshooting

### "Rate limit exceeded"

- Check your API tier limits
- Increase rate limiter period
- Enable caching to reduce calls

### "Invalid API key"

- Verify API key in .env file
- Check key is not expired
- Ensure proper environment variable name

### "No providers configured"

- Set at least one API key in .env
- Or use MockThreatIntelProvider for testing

### Slow performance

- Enable caching
- Increase max_concurrent_requests
- Check network connectivity
- Monitor provider API status

## Future Enhancements

- [ ] Additional providers (OTX, Shodan, etc.)
- [ ] Redis-based caching option
- [ ] Batch API support where available
- [ ] Webhook/async enrichment
- [ ] ML-based threat scoring
- [ ] Custom provider plugin system

## License

See main project LICENSE file.
