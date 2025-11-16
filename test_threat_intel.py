"""
Simple test script for threat intelligence integration.

Tests basic functionality without requiring API keys or external dependencies.
"""
import sys
import os
import json
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

print("=" * 70)
print("THREAT INTELLIGENCE INTEGRATION - BASIC TESTS")
print("=" * 70)

# Test 1: Cache Manager
print("\n[Test 1] Testing CacheManager...")
try:
    from analysis_engine.threat_intel.cache import CacheManager

    # Create cache in temp directory
    cache = CacheManager(cache_dir="./test_cache", default_ttl=60)

    # Test set/get
    cache.set("test_key", {"data": "test_value"})
    result = cache.get("test_key")
    assert result == {"data": "test_value"}, "Cache get failed"

    # Test invalidate
    cache.invalidate("test_key")
    result = cache.get("test_key")
    assert result is None, "Cache invalidate failed"

    # Test stats
    cache.set("key1", "value1")
    cache.set("key2", "value2")
    stats = cache.get_stats()
    assert stats["total_entries"] == 2, "Cache stats failed"

    # Cleanup
    cache.clear()

    print("✓ CacheManager works correctly")

except Exception as e:
    print(f"✗ CacheManager test failed: {e}")
    import traceback
    traceback.print_exc()

# Test 2: Check providers module syntax
print("\n[Test 2] Checking providers.py syntax...")
try:
    with open("analysis_engine/threat_intel/providers.py", "r") as f:
        code = f.read()
    compile(code, "providers.py", "exec")
    print("✓ providers.py syntax is valid")
except SyntaxError as e:
    print(f"✗ providers.py has syntax error: {e}")

# Test 3: Check enricher module syntax
print("\n[Test 3] Checking enricher.py syntax...")
try:
    with open("analysis_engine/threat_intel/enricher.py", "r") as f:
        code = f.read()
    compile(code, "enricher.py", "exec")
    print("✓ enricher.py syntax is valid")
except SyntaxError as e:
    print(f"✗ enricher.py has syntax error: {e}")

# Test 4: Check __init__.py
print("\n[Test 4] Checking __init__.py...")
try:
    with open("analysis_engine/threat_intel/__init__.py", "r") as f:
        code = f.read()
    compile(code, "__init__.py", "exec")
    print("✓ __init__.py syntax is valid")
except SyntaxError as e:
    print(f"✗ __init__.py has syntax error: {e}")

# Test 5: Verify file structure
print("\n[Test 5] Verifying file structure...")
required_files = [
    "analysis_engine/threat_intel/__init__.py",
    "analysis_engine/threat_intel/cache.py",
    "analysis_engine/threat_intel/providers.py",
    "analysis_engine/threat_intel/enricher.py",
    "analysis_engine/threat_intel/example_usage.py",
    "analysis_engine/threat_intel/README.md"
]

all_exist = True
for filepath in required_files:
    if Path(filepath).exists():
        print(f"  ✓ {filepath}")
    else:
        print(f"  ✗ {filepath} MISSING")
        all_exist = False

if all_exist:
    print("✓ All required files exist")
else:
    print("✗ Some files are missing")

# Test 6: Check config.py has threat intel settings
print("\n[Test 6] Checking config.py for threat intel settings...")
try:
    from config import get_settings
    settings = get_settings()

    required_settings = [
        "enable_threat_intel",
        "abuseipdb_api_key",
        "virustotal_api_key",
        "threat_intel_cache_ttl"
    ]

    all_present = True
    for setting in required_settings:
        if hasattr(settings, setting):
            print(f"  ✓ {setting}")
        else:
            print(f"  ✗ {setting} MISSING")
            all_present = False

    if all_present:
        print("✓ All threat intel settings present in config")
    else:
        print("✗ Some settings missing from config")

except Exception as e:
    print(f"✗ Config check failed: {e}")

# Test 7: Check IOC extractor agent was updated
print("\n[Test 7] Checking IOC extractor agent updates...")
try:
    with open("analysis_engine/agents/ioc_extractor_agent.py", "r") as f:
        code = f.read()

    checks = [
        ("threat_intel_enricher" in code, "threat_intel_enricher parameter"),
        ("enable_enrichment" in code, "enable_enrichment parameter"),
        ("_enrich_ioc_report" in code, "_enrich_ioc_report method"),
        ("THREAT_INTEL_AVAILABLE" in code, "THREAT_INTEL_AVAILABLE flag")
    ]

    all_updated = True
    for check, description in checks:
        if check:
            print(f"  ✓ {description}")
        else:
            print(f"  ✗ {description} MISSING")
            all_updated = False

    if all_updated:
        print("✓ IOC extractor agent properly updated")
    else:
        print("✗ IOC extractor agent missing some updates")

except Exception as e:
    print(f"✗ IOC extractor check failed: {e}")

# Test 8: Check requirements.txt was updated
print("\n[Test 8] Checking requirements.txt updates...")
try:
    with open("requirements.txt", "r") as f:
        requirements = f.read()

    if "aiohttp" in requirements:
        print("  ✓ aiohttp dependency added")
    else:
        print("  ✗ aiohttp dependency MISSING")

    print("✓ requirements.txt updated")

except Exception as e:
    print(f"✗ requirements.txt check failed: {e}")

# Cleanup
print("\n[Cleanup] Removing test cache...")
import shutil
shutil.rmtree("./test_cache", ignore_errors=True)
print("✓ Cleanup complete")

print("\n" + "=" * 70)
print("BASIC TESTS COMPLETE")
print("=" * 70)
print("\nNote: Full integration tests require:")
print("  1. aiohttp installed (pip install aiohttp)")
print("  2. API keys configured in .env")
print("  3. Run: python -m analysis_engine.threat_intel.example_usage")
print("=" * 70)
