"""
AI Threat Hunting Simulator - Setup Configuration
"""
from setuptools import setup, find_packages
from pathlib import Path

# Read the README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8")

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
with open(requirements_file) as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith('#'):
            requirements.append(line)

setup(
    name="ai-threat-hunting-simulator",
    version="3.0.0",
    author="AI Threat Hunting Simulator Contributors",
    author_email="",
    description="Production-grade synthetic lab for AI-assisted threat hunting on cloud telemetry",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/ai-threat-hunting-simulator",
    packages=find_packages(exclude=["tests", "tests.*", "docs", "scripts"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.11",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.11.0",
            "flake8>=6.1.0",
            "mypy>=1.7.0",
            "isort>=5.12.0",
            "bandit>=1.7.5",
        ],
        "llm": [
            "openai>=1.3.0",
            "anthropic>=0.7.0",
        ],
        "threat-intel": [
            "abuseipdb-wrapper>=1.0.0",
            "vt-py>=0.17.0",
        ],
        "monitoring": [
            "prometheus-client>=0.19.0",
            "sentry-sdk[fastapi]>=1.38.0",
        ],
        "all": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.11.0",
            "flake8>=6.1.0",
            "mypy>=1.7.0",
            "isort>=5.12.0",
            "bandit>=1.7.5",
            "openai>=1.3.0",
            "anthropic>=0.7.0",
            "abuseipdb-wrapper>=1.0.0",
            "vt-py>=0.17.0",
            "prometheus-client>=0.19.0",
            "sentry-sdk[fastapi]>=1.38.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "threat-hunt=cli.run_scenario:main",
            "threat-validate=cli.validate_traces:main",
            "threat-analyze=cli.analyze:main",
        ],
    },
    include_package_data=True,
    package_data={
        "generator": [
            "schemas/*.json",
            "cloud_topologies/*.json",
        ],
    },
    zip_safe=False,
    keywords=[
        "security",
        "threat-hunting",
        "cybersecurity",
        "mitre-attack",
        "cloud-security",
        "ai",
        "machine-learning",
        "synthetic-data",
        "telemetry",
        "soc",
    ],
    project_urls={
        "Bug Reports": "https://github.com/yourusername/ai-threat-hunting-simulator/issues",
        "Source": "https://github.com/yourusername/ai-threat-hunting-simulator",
        "Documentation": "https://github.com/yourusername/ai-threat-hunting-simulator/tree/main/docs",
    },
)
