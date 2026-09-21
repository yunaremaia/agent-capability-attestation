"""Setup configuration for agent-capability-attestation."""

from setuptools import setup, find_packages

setup(
    name="agent-capability-attestation",
    version="0.1.0",
    description="Detect capability drift and stale attestations in AI agent delegation chains",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Yunare Maia",
    author_email="yunare@gmail.com",
    url="https://github.com/yunaremaia/agent-capability-attestation",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "click>=8.0",
        "cryptography>=41.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "aca=agent_capability_attestation.cli:cli",
            "agent-capability-attestation=agent_capability_attestation.cli:cli",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Software Development :: Testing",
        "Topic :: Security",
    ],
)
