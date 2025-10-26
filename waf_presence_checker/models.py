"""Data models for WAF presence detection.

This module defines the core data structures used throughout the WAF presence checker.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class HttpObservation:
    """Represents an HTTP request/response observation for analysis.

    Attributes:
        url: The URL of the HTTP request
        method: HTTP method (GET, POST, etc.)
        status_code: HTTP response status code
        headers: Dictionary of HTTP response headers
        body_excerpt: Optional excerpt of the response body (limited length for safety)
    """
    url: str = ""
    method: str = "GET"
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body_excerpt: Optional[str] = None


@dataclass
class Indicator:
    """Represents a single detection indicator found during analysis.

    Attributes:
        source: Source of the indicator (e.g., 'header:server', 'cookie', 'body')
        key: The key/name of the indicator
        value: The value found for this indicator
        weight: Confidence weight (0.0-1.0) for this indicator
        note: Human-readable description of what this indicator means
    """
    source: str
    key: str
    value: str
    weight: float
    note: str


@dataclass
class DetectionReport:
    """Final detection report with all findings and confidence assessment.

    Attributes:
        likely_waf: Boolean indicating if WAF presence is likely
        confidence: Overall confidence score (0.0-1.0)
        indicators: List of all indicators found during analysis
        vendor_guesses: List of potential WAF vendors, ordered by likelihood
        rationale: Human-readable explanation of the detection decision
    """
    likely_waf: bool
    confidence: float
    indicators: List[Indicator]
    vendor_guesses: List[str]
    rationale: str
