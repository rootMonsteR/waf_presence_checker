"""Parsers for various HTTP observation formats.

This module provides parsers for different input formats including raw HTTP headers,
JSON observations, and HAR (HTTP Archive) files.
"""

import json
import logging
from typing import Dict, Any
from .models import HttpObservation

logger = logging.getLogger(__name__)

def parse_raw_headers(text: str) -> HttpObservation:
    """Parse raw HTTP headers from curl -i output or RFC822-style header blocks.

    Args:
        text: Raw text containing HTTP response headers and optional body

    Returns:
        HttpObservation object with parsed data

    Raises:
        ValueError: If the input text is empty or invalid
    """
    if not text or not text.strip():
        raise ValueError("Input text is empty")

    lines = [l.rstrip('\r\n') for l in text.splitlines() if l.strip()]
    if not lines:
        raise ValueError("No valid content found in input")

    status_code = 0
    headers: Dict[str, str] = {}
    url = ""
    body_excerpt = None

    # Find status line and headers until blank line
    in_headers = True
    for l in lines:
        if in_headers and l.lower().startswith('http/'):
            # HTTP/1.1 200 OK
            parts = l.split()
            for p in parts:
                if p.isdigit():
                    try:
                        status_code = int(p)
                    except ValueError:
                        logger.warning(f"Could not parse status code from: {p}")
                    break
            continue
        if in_headers and ':' in l:
            k, v = l.split(':', 1)
            headers[k.strip()] = v.strip()
            continue
        # crude separation; if we see something without colon after status, treat remainder as body
        if ':' not in l and in_headers:
            in_headers = False
        if not in_headers:
            body_excerpt = (body_excerpt or "") + (l + "\n")

    logger.debug(f"Parsed raw headers: status={status_code}, headers={len(headers)}")
    return HttpObservation(
        url=url,
        method='GET',
        status_code=status_code,
        headers=headers,
        body_excerpt=body_excerpt[:4096] if body_excerpt else None  # Limit body excerpt
    )

def parse_json_obs(text: str) -> HttpObservation:
    """Parse HTTP observation from JSON format.

    Args:
        text: JSON string containing observation data

    Returns:
        HttpObservation object with parsed data

    Raises:
        ValueError: If JSON is invalid or missing required fields
        json.JSONDecodeError: If the input is not valid JSON
    """
    if not text or not text.strip():
        raise ValueError("Input text is empty")

    try:
        data: Dict[str, Any] = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format: {e}") from e

    # Validate and extract data with proper error handling
    try:
        status_code = int(data.get('status_code', 0))
    except (ValueError, TypeError) as e:
        logger.warning(f"Invalid status_code in JSON: {e}")
        status_code = 0

    headers = data.get('headers', {})
    if not isinstance(headers, dict):
        logger.warning("Headers field is not a dictionary, using empty dict")
        headers = {}

    body_excerpt = data.get('body_excerpt')
    if body_excerpt and len(body_excerpt) > 4096:
        body_excerpt = body_excerpt[:4096]

    logger.debug(f"Parsed JSON observation: status={status_code}, headers={len(headers)}")
    return HttpObservation(
        url=data.get('url', ''),
        method=data.get('method', 'GET'),
        status_code=status_code,
        headers=headers,
        body_excerpt=body_excerpt
    )

def parse_har(text: str) -> HttpObservation:
    """Parse HTTP observation from HAR (HTTP Archive) format.

    Args:
        text: JSON string in HAR format

    Returns:
        HttpObservation object with parsed data from the first entry

    Raises:
        ValueError: If HAR format is invalid or contains no entries
        json.JSONDecodeError: If the input is not valid JSON
    """
    if not text or not text.strip():
        raise ValueError("Input text is empty")

    try:
        data: Dict[str, Any] = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format: {e}") from e

    # Validate HAR structure
    if 'log' not in data:
        raise ValueError("Invalid HAR format: missing 'log' field")

    entries = data.get('log', {}).get('entries', [])
    if not entries:
        raise ValueError("HAR file contains no entries")

    # Extract first entry
    e = entries[0]
    res = e.get('response', {})

    try:
        status = int(res.get('status', 0))
    except (ValueError, TypeError):
        logger.warning("Invalid status code in HAR, using 0")
        status = 0

    # Parse headers safely
    headers: Dict[str, str] = {}
    for h in res.get('headers', []):
        if isinstance(h, dict) and 'name' in h and 'value' in h:
            headers[h['name']] = h['value']

    # Extract body excerpt with size limit
    body_excerpt = None
    content = res.get('content', {})
    if isinstance(content, dict) and content.get('text'):
        body_excerpt = content['text'][:4096]  # Limit to 4KB

    url = e.get('request', {}).get('url', '')
    method = e.get('request', {}).get('method', 'GET')

    logger.debug(f"Parsed HAR file: status={status}, headers={len(headers)}, url={url}")
    return HttpObservation(
        url=url,
        method=method,
        status_code=status,
        headers=headers,
        body_excerpt=body_excerpt
    )
