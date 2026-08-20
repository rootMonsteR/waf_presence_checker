"""Parsers for various HTTP observation formats.

This module provides parsers for different input formats including raw HTTP headers,
JSON observations, and HAR (HTTP Archive) files.
"""

import json
import logging
from typing import Any

from .models import HttpObservation

#: Maximum body bytes retained for analysis. Bodies are only ever pattern-matched,
#: so a bounded excerpt is enough, and the bound must be identical across parsers
#: or body-signal detection becomes format-dependent.
MAX_BODY_EXCERPT = 4096

logger = logging.getLogger(__name__)


def _add_header(headers: dict, key: str, value: str) -> None:
    """Record a header, preserving repeats instead of overwriting them.

    Repeated fields are legal and load-bearing: a response commonly sends several
    ``Set-Cookie`` lines, and overwriting kept only the last one, silently
    discarding cookie signals. ``Set-Cookie`` is joined with newlines because a
    comma is ambiguous inside cookie ``Expires`` dates; other fields use the
    comma form from RFC 7230 section 3.2.2.

    Matching is case-insensitive: HAR exports and proxy logs do not normalise
    header case, so ``Set-Cookie`` and ``set-cookie`` must land in one entry or
    the overwrite this function prevents simply reappears downstream.
    """
    for existing in headers:
        if existing.lower() == key.lower():
            sep = "\n" if key.lower() == "set-cookie" else ", "
            headers[existing] = headers[existing] + sep + value
            return
    headers[key] = value


def parse_raw_headers(text: str) -> HttpObservation:
    """Parse raw HTTP headers from curl -i output or RFC822-style header blocks.

    The header section ends at the first empty line, per RFC 7230 section 3. An
    earlier version stripped blank lines and guessed the boundary from the first
    line without a colon, which absorbed bodies containing CSS or quoted headers
    into the header map.

    Args:
        text: Raw text containing HTTP response headers and optional body

    Returns:
        HttpObservation object with parsed data

    Raises:
        ValueError: If the input text is empty or contains no usable content
    """
    if not text or not text.strip():
        raise ValueError("Input text is empty")

    lines = text.splitlines()
    status_code = 0
    headers: dict = {}
    body_lines: list = []
    in_headers = True

    for line in lines:
        if in_headers:
            if not line.strip():
                # Blank line terminates the header section, but skip leading
                # blanks before the status line has been seen.
                if headers or status_code:
                    in_headers = False
                continue
            stripped = line.rstrip("\r\n")
            if stripped.lower().startswith("http/"):
                for part in stripped.split():
                    if part.isdigit():
                        status_code = int(part)
                        break
                continue
            if ":" in stripped:
                k, v = stripped.split(":", 1)
                _add_header(headers, k.strip(), v.strip())
                continue
            # A non-blank, colon-free line inside the header block is malformed;
            # treat everything from here as body rather than dropping it.
            in_headers = False
            body_lines.append(stripped)
        else:
            body_lines.append(line)

    if not headers and status_code == 0 and not body_lines:
        raise ValueError("No valid content found in input")

    body_excerpt = "\n".join(body_lines).strip() or None

    logger.debug(f"Parsed raw headers: status={status_code}, headers={len(headers)}")
    return HttpObservation(
        url="",
        method="GET",
        status_code=status_code,
        headers=headers,
        body_excerpt=body_excerpt[:MAX_BODY_EXCERPT] if body_excerpt else None,
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
        data: dict[str, Any] = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format: {e}") from e

    # Validate and extract data with proper error handling
    try:
        status_code = int(data.get("status_code", 0))
    except (ValueError, TypeError) as e:
        logger.warning(f"Invalid status_code in JSON: {e}")
        status_code = 0

    headers = data.get("headers", {})
    if not isinstance(headers, dict):
        logger.warning("Headers field is not a dictionary, using empty dict")
        headers = {}

    body_excerpt = data.get("body_excerpt")
    if body_excerpt is not None and not isinstance(body_excerpt, str):
        logger.warning("body_excerpt is not a string, ignoring")
        body_excerpt = None
    if body_excerpt and len(body_excerpt) > MAX_BODY_EXCERPT:
        body_excerpt = body_excerpt[:MAX_BODY_EXCERPT]

    logger.debug(f"Parsed JSON observation: status={status_code}, headers={len(headers)}")
    return HttpObservation(
        url=data.get("url", ""),
        method=data.get("method", "GET"),
        status_code=status_code,
        headers=headers,
        body_excerpt=body_excerpt,
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
        data: dict[str, Any] = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format: {e}") from e

    # Validate HAR structure
    if "log" not in data:
        raise ValueError("Invalid HAR format: missing 'log' field")

    entries = data.get("log", {}).get("entries", [])
    if not entries:
        raise ValueError("HAR file contains no entries")

    # Extract first entry
    entry = entries[0]
    res = entry.get("response", {})

    try:
        status = int(res.get("status", 0))
    except (ValueError, TypeError):
        logger.warning("Invalid status code in HAR, using 0")
        status = 0

    # Parse headers safely
    headers: dict[str, str] = {}
    for h in res.get("headers", []):
        if isinstance(h, dict) and "name" in h and "value" in h:
            _add_header(headers, h["name"], h["value"])

    # Extract body excerpt with size limit
    body_excerpt = None
    content = res.get("content", {})
    if isinstance(content, dict) and content.get("text"):
        body_excerpt = content["text"][:MAX_BODY_EXCERPT]

    url = entry.get("request", {}).get("url", "")
    method = entry.get("request", {}).get("method", "GET")

    logger.debug(f"Parsed HAR file: status={status}, headers={len(headers)}, url={url}")
    return HttpObservation(
        url=url, method=method, status_code=status, headers=headers, body_excerpt=body_excerpt
    )
