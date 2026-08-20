"""Output formatters for detection reports."""

import json

from .models import DetectionReport


def _verdict(report: DetectionReport) -> str:
    if report.likely_waf:
        return "WAF LIKELY PRESENT"
    if report.likely_edge:
        return "EDGE/CDN PRESENT, NO WAF EVIDENCE"
    return "NO EDGE PROTECTION DETECTED"


def to_text(report: DetectionReport) -> str:
    lines = [f"Edge protection: {_verdict(report)} (confidence={report.confidence:.2f})"]
    if report.layers:
        by_conf = sorted(report.layers.items(), key=lambda kv: kv[1], reverse=True)
        lines.append("Layers: " + ", ".join(f"{name}={conf:.2f}" for name, conf in by_conf))
    if report.vendor_guesses:
        lines.append("Possible vendors: " + ", ".join(report.vendor_guesses))
    if report.rationale:
        lines.append("Rationale: " + report.rationale)
    if report.indicators:
        lines.append("Indicators:")
        for i in report.indicators:
            lines.append(f"  - [{i.weight:.2f}] {i.source} :: {i.key} :: {i.note}")
    return "\n".join(lines)


def to_json(report: DetectionReport) -> str:
    return json.dumps(
        {
            "likely_waf": report.likely_waf,
            "likely_edge": report.likely_edge,
            "confidence": report.confidence,
            "layers": report.layers,
            "vendor_guesses": report.vendor_guesses,
            "rationale": report.rationale,
            "indicators": [
                {
                    "source": i.source,
                    "key": i.key,
                    "value": i.value,
                    "weight": i.weight,
                    "note": i.note,
                }
                for i in report.indicators
            ],
        },
        indent=2,
    )
