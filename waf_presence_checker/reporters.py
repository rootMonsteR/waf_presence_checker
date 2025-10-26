from .models import DetectionReport
import json

def to_text(report: DetectionReport) -> str:
    lines = []
    verdict = "LIKELY PRESENT" if report.likely_waf else "UNLIKELY/INDETERMINATE"
    lines.append(f"WAF Presence: {verdict} (confidence={report.confidence:.2f})")
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
    return json.dumps({
        "likely_waf": report.likely_waf,
        "confidence": report.confidence,
        "vendor_guesses": report.vendor_guesses,
        "rationale": report.rationale,
        "indicators": [{
            "source": i.source,
            "key": i.key,
            "value": i.value,
            "weight": i.weight,
            "note": i.note
        } for i in report.indicators]
    }, indent=2)
