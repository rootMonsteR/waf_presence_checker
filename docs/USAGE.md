# Usage Notes

This project does **not** send network traffic. It analyzes files you provide.

## Prepare a Capture

Using `curl` (authorized target only):
```bash
curl -I -sD - -o /dev/null https://example.com > examples/sample_headers.txt
```

Export a HAR from your browser (DevTools > Network > Save all as HAR with content), then:
```bash
wafpc analyze -i path/to/export.har --format har
```

Provide JSON observations (example schema):
```json
{
  "url": "https://example.com/",
  "method": "GET",
  "status_code": 200,
  "headers": {
    "server": "cloudflare",
    "cf-ray": "123",
    "set-cookie": "__cfduid=..."
  },
  "body_excerpt": "..."  // optional
}
```

Run the analyzer:
```bash
wafpc analyze -i examples/sample_headers.txt --format raw
wafpc analyze -i observation.json --format json --json
```

Exit codes are described in the README.
