# Contributing to WAF Presence Checker

Thank you for your interest in contributing to the WAF Presence Checker project! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Contribution Guidelines](#contribution-guidelines)
- [Adding WAF Fingerprints](#adding-waf-fingerprints)
- [Submitting Changes](#submitting-changes)

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce** the issue
- **Expected behavior** vs. actual behavior
- **Python version** and OS
- **Sample input files** (if applicable and safe to share)
- **Error messages** or logs

### Suggesting Enhancements

Enhancement suggestions are welcome! Please include:

- **Use case** for the enhancement
- **Expected behavior** and benefits
- **Alternative solutions** you've considered
- **Impact on existing functionality**

### Adding WAF Fingerprints

See [Adding WAF Fingerprints](#adding-waf-fingerprints) section below.

### Improving Documentation

Documentation improvements are always appreciated:

- Fix typos or clarify existing documentation
- Add examples or usage scenarios
- Improve code comments
- Create tutorials or guides

## Development Setup

### Prerequisites

- Python 3.9 or higher
- Git
- pip

### Setup Steps

1. **Fork the repository** on GitHub

2. **Clone your fork:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/waf-presence-checker.git
   cd waf-presence-checker
   ```

3. **Create a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

4. **Install development dependencies:**
   ```bash
   pip install -e ".[dev]"
   ```

5. **Create a feature branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Contribution Guidelines

### Code Style

- Follow PEP 8 style guidelines
- Use **Black** for code formatting (line length: 100)
- Use **Ruff** for linting
- Add type hints to all functions
- Write docstrings for modules, classes, and functions

**Format your code:**
```bash
black waf_presence_checker/
ruff check waf_presence_checker/ --fix
```

### Type Checking

Run mypy to ensure type correctness:
```bash
mypy waf_presence_checker/
```

### Documentation

- Add docstrings to all new functions and classes
- Update README.md if adding new features
- Include usage examples for new functionality

### Commit Messages

Write clear, descriptive commit messages:

```
Add Barracuda WAF fingerprint

- Add header patterns for Barracuda WAF
- Include cookie signatures
- Add test case for detection
```

**Guidelines:**
- Use present tense ("Add feature" not "Added feature")
- Use imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit first line to 72 characters
- Reference issues and pull requests

## Adding WAF Fingerprints

### Guidelines for Fingerprints

When adding new WAF fingerprints, follow these guidelines:

1. **Use Publicly Available Information Only**
   - Only include patterns from official documentation or public knowledge
   - Do not include proprietary or reverse-engineered signatures
   - Cite sources when possible

2. **Minimize False Positives**
   - Use multiple indicators when possible
   - Test against non-WAF responses
   - Consider generic vs. specific patterns

3. **Provide Documentation**
   - Document the source of the fingerprint
   - Explain the reasoning behind the patterns
   - Include example responses (redacted if necessary)

### Fingerprint Structure

Add fingerprints to `waf_presence_checker/fingerprints.py`:

```python
{
    "vendor": "VendorName WAF",
    "header_contains": [
        ("header-name", "value-substring"),  # Check if header contains value
        ("x-vendor-id", ""),  # Check if header exists (empty string)
    ],
    "cookie_contains": ["vendor_cookie_prefix", "vendor_session"],
    "body_contains": ["vendor signature", "unique error message"]
}
```

### Testing Fingerprints

Before submitting:

1. **Test with real samples:**
   ```bash
   wafpc analyze -i test_sample.txt --verbose
   ```

2. **Verify detection:**
   - Ensure the fingerprint correctly identifies the WAF
   - Check that confidence scores are reasonable
   - Test that it doesn't trigger on unrelated responses

3. **Document your testing:**
   - Include test methodology in PR description
   - Provide sanitized sample responses
   - List any edge cases discovered

### Example Contribution

```python
# In fingerprints.py
{
    "vendor": "Example WAF Pro",
    "header_contains": [
        ("server", "examplewaf"),
        ("x-example-ray", ""),
        ("x-example-cache", ""),
    ],
    "cookie_contains": ["example_waf_", "ewaf_session"],
    "body_contains": ["example waf protection", "request blocked by example"]
}
```

## Submitting Changes

### Pull Request Process

1. **Update documentation** if needed
2. **Ensure all code follows** style guidelines
3. **Run type checking** with mypy
4. **Test your changes** thoroughly
5. **Update CHANGELOG.md** with your changes
6. **Create a pull request** with:
   - Clear title and description
   - Reference to related issues
   - Summary of changes
   - Testing methodology

### Pull Request Template

```markdown
## Description
Brief description of the changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update
- [ ] WAF fingerprint addition

## Changes Made
- List key changes
- Include any breaking changes

## Testing
- Describe testing performed
- Include test results

## Checklist
- [ ] Code follows project style guidelines
- [ ] Documentation has been updated
- [ ] Changes have been tested
- [ ] CHANGELOG.md has been updated
```

### Review Process

- Maintainers will review your PR
- Address any requested changes
- Once approved, your PR will be merged
- You'll be credited in the CHANGELOG

## Questions?

If you have questions about contributing:

- Open an issue with the `question` label
- Reach out to the maintainers
- Check existing documentation

## Recognition

Contributors will be recognized in:
- CHANGELOG.md
- Project documentation
- Release notes (for significant contributions)

Thank you for contributing to make security testing safer and more accessible!

---

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
