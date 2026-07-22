from typing import List, Optional

from presidio_patterns import Pattern, PatternRecognizer

# NOT part of the vendored Microsoft Presidio source (see vendor/presidio_patterns/NOTICE.md).
# Upstream Presidio's EmailRecognizer additionally validates the matched domain's
# public suffix via `tldextract`, which pulls in `requests` -> `certifi` (MPL-2.0)
# — a copyleft dependency this package's license gate rejects (see requirements.txt).
# This is a from-scratch RFC 5322-style regex recognizer (same detection technique
# Presidio itself uses for its other pattern-based recognizers — regex, no ML) that
# covers the realistic email-address surface without that dependency.


class EmailRecognizer(PatternRecognizer):
    """
    Recognize email addresses using regex.

    :param patterns: List of patterns to be used by this recognizer
    :param context: List of context words to increase confidence in detection
    :param supported_language: Language this recognizer supports
    :param supported_entity: The entity this recognizer can detect
    """

    PATTERNS = [
        Pattern(
            "Email (RFC 5322-ish)",
            r"\b[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\b",  # noqa: E501
            0.6,
        ),
    ]

    CONTEXT = ["email", "e-mail", "mail", "address", "contact"]

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "en",
        supported_entity: str = "EMAIL_ADDRESS",
        name: Optional[str] = None,
    ):
        patterns = patterns if patterns else self.PATTERNS
        context = context if context else self.CONTEXT
        super().__init__(
            supported_entity=supported_entity,
            patterns=patterns,
            context=context,
            supported_language=supported_language,
            name=name,
        )

    def validate_result(self, pattern_text: str) -> Optional[bool]:  # noqa: D102
        # A trailing dot-label longer than 63 chars or more than 253 total chars
        # is not a real domain (RFC 1035 label/name length limits) — cheap
        # invalidation without a live TLD list.
        if len(pattern_text) > 254:
            return False
        local, _, domain = pattern_text.rpartition("@")
        if not local or not domain:
            return False
        if any(len(label) > 63 for label in domain.split(".")):
            return False
        return None
