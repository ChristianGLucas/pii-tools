# Vendored subset of Microsoft Presidio (presidio-analyzer, MIT) — see LICENSE
# and NOTICE.md in this directory for provenance and what was changed.
#
# Only the regex/checksum "pattern recognizer" engine is vendored here — the
# base classes any PatternRecognizer subclass needs, with zero dependency on
# presidio-analyzer's spaCy-based NLP engine (which this package's license
# gate rejects; see NOTICE.md). This __init__ mirrors the small slice of
# presidio_analyzer's own top-level namespace that vendored recognizer code
# imports from.

from .analysis_explanation import AnalysisExplanation
from .recognizer_result import RecognizerResult
from .entity_recognizer import EntityRecognizer
from .local_recognizer import LocalRecognizer
from .pattern import Pattern
from .pattern_recognizer import PatternRecognizer

__all__ = [
    "AnalysisExplanation",
    "RecognizerResult",
    "EntityRecognizer",
    "LocalRecognizer",
    "Pattern",
    "PatternRecognizer",
]
