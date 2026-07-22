from abc import ABC

from presidio_patterns import EntityRecognizer


class LocalRecognizer(ABC, EntityRecognizer):
    """PII entity recognizer which runs on the same process as the AnalyzerEngine."""
