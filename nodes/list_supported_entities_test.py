from gen.messages_pb2 import DetectPiiRequest, ListSupportedEntitiesRequest, ListSupportedEntitiesResponse
from nodes.list_supported_entities import list_supported_entities
from nodes.detect_pii import detect_pii
from nodes.testkit import FakeAxiomContext


def test_lists_every_registered_entity_with_generic_and_us_categories():
    ax = FakeAxiomContext()
    r = list_supported_entities(ax, ListSupportedEntitiesRequest())
    assert isinstance(r, ListSupportedEntitiesResponse)
    assert not r.error
    types = {e.entity_type for e in r.entities}
    assert "EMAIL_ADDRESS" in types
    assert "US_SSN" in types
    categories = {e.category for e in r.entities}
    assert categories == {"generic", "us"}
    # Every entry must be genuinely documented, not a placeholder.
    for e in r.entities:
        assert e.description
        assert e.example


def test_category_filter():
    ax = FakeAxiomContext()
    r = list_supported_entities(ax, ListSupportedEntitiesRequest(category="us"))
    assert not r.error
    assert len(r.entities) > 0
    assert all(e.category == "us" for e in r.entities)


def test_unknown_category_is_structured_error():
    ax = FakeAxiomContext()
    r = list_supported_entities(ax, ListSupportedEntitiesRequest(category="atlantis"))
    assert r.error


def test_every_catalog_example_is_actually_detected_as_its_claimed_type():
    """Claim <-> test: every SupportedEntity.example must round-trip through
    DetectPii as a full-span match of its own entity_type — otherwise the
    catalog is lying about what DetectPii will actually find.
    """
    ax = FakeAxiomContext()
    catalog = list_supported_entities(ax, ListSupportedEntitiesRequest())
    assert not catalog.error
    assert len(catalog.entities) >= 15  # liberal coverage, not a token handful

    for entry in catalog.entities:
        result = detect_pii(ax, DetectPiiRequest(text=entry.example, entity_types=[entry.entity_type]))
        assert not result.error, f"{entry.entity_type}: {result.error}"
        matches = [
            e for e in result.entities if e.start == 0 and e.end == len(entry.example)
        ]
        assert matches, (
            f"{entry.entity_type}'s example {entry.example!r} was not detected as a "
            f"full-span match: got {list(result.entities)}"
        )
