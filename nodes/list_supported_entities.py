from gen.messages_pb2 import (
    ListSupportedEntitiesRequest,
    ListSupportedEntitiesResponse,
    SupportedEntity,
)
from gen.axiom_context import AxiomContext

from nodes import _pii


def list_supported_entities(ax: AxiomContext, input: ListSupportedEntitiesRequest) -> ListSupportedEntitiesResponse:
    """List every PII entity type DetectPii (and AnonymizeText) can
    recognize, each with a human-readable description and a realistic
    example of matching text. Filter to one category ("generic" or "us")
    with `category`, or leave it empty to list everything. An unrecognized
    category returns a structured error rather than crashing.
    """
    try:
        entities = _pii.supported_entities(input.category or None)
    except _pii.PiiError as e:
        return ListSupportedEntitiesResponse(error=str(e))

    return ListSupportedEntitiesResponse(
        entities=[
            SupportedEntity(
                entity_type=e["entity_type"],
                description=e["description"],
                category=e["category"],
                example=e["example"],
            )
            for e in entities
        ]
    )
