from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

TERRAFORM_REFERENCE_PATTERN = re.compile(
    r"\b([a-zA-Z0-9_]+\.[a-zA-Z0-9_-]+)(?:\.[a-zA-Z0-9_-]+)*\b"
)


def extract_references(value: Any) -> set[str]:
    """Extract Terraform resource addresses from nested attribute values."""

    references: set[str] = set()

    for string_value in _walk_strings(value):
        matches = TERRAFORM_REFERENCE_PATTERN.findall(string_value)
        references.update(matches)

    return references


def _walk_strings(value: Any) -> Iterator[str]:
    """Yield strings from nested Terraform attribute structures."""

    if isinstance(value, str):
        yield value
        return

    if isinstance(value, dict):
        for nested_value in value.values():
            yield from _walk_strings(nested_value)
        return

    if isinstance(value, list | tuple | set):
        for nested_value in value:
            yield from _walk_strings(nested_value)
