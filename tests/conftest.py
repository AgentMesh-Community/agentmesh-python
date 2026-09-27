import json
from pathlib import Path

import pytest

VECTORS = Path(__file__).parent / "vectors"


def load(name: str) -> dict:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def ts_vectors() -> dict:
    return load("ts-sdk-vectors.json")
