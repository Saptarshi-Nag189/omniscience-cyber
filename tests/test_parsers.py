import pytest
from rag.parsers import parse_generic

def test_generic_parser():
    output = "This is some standard output from a tool"
    result = parse_generic(output, "error stream")
    assert isinstance(result, list)
    assert len(result) == 0
