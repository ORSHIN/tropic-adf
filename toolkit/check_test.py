"""
check_tests.py

"""
from pathlib import Path

from check import (
    check,
)


def test_templates():
    """Test check using the ADs from template folder."""
    yaml_dict = check(Path("template/ad.yaml"))
    assert type(yaml_dict) == dict
    toml_dict = check(Path("template/ad.toml"))
    assert type(toml_dict) == dict
    json_dict = check(Path("template/ad.json"))
    assert type(json_dict) == dict
    xml_dict = check(Path("template/ad.xml"))
    assert type(xml_dict) == dict
