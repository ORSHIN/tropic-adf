"""
parse_tests.py

"""
from pathlib import Path
from template.ad import AD_PARSE_TEST

from parse import (
    parse,
)


def test_parsers():
    """Test the parsers using the ADs from template folder."""
    yaml_dict = parse(Path("template/ad.yaml"))
    toml_dict = parse(Path("template/ad.toml"))
    json_dict = parse(Path("template/ad.json"))
    xml_dict = parse(Path("template/ad.xml"))

    assert yaml_dict == AD_PARSE_TEST
    assert yaml_dict == toml_dict
    assert yaml_dict == json_dict
    assert yaml_dict == xml_dict
