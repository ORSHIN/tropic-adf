"""
ad.py

File containing the AD datastructure templates
"""

AD_DICT = {
    "ad_name1": {
        # Mandatory fields
        "a": "Attack 1",
        "d": {"policy1": ["mech1", "mech2"], "policy2": ["mech1", "mech2"]},
        "surf": ["surf", "subsurf", "subsubsurf"],
        "vect": ["vector1", "vector2"],
        "model": ["model1", "model2"],
        "tag": ["tag1", "tag2"],
        # Optional fields
        "risk": ["score1", "score2"],
        "year": 2023,
        "cve": ["123", "456"],
        "cwe": ["123", "456"],
        "capec": ["123", "456"],
        "vref": ["vendor-ref1"],
    }
}

AD_PARSE_TEST = {
    "ad_name1": {
        "a": "Attack 1",
        "capec": ["123", "456"],
        "cve": ["123", "456"],
        "cwe": ["123", "456"],
        "d": {"policy1": ["mech1", "mech2"], "policy2": ["mech1", "mech2"]},
        "model": ["model1", "model2"],
        "risk": ["score1", "score2"],
        "surf": ["surf", "subsurf", "subsubsurf"],
        "tag": ["tag1", "tag2"],
        "vect": ["vector1", "vector2"],
        "vref": ["vendor-ref1"],
        "year": 2023,
    },
    "ad_name2": {
        "a": "Attack 2",
        "capec": ["123", "456"],
        "cve": ["123", "456"],
        "cwe": ["123", "456"],
        "d": {"policy1": ["mech1", "mech2"], "policy2": ["mech1", "mech2"]},
        "model": ["model1", "model2"],
        "risk": ["score1", "score2"],
        "surf": ["surf", "subsurf", "subsubsurf"],
        "tag": ["tag1", "tag2"],
        "vect": ["vector1", "vector2"],
        "vref": ["vendor-ref1"],
        "year": 2023,
    },
    "ad_name3": {
        "a": "Attack 3",
        "capec": ["123", "456"],
        "cve": ["123", "456"],
        "cwe": ["123", "456"],
        "d": {"policy1": ["mech1", "mech2"], "policy2": ["mech1", "mech2"]},
        "model": ["model1", "model2"],
        "risk": ["score1", "score2"],
        "surf": ["surf", "subsurf", "subsubsurf"],
        "tag": ["tag1", "tag2"],
        "vect": ["vector1", "vector2"],
        "vref": ["vendor-ref1"],
        "year": 2023,
    },
}
