"""
generate.py

Generate ADs from known catalogues.

"""

# NOTE: https://realpython.com/python-xml-parser/
from defusedxml.ElementTree import parse
from pprint import pprint

ATT_BLOCKLIST = [
    "SOAP",
    "Web",
]

ATT_ALLOWLIST = [
    "Assembly",
    "Authentication",
    "Bluetooth",
    "Brute",
    "Certificate",
    "Design",
    "Eavesdropping",
    "Fault",
    "Firmware",
    "FPGA",
    "Fuzzing",
    "Hardware",
    "Integer",
    "Integrity",
    "IoT",
    "Overflow",
    "Pointer",
    "Privilege",
    "Protocol",
    "Signature Spoof",
]


def from_linddun():
    """Get the ads from LINDDUN catalogue"""
    raise NotImplementedError


def from_mtc():
    """Get the ads from mtc"""
    raise NotImplementedError


def from_vex():
    """Get the ads from a vex file"""
    raise NotImplementedError


def from_opencti():
    """Get the ads from a Open CTI"""
    raise NotImplementedError


def from_misp():
    """Get the ads from MISP"""
    raise NotImplementedError


def from_pytm():
    """Get the ads from  pytm threat catalogue"""
    raise NotImplementedError


def from_attack_tec_enterprise():
    """Get the ads from  ATT&CK enterprise techniques catalogue"""
    raise NotImplementedError


def from_attack_tec_mobile():
    """Get the ads from  ATT&CK mobile techniques  catalogue"""
    raise NotImplementedError


def from_attack_tec_ics():
    """Get the ads from  ATT&CK ICS techniques catalogue"""
    raise NotImplementedError


def from_attack_tac_enterprise():
    """Get the ads from  ATT&CK enterprise tactics catalogue"""
    raise NotImplementedError


def from_attack_tac_mobile():
    """Get the ads from  ATT&CK mobile tactics catalogue"""
    raise NotImplementedError


def from_attack_tac_ics():
    """Get the ads from  ATT&CK ICS tactics catalogue"""
    raise NotImplementedError


def from_cve():
    """Get the ads from  a cve"""
    raise NotImplementedError


def from_cwe():
    """Get the ads from  a cwe"""
    raise NotImplementedError


def from_capec():
    """Get the ads from the CAPEC catalogue"""
    FILENAME = "capec_v3.9.xml"
    # ATT_PATS = 615
    # ATT_PATS_NON_DEPR = 559
    # CATS = 78
    # VIEWS = 13
    # EXT_REFS = 440

    attacks = []

    et = parse(FILENAME)
    root = et.getroot()
    # root_att = root.attrib
    # root_tag = root.tag

    att_pats = root[0]
    # cats = root[1]
    # views = root[2]
    # ext_refs = root[3]

    for att_pat in att_pats:
        attack = att_pat.attrib["Name"]
        status = att_pat.attrib["Status"]
        skip = False

        # NOTE: skip Deprecated patterns
        if status == "Deprecated":
            continue

        # NOTE: skip ATT_BLOCKLIST
        for attack_block in ATT_BLOCKLIST:
            if attack_block in attack:
                skip = True
                break

        # NOTE: accept ATT_ALLOWLIST, without duplicates
        for attack_allow in ATT_ALLOWLIST:
            if (not skip) and (attack_allow in attack) and (attack not in attacks):
                attacks.append(attack)
        # assert len(ads) == ATT_PATS

    # NOTE: alphabetically sort attacks
    attacks.sort()

    return attacks


if __name__ == "__main__":
    pprint("generate.py")
    print(f"Blocklist: {ATT_BLOCKLIST}")
    print(f"Allowlist: {ATT_ALLOWLIST}")
    ads = []

    # NOTE: CAPEC
    # capec_attacks = from_capec()
    # for attack in capec_attacks:
    #     ads.append(Apc(attack))
    # print(f"CAPEC ads: {len(capec_attacks)}")

    # NOTE: MTC
    FILENAME = "mtc-data.xml"
    attacks = []

    et = parse(FILENAME)
    root = et.getroot()
    for row in root:
        threat_id = row.find("ThreatID").text
        threat_category = row.find("ThreatCategory").text
        threat = row.find("Threat").text
        __import__("ipdb").set_trace()

    print(f"TOTAL ads: {len(ads)}")
    # __import__("ipdb").set_trace()
