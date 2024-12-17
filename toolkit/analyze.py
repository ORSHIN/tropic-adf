"""
analyze.py

Perform some analyses to show the effectiveness of the framework.

"""

import os
from pathlib import Path
from typing import List
from wordcloud import WordCloud
from collections import Counter

import graphviz

# NOTE: switch to pandas 2.0?
import pandas as pd

from check import check


def get_dataframe(path: Path) -> pd.DataFrame:
    """Get a pandas dataframe from an AD file"""

    ad_dict = check(path)

    # NOTE: unique rows of ads
    ads = pd.DataFrame.from_dict(ad_dict, orient="index").set_flags(
        allows_duplicate_labels=False
    )

    # NOTE: check for duplicates
    assert ads.index.is_unique
    assert ads.columns.is_unique

    # FIXME: this should not be required as we are parsing a typed dict
    ads = ads.astype(
        {
            "a": "string",
        }
    )
    # print(ads.index)
    # print(ads.year)

    return ads


def filter_dataframe(ads: pd.DataFrame, key: str, val: str) -> pd.DataFrame:
    include = [v.strip() for v in val.split(",") if not v.startswith(" not ")]
    exclude = [v.strip()[4:] for v in val.split(",") if v.startswith(" not ")]

    if include:
        filtered_ads = ads[
            ads[key].map(lambda x: all(val in x for val in include))
        ].copy()

    if exclude:
        filtered_ads = filtered_ads[
            ~filtered_ads[key].map(lambda x: any(val in x for val in exclude))
        ].copy()

    return filtered_ads


# TODO: rename this func
def get_set(ads: pd.DataFrame, key: str, val: str) -> pd.DataFrame:
    """Return a set of rows containing key and val in a DataFrame"""

    return filter_dataframe(ads, key, val)

    # for v in val.split("and"):
    #     v = v.strip()
    #     if v.startswith("not "):
    #         negated.append(v[4:].strip())
    #     else:
    #         non_negated.append(v.strip())

    # if non_negated:
    #     ads_set = ads[
    #         ads[key].map(lambda x: any(val in x for val in non_negated))
    #     ].copy()

    # if negated:
    #     ads_set = ads_set[
    #         ~ads_set[key].map(lambda x: any(val in x for val in negated))
    #     ].copy()

    # return ads_set


def get_map(ads: pd.DataFrame, taxonomy: List[str], key: str) -> list[pd.DataFrame]:
    """High level map function

    We support the following taxonomies: stride, cia, uit, linddun, ott21,
    ott17. ckc.
    """

    taxonomies = {
        # NOTE: security
        "stride": ["Spoofing", "Tampering", "Repudiation", "ID", "DoS", "EoP"],
        "cia": ["Confidentiality", "Integrity", "Availability"],
        # NOTE: privacy
        # protection goals for privacy engineering (2015)
        "uit": ["Unlinkability", "Intervenability", "Transparency"],
        # NISTIR 8062 (2017)
        "pmd": ["Predictability", "Manageability", "Dissassociability"],
        "linddun": [
            "Linkability",
            "Identifiability",
            "Non repudiation",
            "Detectability",
            "ID",  # Same as STRIDE
            "Unawareness",
            "Non compliance",
        ],
        # NOTE: OWASP top tens for web apps
        "ott21": [
            "Broken access control",
            "Cryptographic failure",
            "Injection",
            "Insecure design",
            "Security misconfiguration",
            "Vulnerable and outdated component",
            "Identification and authentication failure",
            "Software and data integrity failure",
            "Security logging and monitoring failure",
            "Server-side request forgery",
        ],
        "ott17": [
            "Injection",
            "Broken authentication",
            "Sensitive data exposure",
            "XML external entities",
            "Broken access control",
            "Security misconfiguration",
            "Cross-site scripting",
            "Insecure deserialization",
            "Using components with known vulnerabilities",
            "Insufficient logging and monitoring",
        ],
        "ckc": [
            "Reconnaissance",
            "Weaponization",
            "Delivery",
            "Exploitation",
            "Installation",
            "Command and control",
            "Actions on objectives",
        ],
        # 2021 CWE Most Important Hardware Weaknesses
        "mthcwe21": [
            "1189",
            "1191",
            "1231",
            "1233",
            "1240",
            "1244",
            "1256",
            "1260",
            "1272",
            "1274",
            "1277",
            "1300",
        ],
        # 2022 CWE Top 25 Most Dangerous Software Weaknesses
        "mtscwe22": [
            "787",
            "79",
            "89",
            "20",
            "125",
            "78",
            "416",
            "22",
            "352",
            "434",
            "476",
            "502",
            "190",
            "287",
            "798",
            "862",
            "77",
            "306",
            "119",
            "276",
            "918",
            "362",
            "400",
            "611",
            "94",
        ],
        # 2023 CWE Top 25 Most Dangerous Software Weaknesses
        "mtscwe23": [
            "787",
            "79",
            "89",
            "416",
            "78",
            "20",
            "125",
            "22",
            "352",
            "434",
            "862",
            "476",
            "287",
            "190",
            "502",
            "77",
            "119",
            "798",
            "918",
            "306",
            "362",
            "269",
            "94",
            "863",
            "276",
        ],
    }
    assert taxonomy in taxonomies.keys()

    ads_map = [get_set(ads, key, val) for val in taxonomies[taxonomy]]

    return ads_map


def map_atree(ads: pd.DataFrame):
    """Map to attack tree"""
    raise NotImplementedError


def get_tree(ads: pd.DataFrame):
    """Get a tree of ads"""
    raise NotImplementedError


def get_report(ads: pd.DataFrame):
    """Get a report from the ads"""
    raise NotImplementedError


def get_wordcloud(ads: pd.DataFrame, key: str) -> WordCloud:
    """Get a wordcloud from the ads based on key"""

    keys = ads[key]

    words_list = []
    for k in keys:
        for word in k:
            words_list.append(str(word))
    # NOTE: count multiword vals as one
    words_counter = Counter(words_list)
    wordcloud = WordCloud().generate_from_frequencies(words_counter)

    return wordcloud


# NOTE: can be generalized to any hierachical surf
def get_surf_tree(
    ads: pd.DataFrame, tag: str = None, tname: str = "tree"
) -> graphviz.Digraph:
    """Return a tree of ADs filtered by tag using surf as a hierarchy. If tag is None, do not filter"""

    # NOTE: strict to True prevents double edges
    tree = graphviz.Digraph(tname, filename=tname + ".gv", strict=True)

    for index, row in ads.iterrows():
        surf_lev = 0
        if tag in row.tag or tag is None:
            try:
                prev_surf = None
                for i in range(len(row.surf)):
                    # Use the current surf as the node name
                    current_surf = row.surf[i]

                    # Connect to previous surf if exists
                    if prev_surf is not None:
                        tree.edge(prev_surf, current_surf)

                    prev_surf = current_surf

                # Mark leaf nodes as boxes
                tree.attr("node", shape="box")
                # Connect last surf to the index (attack name)
                tree.edge(prev_surf, index)
                tree.attr("node", shape="ellipse")
            except IndexError:
                # if surf_lev == 1:
                #     tree.attr("node", shape="box")
                #     tree.edge(surf1, index)
                #     tree.attr("node", shape="ellipse")
                # else:
                #     print(f"get_surf_tree: tag {tag}, skip {index}")
                continue

    return tree


def get_row(ads: pd.DataFrame, index: str) -> pd.Series:
    """Return an ad (row) by index"""
    row = ads.loc[index].copy()
    return row


def get_chain(ads: pd.DataFrame, adname: str, cname: str = "cname") -> graphviz.Digraph:
    """Get a chain based on surf and vect"""

    # NOTE: strict to False allows double edges, rankdir for horizontal chain
    chain = graphviz.Digraph(
        cname, filename=cname + ".gv", strict=False, graph_attr={"rankdir": "LR"}
    )
    chain.attr("node", shape="box")

    ad = get_row(ads, adname)

    # NOTE: select ads with same surf and subsurf
    surf = get_set(ads, "surf", ad.surf[0])
    sub_surf = get_set(surf, "surf", ad.surf[1])
    # NOTE: filter out adname
    sub_surf.drop(index=adname, inplace=True)

    # NOTE: build chains by vect
    ad_vect_set = set(ad.vect)
    for index, row in sub_surf.iterrows():
        row_vect_set = set(row.vect)
        if row_vect_set.issubset(ad_vect_set):
            chain.edge(adname, index)
        elif ad_vect_set.issubset(row_vect_set):
            # NOTE: check the position in the chain
            if ad.vect[-1] == row.vect[-1]:
                chain.edge(index, adname)
            else:
                chain.edge(adname, index)

    return chain


def get_graph(ads: pd.DataFrame):
    """Get a graph of ads"""
    raise NotImplementedError


def gen_bc_session_tree(view: bool = False):
    """Generate bc-session-tree.gv"""

    g = graphviz.Digraph("bc-session-tree", strict=False)
    g.edge("Feature exchange", "Pairing key authentication")
    g.edge("Pairing key authentication", "Entropy negotiation")
    g.edge("Entropy negotiation", "Session key derivation")
    g.edge("Session key derivation", "Session start")

    if view:
        g.view()


def gen_bc_pairing_tree(view: bool = False):
    """Generate bc-pairing-tree.gv"""

    g = graphviz.Digraph("bc-pairing-tree", strict=False)
    g.edge("Feature exchange", "Pairing key derivation")
    g.edge("Pairing key derivation", "Association")
    g.edge("Association", "CTKD")

    if view:
        g.view()


def get_hist(ads: pd.DataFrame, key: str):
    """Get an histogram of ads"""
    raise NotImplementedError


def get_defenses(ads: pd.DataFrame):
    """Get a list of defenses from the ads"""
    for index, row in ads.sort_values(by="risk", ascending=False).iterrows():
        print(f"{index}:\n    Attack: {row['a']}")
        print(f"    Risk: {row['risk']}")
        print("    Defenses:")
        for d, d1 in row["d"].items():
            print(f"        - {d}:")
            for d2 in d1:
                print(f"            - {d2}")
        print()


if __name__ == "__main__":
    bt_ads = get_dataframe(Path("toolkit/yaml/bt.yaml"))
    # bt_surf_wc = get_wordcloud(bt_ads, "surf")

    # # NOTE: BC
    # bc_ads = get_set(bt_ads, "surf", "BC")
    # bc_ses_ads = get_set(bc_ads, "surf", "Session")
    # bc_pro_tree = get_surf_tree(bc_ses_ads, "Protocol")

    # knob_bc_chain = get_chain(bt_ads, "knob_bc", "chain-knob-bc")
    # gen_bc_session_tree()
    # gen_bc_pairing_tree()

    # NOTE: BLE
    ble_ads = get_set(bt_ads, "surf", "BLE, SMP, Pairing")
    ble_ads = pd.concat([ble_ads, get_set(bt_ads, "surf", "BLE, Session")])
    ble_ads = get_set(ble_ads, "tag", "Protocol, not dual-mode")
    # ble_ads.drop(index="injectable_1", inplace=True)
    # ble_ads.drop(index="pairing_method_confusion_ble", inplace=True)
    # ble_ads.drop(index="blur_ble", inplace=True)
    # ble_pa_ads = get_set(ble_ads, "surf", "Pairing, Session")
    # ble_se_ads = get_set(ble_ads, "surf", "Session")

    # blesec_ads = pd.concat([ble_pa_ads, ble_se_ads])
    # blesec_ads = get_set(ble_ads, "tag", "Protocol")
    # get_defenses(blesec_ads)
    ble_pro_tree = get_surf_tree(ble_ads)
    ble_pro_tree.view()
    get_defenses(ble_ads)
    # NOTE: Pegasus chain
    # chain = graphviz.Digraph(graph_attr={"rankdir": "LR"})
    # chain.attr("node", shape="box")
    # chain.edge("Trident CVE-2016-4655", "Trident CVE-2016-4656")
    # chain.edge("Trident CVE-2016-4656", "Trident CVE-2016-4657")
    # chain.attr("node", shape="ellipse")
    # chain.edge("Trident CVE-2016-4657", "iMessage CVE-2019-8646")
    # chain.view()
