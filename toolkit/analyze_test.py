"""
analyze_test.py

"""
from pathlib import Path
from wordcloud import WordCloud
import pandas as pd
import pytest
import graphviz
from analyze import (
    get_set,
    get_map,
    get_dataframe,
    get_surf_tree,
    get_chain,
    get_wordcloud,
    get_hist,
)


@pytest.fixture
def bt_ads():
    # TODO: review this one because depending on where you execute pytest changes
    bt_path = Path("yaml/bt.yaml")
    return get_dataframe(bt_path)


def test_get_dataframe():
    assert type(get_dataframe(Path("template/ad.yaml"))) == pd.DataFrame
    assert type(get_dataframe(Path("template/ad.toml"))) == pd.DataFrame
    assert type(get_dataframe(Path("template/ad.json"))) == pd.DataFrame
    assert type(get_dataframe(Path("template/ad.xml"))) == pd.DataFrame


def test_get_set(bt_ads: pd.DataFrame):
    """test_get_set"""

    cases = [
        ["surf", "BC"],
        ["model", "MitM"],
        ["tag", "Protocol"],
        ["tag", "LMP"],
        ["tag", "Impl"],
        ["tag", "Fuzz"],
    ]

    for case in cases:
        ads_set = get_set(bt_ads, case[0], case[1])
        assert len(ads_set) > 0


def test_get_map(bt_ads: pd.DataFrame):
    """test_maps"""

    # NOTE: security
    stride_map = get_map(bt_ads, "stride", "tag")
    assert len(stride_map) > 0
    cia_map = get_map(bt_ads, "cia", "tag")
    assert len(cia_map) > 0

    # NOTE: privacy
    uit_map = get_map(bt_ads, "uit", "tag")
    pmd_map = get_map(bt_ads, "pmd", "tag")
    lin_map = get_map(bt_ads, "linddun", "tag")

    # NOTE: OWASP top ten
    ott17_map = get_map(bt_ads, "ott17", "tag")
    ott21_map = get_map(bt_ads, "ott21", "tag")

    ckc_map = get_map(bt_ads, "ckc", "tag")


def test_trees(bt_ads: pd.DataFrame):
    """test_trees"""

    prot_tree = get_surf_tree(bt_ads, "Protocol", "prot-tree")
    assert type(prot_tree) == graphviz.Digraph
    smp_tree = get_surf_tree(bt_ads, "SMP", "smp-tree")
    assert type(smp_tree) == graphviz.Digraph


def test_chains(bt_ads: pd.DataFrame):
    """test_chains"""

    knob_bc_chain = get_chain(bt_ads, "knob_bc", "chain-knob-bc")
    assert type(knob_bc_chain) == graphviz.Digraph
    bias_lsc_chain = get_chain(bt_ads, "bias_lsc", "chain-bias-lsc")
    assert type(bias_lsc_chain) == graphviz.Digraph
    bias_screfl_chain = get_chain(bt_ads, "bias_screfl", "chain-bias-screfl")
    assert type(bias_screfl_chain) == graphviz.Digraph
    # FIXME: knob_bc should be after bias_lsc
    # get_chain(bt_ads, "bias_scdown", "chain-bias-scdown")


@pytest.mark.filterwarnings("ignore:The get_cmap function")
@pytest.mark.filterwarnings("ignore:textsize is deprecated")
def test_wordclouds(bt_ads: pd.DataFrame):
    surf_wc = get_wordcloud(bt_ads, "surf")
    assert type(surf_wc) == WordCloud


def test_plots(bt_ads: pd.DataFrame):
    pass
