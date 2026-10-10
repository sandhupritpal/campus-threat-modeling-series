"""
Unit tests for DREAD risk calculator and scoring engine.
"""

from tools.model import (
    ComponentType,
    STRIDECategory,
    IdentifiedThreat,
    DREADScore,
)
from tools.dread_calculator import score_threat, rank_threats_by_risk, calculate_risk_summary


def test_dread_score_calculation():
    score = DREADScore(
        damage_potential=10,
        reproducibility=8,
        exploitability=8,
        affected_users=10,
        discoverability=9
    )
    # (10 + 8 + 8 + 10 + 9) / 5 = 45 / 5 = 9.0
    assert score.total_score == 9.0
    assert score.severity_level == "Critical"


def test_dread_severity_brackets():
    low_score = DREADScore(
        damage_potential=2,
        reproducibility=3,
        exploitability=2,
        affected_users=1,
        discoverability=2
    )
    assert low_score.severity_level == "Low"

    med_score = DREADScore(
        damage_potential=5,
        reproducibility=5,
        exploitability=5,
        affected_users=5,
        discoverability=5
    )
    assert med_score.severity_level == "Medium"


def test_ranking_threats():
    t1 = IdentifiedThreat(
        id="T1", target_component="CompA", component_type=ComponentType.PROCESS,
        stride_category=STRIDECategory.TAMPERING, title="Low Threat", description="", impact="", recommended_mitigation=""
    )
    score_threat(t1, 2, 2, 2, 2, 2) # 2.0

    t2 = IdentifiedThreat(
        id="T2", target_component="CompB", component_type=ComponentType.PROCESS,
        stride_category=STRIDECategory.TAMPERING, title="High Threat", description="", impact="", recommended_mitigation=""
    )
    score_threat(t2, 8, 8, 8, 8, 8) # 8.0

    ranked = rank_threats_by_risk([t1, t2])
    assert ranked[0].id == "T2"
    assert ranked[1].id == "T1"

    summary = calculate_risk_summary([t1, t2])
    assert summary["total_threats"] == 2
    assert summary["Critical"] == 1
    assert summary["Low"] == 1
    assert summary["average_score"] == 5.0
