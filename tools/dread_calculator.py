"""
DREAD Quantitative Risk Scoring Calculator and Prioritization Engine.
Calculates Damage, Reproducibility, Exploitability, Affected Users, Discoverability.
"""

from typing import List, Dict, Any
from tools.model import IdentifiedThreat, DREADScore


def score_threat(
    threat: IdentifiedThreat,
    damage: int,
    reproducibility: int,
    exploitability: int,
    affected_users: int,
    discoverability: int
) -> IdentifiedThreat:
    """Attaches a calculated DREAD score to an identified threat."""
    threat.dread_score = DREADScore(
        damage_potential=damage,
        reproducibility=reproducibility,
        exploitability=exploitability,
        affected_users=affected_users,
        discoverability=discoverability
    )
    return threat


def rank_threats_by_risk(threats: List[IdentifiedThreat]) -> List[IdentifiedThreat]:
    """Sorts threats descending by their DREAD total score."""
    def get_score(t: IdentifiedThreat) -> float:
        return t.dread_score.total_score if t.dread_score else 0.0

    return sorted(threats, key=get_score, reverse=True)


def calculate_risk_summary(threats: List[IdentifiedThreat]) -> Dict[str, Any]:
    """Computes distribution of threat severities across the system."""
    summary = {
        "total_threats": len(threats),
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Unscored": 0,
        "average_score": 0.0
    }
    
    total_score = 0.0
    scored_count = 0
    
    for t in threats:
        if t.dread_score:
            summary[t.dread_score.severity_level] += 1
            total_score += t.dread_score.total_score
            scored_count += 1
        else:
            summary["Unscored"] += 1
            
    if scored_count > 0:
        summary["average_score"] = round(total_score / scored_count, 2)
        
    return summary
