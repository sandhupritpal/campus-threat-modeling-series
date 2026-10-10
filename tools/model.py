"""
Threat modeling data models and schemas.
Supports components, data flows, trust boundaries, STRIDE categories, and DREAD scores.
"""

from enum import Enum
from typing import List, Optional, Dict
from pydantic import BaseModel, Field


class ComponentType(str, Enum):
    EXTERNAL_ENTITY = "external_entity"  # e.g., Student Browser, Mobile App
    PROCESS = "process"                  # e.g., Web App, Microservice, Background Worker
    DATA_STORE = "data_store"            # e.g., PostgreSQL DB, Redis Cache, File Storage
    DATA_FLOW = "data_flow"              # e.g., HTTPS Request, Database Query, Message Queue


class STRIDECategory(str, Enum):
    SPOOFING = "Spoofing"                        # Impersonating an identity
    TAMPERING = "Tampering"                      # Modifying data on disk or in transit
    REPUDIATION = "Repudiation"                  # Denying having performed an action
    INFORMATION_DISCLOSURE = "Information Disclosure" # Leaking private/sensitive data
    DENIAL_OF_SERVICE = "Denial of Service"      # Degrades or interrupts availability
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege" # Gaining unauthorized capabilities


class DREADScore(BaseModel):
    damage_potential: int = Field(ge=1, le=10, description="How severe is the damage if exploited? (1-10)")
    reproducibility: int = Field(ge=1, le=10, description="How easily can the attack be reproduced? (1-10)")
    exploitability: int = Field(ge=1, le=10, description="How much effort/skill to execute? (1-10)")
    affected_users: int = Field(ge=1, le=10, description="What proportion of users are affected? (1-10)")
    discoverability: int = Field(ge=1, le=10, description="How easy is it to find the vulnerability? (1-10)")

    @property
    def total_score(self) -> float:
        return round((self.damage_potential + self.reproducibility + self.exploitability + self.affected_users + self.discoverability) / 5.0, 2)

    @property
    def severity_level(self) -> str:
        score = self.total_score
        if score >= 8.0:
            return "Critical"
        elif score >= 6.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        else:
            return "Low"


class IdentifiedThreat(BaseModel):
    id: str
    target_component: str
    component_type: ComponentType
    stride_category: STRIDECategory
    title: str
    description: str
    impact: str
    recommended_mitigation: str
    dread_score: Optional[DREADScore] = None
    status: str = "Open"


class SystemComponent(BaseModel):
    id: str
    name: str
    type: ComponentType
    description: str
    trust_zone: str = "Internal" # e.g. "Public Internet", "DMZ", "Secure Enclave"
