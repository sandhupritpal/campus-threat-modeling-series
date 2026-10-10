"""
Unit tests for STRIDE threat enumeration engine.
"""

from tools.model import ComponentType, SystemComponent, STRIDECategory
from tools.stride_engine import enumerate_stride_threats, STRIDE_MATRIX


def test_stride_matrix_coverage():
    # Verify Process component has all 6 STRIDE threats
    assert len(STRIDE_MATRIX[ComponentType.PROCESS]) == 6
    
    # Verify External Entity has Spoofing and Repudiation
    assert STRIDECategory.SPOOFING in STRIDE_MATRIX[ComponentType.EXTERNAL_ENTITY]
    assert STRIDECategory.REPUDIATION in STRIDE_MATRIX[ComponentType.EXTERNAL_ENTITY]
    assert STRIDECategory.TAMPERING not in STRIDE_MATRIX[ComponentType.EXTERNAL_ENTITY]


def test_enumerate_process_threats():
    comp = SystemComponent(
        id="COMP-TEST",
        name="Test API Gateway",
        type=ComponentType.PROCESS,
        description="Handles routing and rate limiting."
    )
    threats = enumerate_stride_threats(comp)
    assert len(threats) == 6
    
    categories = [t.stride_category for t in threats]
    assert STRIDECategory.SPOOFING in categories
    assert STRIDECategory.TAMPERING in categories
    assert STRIDECategory.DENIAL_OF_SERVICE in categories
    assert STRIDECategory.ELEVATION_OF_PRIVILEGE in categories


def test_enumerate_datastore_threats():
    comp = SystemComponent(
        id="DB-01",
        name="Gradebook DB",
        type=ComponentType.DATA_STORE,
        description="Stores student grades."
    )
    threats = enumerate_stride_threats(comp)
    assert len(threats) == 4
    categories = [t.stride_category for t in threats]
    assert STRIDECategory.SPOOFING not in categories
    assert STRIDECategory.INFORMATION_DISCLOSURE in categories
