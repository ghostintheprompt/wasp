import pytest
import json
import os
from pathlib import Path
from wasp import CyberSOC, ThreatSimulator, GuardrailEngine

@pytest.fixture
def soc():
    """Fixture for CyberSOC with a temporary incidents file"""
    soc_obj = CyberSOC()
    soc_obj.incidents_path = Path("test_incidents.json")
    if soc_obj.incidents_path.exists():
        os.remove(soc_obj.incidents_path)
    soc_obj.incidents = []
    return soc_obj

def test_soc_logging(soc):
    """Verify that incidents are correctly logged to JSON"""
    soc.log_incident("INC-TEST-001", "Test Incident", "LOW")
    assert len(soc.incidents) == 1
    assert soc.incidents[0]["id"] == "INC-TEST-001"
    assert soc.incidents_path.exists()
    
    with open(soc.incidents_path, "r") as f:
        data = json.load(f)
        assert data[0]["id"] == "INC-TEST-001"
    
    # Cleanup
    os.remove(soc.incidents_path)

def test_scenario_logic_mapping(soc):
    """Verify that the ThreatSimulator correctly identifies scenarios"""
    sim = ThreatSimulator("test_iface", soc)
    # Check if a non-existent scenario is handled
    sim.run_scenario("non_existent")
    assert len(soc.incidents) == 0

def test_guardrail_engine_init(soc):
    """Verify GuardrailEngine initialization"""
    engine = GuardrailEngine("test_iface", soc)
    assert engine.interface == "test_iface"
    assert engine.soc == soc

if __name__ == "__main__":
    pytest.main([__file__])
