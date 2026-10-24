import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch
import pytest
from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, Ether, wrpcap
from wasp import CyberSOC, ThreatSimulator, GuardrailEngine, WaspVerifier

@pytest.fixture
def soc(tmp_path):
    return CyberSOC(tmp_path / 'incidents.json')

def beacon(address='02:11:22:33:44:55', ssid=b'lab'):
    packet = RadioTap()/Dot11(type=0,subtype=8,addr1='ff:ff:ff:ff:ff:ff',addr2=address,addr3=address)/Dot11Beacon()/Dot11Elt(ID=0,info=ssid)
    packet.time = 100
    return packet

def test_ledger_roundtrip(soc):
    soc.log_incident('TEST','test')
    assert CyberSOC(soc.incidents_path).incidents[0]['id'] == 'TEST'

def test_bad_ledger_not_silently_erased(tmp_path):
    p=tmp_path/'bad.json';p.write_text('broken')
    with pytest.raises(ValueError): CyberSOC(p)

def test_zero_prefix_only_flags_management(soc):
    data=RadioTap()/Dot11(type=2,addr2='00:00:00:11:22:33')
    sim=ThreatSimulator(None,soc,[data,beacon()])
    assert sim.run_scenario('s1')['status']=='NO_FINDINGS'
    sim.packets=[beacon('00:00:00:11:22:33')]
    assert sim.run_scenario('s1')['status']=='FINDING'

def test_ethernet_not_claimed_as_wifi(soc):
    sim=ThreatSimulator(None,soc,[Ether()])
    assert sim.run_scenario('s1')['status']=='UNAVAILABLE'
    assert sim.run_scenario('s4')['status']=='UNAVAILABLE'

def test_ssid_length_detection(soc):
    sim=ThreatSimulator(None,soc,[beacon(ssid=b'x'*33)])
    assert sim.run_scenario('s4')['malformed']==1
    sim.packets=[beacon(ssid=b'x'*32)]
    assert sim.run_scenario('s4')['status']=='NO_FINDINGS'

def test_ssid_declared_length_mismatch(soc):
    packet=beacon(); packet[Dot11Elt].len=20
    assert ThreatSimulator(None,soc,[packet]).run_scenario('s4')['status']=='FINDING'

def test_beacon_threshold_uses_capture_timestamps(soc):
    packets=[beacon() for _ in range(100)]
    sim=ThreatSimulator(None,soc,packets)
    assert sim.run_scenario('s8')['status']=='FINDING'
    for i,p in enumerate(packets): p.time=100+i
    assert sim.run_scenario('s8')['status']=='NO_FINDINGS'

def test_unknown_mode_never_passes(soc):
    sim=ThreatSimulator('fake',soc)
    with patch.object(sim,'_get_mode',return_value=None):
        assert sim.run_scenario('s2')['status']=='UNAVAILABLE'

def test_changed_mode_does_not_assert_attacker(soc):
    sim=ThreatSimulator('fake',soc)
    with patch.object(sim,'_get_mode',side_effect=['managed','monitor']),patch('wasp.time.sleep'):
        output=sim.run_scenario('s2')
    assert output['status']=='FINDING'
    assert 'authorization are not determined' in output['detail']

def test_stable_mode_and_lost_visibility(soc):
    sim=ThreatSimulator('fake',soc)
    with patch.object(sim,'_get_mode',return_value='managed'),patch('wasp.time.sleep'):
        assert sim.run_scenario('s2')['status']=='NO_FINDINGS'
    with patch.object(sim,'_get_mode',side_effect=['managed',None]),patch('wasp.time.sleep'):
        assert sim.run_scenario('s2')['status']=='UNAVAILABLE'

def test_power_not_fabricated(soc):
    assert GuardrailEngine('fake',soc)._check_power_circuit_breaker()['status']=='UNSUPPORTED'

def test_usb_id_match_must_be_same_device(soc):
    verifier=WaspVerifier(soc=soc,packets=[])
    verifier.known_signatures={'example':{'vendor_id':'1234','product_id':'abcd'}}
    with patch('wasp.sys.platform','linux'),patch('wasp.subprocess.check_output',return_value='Bus 001 Device 001: ID 1234:0000\nBus 001 Device 002: ID 0000:abcd'):
        assert verifier.verify_hardware()['candidates']==[]
    with patch('wasp.sys.platform','linux'),patch('wasp.subprocess.check_output',return_value='Bus 001 Device 001: ID 1234:abcd'):
        assert verifier.verify_hardware()['candidates']==['example']

def test_hardware_command_failure_is_unavailable(soc):
    with patch('wasp.sys.platform','linux'),patch('wasp.subprocess.check_output',side_effect=FileNotFoundError('lsusb')):
        assert WaspVerifier(soc=soc).verify_hardware()['status']=='UNAVAILABLE'

def test_unknown_scenario_rejected(soc):
    with pytest.raises(ValueError): ThreatSimulator(None,soc).run_scenario('s12')

def test_overall_never_certifies_hardware(soc):
    verifier=WaspVerifier(soc=soc,packets=[beacon()])
    with patch.object(verifier,'verify_hardware',return_value={'status':'OBSERVED'}):
        assert verifier.run_all_checks()['overall']=='OBSERVATIONS_ONLY'

def test_offline_cli_replays_real_pcap_without_root(tmp_path):
    capture=tmp_path/'input.pcap';report=tmp_path/'report.json';ledger=tmp_path/'ledger.json'
    wrpcap(str(capture),[beacon(ssid=b'x'*33)])
    output=subprocess.run([sys.executable,str(Path(__file__).with_name('wasp.py')),'--pcap',str(capture),'--scenario','s4','--report',str(report),'--incidents',str(ledger)],capture_output=True,text=True)
    assert output.returncode==1,output.stderr
    assert json.loads(report.read_text())['s4']['malformed']==1

def test_offline_mode_claim_rejected(tmp_path):
    output=subprocess.run([sys.executable,str(Path(__file__).with_name('wasp.py')),'--pcap','unused','--scenario','s2','--incidents',str(tmp_path/'ledger')],capture_output=True,text=True)
    assert output.returncode==2
    assert 'cannot be inferred' in output.stderr

def test_mac_usb_inventory_pairs_within_device(soc):
    verifier=WaspVerifier(soc=soc)
    verifier.known_signatures={'example':{'vendor_id':'1234','product_id':'abcd'}}
    tree={'SPUSBDataType':[{'_items':[{'vendor_id':'0x1234 Vendor','product_id':'0xabcd'}]}]}
    with patch('wasp.sys.platform','darwin'),patch('wasp.subprocess.check_output',return_value=json.dumps(tree)):
        assert verifier.verify_hardware()['candidates']==['example']

@pytest.mark.parametrize('packet,expected',[(beacon(),0),(Ether(),2)])
def test_cli_distinguishes_no_finding_from_unavailable(tmp_path,packet,expected):
    capture=tmp_path/'input.pcap';wrpcap(str(capture),[packet])
    output=subprocess.run([sys.executable,str(Path(__file__).with_name('wasp.py')),'--pcap',str(capture),'--scenario','s4','--report',str(tmp_path/'report.json'),'--incidents',str(tmp_path/'ledger.json')],capture_output=True,text=True)
    assert output.returncode==expected,output.stderr
