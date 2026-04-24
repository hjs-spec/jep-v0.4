import pytest
import time
from app import JEPEvent, JEPSigner, JEPValidator

def test_judgment_event_structure():
    """JEP Section 2.2: 核心事件格式验证"""
    event = JEPEvent("J", "did:example:agent-001", "approve-transfer")
    event_dict = event.to_dict(include_sig=False)
    assert event_dict["jep"] == "1"
    assert event_dict["verb"] == "J"
    assert event_dict["who"] == "did:example:agent-001"
    assert event_dict["what"].startswith("sha256:")
    assert len(event_dict["nonce"]) == 36
    assert event_dict["ref"] is None

def test_digest_only_anonymity():
    """Section 2.5.1: Digest-Only 扩展"""
    event = JEPEvent("J", "user@example.com", "content", privacy_mode="digest_only", salt="test-salt")
    assert event.who != "user@example.com"
    assert event.who.startswith("sha256:")

def test_signature_and_verification():
    """Section 2.4: JWS 签名与验证"""
    event = JEPEvent("J", "did:example:agent-001", "test-content")
    signer = JEPSigner()
    payload = event.canonicalize()
    event.sig = signer.sign(payload)
    
    event_dict = event.to_dict()
    validator = JEPValidator()
    valid, msg = validator.verify(event_dict, event_dict["sig"], signer.get_public_key_pem())
    assert valid is True
    assert "all checks passed" in msg

def test_replay_protection():
    """Section 2.3: 防重放机制"""
    event = JEPEvent("J", "did:example:agent-001", "content")
    signer = JEPSigner()
    event.sig = signer.sign(event.canonicalize())
    
    validator = JEPValidator()
    event_dict = event.to_dict()
    
    valid1, _ = validator.verify(event_dict.copy(), event_dict["sig"], signer.get_public_key_pem())
    assert valid1 is True
    
    valid2, msg2 = validator.verify(event_dict.copy(), event_dict["sig"], signer.get_public_key_pem())
    assert valid2 is False
    assert "REPLAY" in msg2

def test_clock_skew():
    """Section 2.3: 时钟容差 ±5 分钟"""
    event = JEPEvent("J", "did:example:agent-001", "content")
    event.when = int(time.time()) - 400
    signer = JEPSigner()
    event.sig = signer.sign(event.canonicalize())
    
    validator = JEPValidator(clock_skew=300)
    valid, msg = validator.verify(event.to_dict(), event.sig, signer.get_public_key_pem())
    assert valid is False
    assert "Clock skew" in msg

def test_ttl_extension():
    """Section 2.5.3: TTL 扩展"""
    event = JEPEvent("J", "did:example:agent-001", "content", ttl_minutes=60)
    event_dict = event.to_dict()
    assert "ttl" in event_dict
    assert event_dict["ttl"] > int(time.time())