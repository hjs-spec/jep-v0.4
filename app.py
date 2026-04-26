import gradio as gr
import json
import uuid
import time
import hashlib
import base64
from collections import defaultdict
from canonicaljson import encode_canonical_json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

class JEPEvent:
    def __init__(self, verb, who, what_content, aud=None, ref=None, ttl=None, digest_only=False, salt=None):
        self.jep = "1"
        self.verb = verb
        self.when = int(time.time())
        self.what_content = what_content
        self.what = self._compute_multihash(what_content)
        self.nonce = str(uuid.uuid4())
        self.aud = aud
        self.ref = ref
        self.ttl = ttl
        self.sig = None
        if digest_only:
            self.who = self._compute_multihash(f"{who}:{salt}")
        else:
            self.who = who
    
    def _compute_multihash(self, content):
        if isinstance(content, str):
            content = content.encode('utf-8')
        return f"sha256:{hashlib.sha256(content).hexdigest()}"
    
    def to_dict(self, include_sig=True):
        d = {
            "jep": self.jep,
            "verb": self.verb,
            "who": self.who,
            "when": self.when,
            "what": self.what,
            "nonce": self.nonce,
        }
        if self.aud:
            d["aud"] = self.aud
        if self.ref is not None:
            d["ref"] = self.ref
        else:
            d["ref"] = None
        if self.ttl:
            d["ttl"] = self.ttl
        if include_sig and self.sig:
            d["sig"] = self.sig
        return d
    
    def canonicalize(self):
        payload = {k: v for k, v in self.to_dict(include_sig=False).items()}
        return encode_canonical_json(payload)


class JEPSigner:
    def __init__(self):
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
    
    def get_public_key_pem(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    
    def sign(self, payload_bytes):
        sig = self.private_key.sign(payload_bytes)
        return base64.urlsafe_b64encode(sig).rstrip(b'=').decode()


class JEPValidator:
    def __init__(self, clock_skew=300):
        self.nonces = set()
        self.clock_skew = clock_skew
    
    def verify(self, event_dict, signature_b64, public_key_pem):
        if event_dict.get("jep") != "1":
            return False, "Invalid jep version"
        if event_dict.get("verb") not in ["J", "D", "T", "V"]:
            return False, "Invalid verb"
        
        nonce = event_dict.get("nonce")
        if not nonce:
            return False, "Missing nonce"
        if nonce in self.nonces:
            return False, "REPLAY DETECTED"
        self.nonces.add(nonce)
        
        now = int(time.time())
        when = event_dict.get("when", 0)
        if abs(now - when) > self.clock_skew:
            return False, "Clock skew exceeded"
        
        try:
            pub_key = serialization.load_pem_public_key(public_key_pem.encode())
        except Exception as e:
            return False, f"Invalid public key: {str(e)}"
        
        payload_dict = {k: v for k, v in event_dict.items() if k != "sig"}
        payload_bytes = encode_canonical_json(payload_dict)
        
        padding_needed = 4 - (len(signature_b64) % 4)
        if padding_needed != 4:
            signature_b64 += '=' * padding_needed
        
        try:
            sig_bytes = base64.urlsafe_b64decode(signature_b64)
            pub_key.verify(sig_bytes, payload_bytes)
            return True, "Valid — all checks passed"
        except InvalidSignature:
            return False, "Invalid JWS signature"
        except Exception as e:
            return False, f"Verification error: {str(e)}"


def generate_event(verb, who, what_content, aud, ref_mode, ref_hash, ttl_minutes, digest_only):
    if not who.strip():
        return "❌ who REQUIRED", "", "", ""
    
    ref = ref_hash if ref_mode == "Reference existing event (ref)" else None
    ttl = int(time.time()) + ttl_minutes * 60 if ttl_minutes > 0 else None
    
    event = JEPEvent(verb, who, what_content, aud=aud or None, ref=ref, ttl=ttl, digest_only=digest_only, salt="jep-salt")
    signer = JEPSigner()
    payload = event.canonicalize()
    event.sig = signer.sign(payload)
    
    event_dict = event.to_dict()
    pretty_json = json.dumps(event_dict, indent=2, ensure_ascii=False)
    canonical_str = payload.decode('utf-8')
    pub_key = signer.get_public_key_pem()
    
    return pretty_json, canonical_str, event.sig, pub_key


def verify_event(event_json, public_key_pem, clock_skew):
    if not event_json.strip() or not public_key_pem.strip():
        return "❌ Please enter event JSON and public key PEM"
    
    try:
        event_dict = json.loads(event_json)
    except json.JSONDecodeError as e:
        return f"❌ JSON parse error: {str(e)}"
    
    sig = event_dict.pop("sig", None)
    if not sig:
        return "❌ Missing sig field"
    
    validator = JEPValidator(clock_skew=int(clock_skew))
    valid, msg = validator.verify(event_dict, sig, public_key_pem)
    icon = "✅" if valid else "❌"
    return f"{icon} {msg}"


EXAMPLE = json.dumps([
    {"id": "C1", "tool_type": "code", "has_verification": 1, "verif_hash": "valid_hash",   "output": "correct", "target": 1},
    {"id": "C2", "tool_type": "code", "has_verification": 0, "verif_hash": "none",       "output": "correct", "target": 0},
    {"id": "C3", "tool_type": "calc", "has_verification": 0, "verif_hash": "none",       "output": "correct", "target": 0},
    {"id": "C4", "tool_type": "search", "has_verification": 0, "verif_hash": "none",     "output": "correct", "target": 0},
    {"id": "C5", "tool_type": "code", "has_verification": 1, "verif_hash": "failed_hash", "output": "error",   "target": 0},
    {"id": "C6", "tool_type": "code", "has_verification": 1, "verif_hash": "forged_hash", "output": "correct", "target": 0},
    {"id": "C7", "tool_type": "search", "has_verification": 0, "verif_hash": "none",    "output": "error",   "target": 0},
    {"id": "C8", "tool_type": "calc", "has_verification": 0, "verif_hash": "none",      "output": "error",   "target": 0}
], ensure_ascii=False, indent=2)


def analyze(configs_json, observed_keys_str, target_key):
    try:
        configs = json.loads(configs_json)
        if not isinstance(configs, list):
            return "❌ Error: Configuration must be a JSON list", "", ""
        observed_keys = [k.strip() for k in observed_keys_str.split(",") if k.strip()]
        if not observed_keys:
            return "❌ Error: Observation function requires at least one attribute", "", ""
        if not target_key.strip():
            return "❌ Error: Target attribute cannot be empty", "", ""
        
        groups = defaultdict(list)
        for C in configs:
            omega_val = tuple(sorted((k, C.get(k)) for k in observed_keys if k in C))
            groups[omega_val].append(C)
        
        for w, group in groups.items():
            values = {C.get(target_key) for C in group}
            if len(values) > 1:
                vals = list(values)
                C1 = next(C for C in group if C.get(target_key) == vals[0])
                C2 = next(C for C in group if C.get(target_key) == vals[1])
                return (
                    f"## ❌ NotDetermined\n\n"
                    f"**Observation Signature**: `{json.dumps(dict(w), ensure_ascii=False)}`\n\n"
                    f"**Counterexample Pair**:\n"
                    f"- C₁ = `{C1.get(target_key)}`: `{json.dumps(C1, ensure_ascii=False)}`\n"
                    f"- C₂ = `{C2.get(target_key)}`: `{json.dumps(C2, ensure_ascii=False)}`",
                    json.dumps([C1, C2], ensure_ascii=False, indent=2),
                    ""
                )
        
        delta = {w: group[0].get(target_key) for w, group in groups.items()}
        delta_str = {str(k): v for k, v in delta.items()}
        return (
            f"## ✅ Determined\n\n"
            f"All observation equivalence classes are target-monochromatic.\n\n"
            f"**Decision Table δ**:\n```json\n{json.dumps(delta_str, ensure_ascii=False, indent=2)}\n```",
            "",
            json.dumps(delta_str, ensure_ascii=False, indent=2)
        )
    except Exception as e:
        return f"❌ Error: {str(e)}", "", ""


with gr.Blocks(title="JEP Spec — Judgment Event Protocol", css=".contain { max-width: 1400px; margin: auto; }") as demo:
    gr.Markdown("""
    # JEP Spec — Judgment Event Protocol
    ### J/D/T/V Event Encoder + Verifier (JEP-04)
    
    > **Core Theorem**: D is determinable from Ω with zero error ⟺ D is constant on every Ω-equivalence class.
    """)
    
    with gr.Row():
        with gr.Column(scale=1):
            gr.Markdown("### 🛠️ Generate JEP Event")
            
            verb = gr.Dropdown(
                choices=["J", "D", "T", "V"],
                value="J",
                label="verb (Event Primitive)",
                info="J=Decision, D=Delegate, T=Terminate, V=Verify"
            )
            who = gr.Textbox(
                label="who (Actor)",
                value="did:example:agent-001",
                info="URI / DID / Public Key Hash"
            )
            what_content = gr.Textbox(
                label="Decision Content (Raw Content)",
                value="approve-cross-border-data-transfer",
                info="The 'what' field will be automatically computed as the SHA-256 multihash of this content"
            )
            aud = gr.Textbox(
                label="aud (Recipient, RECOMMENDED)",
                value="https://platform.example.com",
                info="Bind event to specific recipient to reduce attack surface"
            )
            ref_mode = gr.Radio(
                choices=["No reference (root event)", "Reference existing event (ref)"],
                value="No reference (root event)",
                label="ref (Chain Reference)"
            )
            ref_hash = gr.Textbox(
                label="ref Target Hash",
                value="sha256:e8878aa9a38f4d123456789abcdef01234",
                visible=False,
                info="V events SHOULD reference the target event being verified"
            )
            
            def toggle_ref(choice):
                return gr.update(visible=(choice == "Reference existing event (ref)"))
            ref_mode.change(toggle_ref, inputs=ref_mode, outputs=ref_hash)
            
            ttl_minutes = gr.Number(
                label="TTL Extension (minutes, 0=disabled)",
                value=0,
                minimum=0,
                info="Section 2.5.3 — Data lifecycle management"
            )
            digest_only = gr.Checkbox(
                label="Enable Digest-Only Anonymity Extension",
                value=False,
                info="Section 2.5.1 — who will display as salted hash"
            )
            
            gen_btn = gr.Button("Generate and Sign Event", variant="primary")
            
            gr.Markdown("""
            **Quick Experiment:**
            1. Select **V** → Enable `ref` → Enter target hash → Observe Verify event structure
            2. Check **Digest-Only** → Observe `who` becomes a hash value
            3. Set **TTL=60** → Observe `ttl` field appears
            """)
        
        with gr.Column(scale=1):
            gr.Markdown("### 📤 Output")
            event_json = gr.Textbox(
                label="JEP Event (JSON)",
                lines=16,
                info="Complete signed event, ready for transmission or storage"
            )
            canonical = gr.Textbox(
                label="JCS Canonical Payload (RFC 8785)",
                lines=6,
                info="Canonicalized byte sequence before signing"
            )
            signature = gr.Textbox(
                label="JWS Signature (base64url)",
                lines=2,
                info="Ed25519 signature value"
            )
            pub_key_out = gr.Textbox(
                label="Ed25519 Public Key (PEM)",
                lines=4,
                info="Please save this public key for verification below"
            )
        
        with gr.Column(scale=1):
            gr.Markdown("### 🔍 Verify JEP Event")
            verify_input = gr.Textbox(
                label="Paste event JSON to verify",
                lines=10,
                info="Must include complete sig field"
            )
            verify_key = gr.Textbox(
                label="Public Key PEM (for signature verification)",
                lines=4,
                info="Copy public key from the generation panel on the left"
            )
            clock_skew = gr.Number(
                label="Clock Skew Tolerance (seconds)",
                value=300,
                minimum=0,
                info="Default ±5 minutes (Section 2.3)"
            )
            verify_btn = gr.Button("Verify", variant="secondary")
            verify_result = gr.Textbox(
                label="Verification Result",
                lines=3,
                info="Structure / nonce / timestamp / signature"
            )
    
    gen_btn.click(
        generate_event,
        inputs=[verb, who, what_content, aud, ref_mode, ref_hash, ttl_minutes, digest_only],
        outputs=[event_json, canonical, signature, pub_key_out]
    )
    
    verify_btn.click(
        verify_event,
        inputs=[verify_input, verify_key, clock_skew],
        outputs=verify_result
    )
    
    gr.Markdown("""
    ---
    ### Specification Reference
    
    | Spec Section | This Demo Implementation |
    |---------|-----------|
    | 2.1 Four Primitives (J/D/T/V) | Dropdown selection + Event class |
    | 2.2 Core Event Format | JSON output structure |
    | 2.3 Anti-Replay Mechanism | UUIDv4 nonce + Validator cache |
    | 2.4 Signature and Verification | Ed25519 + JCS (RFC 8785) + JWS |
    | 2.5.1 Digest-Only | Checkbox anonymity extension |
    | 2.5.3 TTL | Numeric input + auto-calculated expiry |
    | 3.1 Algorithm Compatibility | Ed25519 (RECOMMENDED) |
    
    **Note**: This demo uses an ephemeral in-memory Ed25519 key pair. Production environments should use persistent key management (HSM/TEE).
    
    ### License
    Apache-2.0 — JEP belongs to the public domain forever.
    """)

if __name__ == "__main__":
    demo.launch()
