import gradio as gr
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
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

# =============================================================================
# JEP Core (shared between UI and API)
# =============================================================================

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
            return False, f"Clock skew exceeded"
        
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


# =============================================================================
# FastAPI Models & State
# =============================================================================

class CreateEventRequest(BaseModel):
    verb: str = Field(..., pattern="^[JDTV]$")
    who: str
    what_content: str
    aud: Optional[str] = None
    ref: Optional[str] = None
    ttl_minutes: int = 0
    digest_only: bool = False
    salt: Optional[str] = "jep-api-salt"

class VerifyEventRequest(BaseModel):
    event_json: str
    public_key_pem: str
    clock_skew: int = 300

class APIResponse(BaseModel):
    success: bool
    event_id: Optional[str] = None
    event_json: Optional[str] = None
    signature: Optional[str] = None
    public_key_pem: Optional[str] = None
    message: str

EVENT_STORE = {}

# =============================================================================
# FastAPI App
# =============================================================================

app = FastAPI(
    title="JEP Core API & Demo",
    description="REST API + Interactive Demo for Judgment Event Protocol (JEP-04)",
    version="0.2.0"
)

@app.get("/")
def root():
    return {
        "service": "JEP Core API & Demo",
        "ui": "/",
        "docs": "/docs",
        "endpoints": {
            "POST /api/v1/events/create": "Create and sign a JEP event",
            "POST /api/v1/events/verify": "Verify a JEP event",
            "GET /api/v1/health": "Health check"
        }
    }

@app.get("/api/v1/health")
def health():
    return {"status": "ok", "protocol": "JEP", "version": "0.2.0"}

@app.post("/api/v1/events/create", response_model=APIResponse)
def api_create_event(req: CreateEventRequest):
    try:
        event = JEPEvent(
            verb=req.verb,
            who=req.who,
            what_content=req.what_content,
            aud=req.aud,
            ref=req.ref,
            ttl=req.ttl_minutes if req.ttl_minutes > 0 else None,
            digest_only=req.digest_only,
            salt=req.salt
        )
        
        signer = JEPSigner()
        payload = event.canonicalize()
        event.sig = signer.sign(payload)
        
        EVENT_STORE[event.nonce] = event.to_dict()
        
        return APIResponse(
            success=True,
            event_id=event.nonce,
            event_json=json.dumps(event.to_dict(), indent=2, ensure_ascii=False),
            signature=event.sig,
            public_key_pem=signer.get_public_key_pem(),
            message="Event created and signed"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/events/verify", response_model=APIResponse)
def api_verify_event(req: VerifyEventRequest):
    try:
        event_dict = json.loads(req.event_json)
        sig = event_dict.pop("sig", None)
        if not sig:
            return APIResponse(success=False, message="Missing sig")
        
        nonce = event_dict.get("nonce")
        if nonce in EVENT_STORE:
            return APIResponse(success=False, message="REPLAY: nonce consumed")
        
        validator = JEPValidator(clock_skew=req.clock_skew)
        valid, msg = validator.verify(event_dict, sig, req.public_key_pem)
        
        if valid:
            EVENT_STORE[nonce] = event_dict
        
        return APIResponse(success=valid, message=msg)
    except Exception as e:
        return APIResponse(success=False, message=f"Error: {str(e)}")


# =============================================================================
# Gradio UI
# =============================================================================

def generate_event(verb, who, what_content, aud, ref_mode, ref_hash, ttl_minutes, digest_only):
    if not who.strip():
        return "❌ who REQUIRED", "", "", ""
    
    ref = ref_hash if ref_mode == "引用已有事件 (ref)" else None
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
        return "❌ 请输入事件 JSON 和公钥 PEM"
    
    try:
        event_dict = json.loads(event_json)
    except json.JSONDecodeError as e:
        return f"❌ JSON 解析错误: {str(e)}"
    
    sig = event_dict.pop("sig", None)
    if not sig:
        return "❌ 缺少 sig 字段"
    
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
            return "❌ 错误：配置必须是 JSON 列表", "", ""
        observed_keys = [k.strip() for k in observed_keys_str.split(",") if k.strip()]
        if not observed_keys:
            return "❌ 错误：观察函数至少需要一个属性", "", ""
        if not target_key.strip():
            return "❌ 错误：目标属性不能为空", "", ""
        
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
                    f"**观察签名**：`{json.dumps(dict(w), ensure_ascii=False)}`\n\n"
                    f"**反例对**：\n"
                    f"- C₁ = `{C1.get(target_key)}`：`{json.dumps(C1, ensure_ascii=False)}`\n"
                    f"- C₂ = `{C2.get(target_key)}`：`{json.dumps(C2, ensure_ascii=False)}`",
                    json.dumps([C1, C2], ensure_ascii=False, indent=2),
                    ""
                )
        
        delta = {w: group[0].get(target_key) for w, group in groups.items()}
        delta_str = {str(k): v for k, v in delta.items()}
        return (
            f"## ✅ Determined\n\n"
            f"所有观察等价类都是目标单色的。\n\n"
            f"**决策表 δ**：\n```json\n{json.dumps(delta_str, ensure_ascii=False, indent=2)}\n```",
            "",
            json.dumps(delta_str, ensure_ascii=False, indent=2)
        )
    except Exception as e:
        return f"❌ 错误：{str(e)}", "", ""


with gr.Blocks(title="JEP Spec — Judgment Event Protocol", css=".contain { max-width: 1400px; margin: auto; }") as demo:
    gr.Markdown("""
    # JEP Spec — Judgment Event Protocol
    ### J/D/T/V Event Encoder + Verifier + REST API (v0.2)
    
    > **核心定理**：D 可从 Ω 零误差确定 ⟺ D 在每个 Ω-等价类上为常数。
    > 
    > 本 Space 同时提供 **交互式界面**（下方）和 **REST API**（见 `/docs`）。
    """)
    
    with gr.Row():
        with gr.Column(scale=1):
            gr.Markdown("#### 输入")
            configs_input = gr.Textbox(
                label="配置族 F（JSON 列表）",
                value=EXAMPLE,
                lines=18,
                info="论文 10.2 节 LLM 代理审计的 8 配置已预填。"
            )
            observed_input = gr.Textbox(
                label="观察函数 Ω（可见属性，逗号分隔）",
                value="output",
                info="例如：output / output,tool_type / output,tool_type,has_verification / output,tool_type,has_verification,verif_hash"
            )
            target_input = gr.Textbox(
                label="目标函数 D（目标属性键）",
                value="target",
                info="审计者试图确定的事实"
            )
            btn = gr.Button("运行 CheckDeterminability", variant="primary")
            
            gr.Markdown("""
            #### 快速实验
            依次尝试以下观察函数，观察从 NotDetermined 到 Determined 的演进：
            1. `output` —— 仅看最终输出（Ω₀）
            2. `output,tool_type` —— 加入工具类型（Ωₜ）
            3. `output,tool_type,has_verification` —— 加入验证标志（Ωₜ,ᵥ）
            4. `output,tool_type,has_verification,verif_hash` —— 加入防篡改哈希（Ωₜ,ᵥ,ₕ）
            """)
        
        with gr.Column(scale=1):
            gr.Markdown("#### 输出")
            result_md = gr.Markdown()
            counterexample = gr.Textbox(label="反例对 Certificate", lines=6, info="NotDetermined 时输出")
            decision_table = gr.Textbox(label="决策表 Delta", lines=10, info="Determined 时输出")
    
    btn.click(
        analyze,
        inputs=[configs_input, observed_input, target_input],
        outputs=[result_md, counterexample, decision_table]
    )
    
    gr.Markdown("""
    ---
    ### REST API 文档
    
    本 Space 同时暴露以下 REST 端点（访问 `/docs` 查看 Swagger UI）：
    
    | 方法 | 端点 | 说明 |
    |------|------|------|
    | POST | `/api/v1/events/create` | 创建并签名 JEP 事件 |
    | POST | `/api/v1/events/verify` | 验证 JEP 事件 |
    | GET  | `/api/v1/health` | 健康检查 |
    
    **示例 cURL**：
    ```bash
    curl -X POST https://your-space.hf.space/api/v1/events/create \\
      -H "Content-Type: application/json" \\
      -d '{"verb":"J","who":"did:test","what_content":"action"}'
    ```
    """)

app = gr.mount_gradio_app(app, demo, path="/")