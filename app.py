import gradio as gr
import json
import uuid
import time
import hashlib
import base64
from canonicaljson import encode_canonical_json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# =============================================================================
# JEP Core Implementation — based on draft-wang-jep-04
# =============================================================================

class JEPEvent:
    """
    JEP Event structure per Section 2.2:
    jep, verb, who, when, what, nonce, [aud], [ref], [sig], [ext]
    """
    def __init__(self, verb, who, what_content, aud=None, ref=None, ttl=None, digest_only=False):
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
        
        # Digest-Only Anonymity Extension (Section 2.5.1)
        if digest_only:
            self.who = self._compute_multihash(who)
        else:
            self.who = who
    
    def _compute_multihash(self, content):
        if isinstance(content, str):
            content = content.encode('utf-8')
        h = hashlib.sha256(content).hexdigest()
        return f"sha256:{h}"
    
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
        if self.ref:
            d["ref"] = self.ref
        else:
            d["ref"] = None
        if self.ttl:
            d["ttl"] = self.ttl
        if include_sig and self.sig:
            d["sig"] = self.sig
        return d
    
    def canonicalize(self):
        """RFC 8785 JSON Canonicalization Scheme (JCS)"""
        payload = {k: v for k, v in self.to_dict(include_sig=False).items()}
        return encode_canonical_json(payload)


class JEPSigner:
    """Ed25519 JWS signer per Section 2.4"""
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
    """Verification logic per Section 2.4"""
    def __init__(self, clock_skew=300):
        self.nonces = set()
        self.clock_skew = clock_skew
    
    def verify(self, event_dict, signature_b64, public_key_pem):
        # 1. Parse & structural checks
        if event_dict.get("jep") != "1":
            return False, "Invalid jep version (MUST be '1')"
        if event_dict.get("verb") not in ["J", "D", "T", "V"]:
            return False, "Invalid verb (MUST be J/D/T/V)"
        
        # 2. Nonce uniqueness (anti-replay)
        nonce = event_dict.get("nonce")
        if not nonce:
            return False, "Missing nonce"
        if nonce in self.nonces:
            return False, "REPLAY DETECTED: nonce already consumed"
        self.nonces.add(nonce)
        
        # 3. Timestamp window (±5 min default)
        now = int(time.time())
        when = event_dict.get("when", 0)
        if abs(now - when) > self.clock_skew:
            return False, f"Clock skew exceeded (|now-when|={abs(now-when)}s > {self.clock_skew}s)"
        
        # 4. JWS signature verification
        try:
            pub_key = serialization.load_pem_public_key(public_key_pem.encode())
        except Exception as e:
            return False, f"Invalid public key: {str(e)}"
        
        # Reconstruct canonical payload (sig excluded)
        payload_dict = {k: v for k, v in event_dict.items() if k != "sig"}
        payload_bytes = encode_canonical_json(payload_dict)
        
        # Base64URL decode (add padding if needed)
        padding_needed = 4 - (len(signature_b64) % 4)
        if padding_needed != 4:
            signature_b64 += '=' * padding_needed
        
        try:
            sig_bytes = base64.urlsafe_b64decode(signature_b64)
            pub_key.verify(sig_bytes, payload_bytes)
            return True, "Valid — all checks passed (structure, nonce, timestamp, signature)"
        except InvalidSignature:
            return False, "Invalid JWS signature"
        except Exception as e:
            return False, f"Verification error: {str(e)}"


# =============================================================================
# Gradio Interface
# =============================================================================

def generate_event(verb, who, what_content, aud, ref_mode, ref_hash, ttl_minutes, digest_only):
    """Generate a JEP event with Ed25519 JWS signature"""
    if not who.strip():
        return "❌ Actor (who) is REQUIRED", "", "", ""
    
    ref = ref_hash if ref_mode == "引用已有事件 (ref)" else None
    ttl = int(time.time()) + ttl_minutes * 60 if ttl_minutes > 0 else None
    
    event = JEPEvent(verb, who, what_content, aud=aud or None, ref=ref, ttl=ttl, digest_only=digest_only)
    signer = JEPSigner()
    payload = event.canonicalize()
    event.sig = signer.sign(payload)
    
    event_dict = event.to_dict()
    pretty_json = json.dumps(event_dict, indent=2, ensure_ascii=False)
    canonical_str = payload.decode('utf-8')
    pub_key = signer.get_public_key_pem()
    
    return pretty_json, canonical_str, event.sig, pub_key


def verify_event(event_json, public_key_pem, clock_skew):
    """Verify a JEP event"""
    if not event_json.strip():
        return "❌ 请输入事件 JSON"
    if not public_key_pem.strip():
        return "❌ 请输入公钥 PEM"
    
    try:
        event_dict = json.loads(event_json)
    except json.JSONDecodeError as e:
        return f"❌ JSON 解析错误: {str(e)}"
    
    sig = event_dict.pop("sig", None)
    if not sig:
        return "❌ 缺少 sig 字段 (JWS signature REQUIRED)"
    
    validator = JEPValidator(clock_skew=clock_skew)
    valid, msg = validator.verify(event_dict, sig, public_key_pem)
    icon = "✅" if valid else "❌"
    return f"{icon} {msg}"


with gr.Blocks(
    title="JEP Spec — Judgment Event Protocol",
    css=".contain { max-width: 1400px; margin: auto; }"
) as demo:
    gr.Markdown("""
    # JEP Spec — Judgment Event Protocol
    ### A Minimal Verifiable Log Format for Agent Decisions (draft-wang-jep-04)
    
    本演示实现了 **JEP-04** 协议的核心规范：
    - **J** (Judge) — 发起决策
    - **D** (Delegate) — 转移决策权
    - **T** (Terminate) — 终止决策生命周期
    - **V** (Verify) — 验证已有事件
    
    > 每个事件包含 **RFC 8785 JCS** 规范化载荷 + **Ed25519 JWS** 数字签名 + **UUIDv4 nonce** 防重放保护。
    """)
    
    with gr.Row():
        # =================== LEFT: Event Generator ===================
        with gr.Column(scale=1):
            gr.Markdown("### 🛠️ 生成 JEP 事件")
            
            verb = gr.Dropdown(
                choices=["J", "D", "T", "V"],
                value="J",
                label="verb (事件原语)",
                info="J=决策, D=授权, T=终止, V=验证"
            )
            who = gr.Textbox(
                label="who (行为主体)",
                value="did:example:agent-001",
                info="URI / DID / 公钥哈希"
            )
            what_content = gr.Textbox(
                label="决策内容 (原始内容)",
                value="approve-cross-border-data-transfer",
                info="what 字段将自动计算为该内容的 SHA-256 multihash"
            )
            aud = gr.Textbox(
                label="aud (接收方, RECOMMENDED)",
                value="https://platform.example.com",
                info="绑定事件到特定接收方，减少攻击面"
            )
            ref_mode = gr.Radio(
                choices=["无引用 (root event)", "引用已有事件 (ref)"],
                value="无引用 (root event)",
                label="ref (链引用)"
            )
            ref_hash = gr.Textbox(
                label="ref 目标哈希",
                value="sha256:e8878aa9a38f4d123456789abcdef01234",
                visible=False,
                info="V 事件 SHOULD 引用被验证的目标事件"
            )
            
            def toggle_ref(choice):
                return gr.update(visible=(choice == "引用已有事件 (ref)"))
            ref_mode.change(toggle_ref, inputs=ref_mode, outputs=ref_hash)
            
            ttl_minutes = gr.Number(
                label="TTL 扩展 (分钟, 0=禁用)",
                value=0,
                minimum=0,
                info="Section 2.5.3 — 数据生命周期管理"
            )
            digest_only = gr.Checkbox(
                label="启用 Digest-Only 匿名扩展",
                value=False,
                info="Section 2.5.1 — who 将显示为 salted hash"
            )
            
            gen_btn = gr.Button("生成并签名事件", variant="primary")
            
            gr.Markdown("""
            **快速实验：**
            1. 选择 **V** → 开启 `ref` → 输入目标哈希 → 观察 Verify 事件结构
            2. 勾选 **Digest-Only** → 观察 `who` 变为哈希值
            3. 设置 **TTL=60** → 观察 `ttl` 字段出现
            """)
        
        # =================== CENTER: Output ===================
        with gr.Column(scale=1):
            gr.Markdown("### 📤 输出")
            event_json = gr.Textbox(
                label="JEP 事件 (JSON)",
                lines=16,
                info="完整的签名后事件，可直接用于传输或存储"
            )
            canonical = gr.Textbox(
                label="JCS 规范化载荷 (RFC 8785)",
                lines=6,
                info="签名前的规范化字节序列"
            )
            signature = gr.Textbox(
                label="JWS 签名 (base64url)",
                lines=2,
                info="Ed25519 签名值"
            )
            pub_key_out = gr.Textbox(
                label="Ed25519 公钥 (PEM)",
                lines=4,
                info="请保存此公钥用于下方验证"
            )
        
        # =================== RIGHT: Verifier ===================
        with gr.Column(scale=1):
            gr.Markdown("### 🔍 验证 JEP 事件")
            verify_input = gr.Textbox(
                label="粘贴待验证的事件 JSON",
                lines=10,
                info="必须包含完整的 sig 字段"
            )
            verify_key = gr.Textbox(
                label="公钥 PEM (用于验证签名)",
                lines=4,
                info="从左侧生成面板复制公钥"
            )
            clock_skew = gr.Number(
                label="时钟容差 (秒)",
                value=300,
                minimum=0,
                info="默认 ±5 分钟 (Section 2.3)"
            )
            verify_btn = gr.Button("验证", variant="secondary")
            verify_result = gr.Textbox(
                label="验证结果",
                lines=3,
                info="结构 / nonce / 时间戳 / 签名"
            )
    
    # Bind buttons
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
    ### 规范引用
    
    | 规范章节 | 本演示实现 |
    |---------|-----------|
    | 2.1 四原语 (J/D/T/V) | Dropdown 选择 + 事件类 |
    | 2.2 核心事件格式 | JSON 输出结构 |
    | 2.3 防重放机制 | UUIDv4 nonce + 验证器缓存 |
    | 2.4 签名与验证 | Ed25519 + JCS (RFC 8785) + JWS |
    | 2.5.1 Digest-Only | Checkbox 匿名扩展 |
    | 2.5.3 TTL | 数值输入 + 自动计算过期时间 |
    | 3.1 算法兼容性 | Ed25519 (RECOMMENDED) |
    
    **注意**：本演示使用内存中临时生成的 Ed25519 密钥对。生产环境应使用持久化密钥管理 (HSM/TEE)。
    
    ### 许可证
    Apache-2.0 — JEP 永远属于公共领域。
    """)

if __name__ == "__main__":
    demo.launch()