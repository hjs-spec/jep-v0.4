---
title: JEP Spec - Judgment Event Protocol
emoji: ⚖️
colorFrom: green
colorTo: blue
sdk: gradio
sdk_version: 5.20.0
app_file: app.py
pinned: false
---

# JEP Spec — Judgment Event Protocol

**A Minimal Verifiable Log Format for Agent Decisions**

本仓库托管 **JEP-04** IETF Internet-Draft 的交互式参考实现。

## 协议核心

- **J** (Judge) — 发起决策
- **D** (Delegate) — 转移决策权
- **T** (Terminate) — 终止决策生命周期
- **V** (Verify) — 验证已有事件

## 技术特性

| 规范 | 实现 |
|------|------|
| RFC 8785 JCS | `canonicaljson` 规范化 |
| RFC 7515 JWS | Ed25519 数字签名 |
| RFC 9562 UUIDv4 | 密码学安全随机 nonce |
| 防重放 | 验证器 nonce 缓存 |
| 时钟容差 | ±5 分钟默认窗口 |

## 关联资源

- **数学基础**：[causal-observability-demo](https://huggingface.co/spaces/cognitiveemergencelab/causal-observability-demo)
- **论文与语料**：[jep-papers-and-corpus](https://huggingface.co/datasets/cognitiveemergencelab/jep-papers-and-corpus)
- **协议草案**：`draft-wang-jep-judgment-event-protocol-04`

## 许可证

Apache-2.0

## 作者

Cognitive Emergence Lab / Human Judgment Systerms Foundation
