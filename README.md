> Historical repository.
>
> This repository reflects an earlier design line and is no longer the current implementation track.
>
> Current versions:
>
> - JEP v0.6: https://github.com/hjs-spec/jep-v06
> - JEP API v0.6: https://github.com/hjs-spec/jep-api
> - HJS v0.5: https://github.com/hjs-spec/hjs-05
> - JAC v0.5: https://github.com/hjs-spec/jac-agent-02
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

This repository hosts the interactive reference implementation of the **JEP-04** IETF Internet-Draft.

## Protocol Core

- **J** (Judge) — Initiate a decision
- **D** (Delegate) — Transfer decision authority
- **T** (Terminate) — Terminate decision lifecycle
- **V** (Verify) — Verify an existing event

## Technical Features

| Specification | Implementation |
|------|------|
| RFC 8785 JCS | `canonicaljson` canonicalization |
| RFC 7515 JWS | Ed25519 digital signature |
| RFC 9562 UUIDv4 | Cryptographically secure random nonce |
| Anti-replay | Verifier nonce cache |
| Clock skew tolerance | ±5 minute default window |

## Related Resources

- **Mathematical Foundation**: [causal-observability-demo](https://huggingface.co/spaces/cognitiveemergencelab/causal-observability-demo )
- **Papers and Corpus**: [jep-papers-and-corpus](https://huggingface.co/datasets/cognitiveemergencelab/jep-papers-and-corpus )
- **Protocol Draft**: `draft-wang-jep-judgment-event-protocol-04`

## License

Apache-2.0

## Author

Cognitive Emergence Lab / Human Judgment Systems Foundation
