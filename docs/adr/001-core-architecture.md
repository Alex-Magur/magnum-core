# 🚀 Forge Core Ultra v12.0 (The Diamond Citadel) — MCP-Native, A2A & Zero-Trust Architecture Specification

**Статус:** 🟢 READY FOR IMPLEMENTATION (PROD-CANDIDATE)

**Формат:** 📄 Architecture Decision Record (ADR)

**Контекст:** 💻 Single-node hardened deployment, VPS (48 GB Min / 96 GB Target), MCP-native, A2A-ready, SLM-powered, Zero-Trust LLM code-agent система

**Горизонт:** 📅 Q2 2026 — Q1 2027

---

## 🧱 БЛОК 0. ФУНДАМЕНТАЛЬНЫЕ ПРИНЦИПЫ

**0.1. 🔌 MCP-First, Scopes & Secure Sampling**
Инструменты интегрируются через MCP. Доступ регламентирован через **OAuth 2.1**. Внедрена поддержка **MCP Sampling** (Reverse LLM Calls) со строгим Allowlist-ом и жесткими лимитами для сжатия тяжелых данных до попадания в граф.

**0.2. 🛡️ Constrained Decoding, Zero-Trust & Replay Protection**
Генерация вызовов инструментов обеспечивается через **Constrained Decoding** (OpenAI Structured Outputs / llama.cpp `--grammar`). Синтаксические ошибки обрабатываются детерминированной политикой `reject -> retry -> fail+alert`. Внутренняя сеть защищена **strict mTLS**. Все JIT-токены имеют защиту от replay-атак.

**0.3. 🔐 Kernel-Level & Supply-Chain Isolation**
Изоляция через NVIDIA OpenShell (Landlock, OPA). Внедрен полноформатный Supply-Chain контур: подпись описаний инструментов и строгий CVE-gate для контейнеров (cosign/Trivy).

**0.4. 🔄 Durable & Idempotent Graph**
Цикл агента — это асинхронный StateGraph (LangGraph). Все побочные эффекты транзакционно идемпотентны (через `side_effects` registry и паттерн `PREPARE/COMMIT`).

**0.5. ⚡ Provider-Aware Prompt Caching**
Кэширование адаптируется под провайдера. Динамические результаты тулов и секреты **не кэшируются**.

**0.6. 🧠 OpenViking & Hybrid Retrieval**
Поиск работает на трех слоях: Structural (SQLite), Semantic (Qdrant) и **Cross-Encoder Reranker** (SLM). Эпизодическая память вынесена в `viking://`.

**0.7. 🗄️ Zero Custom Storage Engines**
Только SQLite (с бинарным JSONB), Qdrant и файловая система. Никаких Redis/K8s/Kafka.

**0.8. 📊 Observability First**
End-to-end tracing (от `job_id` до MCP-вызовов и песочницы) через OpenTelemetry.

**0.9. 🚧 Phase Gates**
Ни один блок кода не сливается в main без прохождения 100% Acceptance Criteria (Given/When/Then).

---

## 🏗️ БЛОК 1. DEPLOYMENT TOPOLOGY & RESOURCE BUDGET

### 🌐 1.1. Сервисы, Сети и Strict mTLS
Используются изолированные сети Docker. Внутренний трафик защищен **strict mTLS (SPIFFE/SPIRE)**. 
**Контракт mTLS:** TTL SVID сертификатов = 1h, обязательный graceful connection cycling. Plaintext fallback физически невозможен (все сервисы слушают исключительно mTLS порты).

```text
┌──────────────────────────────────────────────────────────────────────┐
│                  VPS (48 GB MIN / 96 GB TARGET)                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐    │
│  │     n8n      │  │ forge-core-  │  │   forge-graph-worker     │    │
│  │(Sys Webhooks)│──▶     api      │  │ (Durable State Machine)  │    │
│  └──────────────┘  │  (REST API)  │  └──────────┬───────────────┘    │
│                    └──────┬───────┘             │ (MCP Client)       │
│                           │ mTLS strict         ▼ mTLS strict        │
│                           │          ┌──────────────────────────┐    │
│                    ┌──────┴───────┐  │ MCP Gateway (OAuth 2.1)  │    │
│                    │   Qdrant     │  └──────┬────────────┬──────┘    │
│                    │ (code only)  │         │ mTLS       │ mTLS      │
│                    └──────────────┘         ▼            ▼           │
│  SQLite:                           ┌────────────┐ ┌─────────────┐    │
│  - control_plane.db                │ jCodeMunch │ │ OpenSandbox │    │
│  - agent_state_graph.db            │(MCP Server)│ │(OpenShell)  │    │
│  - code_index.db                   └────────────┘ └─────────────┘    │
│                                      (Reranker)                      │
│  SLM Service:                                                        │
│  - llama.cpp server (Content Factory, Reranking, Log Compression)    │
│                                                                      │
│  FS: viking:// (vfs_memory)                                          │
│  Observability: OTEL Collector, Prometheus, Jaeger                   │
└──────────────────────────────────────────────────────────────────────┘
```

### 💾 1.2. Бюджет памяти и Graceful Degradation
**Целевая конфигурация (96 GB):** ~66 GB Steady State, ~30 GB Headroom (Включает 40GB под llama.cpp и 4.5 GB под jCodeMunch с Reranker).
**Минимальная конфигурация (48 GB) - Политика Деградации:** * SLM Service физически отключен. 
* *Reranker:* Отключается, Pipeline деградирует до базового Hybrid (Qdrant + SQLite). 
* *MCP Sampling:* Маршрутизируется во внешнее облачное API (с жестким лимитом токенов). При этом сохраняется строгая Content Policy (удаление PII/секретов до отправки), и результат обязательно упаковывается в JWS Envelope.

---

## 🔒 БЛОК 2. SECURITY, OAUTH 2.1 & SUPPLY CHAIN

### 🔑 2.1. OIDC/OAuth 2.1 Resource Server (Class A)
`forge-core-api` валидирует JWT, кэширует JWKS с ротацией. Обязательна публикация Protected Resource Metadata (RFC 9728).
**Token Binding:** Access token содержит claim `job_id`. Gateway отвергает токен, не совпадающий с активным контекстом задачи.

### 📦 2.2. Immutable Tool Manifest, Pinning & Container SBOM
Двухуровневая подпись манифестов (Offline Root -> Online).
**Контейнерный Supply-Chain:** Внедрена подпись Docker-образов (cosign/sigstore) и генерация SBOM (CycloneDX/SPDX).
**CVE-Gate Регламент:** Сканирование через `Trivy` (источники: OSV/NVD). Деплой блокируется при наличии уязвимостей со статусом `CRITICAL` (CVSS >= 9.0). Ложные срабатывания (False Positives) вносятся исключительно через ревью в файл `CVE_allowlist.yaml`. Запуск образов без подписи или с непроверенными CVE физически запрещен политикой CI/CD.
**Разделение JWKS:** Gateway публикует `/.well-known/forge-provenance-jwks.json` ИСКЛЮЧИТЕЛЬНО для верификации provenance-подписей.
**Server Identity Pinning:** Инструмент привязан связкой `tool_name + server_id (SPIFFE ID) + manifest_hash`. 

### 🛡️ 2.3. Tiered Risk Engine (ONNX Classifier)
Локальная ONNX-модель:
* **Score > 0.95:** BLOCK.
* **Score 0.70 – 0.95:** QUARANTINE + HITL Approval.
* **Score < 0.70:** ALLOW + Прикрепление JWS Provenance.

### 🔐 2.4. Key Management & Cryptographic Operations Contract
Управление криптографическим хозяйством формализовано:
* **Offline Root Key:** Хранится в air-gapped среде (холодное хранение). Требует ручной церемонии для подписи дочерних ключей.
* **Online Signing Keys (Provenance / Agent-Card):** Строгая автоматическая ротация (Rotation Cadence) каждые 30 дней.
* **Revoke Procedure:** При компрометации ключ мгновенно отзывается через API Gateway, все связанные с ним манифесты/инструменты переводятся в статус `QUARANTINED`.
* **Audit Trail:** Любая операция с ключами (ротация, отзыв, выдача) генерирует обязательную запись в `audit_log` в формате: `[key_id, action, operator, reason, timestamp]`.

---

## 📦 БЛОК 3. AGENT RUNTIME: OPENSHELL SANDBOX (MCP)

### 📜 3.1. OpenShell Policy (SSRF & DNS Rebinding Hardened)
```yaml
# openshell-policy.yaml
version: "1.0"
sandbox:
  isolation_level: strict
  network:
    egress: opa_policy 
    l7_inspection:
      protocol: rest
      ssrf_protection:
        deny_ip_literals: true
        deny_private_ranges: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]
        deny_redirect_chains: true
        deny_resolved_private_ips: true 
      rules:
        - allow: ["GET", "POST", "PATCH"]
          hosts: ["api.github.com"]
  filesystem:
    landlock: hard_requirement 
    mounts:
      - path: /workspace
        mode: rw
  routing:
    inference: local_proxy 
```

### 🤐 3.2. JIT Ephemeral Secrets & Replay Protection
Сырые ENV запрещены. MCP Gateway генерирует JIT токены (TTL 60s). 
**Replay Protection:** Токен привязан к `sandbox_instance_id + job_id + spiffe_id` и использует одноразовый `nonce`.

---

## 🕸️ БЛОК 4. DURABLE GRAPH, IDEMPOTENCY & SAMPLING

### 🗺️ 4.1. Agent State Graph & Transactional Registry
Внедрен транзакционный протокол для `side_effects`:
1. `INSERT side_effects (status='PREPARED')`
2. Выполнение побочного эффекта (API вызов)
3. `UPDATE side_effects (status='COMMITTED', result_hash=...)`
**Таймаут транзакции:** Если статус `PREPARED` не обновляется старше 10 минут, запускается reconciliation — job переводится в QUARANTINE с требованием HITL-ревью и генерацией алерта.

### 🔄 4.2. Secure MCP Sampling Protocol
* **Sampling Allowlist:** Только авторизованные `server_id`.
* **Sampling Limits:** Max calls: 20/job, Max input: 256KB, Max output: 256 tokens.
* **Content Policy:** Запрет на передачу raw-веб-контента и секретов.
* **Provenance:** Результат упаковывается в JWS Envelope.

---

## 🗂️ БЛОК 5. CONTEXT, CACHING & CRYPTO-PROVENANCE

### 🏷️ 5.1. Cryptographic Provenance Envelope & Lifecycle
`provenance_envelope = JWS(gateway_signing_key, {server_id, spiffe_id, manifest_hash, tool_name, ts, policy_decision_id, body_hash, exp})`
**Жизненный цикл и разделение Reject/Audit:** * Envelope имеет строгий `exp` (TTL) и поддерживает verify-window политику после ротации ключей Gateway. 
* Если `exp` истёк — данные **детерминированно не допускаются в контекст (prompt) LLM** (reject for prompt admission).
* Однако, эти данные **сохраняются в `raw_storage` и `audit_log`** как "expired but verifiable at time T" артефакт для форензики и расследований.

### 🧠 5.2. Provider-Aware Prompt Caching
Динамика тулов строго исключается из кэша. Адаптер использует breakpoints (Anthropic) или retention (OpenAI).

---

## 💾 БЛОК 6. CONTROL PLANE PERSISTENCE (SQLite)

Требование: **SQLite >= 3.45.0**.

### 📋 6.1. Системные таблицы (Правильный DDL для JSONB)
JSONB хранится как бинарный `BLOB`. Сериализация идет через нативные функции `jsonb()`, `json_extract()`.

```sql
CREATE TABLE agent_states (
    job_id TEXT PRIMARY KEY,
    checkpoint_id TEXT NOT NULL,
    state_payload BLOB NOT NULL,
    updated_at TEXT NOT NULL
);
```

---

## 🧭 БЛОК 7. SEMANTIC CODE INDEX (QDRANT)
Конфигурация: `oom_score_adj: -900`.

---

## 🏗️ БЛОК 8. STRUCTURAL CODE INDEX (SQLite FTS5)
Точная навигация по AST.

---

## 🧩 БЛОК 9. jCodeMunch (MCP SERVER)
AST-Aware Semantic Chunking и проверка цифровой подписи артефактов индексации.

---

## 🚦 БЛОК 10. RETRIEVAL PIPELINE & RERANKER (CORE)
Пайплайн интегрирован с локальным SLM Reranker. Метрики (MRR/Recall) замеряются в Phase 0.

---

## 📡 БЛОК 11. COMMUNICATION GATEWAY & API
REST API с TLS Termination. Внутренний трафик: Strict mTLS.

---

## ⚖️ БЛОК 12. EXECUTION GATE & TRAFFIC CONTROL
Контроль ресурсов: Per-tool rate limits, Per-user quotas, RAM limit gate.

---

## 📈 БЛОК 13. OBSERVABILITY & TELEMETRY
End-to-end Tracing. **Обязательные атрибуты спана:** `job_id`, `tool_name`, `server_id`, `spiffe_id`, `manifest_hash`, `risk_score`, `policy_decision_id`. Корреляция с `audit_log`.

---

## 📜 БЛОК 14. DATA GOVERNANCE & A2A PROTOCOL
Forge Core поддерживает **Dual Discovery**. Canonicalization для JWS-подписи Agent Card задана строго по RFC 8785.

**GET /.well-known/agent-card.json** (И алиас `/agent.json`)
```json
{
    "supportedInterfaces": ["json-rpc", "http"],
    "version": "13.0.0"
}
```

---

## 🚫 БЛОК 15. EXPLICIT ANTI-GOALS
* **Redis/K8s/RabbitMQ:** Запрещены.
* **LLM для Runtime Security Evals:** Запрещено.
* **Голые ENV-секреты:** Запрещено.

---

## 🚀 БЛОК 16. ROLLOUT PLAN & PHASE GATES (HARD GATES)

### 🏁 Phase 0: Benchmarks & CI Evals
* **P0-AC1 (Retrieval Baseline):** Given репо >= 500 файлов. When прогоняется retrieval eval suite. Then публикуются метрики `Recall@5`, `MRR@10`, `P95 latency`.
* **P0-AC2 (Security Coverage):** When прогоняется injection test suite. Then каждая батарея фиксирует outcome: BLOCK/QUARANTINE/ALLOW.
* **P0-AC3 (DoS Safety):** When sampling получает вход 1MB. Then действует `max_sampling_input_bytes` (256KB) и вход отклоняется детерминированно.

### 🏗️ Phase 1: Foundation, Constrained Decoding & mTLS (HARD GATE 1)
* **P1-AC1 (mTLS Strict):** When клиент делает plaintext HTTP запрос на внутренний порт. Then соединение детерминированно отвергается.
* **P1-AC2 (SPIFFE Rotation):** Given TTL=1h. When сервис держит соединение >1h. Then соединение пересоздается без даунтайма с новым SVID.
* **P1-AC3 (OAuth Metadata):** When `GET /.well-known/oauth-protected-resource`. Then ответ валиден, содержит issuer, jwks_uri и кэшируется.
* **P1-AC4 (JWT Correctness):** When токен имеет неверный `iss`/`aud` или истек. Then `401 invalid_token` + audit_log.
* **P1-AC5 (Constrained Decoding):** When агент формирует tool call. Then Gateway принимает ТОЛЬКО валидный JSON Schema. При невалидности: `reject -> retry (constrained) -> fail (после K=2)`.
* **P1-AC6 (Tool Verification):** When manifest подпись невалидна. Then tool = `QUARANTINED`, вызовы блокируются, срабатывает alert.
* **P1-AC7 (OAuth Binding Test):** When токен имеет `job_id` не совпадающий с активным `request job_id`. Then reject (403/401) + audit.
* **P1-AC8 (Key Ceremony Audit):** When происходит ротация/отзыв ключей Gateway. Then генерируется обязательная запись `[key_id, action, operator, reason, ts]` в `audit_log`.

### 🛡️ Phase 2: Execution, Container Supply-Chain & SSRF (HARD GATE 2)
* **P2-AC1 (Landlock Enforced):** When sandbox читает вне `/workspace`. Then отказ доступа (EPERM) + audit.
* **P2-AC2 (OPA & SSRF):** When sandbox запрашивает IP literal, `10.0.0.0/8`, или *resolved IP* указывает на private subnet. Then запрос блокируется на прокси (DNS Rebinding protection).
* **P2-AC3 (L7 Allowlist):** When метод/хост не из allowlist. Then блок.
* **P2-AC4 (JIT Anti-Replay):** When `nonce` используется повторно или токен истёк. Then reject.
* **P2-AC5 (Container Supply Chain):** When попытка деплоя неподписанного образа Docker или образа с `CVSS >= 9.0` (сканер Trivy, DB: OSV/NVD) без записи в `CVE_allowlist.yaml`. Then деплой детерминированно блокируется CI/CD политикой.

### 🔍 Phase 3: Retrieval, Qdrant & Reranker (HARD GATE 3)
* **P3-AC1 (Reranker Measured):** When прогоняется eval suite. Then фиксируется improvement hybrid -> hybrid+reranker по метрикам.
* **P3-AC2 (Fallback Correctness):** When Reranker недоступен. Then выдается Top-10 из базового hybrid без ошибок. When Qdrant недоступен. Then SQLite retrieval отвечает за P95 < 50ms.

### 🕸️ Phase 4: Graph, Idempotency & Secure Sampling (HARD GATE 4)
* **P4-AC1 (Kill -9 & Side-Effects):** When воркер убит `kill -9` в статусе `PREPARED`. Then после рестарта side-effect требует safe-noop или HITL (Idempotency Registry).
* **P4-AC1.1 (Prepared Timeout):** When запись в `side_effects` имеет статус `PREPARED` старше 10 минут. Then job переводится в QUARANTINE + alert (Reconciliation).
* **P4-AC2 (Sampling Limits Enforced):** Given лимиты (256KB/20 calls). When превышены. Then reject + audit + metric.
* **P4-AC3 (Sampling Allowlist):** When `server_id` не в allowlist запрашивает sampling. Then reject + alert.
* **P4-AC4 (Sampling Content Policy):** When sampling содержит сырые секреты/веб-контент. Then reject или QUARANTINE.
* **P4-AC5 (Min Sampling Cloud Policy):** Given Min (48GB) режим. When sampling уходит в облако. Then PII/секреты принудительно вырезаются до отправки, результат упаковывается в JWS.
* **P4-AC6 (JWS Verification):** When tool output приходит без валидного JWS. Then контент не попадает в LLM контекст.

### 📡 Phase 5: SLM Factory, A2A & Observability (HARD GATE 5)
* **P5-AC1 (Dual Discovery):** When `GET /agent.json` и `/agent-card.json`. Then эквивалентны, ETag/Cache-Control, JWS валиден по RFC 8785.
* **P5-AC2 (Span Attributes):** Then каждый span имеет `job_id`, `tool_name`, `server_id`, `spiffe_id`, `manifest_hash`, `risk_score`, `policy_decision_id`, корреляция с audit_log.
* **P5-AC3 (Provenance JWKS):** Then Gateway публикует `/.well-known/forge-provenance-jwks.json` ТОЛЬКО для верификации provenance-подписей.
* **P5-AC4 (Provenance EXP & Verify Window):** When валидируется старый provenance envelope после ротации ключа в пределах verify-window. Then подпись успешно верифицируется. When `exp` истёк. Then reject for prompt admission, но сохраняется в `audit_log` как verifiable artifact.

---

Этот документ является **Абсолютным Контрактом (Source of Truth)** проекта Forge Core Ultra v13.0 (Regulated-Grade Diamond).