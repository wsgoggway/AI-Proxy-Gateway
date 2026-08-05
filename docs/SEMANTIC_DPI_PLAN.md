# Семантическая и контекстная проверка запросов в DPI

Спецификация расширения DPI-движка: добавление семантического/контекстного анализа
запросов поверх существующего rule-based DPI (regex + Aho-Corasick).

## Контекст текущего решения

- DPI (`proxy/src/dpi.rs`) — чисто rule-based: regex + Aho-Corasick, ~50 MB/s,
  <1мс на запрос. Ловит секреты и PII (ФИО/телефон/email/компания) по форматам,
  не понимает смысл.
- Точка встраивания: `forward_request` в `proxy/src/forward.rs:261-386` — между
  токенизацией тела и отправкой upstream. Тело уже забуферено (макс 10МБ),
  JSON распарсен.
- Loopback-цели уже поддерживаются (`mitm.rs`) → Ollama на `localhost:11434`
  можно использовать как внутренний сервис без DPI.

## Ключевая идея

Семантика вставляется **после** существующей токенизации (новая `ФАЗА 4.5`):
классификатор видит уже замаскированное тело (`‹KEY_xxx›`, `‹FIO_xxx›`) →
не утекают секреты в модель. Решение принимается до `send_upstream`
(`forward.rs:737`).

## Решения (зафиксированы)

| Параметр | Значение |
|---|---|
| Что детектить | prompt injection / jailbreak; тематический policy; PII что не ловит regex; intent / data exfiltration; дублирование pii/secrets/company name |
| Режим | `warn` (лог + метка) |
| Железо | CPU, слабое (edge/VM 2 vCPU) |
| Поставщик моделей | только локальный Ollama (`localhost:11434`) |

## Архитектура (окончательная)

Warn-режим + слабый 2vCPU → **async-архитектура без блокировки**. Снимает главную
проблему (latency), но ограничивает куда можно положить «метку».

```
forward_request (forward.rs:265):
  buffer body → DPI tokenize (существующий, <1мс) →
  ┌─ spawn_semantic_check(tokenized_body, ctx)   ← НЕ await, fire-and-forget
  │    ↘ Semaphore(permits=2)                     ← backpressure на 2vCPU
  │       Tier1: embed(33M) → score   (~10мс)
  │       if score≥thr: Tier2: qwen2.5:0.5b  (~150-300мс)
  │       → audit event {category, score, mode="warn"}
  │       → metrics.semantic_check_total{category,result}
  │    overflow semaphore → metric semantic_skip_concurrent (drop)
  └─ send_upstream (СРАЗУ, без задержки)
```

**Добавленная latency на hot path: ≈0мс** (только spawn, микросекунды). Весь анализ
идёт параллельно с запросом upstream.

## Компромисс Warn + async

Метку нельзя вернуть в HTTP-ответ — он уже улетел upstream. Доступно только:

- **audit-лог** (всегда) — `ViolationEvent` с `violation_type: "SEMANTIC_*"`
- **Prometheus** — `semantic_check_total{category,result}`, `semantic_score`
- **debug-лог прокси**

Если нужна метка в HTTP-ответе клиенту — придётся sync (ждать verdict), что на 2vCPU
добавит 150–300мс на каждый запрос. Текущая рекомендация — остаться на async+audit.

## Двухуровневая классификация (tiered)

```
запрос → DPI токенизация (существующий) →
  ├─ Tier 1: embeddings (быстро, всегда) → score
  │   └─ score < threshold → ✅ пропустить
  │   └─ score ≥ threshold ↓
  └─ Tier 2: LLM-judge (медленнее, только при флаге) → JSON {allow, category, reason}
      └─ warn mode: лог + метка / observe: только лог / block: 403 (отключено)
```

Плюс LRU-кэш `hash(message)→verdict` (TTL 1ч, ~50% хитов на повторах), circuit breaker
на падение Ollama, жёсткие timeout'ы.

## Модели (минимальные, мультиязычные RU+EN)

| Слой | Модель | Параметры | RAM | p50/p99 на 2vCPU | Примечание |
|---|---|---|---|---|---|
| Embed | `bge-small-ru-v1` / `nomic-embed-text` | 33–137M | 130–500МБ | 10/25мс | cosine vs референсные промпты |
| LLM mini | **`qwen2.5:0.5b` (Q8)** | 0.5B | ~1ГБ | 150/350мс | единственный реальный вариант на 2vCPU |

Стартовый набор: **embed + qwen2.5:0.5b** — ~1.2ГБ RAM дополнительно к прокси.
≥2ГБ RAM на VM обязательно.

`qwen2.5:1.5b` на 2vCPU = 400мс–1.2с — недопустимо. `3b` — нельзя. 0.5b единственный
реалистичный вариант; точность компенсируем хорошим prompt + reference-корпусом.

Ollama настройки: `OLLAMA_NUM_PARALLEL=2`, `keep_alive=-1` (no cold start).

## Справочно: тайминги на разных конфигах

CPU (8 потоков, без GPU):

| Слой | p50 | p99 |
|---|---|---|
| Tier 1 embed | 5–10мс | 20мс |
| Tier 2 qwen2.5:0.5b | 50мс | 150мс |
| Tier 2 qwen2.5:1.5b | 130мс | 350мс |
| Tier 2 qwen2.5:3b | 300мс | 700мс |

GPU (RTX 3060/4060):

| Слой | p50 | p99 |
|---|---|---|
| Tier 1 embed | 2мс | 5мс |
| Tier 2 0.5b | 10мс | 25мс |
| Tier 2 1.5b | 25мс | 60мс |

С кэшем (50% hit): средняя задержка падает вдвое. Tier 2 запускается только для
~10% запросов → общая медиана = tier 1 + cache lookup ≈ 8–15мс.

## Нагрузка / throughput

Один инстанс Ollama:

| Конфиг | 2vCPU RPS | 8vCPU RPS | GPU RPS |
|---|---|---|---|
| только embed | 80 | 100–200 | 500+ |
| embed + 0.5b (tiered, 10% LLM) | 6–7 | ~80 | ~300 |
| embed + 1.5b (tiered) | ~3 | ~30 | ~150 |
| каждый запрос через 3b | <1 | 2–5 | ~50 |

Ollama однопоточный на запрос — узкое место. Решение: `OLLAMA_NUM_PARALLEL`,
батчинг, либо 2 инстанса, либо GPU. На типичной нагрузке AI-прокси (1–20 RPS)
— 0.5b на 2vCPU хватает с запасом при наличии кэша и semaphore.

## Риски

### Критичные

1. **Latency на hot path** — +50–300мс на CPU. *Смягчение:* async warn-режим
   (spawn без блокировки), кэш, tiered. В выбранной архитектуре latency ≈ 0.
2. **False positive** — программист спрашивает «как работает SQL injection» →
   флаг. *Смягчение:* warn-режим (не блокирует), тюнинг порогов, allowlist по
   user/path.
3. **Privacy leak** — если классификатор внешний. *Смягчение:* только local
   Ollama, валидация в коде что endpoint ≡ loopback.
4. **Prompt injection против самого классификатора** — атакующий заставляет LLM
   вернуть `allow`. *Смягчение:* constrained JSON output, fallback→deny при
   ошибке парса, классификатору дают уже токенизированный текст.

### Эксплуатационные (специфично для 2vCPU)

5. **Очередь/дроп при burst** — semaphore сбрасывает проверку. *Смягчение:*
   приоритет scoring выше threshold (быстрый embed-пропуск), enlarge кэш.
   Metric `semantic_drop_total`, alert при росте.
6. **CPU конкуренция proxy ↔ Ollama** — на 2vCPU один всплеск классификаций
   тормозит accept новых соединений. *Смягчение:* `task::spawn_blocking` для
   Ollama-клиента, приоритизация tokio runtime.
7. **Memory на edge-VM** — 1.2ГБ к прокси. Если VM 2ГБ — tight. *Смягчение:*
   embed-only режим (флаг в конфиге), либо отдельный микро-инстанс под Ollama.
8. **0.5b точность** — маленькая модель хуже понимает хитрый jailbreak.
   *Смягчение:* качественный corpus, tier 2 только при embed-флаге, регулярный
   аудит FP/FN.
9. **Cascading failure** — Ollama упал → *смягчение:* circuit breaker
   (5 ошибок подряд → disable на 5 мин, warn-лог).
10. **Cold start** — *смягчение:* `keep_alive=-1`, warmup при старте прокси.
11. **Context window** — длинные переписки (10МБ тело) не влезают. *Смягчение:*
    классифицировать только last N сообщений / system+последний user, не всю
    историю.
12. **Model drift** — обновление тегов в Ollama меняет поведение. *Смягчение:*
    пинить digest в конфиге, регрессионные тесты.
13. **RU+EN смесь** — чисто-английские модели (Phi) плохо понимают русские
    запросы. *Смягчение:* только Qwen2.5/Llama3.2 multilingual.
14. **Audit pollution** — событие на каждый запрос захлёбывает лог. *Смягчение:*
    логировать только score>threshold или flag.

## Категории детекции

Tier 2 prompt для qwen2.5:0.5b возвращает JSON:

```json
{
  "allow": true,
  "category": "prompt_injection|jailbreak|policy|pii|secret|exfiltration|none",
  "score": 0.0,
  "reason": "..."
}
```

Reference-корпус нужен для каждой категории (RU+EN примеры). Существующий regex-DPI
уже ловит `pii/secret/company` по форматам — семантика дублирует + расширяет на
неявное упоминание:

- «мой паспорт 45 07» (без чёткого формата)
- «отправь на мою почту» (без адреса)
- генерация кода для кражи данных / обхода защиты

## План реализации (8–10 рабочих дней)

| Фаза | Дни | Что | Файлы |
|---|---|---|---|
| 0. Config + infra | 1 | `[semantic]` в config.toml, Ollama healthcheck, semaphore, circuit breaker | `config.rs`, `main.rs`, новый `semantic.rs` |
| 1. Tier 1 embed | 2 | клиент `/api/embed`, загрузка reference-корпуса, cosine, metrics | `semantic.rs` |
| 2. Reference-корпус | 1 | набрать RU+EN примеры 4 категорий + policy (TOML/YAML) | `data/semantic_corpus.*` |
| 3. Tier 2 LLM judge | 3 | клиент `/api/chat`, prompt-template, JSON parse, audit integration | `semantic.rs`, `violation_event.rs` |
| 4. Интеграция в forward | 1 | spawn в `forward_request` после DPI, `ViolationType::SemanticFlag` | `forward.rs:265`, `dpi.rs:11` |
| 5. Hardening + load-тест | 1–2 | timeout, dashboard, k6 через прокси, тюнинг порогов | — |

Новые сущности:

- `ViolationType::SemanticFlag` в `dpi.rs:11`
- модуль `SemanticChecker` (новый файл `semantic.rs`)
- метрики `semantic_check_total{result,category}`, `semantic_check_latency_seconds`,
  `semantic_drop_total`, `semantic_skip_concurrent`

## Конфигурация

```toml
[semantic]
enabled = true
mode = "warn"                 # warn | observe | block
endpoint = "http://localhost:11434"
embed_model = "bge-small-ru-v1"
llm_model = "qwen2.5:0.5b"
concurrency = 2               # = vCPU
cache_size = 10000
cache_ttl_sec = 3600
tier1_threshold = 0.65
timeout_ms = 500
circuit_breaker_failures = 5
circuit_breaker_cooldown_sec = 300
```

## Предусловия для старта

- [ ] Подтвердить наличие ≥2ГБ RAM на VM
- [ ] Поднять Ollama + стянуть модели:
      `ollama pull bge-small-ru-v1` и `ollama pull qwen2.5:0.5b`
- [ ] Решить: corpus пишем вместе в Фазе 2, или заказчик даёт готовые примеры
      policy под свою организацию
