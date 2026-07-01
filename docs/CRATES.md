# CRATES — Структура workspace и модулей

HopTerm собран как Cargo **workspace** (`hopterm/Cargo.toml`, resolver = "2",
edition 2021, rust-version 1.80). Один крейт = один архитектурный слой ТЗ §7.1.
Внутренние крейты именуются `hopterm-<layer>` и объявлены в
`[workspace.dependencies]`, чтобы пути и версии задавались в одном месте.

```
hopterm/
├── Cargo.toml                # workspace + workspace.dependencies
└── crates/
    ├── domain/               # hopterm-domain   — сущности + трейты (pure)
    ├── ssh/                  # hopterm-ssh      — russh transport + chain builder
    ├── terminal/             # hopterm-terminal — alacritty_terminal wrapper
    ├── transfer/             # hopterm-transfer — russh-sftp service
    ├── storage/              # hopterm-storage  — TOML в ~/.hopterm/
    ├── security/             # hopterm-security — creds + host-key verify
    ├── logging/              # hopterm-logging  — tracing init + redaction
    ├── app/                  # hopterm-app      — orchestration/state + Mock
    └── ui/                   # hopterm (bin)    — iced GUI
```

---

## Граф зависимостей между крейтами

```
                 ui ─────────────► app
                 │  └──────────────┐│
                 ▼                 ▼▼
              domain ◄──── ssh terminal transfer storage security logging
                 ▲          │     │       │       │        │        │
                 └──────────┴─────┴───────┴───────┴────────┴────────┘
                       (все внутренние крейты зависят от domain)
```

Текстом (кто → от кого зависит):

| Крейт      | Зависит от (внутренние)                                        | Внешние (основное) |
|------------|----------------------------------------------------------------|--------------------|
| `domain`   | —                                                              | serde, thiserror, uuid, async-trait |
| `logging`  | `domain`                                                       | tracing, tracing-subscriber |
| `storage`  | `domain`, `logging`                                            | serde, toml, directories |
| `security` | `domain`, `logging`                                            | sha2, base64, directories |
| `ssh`      | `domain`, `logging`                                            | russh (+ russh::keys), tokio, async-trait, futures |
| `terminal` | `domain`, `logging`                                            | alacritty_terminal, portable-pty |
| `transfer` | `domain`, `logging`                                            | russh-sftp, tokio, futures |
| `app`      | `domain`, `ssh`, `terminal`, `transfer`, `storage`, `security`, `logging` | tokio, anyhow, uuid |
| `ui`       | `app`, `domain`                                                | iced, rfd |

Ключевой инвариант: **`ui` не зависит от `ssh`/`terminal`/`transfer`/`storage`/
`security`** напрямую. Транспортные крейты не зависят друг от друга. См.
[ARCHITECTURE.md](./ARCHITECTURE.md) §3.

---

## Назначение и экспорт крейтов

### `domain` — сущности и контракты
Чистый крейт, без IO и без сетевых/файловых зависимостей. «Общий низ» всего
workspace.

- **Экспортирует сущности (§8 ТЗ):** `HostProfile`, `Hop`, `AuthMethod`,
  `JumpRoute`, `SessionProfile`, `ActiveSession`, `ConnectionState`,
  `TransferJob`, `TransferDirection`, `TransferStatus`, `HostKey`, `TrustPolicy`.
- **Экспортирует трейты-контракты:** `SshTransport`, `SessionManager`,
  `TransferService`, `ProfileStore`, `HostVerifier`, `CredentialStore`,
  `TerminalBackend` (полные сигнатуры — в [TRAITS.md](./TRAITS.md)).
- **Общие типы ошибок** доменного уровня (`RouteError`, `TransferError`, …).
- Модель данных — в [DATA_MODEL.md](./DATA_MODEL.md).

### `ssh` — SSH-транспорт и multi-hop (слои ssh + routing + connection)
- Реализация `SshTransport` поверх **russh 0.61** (ключи через `russh::keys`).
- **Chain builder:** последовательное построение цепочки hop'ов через
  `direct-tcpip`-каналы (§5.2). Реализует `SessionManager` (lifecycle,
  keepalive, reconnect-стратегия, §5.1).
- Запрос PTY + shell для интерактивной сессии; отдаёт поток вывода и `RouteProgress`.
- Экспортирует `RusshTransport`/`ChainBuilder` (имплементации domain-трейтов).

### `terminal` — терминальная эмуляция
- Обёртка над **alacritty_terminal 0.26**: VT/ANSI parser, screen `Grid`,
  scrollback, resize, Unicode, атрибуты/цвета (§5.3).
- **portable-pty 0.9** — локальный PTY для локальных вкладок и fallback-режима (§3).
- Реализует `TerminalBackend`: feed входных байтов, снимок экрана для отрисовки,
  resize, ввод от пользователя.

### `transfer` — передача файлов
- Реализация `TransferService` поверх **russh-sftp 2.3** (§5.5).
- upload/download с потоком прогресса, отмена; `mkdir`/`rename`/`delete`/`stat`,
  remote directory listing; политика конфликтов overwrite/rename/skip.
- Работает поверх канала к target из `ssh` (переиспользование цепочки).

### `storage` — конфигурация
- Чтение/запись TOML в `~/.hopterm/` через **serde + toml**; путь определяется
  **directories 6**. Файлы: `config.toml`, `known_hosts`, `keys/`.
- Реализует `ProfileStore`: профили хостов, jump-маршруты, сессии, UI/terminal
  preferences, метаданные known_hosts (§10). Импорт/экспорт конфига.

### `security` — учётные данные и доверие
- `CredentialStore`: безопасная работа с паролями/passphrase/ключами; ключи
  читаются через `russh::keys`; пароли не хранятся открыто (§6.3).
- `HostVerifier`: отпечаток host-key (**sha2 0.11** + **base64 0.22**), сверка с
  known_hosts, **trust-on-first-use** и явное подтверждение (`TrustPolicy`, §5.1).

### `logging` — диагностика
- Инициализация **tracing 0.1** + **tracing-subscriber 0.3** (env-filter, fmt).
- Уровни severity, трассировка этапов multi-hop, отдельная диагностика по hop,
  лог transfer-jobs, debug-режим (§11).
- **Redaction секретов:** пароли/passphrase/ключи не попадают в логи (§6.3, §11).

### `app` — оркестрация
- Хранит состояние приложения (открытые `ActiveSession`, очередь `TransferJob`,
  загруженные профили) и обрабатывает команды пользователя (§7.1 app-слой).
- **Wiring сервисов:** собирает конкретные реализации (`ssh`/`terminal`/
  `transfer`/`storage`/`security`) за domain-трейтами (`dyn _`).
- **MockTransport:** реализация `SshTransport`/`SessionManager`/`TransferService`
  без сети — позволяет запускать и тестировать GUI offline.
- Мост между tokio-сервисами и iced-subscription'ами (см. ARCHITECTURE §6).

### `ui` — GUI (бинарь `hopterm`)
- **iced 0.13** (features: tokio, advanced, image, lazy). Точка входа приложения.
- Экраны по мокапу `index.html`: sidebar + **Hosts / Commands / Transfers /
  Settings**, add-host modal с hop-chain и breadcrumb маршрута, host-key
  confirmation dialog (см. [UI_FLOW.md](./UI_FLOW.md)).
- **rfd 0.17** — нативные file-диалоги для upload/download.
- Знает только `app` (команды/состояние) и `domain` (типы для отображения).
