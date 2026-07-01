# HopTerm — GUI SSH Terminal Manager

Кроссплатформенный (приоритет — Linux/Ubuntu) GUI-эмулятор терминала на Rust с
упором на работу с удалёнными SSH-сессиями: **multi-hop / jump host** маршруты,
интерактивные shell-сессии, передача файлов по SFTP через ту же цепочку, менеджер
подключений. Реализация по ТЗ `../agent-spec-rust-ssh-terminal.md`; UI следует
макету `../index.html`.

```
┌─────────────────────────────────────────────────────────────┐
│  ui (wry)        ← webview: HTML/CSS дизайн + xterm.js терминал  │
├─────────────────────────────────────────────────────────────┤
│  app             ← orchestration: SessionManager, wiring,     │
│                    offline MockTransport                       │
├──────────┬──────────┬──────────┬──────────┬──────────────────┤
│  ssh     │ terminal │ transfer │ storage  │ security          │
│ (russh,  │(alacritty│(russh-   │ (toml)   │ (known_hosts,     │
│ multi-hop│ _terminal│ sftp)    │          │  credentials)     │
│  chain)  │  VT)     │          │          │                   │
├──────────┴──────────┴──────────┴──────────┴──────────────────┤
│  domain          ← сущности + traits (контракты слоёв), IO-free│
│  logging         ← tracing + редактирование секретов           │
└─────────────────────────────────────────────────────────────┘
```

**Главный принцип (ТЗ §7.2):** GUI не знает про SSH transport. `ui`/`app` общаются
с нижними слоями только через traits из `domain` (`SshTransport`, `SftpSession`,
`TerminalBackend`, `ProfileStore`, `HostVerifier`, `CredentialStore`). `russh`,
`russh-sftp`, `alacritty_terminal` спрятаны за этими абстракциями.

## Сборка и запуск

```bash
cd hopterm
cargo build                 # собрать весь workspace
cargo run -p hopterm-ui     # запустить GUI (боевой russh transport, без флагов)
cargo test                  # юнит- и интеграционные тесты
```

`HOPTERM_DEBUG=1` включает debug-диагностику; `RUST_LOG` переопределяет уровни.
Конфигурация хранится в `~/.hopterm/` (`config.toml`, `known_hosts`, `keys/`).

В offline-режиме приложение запускается без сервера: `MockTransport` отдаёт тот же
контракт `SshTransport`, что и боевой транспорт, и обслуживает демонстрационный
интерактивный shell — удобно для разработки UI и тестов.

## Crates

| Crate | Слой ТЗ §7.1 | Назначение |
|-------|--------------|------------|
| `hopterm-domain` | — | Сущности (§8) + traits-контракты между слоями (§15.7), без IO |
| `hopterm-logging` | 10 | `tracing`-init, редактирование секретов в логах (§11, §6.3) |
| `hopterm-storage` | 8 | TOML profiles/settings/known_hosts в `~/.hopterm/` (§10) |
| `hopterm-security`| 9 | Credentials, host-key verification, TOFU/trust policy (§6.3) |
| `hopterm-ssh` | 5, 4 | `russh`-транспорт + построитель multi-hop цепочки (§5.1, §5.2) |
| `hopterm-terminal`| 6 | `alacritty_terminal` VT/ANSI движок, grid-снимки (§5.3) |
| `hopterm-transfer`| 7 | SFTP поверх существующей цепочки (§5.5) |
| `hopterm-app` | 2, 3 | SessionManager, wiring сервисов, MockTransport, demo-данные |
| `hopterm-ui` | 1 | wry-webview: рендерит HTML/CSS-дизайн + `xterm.js`, мост к бэкенду по IPC |

## Документация (deliverables ТЗ §15)

| Файл | Что внутри |
|------|-----------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Архитектурный план, слои, data-flow multi-hop и SFTP, async-модель |
| [docs/CRATES.md](docs/CRATES.md) | Структура crates/modules, граф зависимостей |
| [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md) | Зависимости с обоснованием и отвергнутыми альтернативами |
| [docs/DATA_MODEL.md](docs/DATA_MODEL.md) | Модель сущностей (§8), ER-схема, пример `config.toml` |
| [docs/UI_FLOW.md](docs/UI_FLOW.md) | UI flow по макету, multi-hop builder, host-key dialog |
| [docs/TRAITS.md](docs/TRAITS.md) | Интерфейсы/traits между слоями, сигнатуры, кто реализует/вызывает |
| [docs/ROADMAP.md](docs/ROADMAP.md) | MVP roadmap (5 этапов §13), границы MVP §12, критерии приёмки §14 |

## Multi-hop: как строится цепочка (`ssh` crate)

`local → hop1 → … → target` (число хопов не ограничено архитектурно, ТЗ §4.2):

1. К первому хопу — обычный TCP + SSH handshake.
2. К каждому следующему — на предыдущем хопе открывается канал `direct-tcpip`,
   превращается в байтовый поток, поверх него — новый SSH handshake
   (`russh::client::connect_stream`).
3. Все промежуточные `Handle` держатся живыми (иначе туннель под ними рухнет).
   Shell/exec/SFTP-каналы открываются на **последнем** хопе, поэтому прозрачно
   проходят всю цепочку (переиспользование маршрутизации, §5.2).

Host-key каждого хопа проверяется **до** отправки учётных данных (§6.3): handshake
принимается на транспортном уровне, ключ захватывается и сверяется с `known_hosts`;
при несовпадении соединение рвётся (защита от MITM), при первом контакте — TOFU.

## Статус реализации

Рабочее приложение; ядро **проверено на реальных хостах**, не только собрано.

- ✅ Workspace из 9 крейтов по слоям §7.1, чистая сборка без warnings.
- ✅ Полная доменная модель (§8) и контракты-traits между слоями (§15.7).
- ✅ Боевой `russh` multi-hop транспорт (TCP + `connect_stream` по `direct-tcpip`),
  password / public-key / agent auth, host-key verification, keepalive.
- ✅ VT/ANSI движок на `alacritty_terminal` (тесты: цвета, перевод строки, TUI).
- ✅ SFTP-слой (`russh-sftp`): list/stat/mkdir/rename/remove, upload/download с
  прогрессом и отменой.
- ✅ Хранилище TOML (`~/.hopterm/`), known_hosts, TOFU- и интерактивный
  host-key-верификатор (тесты).
- ✅ GUI на **wry (системный webview)**: рендерит HTML/CSS-дизайн из мокапа
  пиксель-в-пиксель + терминал на **`xterm.js`**. Бэкенд (весь SSH) — на Rust,
  webview общается с ним по JSON-IPC. Реализовано:
  - список хостов из реального стораджа, подключение по клику (multi-hop);
  - **живой терминал** `xterm.js` ↔ настоящий PTY (стрим вывода, ввод, ресайз);
  - индикатор состояния подключения по хопам (`Connecting hop i/N`);
  - интерактивные диалоги пароля/passphrase и подтверждения host-key (TOFU).
  - Панели «Команды»/«Передачи» пока отрисованы по дизайну, но к живым job'ам
    ещё не подключены (бэкенд SFTP готов — `crates/transfer`).
- ✅ `MockTransport` для offline-запуска + интеграционный тест полного пайплайна.

### Проверка на реальных хостах

Набор live-тестов (`crates/app/tests/live.rs`, помечены `#[ignore]`) прогоняет
**боевой** транспорт против настоящих SSH-машин и проходит полностью:

```bash
cargo test -p hopterm-app --test live -- --ignored --nocapture
```

Покрывает: password / key / agent auth, single-hop, multi-hop (2 и 3 узла через
`direct-tcpip`), интерактивную shell-сессию (живой PTY, без обрывов), SFTP
upload/download по цепочке, и полный production-путь (`Services` + `SessionManager`
+ `InteractiveHostVerifier`). GUI подключается к реальному хосту и показывает
живой терминал (MOTD, prompt, ввод команд).

Осталось за рамками MVP (§12, [docs/ROADMAP.md](docs/ROADMAP.md)): split panes,
command palette, port/agent forwarding, локальные PTY-вкладки (`portable-pty`),
rsync-режим.
