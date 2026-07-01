# ARCHITECTURE — Архитектурный план HopTerm

GUI-эмулятор терминала на Rust с приоритетом на удалённые SSH-сессии,
multi-hop / jump host маршруты и передачу файлов через ту же SSH-инфраструктуру.
Документ описывает слоистую архитектуру, data-flow ключевых сценариев и
async-модель. Соответствует разделам **§7 (Архитектурные требования)** и
**§6 (Нефункциональные требования)** ТЗ.

---

## 1. Главный принцип

> **§7.2 ТЗ:** GUI не должен напрямую знать детали SSH transport layer.
> Все подключения и передачи файлов идут через абстракции уровня domain/service.

Из этого следует жёсткое правило зависимостей:

- Крейт **`ui`** (iced) не импортирует `russh`, `russh-sftp`, `alacritty_terminal`.
- `ui` оперирует **только** типами из `domain` и командами/состоянием из `app`.
- Конкретные реализации транспорта (`ssh`, `terminal`, `transfer`, `storage`,
  `security`) подключаются в `app` через **trait-объекты** (`dyn SshTransport`,
  `dyn TransferService`, …), описанные в [TRAITS.md](./TRAITS.md).
- Благодаря этому `app` можно собрать с **`MockTransport`** (offline-режим GUI):
  интерфейс работает и тестируется без реальной сети.

Связанность GUI↔транспорт сведена к одному шву — набору domain-трейтов.
Заменить russh на другой SSH-стек или alacritty на иной VT-парсер можно, не
трогая `ui`.

---

## 2. Слои и крейты

ТЗ §7.1 перечисляет 10 логических слоёв. Они отображены на крейты Cargo-workspace
(`hopterm/crates/*`). Несколько мелких логических слоёв ТЗ (`connection`,
`routing`) свёрнуты внутрь крейтов, чтобы не плодить почти-пустые крейты:

| Слой ТЗ §7.1            | Крейт                  | Содержимое |
|-------------------------|------------------------|------------|
| домен / контракты       | `crates/domain`        | сущности + трейты между слоями (pure, без IO) |
| `ssh` + `routing` + `connection` | `crates/ssh`  | russh-транспорт, multi-hop chain builder, keepalive/reconnect, session lifecycle |
| `terminal`              | `crates/terminal`      | обёртка alacritty_terminal: VT/ANSI парсер, grid, scrollback, resize |
| `transfer`              | `crates/transfer`      | russh-sftp: upload/download с прогрессом, mkdir/rename/delete/stat |
| `storage`               | `crates/storage`       | TOML profiles/settings/known_hosts в `~/.hopterm/` |
| `security`              | `crates/security`      | credentials, fingerprint/verification, trust-on-first-use |
| `logging`               | `crates/logging`       | tracing init, structured diagnostics, redaction секретов |
| `app`                   | `crates/app`           | orchestration, state, команды пользователя, wiring сервисов, MockTransport |
| `ui`                    | `crates/ui`            | iced GUI, бинарь `hopterm` |

Детальное назначение и экспорт каждого крейта — в [CRATES.md](./CRATES.md).

---

## 3. Диаграмма зависимостей слоёв (ASCII)

Зависимости направлены **сверху вниз**. `domain` — общий низ, не зависит ни от
кого. Всё зависит от `domain`. `ui` зависит только от `app` (+ `domain` для
типов). Транспортные крейты не знают друг о друге.

```
                         ┌───────────────────────────┐
                         │            ui             │  iced GUI (bin: hopterm)
                         │  sidebar / Hosts / Cmds / │  знает ТОЛЬКО app + domain
                         │  Transfers / Settings     │
                         └─────────────┬─────────────┘
                                       │ depends on
                                       ▼
                         ┌───────────────────────────┐
                         │            app            │  orchestration / state
                         │  команды, wiring,         │  держит dyn-трейты,
                         │  MockTransport            │  собирает сервисы
                         └─┬───┬───┬───┬───┬───┬──────┘
            ┌──────────────┘   │   │   │   │   └──────────────┐
            ▼          ┌───────┘   │   │   └───────┐          ▼
      ┌─────────┐  ┌───▼────┐ ┌────▼───┐ ┌──▼──────┐   ┌──────────┐
      │   ssh   │  │terminal│ │transfer│ │ storage │   │ security │
      │ russh + │  │alacrit-│ │russh-  │ │  TOML   │   │ host-key │
      │ chain   │  │ty_term │ │ sftp   │ │~/.hopterm│  │ creds    │
      └────┬────┘  └───┬────┘ └───┬────┘ └────┬────┘   └────┬─────┘
           │           │          │           │             │
           │           │      ┌───▼───┐       │             │
           └───────────┴──────┤logging├───────┴─────────────┘
                              └───┬───┘   (все крейты пишут tracing-события)
                                  │
                                  ▼
                         ┌───────────────────────────┐
                         │          domain           │  pure entities + traits
                         │  HostProfile, Hop, ...    │  НЕ зависит ни от кого
                         │  SshTransport, ...        │
                         └───────────────────────────┘
```

Правила (проверяются ревью и фактическими `Cargo.toml`):

1. `domain` не зависит ни от одного внутреннего крейта и не делает IO.
2. Все крейты зависят от `domain` (контракты) и от `logging` (трассировка).
3. `app` зависит от `ssh`, `terminal`, `transfer`, `storage`, `security`,
   `logging`, `domain`.
4. `ui` зависит от `app` и `domain` — и **ни от чего транспортного**.
5. Транспортные крейты (`ssh`/`terminal`/`transfer`/`storage`/`security`)
   не зависят друг от друга — общаются только через типы `domain`.

---

## 4. Data-flow: multi-hop подключение

Сценарий §4.2 ТЗ: `local -> jump1 -> jump2 -> ... -> target`. Маршрут описан в
`JumpRoute` (цепочка `Hop`, см. [DATA_MODEL.md](./DATA_MODEL.md)). У каждого hop —
свои credentials и метод аутентификации (§5.2).

```
[ui] пользователь жмёт "Подключиться" на host-card / "Сохранить" в add-host modal
   │  Message::Connect(session_profile_id)
   ▼
[app] resolve SessionProfile -> JumpRoute (цепочка Hop'ов)
   │  app просит CredentialStore (security) распаковать секреты для каждого hop
   │  app вызывает SessionManager::open(route)  ──► исполняется на tokio-задаче
   ▼
[ssh] ChainBuilder строит цепочку ПОСЛЕДОВАТЕЛЬНО:
   │   hop[0]: TCP-connect к jump1  ── russh handshake
   │           HostVerifier (security) сверяет host-key c known_hosts
   │              └─ неизвестный ключ ─► event TrustPrompt ─► [ui] диалог TOFU
   │           аутентификация методом hop[0].auth (key/password/agent)
   │   hop[1]: open-channel "direct-tcpip" jump1 → (jump2:port)
   │           поверх полученного потока — НОВЫЙ russh client handshake к jump2
   │           verify + auth для hop[1]
   │   ...
   │   hop[n]: direct-tcpip к target, handshake, verify, auth
   │   на target: request-pty + shell  ──►  PTY-канал (interactive)
   │   каждый этап эмитит RouteProgress{hop_index, phase} в [logging]+[app]
   ▼
[app] ActiveSession{ connection_state=Connected, current_route, started_at }
   │   PTY-поток вывода сервера ─► стрим байтов
   ▼
[terminal] alacritty_terminal Parser скармливает байты в Grid (VT/ANSI),
   │        scrollback, обновляет screen-снимок
   ▼
[app] iced subscription конвертирует обновления экрана в Message::TerminalUpdated
   ▼
[ui] перерисовывает терминальную вкладку; статусбар = ConnectionState
```

Ключевые свойства:

- **Переиспользование маршрута (§5.2):** та же цепочка (тот же `SshTransport`)
  обслуживает и shell-сессию, и `TransferService` (SFTP-подсистему) — открывается
  дополнительный канал поверх соединения с target.
- **Диагностика по hop-уровням (§6.2, §11):** каждый этап несёт `hop_index`;
  ошибка возвращается как `RouteError{ hop_index, phase, source }`, и `ui` может
  показать «упал на hop 2 (sec-gw): auth failed», см. [UI_FLOW.md](./UI_FLOW.md).
- **Reconnect (§5.1):** при сетевом сбое `SessionManager` повторяет построение
  цепочки по сохранённой стратегии (backoff), не роняя менеджер.

---

## 5. Data-flow: передача файла (SFTP)

Сценарий §4.4 / §5.5. Передача идёт поверх **уже построенной** SSH-цепочки к
target — отдельный коннект не создаётся.

```
[ui] Transfers / host-card: пользователь выбирает файл (rfd file-dialog)
   │  Message::Upload{ session_id, local_path, remote_path }
   ▼
[app] создаёт TransferJob{ id, direction=Upload, status=Queued, progress=0 }
   │   кладёт в очередь, вызывает TransferService::upload(job, on_progress)
   ▼
[transfer] открывает SFTP-subsystem поверх SshTransport.target-канала
   │   russh-sftp: open remote file, цикл write-chunk
   │   после каждого чанка ─► on_progress(bytes_done, bytes_total)
   │            (поток progress-событий, НЕ блокирует runtime)
   ▼
[app] обновляет TransferJob.progress/status; эмитит в iced-subscription
   ▼
[ui] перерисовывает progress-bar (см. VIEW: Transfers в index.html):
        имя файла, X МБ / Y МБ, скорость, ETA, протокол=SFTP
   │  кнопка "Отмена" ─► Message::CancelTransfer(job_id)
   ▼
[app] отменяет tokio-задачу job'а; status=Cancelled
```

Конфликты (overwrite/rename/skip, §5.5) и базовые операции (mkdir/rename/delete/
stat) выражены методами `TransferService`, см. [TRAITS.md](./TRAITS.md).
Прогресс никогда не блокирует UI-поток (§6.1).

---

## 6. Async-модель (tokio + iced)

ТЗ §6.1: все сетевые операции async; UI не блокируется; рендеринг отзывчив при
большом потоке вывода.

### 6.1 Два «мира» и шов между ними

```
   ┌──────────────────────────┐         ┌──────────────────────────────┐
   │   iced runtime (UI)      │         │   tokio runtime (IO)         │
   │   - view()/update()      │         │   - russh соединения         │
   │   - Message-петля        │ ◄─────► │   - SFTP передачи            │
   │   - subscription()       │ events  │   - keepalive/reconnect      │
   └──────────────────────────┘ cmds    └──────────────────────────────┘
                 ▲                                     ▲
                 │ Message                  Command::perform / channels
                 └──────────────── app (orchestration) ┘
```

- **iced 0.13** включён с feature `tokio` — задачи запускаются на общем
  multi-thread tokio-runtime. UI-поток исполняет только `update()`/`view()` —
  чистые, неблокирующие функции.
- **Команды (Task / Command::perform):** разовые async-операции (открыть сессию,
  старт transfer) запускаются из `update()` и возвращают результат как `Message`.
- **Subscriptions / streams:** долгоживущие потоки событий конвертируются в
  поток `Message`:
  - поток вывода терминала (`terminal` → экран-снимки),
  - поток прогресса передач (`transfer` → проценты/скорость),
  - поток статусов соединения и `RouteProgress` (`ssh`),
  - поток `TrustPrompt` (запросы подтверждения host-key).
  Для backpressure при «водопаде» вывода terminal-слой батчит обновления и
  отдаёт UI снимок экрана с разумной частотой (coalescing), а не каждый байт.
- **Каналы:** `app` держит `tokio::sync` каналы между сервисными задачами и
  мостом в iced-subscription. Никакой блокирующий вызов не выполняется в
  `update()`.

### 6.2 Параллельные сессии (§4.3)

Каждая `ActiveSession` — независимая tokio-задача (своё соединение, свой PTY-канал,
свой terminal-Grid). Вкладки в `ui` — это представления над `Vec<ActiveSession>`
в состоянии `app`. Падение или reconnect одной сессии не влияет на другие
(§6.2: «некорректные credentials/разрыв не ломают остальной менеджер»).

### 6.3 Надёжность

- Разрыв соединения ловится в `ssh`-задаче, переводит `ConnectionState` в
  `Reconnecting`/`Failed` и эмитит событие — приложение **не падает** (§6.2).
- Все ошибки структурированы (`thiserror` в крейтах, `anyhow` на границах app)
  и логируются через `logging` с **редактированием секретов** (§6.3, §11).

---

## 7. Ссылки

- Структура крейтов и экспорт: [CRATES.md](./CRATES.md)
- Контракты между слоями: [TRAITS.md](./TRAITS.md)
- Модель данных и TOML: [DATA_MODEL.md](./DATA_MODEL.md)
- Зависимости и их обоснование: [DEPENDENCIES.md](./DEPENDENCIES.md)
- UI-флоу по мокапу: [UI_FLOW.md](./UI_FLOW.md)
- Этапы и критерии приёмки: [ROADMAP.md](./ROADMAP.md)
