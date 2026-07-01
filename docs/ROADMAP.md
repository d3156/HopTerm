# ROADMAP — MVP и этапы реализации

Roadmap соответствует ТЗ §13 (5 этапов), §12 (границы MVP) и §14 (критерии
приёмки). Этапы инкрементальны: каждый оставляет приложение в запускаемом
состоянии. Привязка к крейтам — см. [CRATES.md](./CRATES.md).

---

## Состав MVP (§12)

**Входит в MVP:**
GUI · SSH shell-сессии · multi-hop · вкладки · host profiles · host key
verification · базовый SFTP upload/download · статус соединения · scrollback ·
copy/paste.

**Отложено после MVP (§12):**
split panes · agent forwarding · rsync mode · macros · command palette · plugin
system · session sharing · advanced file sync. (Сюда же из §6.4 — port
forwarding, SOCKS/HTTP proxy, terminal profiles, session recording, cluster mode,
интеграция с внешними secret managers. Экран **Commands** из мокапа —
post-MVP-надстройка над transfer/exec.)

---

## Этап 1 — Core connection engine (§13)

**Цель:** одно single-hop SSH-подключение с живым терминалом в окне iced.

- `domain`: сущности и трейты (контракты для всех слоёв).
- `ssh`: `SshTransport`/`SessionManager` поверх russh — один hop, PTY+shell.
- `terminal`: интеграция alacritty_terminal (feed/snapshot/resize, scrollback).
- `ui` + `app`: каркас приложения, одна shell-вкладка, прокачка ввода/вывода.
- `logging`: базовая инициализация tracing.
- `app::MockTransport`: чтобы GUI запускался offline с самого начала.

**Готово, когда:** запускается desktop-окно, есть интерактивная shell-сессия к
одному хосту, работает scrollback.

---

## Этап 2 — Multi-hop routing (§13)

**Цель:** цепочка из `n` jump-хостов до target.

- `ssh`: ChainBuilder — последовательное построение через `direct-tcpip`, новый
  handshake на каждом hop; пер-hop `AuthMethod` (key/password); `RouteProgress`/
  `RouteError` с `hop_index`.
- `security`: `HostVerifier` (fingerprint sha2/base64, known_hosts, TOFU) +
  `CredentialStore` (пароли/passphrase, `Secret<T>`).
- reconnect-стратегия и keepalive (§5.1).
- `ui`: host-key confirmation dialog; диагностика ошибок по hop-уровням.

**Готово, когда:** подключение к target через несколько хопов; ошибка показывает,
на каком hop упало; host-key подтверждается.

---

## Этап 3 — Session manager UI (§13)

**Цель:** профили, сохранённые маршруты, вкладки, статус.

- `storage`: `ProfileStore` — TOML в `~/.hopterm/` (hosts/routes/sessions/
  settings, known_hosts).
- `ui`: VIEW Hosts (host-grid, фильтры-tabs), sidebar quick-access, add-host
  modal с hop-chain builder и breadcrumb маршрута, статусбар соединения.
- `app`: несколько параллельных сессий (вкладки), быстрое переподключение по
  профилю (§4.5).

**Готово, когда:** можно создать профиль target + цепочку jump-хостов, сохранить,
открыть несколько вкладок, видеть статус.

---

## Этап 4 — File transfer (§13)

**Цель:** SFTP-передача поверх той же цепочки.

- `transfer`: `TransferService` поверх russh-sftp; upload/download с потоком
  прогресса; `cancel`; `list_dir`/`stat`/`mkdir`/`rename`/`delete`.
- `app`: очередь `TransferJob`, привязка к сессии (open_sftp).
- `ui`: VIEW Transfers (progress-bars, скорость/ETA/протокол, отмена); выбор
  файлов через rfd; политика конфликтов overwrite/rename/skip.

**Готово, когда:** файл загружается и скачивается через multi-hop цепочку с
видимым прогрессом; передачу можно отменить.

---

## Этап 5 — Polish (§13)

**Цель:** довести до ежедневного инженерного инструмента (§17).

- `ui`: темы (Settings + sidebar toggle), hotkeys, поиск по подключениям,
  улучшенный error-UX, встроенный diagnostics-viewer (§5.4 желательное).
- copy/paste, выделение мышью, корректная работа `vim`/`tmux`/`htop` (§5.3).
- performance tuning: coalescing вывода терминала, отзывчивость при потоке (§6.1).
- редактирование/импорт/экспорт конфигурации (§10).

**Готово, когда:** интерфейс быстрый, информативный, предсказуемый; темы и
hotkeys работают; полноэкранные TUI рендерятся корректно.

---

## Критерии приёмки (§14) — чеклист

| # | Критерий | Этап | Статус |
|---|----------|------|:---:|
| 1 | Приложение запускается как desktop GUI | 1 | ☐ |
| 2 | Можно создать профиль целевого хоста | 3 | ☐ |
| 3 | Можно задать цепочку из нескольких jump host | 2–3 | ☐ |
| 4 | Успешное подключение к target через `n` hop-узлов | 2 | ☐ |
| 5 | Внутри GUI работает интерактивная shell-сессия | 1 | ☐ |
| 6 | Корректно работают полноэкранные TUI-приложения (vim/tmux/htop) | 1/5 | ☐ |
| 7 | Можно загрузить и скачать файл через ту же цепочку | 4 | ☐ |
| 8 | Пользователь видит прогресс transfer-операций | 4 | ☐ |
| 9 | Ошибки подключения показываются понятно и по hop-уровням | 2 | ☐ |
| 10 | Host key verification присутствует | 2 | ☐ |
| 11 | UI остаётся отзывчивым во время соединения и передачи файлов | 1–5 | ☐ |

---

## Связь этапов и крейтов

```
Этап 1  domain · ssh(1-hop) · terminal · ui/app · logging · MockTransport
Этап 2  ssh(chain) · security(HostVerifier,CredentialStore) · reconnect
Этап 3  storage(ProfileStore) · ui(Hosts, add-host modal, tabs, статусбар)
Этап 4  transfer(TransferService) · ui(Transfers) · rfd
Этап 5  ui(темы,hotkeys,поиск,diag) · performance · импорт/экспорт конфига
```

После MVP (§6.4): port/agent forwarding, proxy, terminal profiles, macros,
command palette, plugin system, session recording/sharing, rsync-sync, cluster
mode, внешние secret managers — архитектура (domain-трейты + слои) рассчитана на
их добавление без переписывания `ui`/`app`.
