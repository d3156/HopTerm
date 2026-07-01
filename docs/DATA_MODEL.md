# DATA_MODEL — Модель данных

Сущности из ТЗ §8 (плюс необходимые для multi-hop вспомогательные типы) живут в
крейте `domain` (pure, без IO). Сериализуются в TOML и хранятся в `~/.hopterm/`
крейтом `storage` (serde + toml). Секреты в открытый конфиг **не пишутся** —
см. раздел 5.

---

## 1. Перечень сущностей

| Сущность           | Назначение                                            | §ТЗ |
|--------------------|-------------------------------------------------------|-----|
| `HostProfile`      | сохранённый узел: адрес, порт, пользователь, auth     | §8.1 |
| `Hop`              | один узел в цепочке (jump или target) с auth          | §5.2 |
| `AuthMethod`       | способ аутентификации узла                            | §5.1 |
| `JumpRoute`        | именованный маршрут = цепочка hop'ов до target        | §8.2 |
| `SessionProfile`   | сохранённая сессия: target + jump_chain + предпочтения| §8.3 |
| `ActiveSession`    | рантайм-состояние открытой сессии                     | §8.4 |
| `ConnectionState`  | статус соединения                                     | §5.1 |
| `TransferJob`      | задача передачи файла                                 | §8.5 |
| `TransferDirection`| upload / download                                     | §5.5 |
| `TransferStatus`   | статус передачи                                        | §5.5 |
| `HostKey`          | host-key + отпечаток для verification                 | §5.1 |
| `TrustPolicy`      | политика доверия (TOFU / спрашивать / strict)         | §5.1 |

---

## 2. Поля сущностей

### HostProfile (§8.1)
```
id: Uuid
name: String                 // "prod-backend-01"
address: String              // host/IP, "192.168.1.100"
port: u16                    // 22
username: String             // "admin"
auth_method: AuthMethod
labels: Vec<String>          // tags: ["production"]
color: Option<String>        // опционально (icon/цвет карточки)
```

### Hop (§5.2 — узел цепочки)
```
order: u32                   // позиция в цепочке (0..n)
host: String                 // "bastion.example.com"
port: u16                    // 22
username: String             // "admin"
auth_method: AuthMethod      // СВОЙ метод на каждый hop
is_target: bool              // true для последнего (целевого) узла
```

### AuthMethod (§5.1) — enum
```
Password                                  // пароль (значение — в CredentialStore)
PublicKey { key_path: PathBuf,            // приватный ключ; passphrase в credstore
            has_passphrase: bool }
Agent                                     // SSH agent (после MVP)
```
В мокапе `index.html` (add-host modal) selektor: «SSH ключ / Пароль / SSH Agent».

### JumpRoute (§8.2)
```
id: Uuid
name: String                 // "prod-db via bastions"
hops: Vec<Hop>               // упорядоченная цепочка, последний — target
target_host: HostProfile     // целевой узел (дублирует последний hop как профиль)
route_policy: RoutePolicy    // { connect_timeout, keepalive_interval, retry }
```

### SessionProfile (§8.3)
```
id: Uuid
display_name: String
target: HostProfile
jump_chain: JumpRoute
terminal_preferences: TerminalPrefs   // шрифт, размер grid, scrollback lines
transfer_preferences: TransferPrefs   // compress-перед-download, conflict policy
```

### ActiveSession (§8.4) — рантайм, НЕ сериализуется
```
session_id: Uuid
connection_state: ConnectionState
current_route: JumpRoute
terminal_buffer_ref: TerminalHandle   // ссылка на Grid в крейте terminal
remote_pwd: Option<String>            // если доступно
started_at: SystemTime
```

### ConnectionState (§5.1) — enum
```
Idle | Connecting { hop_index: u32 } | Connected
     | Reconnecting { attempt: u32 } | Failed { hop_index: u32, reason: String }
     | Disconnected
```
`hop_index` даёт диагностику по hop-уровням (§6.2): статусбар/ошибки знают, на
каком узле застряли.

### TransferJob (§8.5) — рантайм
```
job_id: Uuid
direction: TransferDirection
local_path: PathBuf
remote_path: String
size: u64                     // байт всего
progress: u64                 // байт передано
status: TransferStatus
associated_session: Uuid      // session_id, через чью цепочку идёт SFTP
```

### TransferDirection / TransferStatus (§5.5) — enum
```
TransferDirection = Upload | Download
TransferStatus    = Queued | Active | Paused | Done
                  | Cancelled | Failed { reason: String }
```

### HostKey (§5.1) — для known_hosts/verification
```
host: String                  // "192.168.1.100:22"
algorithm: String             // "ssh-ed25519"
fingerprint_sha256: String    // "SHA256:..." (sha2 + base64)
raw_key_b64: String           // публичный ключ (base64)
first_seen: SystemTime
```

### TrustPolicy (§5.1) — enum
```
TrustOnFirstUse        // принять новый ключ и запомнить
AskAlways              // спрашивать пользователя каждый новый/изменённый ключ
Strict                 // только ключи из known_hosts, иначе отказ
```

---

## 3. ER-подобная схема (ASCII)

```
            ┌──────────────────┐
            │  SessionProfile  │  (сохраняется в config.toml)
            │  id, display_name│
            └───┬──────────┬───┘
       target   │          │  jump_chain
                ▼          ▼
       ┌──────────────┐  ┌──────────────────┐         ┌──────────────┐
       │ HostProfile  │  │   JumpRoute      │ 1     n │     Hop      │
       │ id,name,addr │  │ id,name,policy   ├────────►│ order,host,  │
       │ port,user,   │  │ target_host ─────┼────┐    │ port,user,   │
       │ auth_method  │◄─┘ hops: [Hop] ─────┘    │    │ auth_method, │
       └──────┬───────┘                          │    │ is_target    │
              │ auth_method                       └───►└──────────────┘
              ▼                                         (last hop = target)
       ┌──────────────┐
       │  AuthMethod  │  Password | PublicKey{path,passphrase?} | Agent
       └──────────────┘

   РАНТАЙМ (не сериализуется):
       ┌────────────────┐ 1     n ┌──────────────┐
       │ ActiveSession  ├────────►│ TransferJob  │  associated_session
       │ connection_    │         │ direction,   │
       │   state,route  │         │ status,prog. │
       └───────┬────────┘         └──────────────┘
               │ terminal_buffer_ref
               ▼
       ┌────────────────┐
       │ Terminal Grid  │  (крейт terminal, alacritty_terminal)
       └────────────────┘

   ДОВЕРИЕ (отдельный файл known_hosts):
       ┌──────────────┐         ┌──────────────┐
       │  HostKey     │ сверяется│ TrustPolicy  │
       │ fingerprint  │◄────────►│ TOFU/Ask/...  │
       └──────────────┘         └──────────────┘
```

Связи:
- `SessionProfile 1—1 HostProfile` (target) и `1—1 JumpRoute` (jump_chain).
- `JumpRoute 1—n Hop` (упорядоченная цепочка; `is_target=true` у последнего).
- `HostProfile / Hop 1—1 AuthMethod`.
- `ActiveSession 1—n TransferJob` (передачи идут через цепочку этой сессии).
- `HostKey` сверяется по `TrustPolicy`; хранится отдельно в `known_hosts`.

---

## 4. Файлы в `~/.hopterm/` (§10)

```
~/.hopterm/
├── config.toml      # host profiles, jump routes, session profiles, UI/terminal prefs
├── known_hosts      # HostKey-записи (отпечатки доверенных ключей)
└── keys/            # приватные ключи пользователя (если хранятся локально)
```

Путь определяется крейтом `storage` через `directories`. Соответствует тексту
Settings-view в `index.html`: «`~/.hopterm/` — Файлы: config.toml, known_hosts,
keys/».

---

## 5. Пример `config.toml` (хост + цепочка хопов)

Маршрут из мокапа add-host modal: `localhost → admin@bastion.example.com:22 →
ubuntu@10.10.0.5:2222 → admin@192.168.1.100:22 (target)`.

```toml
# ~/.hopterm/config.toml

[settings]
persist_config = true            # "Сохранять конфиг на диск"
store_hop_passwords = true       # через keychain/зашифрованный файл, НЕ здесь
compress_before_download = true  # tar -czf по умолчанию
confirm_before_exec = false

[ui]
theme = "dark"
config_dir = "~/.hopterm/"

[[hosts]]
id = "9f1c0c2e-7b4a-4e2a-9b6e-1c2d3e4f5a6b"
name = "prod-backend-01"
address = "192.168.1.100"
port = 22
username = "admin"
labels = ["production"]
color = "primary"

  [hosts.auth_method]
  kind = "public_key"
  key_path = "~/.ssh/prod_key"
  has_passphrase = true          # passphrase хранится в credential store, не тут

[[routes]]
id = "2a7d8e90-3f12-4c56-8a9b-0c1d2e3f4a5b"
name = "prod-backend-01 via bastions"
target_host = "9f1c0c2e-7b4a-4e2a-9b6e-1c2d3e4f5a6b"

  [routes.policy]
  connect_timeout_secs = 15
  keepalive_interval_secs = 30
  retry_attempts = 3

  # hop 0 — jump #1
  [[routes.hops]]
  order = 0
  host = "bastion.example.com"
  port = 22
  username = "admin"
  is_target = false
    [routes.hops.auth_method]
    kind = "password"            # значение пароля — в credential store

  # hop 1 — jump #2
  [[routes.hops]]
  order = 1
  host = "10.10.0.5"
  port = 2222
  username = "ubuntu"
  is_target = false
    [routes.hops.auth_method]
    kind = "public_key"
    key_path = "~/.ssh/jump2_key"
    has_passphrase = false

  # hop 2 — target
  [[routes.hops]]
  order = 2
  host = "192.168.1.100"
  port = 22
  username = "admin"
  is_target = true
    [routes.hops.auth_method]
    kind = "public_key"
    key_path = "~/.ssh/prod_key"
    has_passphrase = true

[[sessions]]
id = "5c6d7e8f-9a0b-4c1d-2e3f-4a5b6c7d8e9f"
display_name = "prod-backend-01"
target = "9f1c0c2e-7b4a-4e2a-9b6e-1c2d3e4f5a6b"
route = "2a7d8e90-3f12-4c56-8a9b-0c1d2e3f4a5b"

  [sessions.terminal_preferences]
  scrollback_lines = 10000
  font_size = 13

  [sessions.transfer_preferences]
  compress_before_download = true
  conflict_policy = "ask"        # overwrite | rename | skip | ask
```

`known_hosts` (отдельный файл, формат отпечатков):
```
192.168.1.100:22 ssh-ed25519 SHA256:Zm9vYmFyYmF6cXV4Li4u... first_seen=2026-06-30T12:00:00Z
bastion.example.com:22 ssh-ed25519 SHA256:cXV4YmF6Zm9vYmFy... first_seen=2026-06-29T09:13:00Z
```

### Где секреты
- **Пароли hop'ов и passphrase ключей не пишутся в `config.toml`.** В конфиге —
  только `kind`/`key_path`/`has_passphrase`. Значения хранит `security`
  (`CredentialStore`: системный keychain или зашифрованный файл) — это и есть
  тумблер «Хранить пароли хопов» в Settings (§6.3, §10).
- `ActiveSession`, `TransferJob` — рантайм-сущности, на диск не сериализуются.
