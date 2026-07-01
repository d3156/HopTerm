# TRAITS — Контракты между слоями

Все межслойные интерфейсы объявлены в крейте `domain` (pure, без IO). Это
единственный «шов» между GUI/оркестрацией и транспортом (ТЗ §7.2). `ui`/`app`
работают с трейт-объектами (`dyn _`); конкретные реализации живут в транспортных
крейтах и подставляются в `app` при wiring. Async-методы используют
`#[async_trait]` (крейт `async-trait`), потоковые результаты — `futures::Stream`.

Сигнатуры ниже — проектный контракт (иллюстративный Rust); точные типы ошибок —
доменные (`thiserror`).

---

## 0. Общие типы (domain)

```rust
pub type SessionId = uuid::Uuid;
pub type JobId     = uuid::Uuid;

/// Ошибка построения маршрута с указанием проблемного hop (диагностика §6.2).
#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error("hop {hop_index}: tcp/connect: {source}")]
    Connect { hop_index: u32, source: TransportError },
    #[error("hop {hop_index}: host-key отклонён")]
    HostKeyRejected { hop_index: u32 },
    #[error("hop {hop_index}: аутентификация не удалась ({method})")]
    Auth { hop_index: u32, method: String },
    #[error("hop {hop_index}: канал/pty: {source}")]
    Channel { hop_index: u32, source: TransportError },
}

/// Прогресс/трассировка построения цепочки (поток в app/logging).
pub struct RouteProgress { pub hop_index: u32, pub phase: RoutePhase }
pub enum RoutePhase { Connecting, Verifying, Authenticating, Opening, Ready }
```

---

## 1. `SshTransport` — низкоуровневый SSH (реализует `ssh`)

Абстракция одного «прыжка» и потока данных. **Реализует:** `ssh`
(`RusshTransport` поверх russh) и `app::MockTransport`. **Вызывает:**
`SessionManager` (внутри `ssh`) при построении цепочки.

```rust
#[async_trait]
pub trait SshTransport: Send + Sync {
    /// TCP-подключение + SSH handshake к узлу. Возвращает «соединение».
    async fn connect(&self, hop: &Hop, verifier: &dyn HostVerifier)
        -> Result<Box<dyn SshConnection>, RouteError>;
}

#[async_trait]
pub trait SshConnection: Send + Sync {
    /// Аутентификация на этом узле выбранным методом (creds из CredentialStore).
    async fn authenticate(&mut self, auth: &AuthMethod, creds: &dyn CredentialStore)
        -> Result<(), RouteError>;

    /// Открыть direct-tcpip канал к следующему hop — поверх него идёт
    /// НОВЫЙ handshake (механизм multi-hop, §5.2). Возвращает байтовый поток.
    async fn open_forward(&self, to_host: &str, to_port: u16)
        -> Result<Box<dyn DuplexStream>, RouteError>;

    /// Запросить PTY + shell на ЭТОМ узле (только для target). Даёт интерактивный
    /// дуплекс: ввод пользователя ⇆ вывод сервера.
    async fn open_shell(&self, size: PtySize)
        -> Result<Box<dyn DuplexStream>, RouteError>;

    /// Keepalive-пинг (§5.1).
    async fn keepalive(&self) -> Result<(), TransportError>;
}

/// Дуплексный байтовый канал (PTY-поток или forward).
pub trait DuplexStream: AsyncRead + AsyncWrite + Send + Unpin {}
```

---

## 2. `SessionManager` — lifecycle + chain builder (реализует `ssh`)

Строит цепочку из `SshTransport`/`SshConnection`, держит сессии, делает
reconnect. **Реализует:** `ssh` (`ChainBuilder`) и `app::MockTransport`.
**Вызывает:** `app` (по командам пользователя из `ui`).

```rust
#[async_trait]
pub trait SessionManager: Send + Sync {
    /// Построить всю цепочку local→jump…→target и открыть shell.
    /// Эмитит RouteProgress по каждому hop; ошибка несёт hop_index.
    async fn open(&self, route: &JumpRoute)
        -> Result<SessionHandle, RouteError>;

    /// Открыть SFTP-канал поверх УЖЕ построенной цепочки этой сессии
    /// (переиспользование маршрута для transfer, §5.2/§5.5).
    async fn open_sftp(&self, session: SessionId)
        -> Result<Box<dyn SftpChannel>, RouteError>;

    /// Поток обновлений состояния соединения (для статусбара/ошибок).
    fn states(&self, session: SessionId) -> BoxStream<'static, ConnectionState>;

    /// Стратегия повторного подключения при сетевом сбое (§5.1, §6.2).
    async fn reconnect(&self, session: SessionId) -> Result<(), RouteError>;

    async fn close(&self, session: SessionId) -> Result<(), TransportError>;
}

/// Хэндл активной сессии: id + дуплекс PTY + поток RouteProgress.
pub struct SessionHandle {
    pub id: SessionId,
    pub shell: Box<dyn DuplexStream>,
    pub progress: BoxStream<'static, RouteProgress>,
}
```

---

## 3. `TerminalBackend` — терминальная эмуляция (реализует `terminal`)

Обёртка alacritty_terminal. **Реализует:** `terminal`. **Вызывает:** `app`
(прокачивает байты сессии в parser, отдаёт снимок экрана в `ui`).

```rust
pub trait TerminalBackend: Send {
    /// Скормить байты вывода сервера в VT/ANSI parser (обновляет grid).
    fn feed(&mut self, bytes: &[u8]);

    /// Снимок экрана для отрисовки в iced (видимые строки + курсор + атрибуты).
    fn snapshot(&self) -> ScreenSnapshot;

    /// Изменить размер при ресайзе окна (§5.3) — влияет и на PTY (request).
    fn resize(&mut self, cols: u16, rows: u16);

    /// Прокрутка по scrollback-буферу (§5.3).
    fn scroll(&mut self, delta: i32);

    /// Ввод пользователя (клавиатура/вставка) → байты на отправку в shell.
    fn input(&mut self, event: KeyOrPaste) -> Vec<u8>;
}

pub struct ScreenSnapshot {
    pub cols: u16, pub rows: u16,
    pub cells: Vec<Cell>,          // символ + fg/bg + атрибуты
    pub cursor: CursorState,
    pub scrollback_offset: usize,
}
```

---

## 4. `TransferService` — SFTP-операции (реализует `transfer`)

**Реализует:** `transfer` (russh-sftp) и `app::MockTransport`. **Вызывает:**
`app` (команды upload/download/файловые операции из `ui`). Работает поверх
`SftpChannel`, полученного у `SessionManager::open_sftp`.

```rust
#[async_trait]
pub trait TransferService: Send + Sync {
    /// Загрузка на удалённый хост; прогресс — потоком (не блокирует UI, §6.1).
    async fn upload(&self, job: TransferJob)
        -> Result<BoxStream<'static, TransferProgress>, TransferError>;

    /// Скачивание с удалённого хоста.
    async fn download(&self, job: TransferJob)
        -> Result<BoxStream<'static, TransferProgress>, TransferError>;

    /// Отмена выполняющейся задачи (§5.5).
    async fn cancel(&self, job: JobId) -> Result<(), TransferError>;

    // Навигация и базовые операции (§5.5)
    async fn list_dir(&self, session: SessionId, path: &str)
        -> Result<Vec<RemoteEntry>, TransferError>;
    async fn stat(&self, session: SessionId, path: &str)
        -> Result<RemoteEntry, TransferError>;
    async fn mkdir(&self, session: SessionId, path: &str)  -> Result<(), TransferError>;
    async fn rename(&self, session: SessionId, from: &str, to: &str)
        -> Result<(), TransferError>;
    async fn delete(&self, session: SessionId, path: &str) -> Result<(), TransferError>;
}

pub struct TransferProgress {
    pub job_id: JobId,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub bytes_per_sec: u64,
    pub status: TransferStatus,
}
pub struct RemoteEntry { pub name: String, pub size: u64, pub is_dir: bool, pub mtime: u64 }
```

---

## 5. `ProfileStore` — хранилище конфигурации (реализует `storage`)

**Реализует:** `storage` (TOML в `~/.hopterm/`). **Вызывает:** `app` (загрузка
при старте, сохранение из add-host modal / Settings).

```rust
#[async_trait]
pub trait ProfileStore: Send + Sync {
    async fn load_hosts(&self)    -> Result<Vec<HostProfile>, StoreError>;
    async fn load_routes(&self)   -> Result<Vec<JumpRoute>, StoreError>;
    async fn load_sessions(&self) -> Result<Vec<SessionProfile>, StoreError>;
    async fn load_settings(&self) -> Result<AppSettings, StoreError>;

    async fn save_host(&self, host: &HostProfile)       -> Result<(), StoreError>;
    async fn save_route(&self, route: &JumpRoute)       -> Result<(), StoreError>;
    async fn save_session(&self, s: &SessionProfile)    -> Result<(), StoreError>;
    async fn save_settings(&self, s: &AppSettings)      -> Result<(), StoreError>;
    async fn delete_host(&self, id: SessionId)          -> Result<(), StoreError>;

    /// Импорт/экспорт всего конфига (§10).
    async fn export(&self, path: &std::path::Path) -> Result<(), StoreError>;
    async fn import(&self, path: &std::path::Path) -> Result<(), StoreError>;
}
```

---

## 6. `HostVerifier` — проверка host-key (реализует `security`)

**Реализует:** `security` (sha2 + base64, known_hosts). **Вызывает:**
`SshTransport::connect` во время handshake каждого hop (§5.1).

```rust
#[async_trait]
pub trait HostVerifier: Send + Sync {
    /// Решение по предъявленному ключу. Если ключ неизвестен/изменился —
    /// возвращает Prompt, который app покажет пользователю (диалог TOFU).
    async fn verify(&self, host: &str, port: u16, key: &HostKey)
        -> Result<Verdict, VerifyError>;

    /// Запомнить ключ как доверенный (после подтверждения / TOFU).
    async fn trust(&self, host: &str, port: u16, key: &HostKey)
        -> Result<(), VerifyError>;

    /// Отпечаток для показа в UI: "SHA256:...".
    fn fingerprint(&self, key: &HostKey) -> String;
}

pub enum Verdict {
    Trusted,                       // совпал с known_hosts
    Prompt(TrustPrompt),           // неизвестный ключ → спросить (§5.4)
    Mismatch(TrustPrompt),         // ключ изменился → строгое предупреждение
}
pub struct TrustPrompt { pub host: String, pub port: u16,
                         pub algorithm: String, pub fingerprint: String,
                         pub hop_index: u32 }
```

---

## 7. `CredentialStore` — учётные данные (реализует `security`)

**Реализует:** `security` (keychain/зашифрованный файл). **Вызывает:**
`SshConnection::authenticate`. Секреты не логируются и не пишутся в `config.toml`
(§6.3).

```rust
#[async_trait]
pub trait CredentialStore: Send + Sync {
    /// Достать пароль для узла (или запросить у пользователя при отсутствии).
    async fn password(&self, host: &str, user: &str)
        -> Result<Secret<String>, CredError>;

    /// Загрузить и (при необходимости) расшифровать приватный ключ.
    /// Passphrase берётся из стора/у пользователя (§5.1).
    async fn private_key(&self, key_path: &std::path::Path)
        -> Result<PrivateKey, CredError>;     // PrivateKey из russh::keys

    /// Сохранить секрет (тумблер "Хранить пароли хопов", §10).
    async fn store_password(&self, host: &str, user: &str, secret: Secret<String>)
        -> Result<(), CredError>;
}

/// Обёртка-секрет: НЕ реализует Debug/Display → не утечёт в логи (§6.3).
pub struct Secret<T>(/* private */ T);
```

---

## 8. `logging` — не trait, а функции инициализации

`logging` не объявляет domain-trait; экспортирует `init(level, debug)` (tracing
+ subscriber) и хелперы redaction. Все крейты пишут `tracing`-события; span'ы
покрывают этапы multi-hop и transfer-jobs (§11). Секреты проходят через
`Secret<T>` и поля помечаются как чувствительные, чтобы не попасть в вывод (§6.3).

---

## 9. Кто что реализует / вызывает (сводка)

| Trait              | Объявлен | Реализуют                         | Вызывают |
|--------------------|----------|-----------------------------------|----------|
| `SshTransport`     | domain   | `ssh`, `app::MockTransport`       | `ssh` (SessionManager) |
| `SessionManager`   | domain   | `ssh`, `app::MockTransport`       | `app` |
| `TerminalBackend`  | domain   | `terminal`                        | `app` → `ui` |
| `TransferService`  | domain   | `transfer`, `app::MockTransport`  | `app` |
| `ProfileStore`     | domain   | `storage`                         | `app` |
| `HostVerifier`     | domain   | `security`                        | `ssh` (при connect) |
| `CredentialStore`  | domain   | `security`                        | `ssh` (при auth), `app` |

`app` собирает всё за `dyn`-объектами и предоставляет `ui` только команды/события
— `ui` ни одного из этих трейтов транспорта не видит напрямую (§7.2).
