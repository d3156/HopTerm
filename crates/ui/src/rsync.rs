//! Resumable transfers (downloads and uploads) over a local `rsync` process.
//!
//! rsync rides an external `ssh` that reproduces the profile's hop chain the
//! same way the external-terminal feature does (`-J`, port, key, stored
//! passwords via the askpass helper). `--partial --inplace` keeps interrupted
//! data on disk and the delta algorithm resumes from it without re-sending
//! what the receiver already has; after a transient failure (dropped
//! connection, timeout) the job re-runs rsync with exponential backoff until
//! it finishes, hits a permanent error, or is cancelled. Wildcards in remote
//! paths are expanded by the remote rsync — no client-side glob pass is
//! needed. Uploads are recursive: a directory is sent as a tree.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hopterm_domain::{CancelToken, SessionProfile};
use serde_json::json;
use tao::event_loop::EventLoopProxy;
use tokio::io::AsyncReadExt;

use crate::backend::{build_ssh_argv, emit, password_creds, write_askpass_helper};
use crate::UserEvent;

/// rsync-level I/O timeout: a silently dead connection becomes a retriable
/// error instead of hanging the job forever.
const IO_TIMEOUT_SECS: u32 = 30;
/// Retry pause: doubles up to the cap, resets once an attempt moves new data.
const RETRY_START_SECS: u64 = 2;
const RETRY_CAP_SECS: u64 = 30;
/// Give up after this many consecutive attempts that moved no new data: a
/// permanent failure mislabelled as transient must not spin forever. The
/// partial file stays, so a later download resumes where this one stopped.
const MAX_FRUITLESS_ATTEMPTS: u32 = 8;

/// How one rsync attempt ended.
enum Outcome {
    Success,
    /// Transient (dropped connection, timeout) — retry after a pause.
    Retry,
    /// Permanent — retrying cannot help (missing file, local I/O).
    Fatal(String),
    /// The rsync road is closed (no rsync binary, external ssh can't
    /// authenticate...) but the live SFTP session can still do the job —
    /// the caller's fallback takes over. The reason feeds the user toast.
    Fallback(String),
}

/// Classify an rsync exit. Auth and host-key failures are deliberately
/// *fallback*, not fatal: the in-app session authenticated fine, so SFTP will
/// work where the external ssh (no runtime-entered secrets, own known_hosts)
/// cannot — and a single attempt never hammers a wrong stored password.
fn classify(code: Option<i32>, stderr: &str) -> Outcome {
    if code == Some(0) {
        return Outcome::Success;
    }
    let s = stderr.to_lowercase();
    if s.contains("permission denied") {
        return Outcome::Fallback("внешний ssh не аутентифицировался".into());
    }
    if s.contains("host key verification failed") || s.contains("identification has changed") {
        return Outcome::Fallback("внешний ssh: ключ хоста не прошёл проверку".into());
    }
    if s.contains("bad configuration option") {
        return Outcome::Fallback("локальный ssh не понимает опции".into());
    }
    if s.contains("no such file or directory") {
        return Outcome::Fatal("нет такого файла".into());
    }
    match code {
        // The remote shell answers a missing rsync with 127 — locale-proof,
        // unlike matching "command not found" text.
        Some(127) => Outcome::Fallback("на хосте нет rsync".into()),
        // 10/12 socket & protocol stream errors, 20 killed by a signal (also
        // how a dying transport can surface), 23/24 partial transfer,
        // 30/35 timeouts, 255 ssh transport death.
        Some(10 | 12 | 20 | 23 | 24 | 30 | 35 | 255) | None => Outcome::Retry,
        Some(c) => Outcome::Fatal(format!("rsync (код {c}): {}", last_line(stderr))),
    }
}

fn last_line(s: &str) -> String {
    s.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("").trim().to_string()
}

/// Parse an `--info=progress2` status line — `  1,234,567  42%  1.2MB/s  0:01:23`
/// — into (bytes, percent). Thousands separators are stripped rather than
/// trusted: the child runs under LC_ALL=C, but surviving a stray locale is free.
fn parse_progress(line: &str) -> Option<(u64, u64)> {
    let mut it = line.split_whitespace();
    let bytes = it.next()?.replace([',', '.'], "").parse().ok()?;
    let pct = it.next()?.strip_suffix('%')?.parse().ok()?;
    Some((bytes, pct))
}

/// rsync's `-e` command (ssh + the profile's chain + keepalives) and the
/// `user@host` prefix for the remote path. Keepalives turn a dead link into a
/// fast failure (-> retry); accept-new mirrors HopTerm's own TOFU; LC_ALL=C on
/// the remote keeps its error text matchable by [`classify`]. With no askpass
/// helper BatchMode stops ssh from popping a system password dialog — key and
/// agent auth still work, everything else fails fast into the SFTP fallback.
/// NB: rsync splits `-e` on whitespace, so only space-free options belong here.
/// The third value: transient key files backing the argv, removed by the job.
fn ssh_command(profile: &SessionProfile, batch: bool) -> (String, String, Vec<std::path::PathBuf>) {
    let (mut argv, temp_keys) = build_ssh_argv(profile);
    let user_host = argv.pop().unwrap_or_default();
    for opt in [
        "ServerAliveInterval=10",
        "ServerAliveCountMax=3",
        "StrictHostKeyChecking=accept-new",
        "SetEnv=LC_ALL=C",
    ] {
        argv.push("-o".into());
        argv.push(opt.into());
    }
    if batch {
        argv.push("-o".into());
        argv.push("BatchMode=yes".into());
    }
    (argv.join(" "), user_host, temp_keys)
}

/// Outcome of the whole retry loop.
enum JobEnd {
    Done(u64),
    Error(String),
    /// The rsync road is closed — run the SFTP path instead (reason -> toast).
    Fallback(String),
}

struct Job {
    proxy: EventLoopProxy<UserEvent>,
    id: String,
    name: String,
    /// `"down"` or `"up"` — event tag and rsync argument orientation.
    dir: &'static str,
    ssh_e: String,
    src: String,
    dest: String,
    askpass: Option<std::path::PathBuf>,
    /// Transient key files backing `ssh_e` — removed when the job ends.
    temp_keys: Vec<std::path::PathBuf>,
    cancel: CancelToken,
}

fn basename(path: &str) -> String {
    path.trim_end_matches('/').rsplit('/').next().unwrap_or("file").to_string()
}

/// Start a resumable download job: `remote` (a path, or a wildcard the remote
/// rsync expands) lands at `local` (full file path, or an existing directory
/// for wildcards). `fallback` runs instead of a result when rsync is
/// unavailable, and the job's transfer card is withdrawn.
pub(crate) fn spawn_download(
    proxy: EventLoopProxy<UserEvent>,
    transfers: Arc<Mutex<HashMap<String, CancelToken>>>,
    profile: SessionProfile,
    remote: String,
    local: String,
    fallback: Box<dyn FnOnce(String) + Send>,
) {
    let creds = password_creds(&profile);
    let (ssh_e, user_host, temp_keys) = ssh_command(&profile, creds.is_empty());
    let job = Job {
        proxy,
        id: uuid::Uuid::new_v4().to_string(),
        name: basename(&remote),
        dir: "down",
        ssh_e,
        src: format!("{user_host}:{remote}"),
        dest: local,
        // The helper must outlive every retry (a reconnect an hour in still
        // authenticates with it) — removed when the job ends, not on a timer.
        askpass: if creds.is_empty() { None } else { write_askpass_helper(&creds).ok() },
        temp_keys,
        cancel: CancelToken::new(),
    };
    launch(job, transfers, fallback);
}

/// Start a resumable upload job: the local `local` (file or directory) lands
/// at `remote` (full destination path — for a directory its tree is mirrored
/// there). `fallback` runs instead of a result when rsync is unavailable.
pub(crate) fn spawn_upload(
    proxy: EventLoopProxy<UserEvent>,
    transfers: Arc<Mutex<HashMap<String, CancelToken>>>,
    profile: SessionProfile,
    local: String,
    remote: String,
    fallback: Box<dyn FnOnce(String) + Send>,
) {
    let creds = password_creds(&profile);
    let (ssh_e, user_host, temp_keys) = ssh_command(&profile, creds.is_empty());
    // A directory source needs a trailing slash: a remote destination path is
    // treated as the parent to copy *into*, so a bare name would nest as
    // dest/name/name.
    let is_dir = std::fs::metadata(&local).map(|m| m.is_dir()).unwrap_or(false);
    let src = if is_dir { format!("{}/", local.trim_end_matches('/')) } else { local.clone() };
    let job = Job {
        proxy,
        id: uuid::Uuid::new_v4().to_string(),
        name: basename(&local),
        dir: "up",
        ssh_e,
        src,
        dest: format!("{user_host}:{remote}"),
        askpass: if creds.is_empty() { None } else { write_askpass_helper(&creds).ok() },
        temp_keys,
        cancel: CancelToken::new(),
    };
    launch(job, transfers, fallback);
}

/// Register the job's cancel token, run the retry loop, report the end.
fn launch(
    job: Job,
    transfers: Arc<Mutex<HashMap<String, CancelToken>>>,
    fallback: Box<dyn FnOnce(String) + Send>,
) {
    transfers.lock().unwrap().insert(job.id.clone(), job.cancel.clone());
    tokio::spawn(async move {
        emit(&job.proxy, job.progress_event(0, 0, None));
        let end = job.run().await;
        if let Some(p) = &job.askpass {
            let _ = std::fs::remove_file(p);
        }
        for p in &job.temp_keys {
            let _ = std::fs::remove_file(p);
        }
        transfers.lock().unwrap().remove(&job.id);
        let local = if job.dir == "down" { &job.dest } else { &job.src };
        match end {
            JobEnd::Done(bytes) => emit(
                &job.proxy,
                json!({"ev":"xfer","id":job.id,"name":job.name,"dir":job.dir,"proto":"rsync",
                       "t":bytes,"total":bytes,"status":"done","local":local}),
            ),
            JobEnd::Error(e) => emit(
                &job.proxy,
                json!({"ev":"xfer","id":job.id,"name":job.name,"dir":job.dir,"proto":"rsync",
                       "status":"error","error":e}),
            ),
            JobEnd::Fallback(reason) => {
                emit(&job.proxy, json!({"ev":"xfer","id":job.id,"status":"gone"}));
                fallback(reason);
            }
        }
    });
}

impl Job {
    fn progress_event(&self, t: u64, total: u64, note: Option<String>) -> serde_json::Value {
        json!({"ev":"xfer","id":self.id,"name":self.name,"dir":self.dir,"proto":"rsync",
               "t":t,"total":total,"status":"running","note":note})
    }

    /// The retry loop: rsync attempts until success, a permanent error,
    /// cancellation, the fruitless-attempt cap, or the SFTP fallback.
    async fn run(&self) -> JobEnd {
        let mut best = 0u64; // high-water byte mark across attempts
        let mut total = 0u64;
        let mut delay = RETRY_START_SECS;
        let mut attempt = 0u32;
        let mut fruitless = 0u32;
        loop {
            if self.cancel.is_cancelled() {
                return JobEnd::Error("отменено".into());
            }
            attempt += 1;
            let before = best;
            let (code, stderr, skipped) = match self.attempt(&mut best, &mut total).await {
                Ok(r) => r,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return JobEnd::Fallback("rsync не установлен локально".into())
                }
                Err(e) => return JobEnd::Error(format!("запуск rsync: {e}")),
            };
            if self.cancel.is_cancelled() {
                return JobEnd::Error("отменено".into());
            }
            match classify(code, &stderr) {
                // "skipping directory/non-regular file" + zero bytes is rsync
                // politely doing nothing — a green card would be a lie.
                Outcome::Success if skipped && best == 0 => {
                    return JobEnd::Error("ничего не передано: каталоги/спецфайлы пропущены".into())
                }
                Outcome::Success => return JobEnd::Done(best),
                Outcome::Fallback(reason) => return JobEnd::Fallback(reason),
                Outcome::Fatal(e) => return JobEnd::Error(e),
                Outcome::Retry => {
                    if best > before {
                        delay = RETRY_START_SECS; // data moved — back off gently again
                        fruitless = 0;
                    } else {
                        fruitless += 1;
                        if fruitless >= MAX_FRUITLESS_ATTEMPTS {
                            return JobEnd::Error(format!(
                                "связь не восстановилась ({fruitless} попыток без прогресса): {}",
                                last_line(&stderr)
                            ));
                        }
                    }
                    let note = format!("обрыв связи — повтор №{} через {delay} с", attempt + 1);
                    emit(&self.proxy, self.progress_event(best, total, Some(note)));
                    self.sleep_cancellable(delay).await;
                    delay = (delay * 2).min(RETRY_CAP_SECS);
                }
            }
        }
    }

    /// One rsync run: spawn, stream progress2 into throttled UI events,
    /// capture stderr, honour cancellation by killing the child. The returned
    /// bool = rsync skipped entries ("skipping directory/non-regular file").
    /// Err = the local rsync could not be spawned.
    async fn attempt(
        &self,
        best: &mut u64,
        total: &mut u64,
    ) -> std::io::Result<(Option<i32>, String, bool)> {
        let mut cmd = tokio::process::Command::new("rsync");
        // -L follows symlinks into their target files, like the SFTP path did.
        cmd.arg("--partial").arg("--inplace").arg("-L");
        if self.dir == "up" {
            cmd.arg("-r"); // a directory is sent as a tree
        }
        cmd.arg(format!("--timeout={IO_TIMEOUT_SECS}"))
            .arg("--info=progress2")
            .arg("-e")
            .arg(&self.ssh_e)
            .arg(&self.src)
            .arg(&self.dest)
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        if let Some(p) = &self.askpass {
            cmd.env("SSH_ASKPASS", p).env("SSH_ASKPASS_REQUIRE", "force");
        }
        let mut child = cmd.spawn()?;
        let mut out = child.stdout.take().expect("stdout piped");
        let mut err = child.stderr.take().expect("stderr piped");

        // stderr: keep a bounded tail — enough for classification.
        let err_tail = tokio::spawn(async move {
            let mut tail = Vec::new();
            let mut chunk = [0u8; 1024];
            while let Ok(n) = err.read(&mut chunk).await {
                if n == 0 {
                    break;
                }
                tail.extend_from_slice(&chunk[..n]);
                if tail.len() > 8192 {
                    tail.drain(..tail.len() - 4096);
                }
            }
            String::from_utf8_lossy(&tail).into_owned()
        });

        // stdout: `\r`-separated progress2 lines. `t` goes to the UI as the
        // high-water mark: a resumed attempt re-counts from zero while rsync
        // skips already-local data, and a bar sliding backwards would misread
        // as lost progress.
        let mut line = Vec::new();
        let mut chunk = [0u8; 4096];
        let mut last_emit: Option<Instant> = None;
        let mut skipped = false;
        let mut tick = tokio::time::interval(Duration::from_millis(200));
        loop {
            tokio::select! {
                r = out.read(&mut chunk) => {
                    let n = match r { Ok(0) | Err(_) => break, Ok(n) => n };
                    for &b in &chunk[..n] {
                        if b != b'\r' && b != b'\n' {
                            line.push(b);
                            continue;
                        }
                        let text = String::from_utf8_lossy(&line);
                        if let Some((bytes, pct)) = parse_progress(&text) {
                            *best = (*best).max(bytes);
                            // progress2 gives no exact size — derive it, and
                            // refine as the percentage grows.
                            if let Some(est) = (bytes * 100).checked_div(pct) {
                                *total = est.max(*best);
                            }
                            if last_emit.map_or(true, |t| t.elapsed() >= Duration::from_millis(300)) {
                                last_emit = Some(Instant::now());
                                emit(&self.proxy, self.progress_event(*best, *total, None));
                            }
                        } else if text.starts_with("skipping ") {
                            skipped = true;
                        }
                        line.clear();
                    }
                }
                _ = tick.tick() => {
                    if self.cancel.is_cancelled() {
                        let _ = child.start_kill();
                        break;
                    }
                }
            }
        }
        let status = child.wait().await?;
        Ok((status.code(), err_tail.await.unwrap_or_default(), skipped))
    }

    /// The retry pause, cut short by cancellation.
    async fn sleep_cancellable(&self, secs: u64) {
        for _ in 0..secs * 5 {
            if self.cancel.is_cancelled() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_progress2_lines() {
        assert_eq!(parse_progress("  1,234,567  42% 11.23MB/s 0:01:23"), Some((1234567, 42)));
        assert_eq!(parse_progress("          0   0% 0.00kB/s    0:00:00"), Some((0, 0)));
        assert_eq!(
            parse_progress(" 12.345.678 100% 1.2MB/s 0:00:00 (xfr#1, to-chk=0/1)"),
            Some((12345678, 100))
        );
        assert_eq!(parse_progress("sending incremental file list"), None);
        assert_eq!(parse_progress(""), None);
    }

    #[test]
    fn classifies_exits() {
        assert!(matches!(classify(Some(0), ""), Outcome::Success));
        // success is success even with warnings on stderr
        assert!(matches!(classify(Some(0), "Warning: Permanently added 'h'"), Outcome::Success));
        // auth / host-key / old ssh / no remote rsync -> SFTP fallback
        assert!(matches!(
            classify(Some(255), "user@h: Permission denied (publickey,password)."),
            Outcome::Fallback(_)
        ));
        assert!(matches!(
            classify(Some(255), "Host key verification failed."),
            Outcome::Fallback(_)
        ));
        assert!(matches!(
            classify(Some(255), "command-line: line 0: Bad configuration option: setenv"),
            Outcome::Fallback(_)
        ));
        // missing remote rsync is recognised by exit 127, locale-independent
        assert!(matches!(
            classify(Some(127), "bash: rsync: command not found"),
            Outcome::Fallback(_)
        ));
        assert!(matches!(classify(Some(127), "sh: 1: rsync: не найдено"), Outcome::Fallback(_)));
        assert!(matches!(
            classify(Some(23), "rsync: link_stat \"/x\" failed: No such file or directory (2)"),
            Outcome::Fatal(_)
        ));
        // dotfile noise like "foo: command not found" must NOT divert a
        // dropped connection into the from-scratch SFTP fallback
        assert!(matches!(
            classify(Some(12), "foo: command not found\nrsync error: connection unexpectedly closed"),
            Outcome::Retry
        ));
        for c in [10, 12, 20, 23, 24, 30, 35, 255] {
            assert!(matches!(classify(Some(c), "rsync error: connection unexpectedly closed"), Outcome::Retry));
        }
        assert!(matches!(classify(None, ""), Outcome::Retry)); // killed by a signal
        assert!(matches!(classify(Some(1), "rsync: --bogus: unknown option"), Outcome::Fatal(_)));
    }
}
