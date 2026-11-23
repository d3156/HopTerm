//! Update check against HopTerm's GitHub releases and in-place installation
//! of a newer .deb through `pkexec apt-get`.
//!
//! HTTP goes through the system `wget` (falling back to `curl`): both honour
//! the desktop's proxy environment and no TLS stack is linked in. Releases are
//! published as prereleases, which `/releases/latest` skips, so the newest
//! version is picked from the release list.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{json, Value};
use tao::event_loop::EventLoopProxy;
use tokio::process::Command;

use crate::backend::{emit, last_lines};
use crate::UserEvent;

const RELEASES_API: &str = "https://api.github.com/repos/d3156/HopTerm/releases?per_page=20";
const CURRENT: &str = env!("CARGO_PKG_VERSION");

static INSTALLING: AtomicBool = AtomicBool::new(false);

struct Release {
    version: String,
    deb_url: String,
    page: String,
}

/// Look for a newer release and offer it to the UI. `manual` = the user asked:
/// "up to date" and errors are reported too; the startup check stays silent.
pub(crate) fn spawn_check(proxy: EventLoopProxy<UserEvent>, manual: bool) {
    tokio::spawn(async move {
        match newer_release().await {
            Ok(Some(r)) => emit(&proxy, json!({"ev":"update_available",
                "version": r.version, "current": CURRENT})),
            Ok(None) if manual => emit(&proxy, json!({"ev":"toast",
                "text": format!("У вас последняя версия — v{CURRENT}")})),
            Err(e) if manual => emit(&proxy, json!({"ev":"toast","error":true,
                "text": format!("Проверка обновлений не удалась: {e}")})),
            _ => {}
        }
    });
}

/// Download the newest release's .deb and install it; the desktop's polkit
/// agent asks for the admin password. The running process keeps its old
/// binary — the new version starts with the next launch.
pub(crate) fn spawn_install(proxy: EventLoopProxy<UserEvent>) {
    if INSTALLING.swap(true, Ordering::SeqCst) {
        emit(&proxy, json!({"ev":"toast","text":"Обновление уже идёт"}));
        return;
    }
    tokio::spawn(async move {
        let res = install().await;
        INSTALLING.store(false, Ordering::SeqCst);
        let ev = match res {
            Ok(v) => json!({"ev":"toast",
                "text": format!("HopTerm обновлён до v{v} — перезапустите приложение")}),
            Err(e) => json!({"ev":"toast","error":true, "text": format!("Обновление не удалось: {e}")}),
        };
        emit(&proxy, ev);
    });
}

async fn install() -> Result<String, String> {
    let r = newer_release().await?.ok_or("новой версии на GitHub нет")?;
    let dir = std::env::temp_dir().join(format!("hopterm-update-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).map_err(|e| e.to_string())?;
    let deb = dir.join(format!("hopterm_{}_amd64.deb", r.version));
    let res = download_and_install(&r.deb_url, &deb).await;
    let _ = std::fs::remove_dir_all(&dir);
    res.map(|()| r.version).map_err(|e| format!("{e}. Релиз: {}", r.page))
}

async fn download_and_install(url: &str, deb: &Path) -> Result<(), String> {
    fetch(url, Some(deb)).await?;
    let out = Command::new("pkexec")
        .args(["/usr/bin/apt-get", "install", "-y"])
        .arg(deb)
        .output()
        .await
        .map_err(|e| format!("pkexec: {e}"))?;
    match out.status.code() {
        Some(0) => Ok(()),
        Some(126) => Err("установка отменена".into()),
        code => Err(format!("{} (код {})", last_lines(&String::from_utf8_lossy(&out.stderr), 2),
                            code.unwrap_or(-1))),
    }
}

async fn newer_release() -> Result<Option<Release>, String> {
    let body = fetch(RELEASES_API, None).await?;
    let list: Value =
        serde_json::from_slice(&body).map_err(|e| format!("ответ GitHub не разобран: {e}"))?;
    let current = version_key(CURRENT);
    Ok(list
        .as_array()
        .ok_or("GitHub вернул не список релизов")?
        .iter()
        .filter_map(release_of)
        .filter(|r| version_key(&r.version) > current)
        .max_by_key(|r| version_key(&r.version)))
}

/// A published release with a .deb; tags other than plain `vX.Y.Z` are skipped.
fn release_of(v: &Value) -> Option<Release> {
    let version = v["tag_name"].as_str()?.strip_prefix('v')?.to_string();
    version_key(&version)?;
    let deb_url = v["assets"]
        .as_array()?
        .iter()
        .filter_map(|a| a["browser_download_url"].as_str())
        .find(|u| u.ends_with("_amd64.deb"))?
        .to_string();
    let page = v["html_url"].as_str().unwrap_or_default().to_string();
    Some(Release { version, deb_url, page })
}

/// "0.1.10" -> [0, 1, 10], so versions compare numerically, not as strings.
fn version_key(v: &str) -> Option<Vec<u64>> {
    v.split('.').map(|p| p.parse().ok()).collect()
}

/// GET `url` into `dest`, or return the body when `dest` is None.
async fn fetch(url: &str, dest: Option<&Path>) -> Result<Vec<u8>, String> {
    let out = dest.map_or("-".into(), |p| p.to_string_lossy().into_owned());
    let tools = [
        ("wget", vec!["-nv", "--tries=1", "--timeout=20", "-O", out.as_str(), url]),
        ("curl", vec!["-fsSL", "--connect-timeout", "20", "--speed-time", "20", "--speed-limit", "1",
                     "-o", out.as_str(), url]),
    ];
    for (bin, args) in tools {
        match Command::new(bin).args(&args).output().await {
            Ok(o) if o.status.success() => return Ok(o.stdout),
            Ok(o) => {
                let why = last_lines(&String::from_utf8_lossy(&o.stderr), 1);
                return Err(format!("{bin}: {why} (код {})", o.status.code().unwrap_or(-1)));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("{bin}: {e}")),
        }
    }
    Err("нет ни wget, ни curl".into())
}
