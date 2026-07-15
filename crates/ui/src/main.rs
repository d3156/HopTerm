//! HopTerm desktop GUI.
//!
//! A native window hosting a system webview (via `wry`) that renders the
//! HTML/CSS design directly, with an `xterm.js` terminal. All SSH work happens in
//! the Rust backend ([`backend`]) over the validated `hopterm-app` layer; the
//! webview talks to it through a tiny JSON IPC protocol.

mod backend;

use std::borrow::Cow;

use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tao::window::WindowBuilder;
use wry::http::{header::CONTENT_TYPE, Request, Response};
use wry::WebViewBuilder;

/// Custom user event used to marshal "run this JS" onto the UI thread.
#[derive(Debug)]
pub enum UserEvent {
    Js(String),
}

// Web assets are embedded into the binary.
const INDEX: &str = include_str!("../web/index.html");
const XTERM_JS: &[u8] = include_bytes!("../web/vendor/xterm.js");
const XTERM_CSS: &[u8] = include_bytes!("../web/vendor/xterm.css");
const ADDON_FIT: &[u8] = include_bytes!("../web/vendor/addon-fit.js");
const F_INTER: &[u8] = include_bytes!("../web/vendor/Inter-Regular.ttf");
const F_INTER_SB: &[u8] = include_bytes!("../web/vendor/Inter-SemiBold.ttf");
const F_MONO: &[u8] = include_bytes!("../web/vendor/JetBrainsMono-Regular.ttf");

fn serve(_id: wry::WebViewId, request: Request<Vec<u8>>) -> Response<Cow<'static, [u8]>> {
    // Index is templated so the in-app version label always tracks Cargo.
    if matches!(request.uri().path(), "/" | "/index.html") {
        let html = INDEX.replace("{{APP_VERSION}}", env!("CARGO_PKG_VERSION"));
        return Response::builder()
            .header(CONTENT_TYPE, "text/html")
            .header("Access-Control-Allow-Origin", "*")
            .body(Cow::Owned(html.into_bytes()))
            .unwrap();
    }
    let (body, mime): (&'static [u8], &str) = match request.uri().path() {
        "/" | "/index.html" => (INDEX.as_bytes(), "text/html"),
        "/vendor/xterm.js" => (XTERM_JS, "application/javascript"),
        "/vendor/addon-fit.js" => (ADDON_FIT, "application/javascript"),
        "/vendor/xterm.css" => (XTERM_CSS, "text/css"),
        "/vendor/Inter-Regular.ttf" => (F_INTER, "font/ttf"),
        "/vendor/Inter-SemiBold.ttf" => (F_INTER_SB, "font/ttf"),
        "/vendor/JetBrainsMono-Regular.ttf" => (F_MONO, "font/ttf"),
        _ => (b"not found", "text/plain"),
    };
    Response::builder()
        .header(CONTENT_TYPE, mime)
        .header("Access-Control-Allow-Origin", "*")
        .body(Cow::Borrowed(body))
        .unwrap()
}

fn main() -> wry::Result<()> {
    hopterm_logging::init(std::env::var("HOPTERM_DEBUG").is_ok());

    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();

    let window = WindowBuilder::new()
        .with_title("HopTerm")
        .with_inner_size(tao::dpi::LogicalSize::new(1180.0, 760.0))
        .build(&event_loop)
        .expect("failed to create window");

    // JS → Rust commands flow over this channel into the backend runtime.
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel::<String>();

    let webview = build_webview(&window, cmd_tx)?;

    // The backend runs on its own tokio runtime thread.
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(backend::run(cmd_rx, proxy));
    });

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::UserEvent(UserEvent::Js(js)) => {
                let _ = webview.evaluate_script(&js);
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => *control_flow = ControlFlow::Exit,
            _ => {}
        }
    });
}

#[cfg(target_os = "linux")]
fn build_webview(
    window: &tao::window::Window,
    cmd_tx: tokio::sync::mpsc::UnboundedSender<String>,
) -> wry::Result<wry::WebView> {
    use tao::platform::unix::WindowExtUnix;
    use wry::WebViewBuilderExtUnix;
    let vbox = window.default_vbox().unwrap();
    builder(cmd_tx).build_gtk(vbox)
}

#[cfg(not(target_os = "linux"))]
fn build_webview(
    window: &tao::window::Window,
    cmd_tx: tokio::sync::mpsc::UnboundedSender<String>,
) -> wry::Result<wry::WebView> {
    builder(cmd_tx).build(window)
}

fn builder<'a>(cmd_tx: tokio::sync::mpsc::UnboundedSender<String>) -> WebViewBuilder<'a> {
    WebViewBuilder::new()
        .with_custom_protocol("hop".into(), serve)
        .with_ipc_handler(move |req: Request<String>| {
            let _ = cmd_tx.send(req.into_body());
        })
        .with_url("hop://app/index.html")
}
