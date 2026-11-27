#[cfg(target_os = "linux")]
use gtk::prelude::*;
use serde::Deserialize;
#[cfg(target_os = "linux")]
use std::time::Duration;
use std::{
    env,
    error::Error,
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};
#[cfg(target_os = "linux")]
use tao::platform::unix::WindowExtUnix;
use tao::{
    dpi::{LogicalSize, PhysicalSize},
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy},
    window::{Window, WindowBuilder},
};
use url::Url;
#[cfg(target_os = "linux")]
use wry::WebViewBuilderExtUnix;
use wry::{
    dpi::{LogicalPosition, LogicalSize as WebViewLogicalSize},
    NewWindowResponse, PageLoadEvent, PermissionResponse, ProxyConfig, ProxyEndpoint, Rect,
    WebView, WebViewBuilder,
};

use yukki_browser_runtime::{
    accelerator::{rgba_gain_cpu, BrowserAcceleratorScheduler},
    policy::{resolve_address, validate_navigation},
    store::{self, BrowserState},
    EngineAdapter, MAX_TABS,
};
use yukkios::crawler::{CrawlEvent, Crawler, CrawlerConfig};

const DEFAULT_URL: &str = "https://example.com";
const TOOLBAR_HEIGHT: f64 = 122.0;

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinuxDisplayBackend {
    Auto,
    Wayland,
    X11,
    XWayland,
}

#[cfg(target_os = "linux")]
fn parse_linux_display_backend(value: Option<&str>) -> Result<LinuxDisplayBackend, String> {
    match value.unwrap_or("auto").trim().to_ascii_lowercase().as_str() {
        "" | "auto" => Ok(LinuxDisplayBackend::Auto),
        "wayland" => Ok(LinuxDisplayBackend::Wayland),
        "x11" => Ok(LinuxDisplayBackend::X11),
        "xwayland" => Ok(LinuxDisplayBackend::XWayland),
        other => Err(format!(
            "Unsupported YUKKI_BROWSER_DISPLAY_BACKEND '{other}'; use auto, wayland, x11, or xwayland"
        )),
    }
}

#[cfg(target_os = "linux")]
fn has_display_value(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.trim().is_empty())
}

#[cfg(target_os = "linux")]
fn resolve_linux_gdk_backend(
    requested: Option<&str>,
    wayland_display: Option<&str>,
    x_display: Option<&str>,
    session_type: Option<&str>,
) -> Result<Option<&'static str>, String> {
    match parse_linux_display_backend(requested)? {
        LinuxDisplayBackend::Auto => {
            // Keep GDK_BACKEND untouched so GTK can honor desktop/session policy.
            Ok(None)
        }
        LinuxDisplayBackend::Wayland => {
            if !has_display_value(wayland_display) {
                return Err(
                    "YUKKI_BROWSER_DISPLAY_BACKEND=wayland requires a non-empty WAYLAND_DISPLAY"
                        .to_owned(),
                );
            }
            Ok(Some("wayland"))
        }
        LinuxDisplayBackend::X11 => {
            if !has_display_value(x_display) {
                return Err(
                    "YUKKI_BROWSER_DISPLAY_BACKEND=x11 requires a non-empty DISPLAY (Xorg or XWayland)"
                        .to_owned(),
                );
            }
            Ok(Some("x11"))
        }
        LinuxDisplayBackend::XWayland => {
            if !has_display_value(x_display) {
                return Err(
                    "YUKKI_BROWSER_DISPLAY_BACKEND=xwayland requires a non-empty DISPLAY supplied by XWayland"
                        .to_owned(),
                );
            }
            let wayland_session = has_display_value(wayland_display)
                || session_type.is_some_and(|value| value.trim().eq_ignore_ascii_case("wayland"));
            if !wayland_session {
                return Err(
                    "YUKKI_BROWSER_DISPLAY_BACKEND=xwayland requires a Wayland session (WAYLAND_DISPLAY or XDG_SESSION_TYPE=wayland)"
                        .to_owned(),
                );
            }
            Ok(Some("x11"))
        }
    }
}

#[cfg(target_os = "linux")]
fn configure_linux_display_backend() -> Result<(), Box<dyn Error>> {
    let backend = resolve_linux_gdk_backend(
        env::var("YUKKI_BROWSER_DISPLAY_BACKEND").ok().as_deref(),
        env::var("WAYLAND_DISPLAY").ok().as_deref(),
        env::var("DISPLAY").ok().as_deref(),
        env::var("XDG_SESSION_TYPE").ok().as_deref(),
    )
    .map_err(std::io::Error::other)?;

    if let Some(backend) = backend {
        // GDK reads this during initialization. Set it before GTK/Tao creates
        // any display objects so the requested transport is selected reliably.
        env::set_var("GDK_BACKEND", backend);
    }
    gtk::init()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn create_linux_webview_hosts(window: &Window) -> Result<(gtk::Fixed, gtk::Fixed), Box<dyn Error>> {
    let root = window.default_vbox().ok_or_else(|| {
        std::io::Error::other("Tao did not create its default GTK vertical container")
    })?;
    let toolbar_host = gtk::Fixed::new();
    toolbar_host.set_size_request(-1, TOOLBAR_HEIGHT.ceil() as i32);
    let page_host = gtk::Fixed::new();

    // Wry's GTK-container integration is the supported path for both native
    // Wayland and X11/XWayland. A shared Fixed host also lets tabs overlap and
    // switch visibility without creating unsupported Wayland child surfaces.
    root.pack_start(&toolbar_host, false, false, 0);
    root.pack_start(&page_host, true, true, 0);
    toolbar_host.show();
    page_host.show();
    Ok((toolbar_host, page_host))
}

#[derive(Debug, Deserialize)]
struct CrawlerUiMessage {
    action: String,
    seeds: Option<Vec<String>>,
    allowed_domains: Option<Vec<String>>,
    max_pages: Option<usize>,
    url: Option<String>,
    title: Option<String>,
    summary: Option<String>,
    fetched_at_unix_ms: Option<u128>,
    status_code: Option<u16>,
    document_bytes: Option<u64>,
    depth: Option<usize>,
    sha256: Option<String>,
    links: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct UiMessage {
    action: String,
    url: Option<String>,
    tab_id: Option<u64>,
}

enum RuntimeEvent {
    Ui(UiMessage),
    CrawlerUi {
        tab_id: u64,
        message: CrawlerUiMessage,
    },
    CrawlerUpdate {
        tab_id: u64,
        payload: String,
        acknowledgement: tokio::sync::oneshot::Sender<()>,
    },
    Visited {
        tab_id: u64,
        url: String,
    },
    TitleChanged {
        tab_id: u64,
        title: String,
    },
    LoadFinished {
        tab_id: u64,
        url: String,
        duration_ms: u128,
    },
    Notice(String),
    #[cfg(target_os = "linux")]
    Exit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TabKind {
    Page,
    CrawlerUtility,
}

struct Tab {
    id: u64,
    kind: TabKind,
    engine: WryEngineAdapter,
    url: String,
    title: String,
    last_load_ms: Option<u128>,
}

struct WryEngineAdapter {
    view: WebView,
}

impl EngineAdapter for WryEngineAdapter {
    fn navigate(&self, url: &Url) -> Result<(), String> {
        self.view
            .load_url(url.as_str())
            .map_err(|error| error.to_string())
    }

    fn back(&self) -> Result<(), String> {
        self.view.go_back().map_err(|error| error.to_string())
    }

    fn forward(&self) -> Result<(), String> {
        self.view.go_forward().map_err(|error| error.to_string())
    }

    fn reload(&self) -> Result<(), String> {
        self.view.reload().map_err(|error| error.to_string())
    }

    fn can_go_back(&self) -> Result<bool, String> {
        self.view.can_go_back().map_err(|error| error.to_string())
    }

    fn can_go_forward(&self) -> Result<bool, String> {
        self.view
            .can_go_forward()
            .map_err(|error| error.to_string())
    }
}

fn logical_rect(width: f64, height: f64, y: f64) -> Rect {
    Rect {
        position: LogicalPosition::new(0.0, y).into(),
        size: WebViewLogicalSize::new(width, height.max(1.0)).into(),
    }
}

fn page_rect(size: PhysicalSize<u32>, scale_factor: f64) -> Rect {
    let logical = size.to_logical::<f64>(scale_factor);
    #[cfg(target_os = "linux")]
    let y = 0.0;
    #[cfg(not(target_os = "linux"))]
    let y = TOOLBAR_HEIGHT;
    logical_rect(logical.width, logical.height - TOOLBAR_HEIGHT, y)
}

fn toolbar_rect(size: PhysicalSize<u32>, scale_factor: f64) -> Rect {
    let logical = size.to_logical::<f64>(scale_factor);
    logical_rect(logical.width, TOOLBAR_HEIGHT, 0.0)
}

fn configured_proxy() -> Result<Option<ProxyConfig>, String> {
    let Some(raw) = env::var_os("YUKKI_BROWSER_PROXY") else {
        return Ok(None);
    };
    let raw = raw.to_string_lossy();
    let url = Url::parse(&raw).map_err(|_| {
        "YUKKI_BROWSER_PROXY must be an explicit http://host:port or socks5://host:port URL"
            .to_owned()
    })?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "YUKKI_BROWSER_PROXY cannot contain credentials, paths, queries, or fragments"
                .to_owned(),
        );
    }
    let host = url
        .host_str()
        .ok_or_else(|| "Proxy URL is missing a host".to_owned())?;
    let port = url
        .port()
        .ok_or_else(|| "Proxy URL must include an explicit port".to_owned())?;
    let endpoint = ProxyEndpoint {
        host: host.to_owned(),
        port: port.to_string(),
    };
    match url.scheme() {
        "http" => Ok(Some(ProxyConfig::Http(endpoint))),
        "socks5" => Ok(Some(ProxyConfig::Socks5(endpoint))),
        _ => Err("Only HTTP CONNECT and SOCKS5 browser proxies are supported".to_owned()),
    }
}

fn build_page(
    _window: &Window,
    #[cfg(target_os = "linux")] page_host: &gtk::Fixed,
    proxy: &EventLoopProxy<RuntimeEvent>,
    tab_id: u64,
    url: &str,
    bounds: Rect,
    visible: bool,
) -> Result<WryEngineAdapter, Box<dyn Error>> {
    let navigation_proxy = proxy.clone();
    let title_proxy = proxy.clone();
    let popup_proxy = proxy.clone();
    let load_proxy = proxy.clone();
    let proxy_config = configured_proxy().map_err(std::io::Error::other)?;
    let load_started = Arc::new(Mutex::new(None::<(String, Instant)>));
    let started_state = Arc::clone(&load_started);
    let finished_state = Arc::clone(&load_started);

    let mut builder = WebViewBuilder::new()
        .with_url(url)
        .with_bounds(bounds)
        .with_visible(visible)
        .with_incognito(true)
        .with_autoplay(false)
        .with_clipboard(false)
        .with_devtools(cfg!(debug_assertions))
        .with_navigation_handler(move |candidate| match validate_navigation(&candidate) {
            Ok(validated) => {
                let _ = navigation_proxy.send_event(RuntimeEvent::Visited {
                    tab_id,
                    url: validated.to_string(),
                });
                true
            }
            Err(error) => {
                let _ = navigation_proxy.send_event(RuntimeEvent::Notice(error.to_string()));
                false
            }
        })
        .with_new_window_req_handler(move |candidate, _features| {
            if validate_navigation(&candidate).is_ok() {
                let _ = popup_proxy.send_event(RuntimeEvent::Ui(UiMessage {
                    action: "new_tab".to_owned(),
                    url: Some(candidate),
                    tab_id: None,
                }));
            }
            NewWindowResponse::Deny
        })
        // Keep the engine's platform-native prompt behavior. The UI does not
        // receive privileged host APIs or silently approve site capabilities.
        .with_permission_handler(|_kind| PermissionResponse::Default)
        // Downloads are intentionally denied until a byte-quota and safe
        // destination manager exists. Never silently permit unbounded writes.
        .with_download_started_handler(|_url, _path| false)
        .with_document_title_changed_handler(move |title| {
            let _ = title_proxy.send_event(RuntimeEvent::TitleChanged { tab_id, title });
        })
        .with_on_page_load_handler(move |event, url| {
            if matches!(event, PageLoadEvent::Started) {
                if let Ok(mut started) = started_state.lock() {
                    *started = Some((url, Instant::now()));
                }
            } else if let Some((started_url, started_at)) = finished_state
                .lock()
                .ok()
                .and_then(|mut started| started.take())
            {
                let _ = load_proxy.send_event(RuntimeEvent::LoadFinished {
                    tab_id,
                    url: if started_url.is_empty() {
                        url
                    } else {
                        started_url
                    },
                    duration_ms: started_at.elapsed().as_millis(),
                });
            }
        });
    if let Some(proxy) = proxy_config {
        builder = builder.with_proxy_config(proxy);
    }
    #[cfg(target_os = "linux")]
    let view = builder.build_gtk(page_host)?;
    #[cfg(not(target_os = "linux"))]
    let view = builder.build_as_child(_window)?;

    Ok(WryEngineAdapter { view })
}

fn build_crawler_utility(
    _window: &Window,
    #[cfg(target_os = "linux")] page_host: &gtk::Fixed,
    proxy: &EventLoopProxy<RuntimeEvent>,
    tab_id: u64,
    bounds: Rect,
    visible: bool,
) -> Result<WryEngineAdapter, Box<dyn Error>> {
    let ipc_proxy = proxy.clone();
    let builder = WebViewBuilder::new()
        .with_html(include_str!("../assets/crawler.html"))
        .with_bounds(bounds)
        .with_visible(visible)
        .with_incognito(true)
        .with_autoplay(false)
        .with_clipboard(false)
        .with_devtools(cfg!(debug_assertions))
        .with_ipc_handler(move |request| {
            if request.body().len() > 16 * 1024 {
                return;
            }
            if let Ok(message) = serde_json::from_str::<CrawlerUiMessage>(request.body()) {
                if matches!(
                    message.action.as_str(),
                    "ready" | "start_crawl" | "open_summary"
                ) && message.action.len() <= 32
                {
                    let _ = ipc_proxy.send_event(RuntimeEvent::CrawlerUi { tab_id, message });
                }
            }
        })
        .with_new_window_req_handler(|_, _| NewWindowResponse::Deny)
        .with_permission_handler(|_kind| PermissionResponse::Default)
        .with_download_started_handler(|_url, _path| false);
    #[cfg(target_os = "linux")]
    let view = builder.build_gtk(page_host)?;
    #[cfg(not(target_os = "linux"))]
    let view = builder.build_as_child(_window)?;
    Ok(WryEngineAdapter { view })
}

fn build_toolbar(
    #[cfg(not(target_os = "linux"))] window: &Window,
    #[cfg(target_os = "linux")] toolbar_host: &gtk::Fixed,
    proxy: &EventLoopProxy<RuntimeEvent>,
    size: PhysicalSize<u32>,
    scale_factor: f64,
) -> Result<WebView, Box<dyn Error>> {
    let ipc_proxy = proxy.clone();
    let builder = WebViewBuilder::new()
        .with_html(include_str!("../assets/shell.html"))
        .with_bounds(toolbar_rect(size, scale_factor))
        .with_ipc_handler(move |request| {
            // The toolbar is local, but still treat its IPC as untrusted input:
            // cap the body before JSON parsing and constrain the command schema.
            if request.body().len() > 4096 {
                return;
            }
            if let Ok(message) = serde_json::from_str::<UiMessage>(request.body()) {
                let known_action = matches!(
                    message.action.as_str(),
                    "ready"
                        | "navigate"
                        | "back"
                        | "forward"
                        | "reload"
                        | "bookmark"
                        | "new_tab"
                        | "close_tab"
                        | "switch_tab"
                        | "graphics_test"
                        | "crawler_tab"
                );
                let valid_url = message.url.as_ref().is_none_or(|url| url.len() <= 2048);
                if known_action && message.action.len() <= 32 && valid_url {
                    let _ = ipc_proxy.send_event(RuntimeEvent::Ui(message));
                }
            }
        });
    #[cfg(target_os = "linux")]
    let toolbar = builder.build_gtk(toolbar_host)?;
    #[cfg(not(target_os = "linux"))]
    let toolbar = builder.build_as_child(window)?;
    Ok(toolbar)
}

fn sync_chrome(
    toolbar: &WebView,
    window: &Window,
    tabs: &[Tab],
    selected_tab_id: u64,
    state: &BrowserState,
    status: &str,
) {
    let tab_data: Vec<_> = tabs
        .iter()
        .map(|tab| {
            serde_json::json!({
                "id": tab.id,
                "url": tab.url,
                "title": if tab.title.is_empty() { tab.url.as_str() } else { tab.title.as_str() },
                "load_ms": tab.last_load_ms
            })
        })
        .collect();

    let active = tabs.iter().find(|tab| tab.id == selected_tab_id);
    let can_go_back = active
        .and_then(|tab| tab.engine.can_go_back().ok())
        .unwrap_or(false);
    let can_go_forward = active
        .and_then(|tab| tab.engine.can_go_forward().ok())
        .unwrap_or(false);

    let payload = serde_json::json!({
        "active_tab_id": selected_tab_id,
        "tabs": tab_data,
        "bookmarks": state.bookmarks,
        "history": state.history,
        "can_go_back": can_go_back,
        "can_go_forward": can_go_forward,
        "status": status
    });

    if let Ok(json) = serde_json::to_string(&payload) {
        let script = format!("window.yukkiBrowser && window.yukkiBrowser.render({json});");
        let _ = toolbar.evaluate_script(&script);
    }

    if let Some(tab) = active {
        let title = if tab.title.is_empty() {
            &tab.url
        } else {
            &tab.title
        };
        window.set_title(&format!("YuKKi Browser — {title}"));
    }
}

fn resize_views(toolbar: &WebView, tabs: &[Tab], size: PhysicalSize<u32>, scale_factor: f64) {
    let _ = toolbar.set_bounds(toolbar_rect(size, scale_factor));
    let bounds = page_rect(size, scale_factor);
    for tab in tabs {
        let _ = tab.engine.view.set_bounds(bounds);
    }
}

fn set_active_tab(tabs: &mut [Tab], selected_tab_id: u64) {
    for tab in tabs {
        let _ = tab.engine.view.set_visible(tab.id == selected_tab_id);
    }
}

fn add_tab(
    window: &Window,
    #[cfg(target_os = "linux")] page_host: &gtk::Fixed,
    proxy: &EventLoopProxy<RuntimeEvent>,
    tabs: &mut Vec<Tab>,
    next_tab_id: &mut u64,
    selected_tab_id: &mut u64,
    url: &str,
    size: PhysicalSize<u32>,
) -> Result<(), String> {
    if tabs.len() >= MAX_TABS {
        return Err(format!(
            "The browser tab limit is {MAX_TABS}. Close a tab before opening another."
        ));
    }
    let url = resolve_address(url).map_err(|error| error.to_string())?;
    let id = *next_tab_id;
    *next_tab_id += 1;
    let bounds = page_rect(size, window.scale_factor());
    #[cfg(target_os = "linux")]
    let engine = build_page(window, page_host, proxy, id, url.as_str(), bounds, true)
        .map_err(|error| error.to_string())?;
    #[cfg(not(target_os = "linux"))]
    let engine = build_page(window, proxy, id, url.as_str(), bounds, true)
        .map_err(|error| error.to_string())?;

    for tab in tabs.iter() {
        let _ = tab.engine.view.set_visible(false);
    }
    tabs.push(Tab {
        id,
        kind: TabKind::Page,
        engine,
        url: url.to_string(),
        title: String::new(),
        last_load_ms: None,
    });
    *selected_tab_id = id;
    Ok(())
}

fn add_crawler_tab(
    window: &Window,
    #[cfg(target_os = "linux")] page_host: &gtk::Fixed,
    proxy: &EventLoopProxy<RuntimeEvent>,
    tabs: &mut Vec<Tab>,
    next_tab_id: &mut u64,
    selected_tab_id: &mut u64,
    size: PhysicalSize<u32>,
) -> Result<(), String> {
    if let Some(existing) = tabs.iter().find(|tab| tab.kind == TabKind::CrawlerUtility) {
        *selected_tab_id = existing.id;
        set_active_tab(tabs, *selected_tab_id);
        return Ok(());
    }
    if tabs.len() >= MAX_TABS {
        return Err(format!(
            "The browser tab limit is {MAX_TABS}. Close a tab before opening the crawler utility."
        ));
    }
    let id = *next_tab_id;
    *next_tab_id += 1;
    let bounds = page_rect(size, window.scale_factor());
    #[cfg(target_os = "linux")]
    let engine = build_crawler_utility(window, page_host, proxy, id, bounds, true)
        .map_err(|error| error.to_string())?;
    #[cfg(not(target_os = "linux"))]
    let engine = build_crawler_utility(window, proxy, id, bounds, true)
        .map_err(|error| error.to_string())?;

    for tab in tabs.iter() {
        let _ = tab.engine.view.set_visible(false);
    }
    tabs.push(Tab {
        id,
        kind: TabKind::CrawlerUtility,
        engine,
        url: "yukki://crawler".to_owned(),
        title: "Crawler Utility".to_owned(),
        last_load_ms: None,
    });
    *selected_tab_id = id;
    Ok(())
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn crawler_summary_html(message: &CrawlerUiMessage) -> Result<String, String> {
    let source = message
        .url
        .as_deref()
        .ok_or("summary is missing its source URL")?;
    if source.len() > 2048 {
        return Err("summary source URL exceeds 2,048 bytes".to_owned());
    }
    let source = validate_navigation(source).map_err(|error| error.to_string())?;
    let title = message.title.as_deref().unwrap_or("Untitled page");
    let summary = message
        .summary
        .as_deref()
        .unwrap_or("No text preview was extracted.");
    if title.len() > 256 || summary.len() > 480 {
        return Err("summary title or preview exceeds its size limit".to_owned());
    }
    let original = html_escape(source.as_str());
    let mut discovered = String::new();
    for raw in message.links.as_deref().unwrap_or_default().iter().take(8) {
        if raw.len() > 2048 {
            continue;
        }
        if let Ok(url) = validate_navigation(raw) {
            let href = html_escape(url.as_str());
            let label = html_escape(url.as_str());
            discovered.push_str(&format!(
                "<li><a href=\"{href}\" rel=\"noopener noreferrer\">{label}</a></li>"
            ));
        }
    }
    let links_section = if discovered.is_empty() {
        "<p>No additional links were extracted.</p>".to_owned()
    } else {
        format!("<ul>{discovered}</ul>")
    };
    let status = message
        .status_code
        .map(|code| format!("HTTP {code}"))
        .unwrap_or_else(|| "Fetch failed".to_owned());
    let timestamp = message.fetched_at_unix_ms.unwrap_or_default();
    let bytes = message.document_bytes.unwrap_or_default();
    let depth = message.depth.unwrap_or_default();
    let digest = html_escape(message.sha256.as_deref().unwrap_or(""));
    Ok(format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';"><title>Page summary</title><style>body{{font:16px system-ui,sans-serif;line-height:1.55;max-width:820px;margin:36px auto;padding:0 20px;color:#1d2930}}.eyebrow{{color:#55717e;font-size:12px;letter-spacing:.08em;font-weight:700}}h1{{line-height:1.2}}.summary{{font-size:18px;white-space:pre-wrap}}a{{color:#075f83;overflow-wrap:anywhere}}.meta{{color:#52636c;font-size:13px}}li{{margin:8px 0}}</style></head><body><p class="eyebrow">YUKKI-OS · CRAWLER PAGE SUMMARY</p><h1>{}</h1><p class="meta">{}</p><p class="summary">{}</p><p><a href="{}" rel="noopener noreferrer">Open original HTML</a></p><h2>Discovered links</h2>{}<hr><p class="meta">{} · {} bytes · depth {} · fetched {} Unix ms</p><p class="meta">SHA-256: {}</p></body></html>"#,
        html_escape(title),
        original,
        html_escape(summary),
        original,
        links_section,
        status,
        bytes,
        depth,
        timestamp,
        digest
    ))
}

fn persist_state(path: &PathBuf, state: &BrowserState) {
    if let Err(error) = store::save(path, state) {
        eprintln!("Unable to save YuKKi browser state: {error}");
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    #[cfg(target_os = "linux")]
    configure_linux_display_backend()?;

    let requested = env::args()
        .skip(1)
        .next()
        .unwrap_or_else(|| DEFAULT_URL.to_owned());
    let initial_url = resolve_address(&requested)?;

    let event_loop = EventLoopBuilder::<RuntimeEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();
    let window = WindowBuilder::new()
        .with_title("YuKKi Browser")
        .with_inner_size(LogicalSize::new(1280.0, 820.0))
        .with_min_inner_size(LogicalSize::new(720.0, 480.0))
        .build(&event_loop)?;

    let initial_size = window.inner_size();
    let scale_factor = window.scale_factor();
    #[cfg(target_os = "linux")]
    let (toolbar_host, page_host) = create_linux_webview_hosts(&window)?;
    #[cfg(target_os = "linux")]
    let toolbar = build_toolbar(&toolbar_host, &proxy, initial_size, scale_factor)?;
    #[cfg(not(target_os = "linux"))]
    let toolbar = build_toolbar(&window, &proxy, initial_size, scale_factor)?;
    let state_path = store::default_state_path();
    let mut browser_state = store::load(&state_path);
    let mut tabs = Vec::new();
    let mut next_tab_id = 1_u64;
    let mut selected_tab_id = 0_u64;
    let mut main_page_tab_id;
    #[cfg(target_os = "linux")]
    let initial_tab_result = add_tab(
        &window,
        &page_host,
        &proxy,
        &mut tabs,
        &mut next_tab_id,
        &mut selected_tab_id,
        initial_url.as_str(),
        initial_size,
    );
    #[cfg(not(target_os = "linux"))]
    let initial_tab_result = add_tab(
        &window,
        &proxy,
        &mut tabs,
        &mut next_tab_id,
        &mut selected_tab_id,
        initial_url.as_str(),
        initial_size,
    );
    initial_tab_result.map_err(std::io::Error::other)?;
    main_page_tab_id = selected_tab_id;

    sync_chrome(
        &toolbar,
        &window,
        &tabs,
        selected_tab_id,
        &browser_state,
        "Ready · private page storage",
    );

    // Runtime construction is intentionally non-fatal: page browsing still
    // works when broker configuration is absent. The toolbar diagnostic reports
    // configuration errors instead of blocking ordinary navigation.
    let accelerator_scheduler = Arc::new(BrowserAcceleratorScheduler::from_env());
    let graphics_test_running = Arc::new(AtomicBool::new(false));
    let crawler_running = Arc::new(AtomicBool::new(false));
    let async_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;

    // CI can exercise the real GTK/WebKit host under headless Wayland and
    // XWayland without leaving a GUI process running after the smoke check.
    #[cfg(target_os = "linux")]
    if let Some(raw_delay) = env::var_os("YUKKI_BROWSER_SMOKE_EXIT_AFTER_MS") {
        let delay_ms = raw_delay
            .to_string_lossy()
            .parse::<u64>()
            .map_err(|_| "YUKKI_BROWSER_SMOKE_EXIT_AFTER_MS must be an integer")?;
        if !(100..=60_000).contains(&delay_ms) {
            return Err("YUKKI_BROWSER_SMOKE_EXIT_AFTER_MS must be between 100 and 60000".into());
        }
        let exit_proxy = proxy.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(delay_ms));
            let _ = exit_proxy.send_event(RuntimeEvent::Exit);
        });
    }

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                *control_flow = ControlFlow::Exit;
            }
            Event::WindowEvent {
                event: WindowEvent::Resized(size),
                ..
            } => resize_views(&toolbar, &tabs, size, window.scale_factor()),
            Event::UserEvent(RuntimeEvent::Visited { tab_id, url }) => {
                if let Some(tab) = tabs.iter_mut().find(|tab| tab.id == tab_id) {
                    tab.url = url.clone();
                    tab.last_load_ms = None;
                    browser_state.record_visit(&url);
                    persist_state(&state_path, &browser_state);
                }
                sync_chrome(&toolbar, &window, &tabs, selected_tab_id, &browser_state, "Page navigation");
            }
            Event::UserEvent(RuntimeEvent::TitleChanged { tab_id, title }) => {
                if let Some(tab) = tabs.iter_mut().find(|tab| tab.id == tab_id) {
                    tab.title = title;
                }
                sync_chrome(&toolbar, &window, &tabs, selected_tab_id, &browser_state, "Page title updated");
            }
            Event::UserEvent(RuntimeEvent::LoadFinished { tab_id, url, duration_ms }) => {
                if let Some(tab) = tabs.iter_mut().find(|tab| tab.id == tab_id) {
                    tab.url = url;
                    tab.last_load_ms = Some(duration_ms);
                }
                let message = format!("Page load completed in {duration_ms} ms");
                sync_chrome(&toolbar, &window, &tabs, selected_tab_id, &browser_state, &message);
            }
            Event::UserEvent(RuntimeEvent::Notice(message)) => {
                sync_chrome(&toolbar, &window, &tabs, selected_tab_id, &browser_state, &message);
            }
            Event::UserEvent(RuntimeEvent::CrawlerUpdate { tab_id, payload, acknowledgement }) => {
                if let Some(tab) = tabs.iter().find(|tab| tab.id == tab_id && tab.kind == TabKind::CrawlerUtility) {
                    let script = format!("window.yukkiCrawler && window.yukkiCrawler.append({payload});");
                    let _ = tab.engine.view.evaluate_script(&script);
                }
                let _ = acknowledgement.send(());
            }
            Event::UserEvent(RuntimeEvent::CrawlerUi { message, .. }) if message.action == "ready" => {}
            Event::UserEvent(RuntimeEvent::CrawlerUi { tab_id, message }) => {
                match message.action.as_str() {
                    "start_crawl" => {
                        let seeds = message.seeds.unwrap_or_default();
                        let domains = message.allowed_domains.unwrap_or_default();
                        let max_pages = message.max_pages.unwrap_or(100);
                        let valid_seeds = !seeds.is_empty() && seeds.len() <= 16
                            && seeds.iter().all(|seed| !seed.trim().is_empty() && seed.len() <= 2048);
                        let valid_domains = !domains.is_empty() && domains.len() <= 256
                            && domains.iter().all(|domain| {
                                let value = domain.trim();
                                !value.is_empty() && value.len() <= 253
                                    && !value.contains('/') && !value.contains(':')
                                    && !value.contains('*') && !value.chars().any(char::is_whitespace)
                            });
                        if !valid_seeds || !valid_domains || !(1..=1000).contains(&max_pages) {
                            let payload = serde_json::json!({"kind":"error","message":"Provide 1–16 valid seed URLs, 1–256 DNS allowlist domains, and 1–1,000 maximum pages."});
                            if let Some(tab) = tabs.iter().find(|tab| tab.id == tab_id) {
                                let _ = tab.engine.view.evaluate_script(&format!(
                                    "window.yukkiCrawler && window.yukkiCrawler.append({});", payload
                                ));
                            }
                        } else if crawler_running.swap(true, Ordering::AcqRel) {
                            let payload = serde_json::json!({"kind":"status","message":"A crawl is already running."});
                            if let Some(tab) = tabs.iter().find(|tab| tab.id == tab_id) {
                                let _ = tab.engine.view.evaluate_script(&format!(
                                    "window.yukkiCrawler && window.yukkiCrawler.append({});", payload
                                ));
                            }
                        } else {
                            let wasm_path = env::var_os("YUKKI_CRAWLER_WASM").map(PathBuf::from);
                            let setup = wasm_path
                                .ok_or_else(|| "Set YUKKI_CRAWLER_WASM to the compiled crawler extraction guest.".to_owned())
                                .and_then(|path| fs::read(&path).map_err(|error| format!("Cannot read crawler guest {}: {error}", path.display())))
                                .and_then(|wasm| {
                                    let mut config = CrawlerConfig::default();
                                    config.allowed_domains = domains;
                                    config.max_pages = max_pages;
                                    Crawler::new(config, &wasm).map_err(|error| error.to_string())
                                });
                            match setup {
                                Ok(crawler) => {
                                    let (event_sender, mut event_receiver) = tokio::sync::mpsc::channel(8);
                                    let event_proxy = proxy.clone();
                                    let running = Arc::clone(&crawler_running);
                                    async_runtime.spawn(async move {
                                        let job = tokio::spawn(async move {
                                            crawler.crawl_with_events(&seeds, event_sender).await
                                        });
                                        while let Some(event) = event_receiver.recv().await {
                                            let payload = match event {
                                                CrawlEvent::PageCompleted(page) => serde_json::json!({"kind":"page","page":page}),
                                                CrawlEvent::Finished(metrics) => serde_json::json!({"kind":"finished","metrics":metrics}),
                                            };
                                            if let Ok(payload) = serde_json::to_string(&payload) {
                                                let (acknowledgement, acknowledged) = tokio::sync::oneshot::channel();
                                                if event_proxy.send_event(RuntimeEvent::CrawlerUpdate {
                                                    tab_id,
                                                    payload,
                                                    acknowledgement,
                                                }).is_ok() {
                                                    let _ = acknowledged.await;
                                                }
                                            }
                                        }
                                        let failure = match job.await {
                                            Ok(Ok(_)) => None,
                                            Ok(Err(error)) => Some(error.to_string()),
                                            Err(error) => Some(format!("Crawler task failed: {error}")),
                                        };
                                        if let Some(message) = failure {
                                            let payload = serde_json::json!({"kind":"error","message":message});
                                            if let Ok(payload) = serde_json::to_string(&payload) {
                                                let (acknowledgement, acknowledged) = tokio::sync::oneshot::channel();
                                                if event_proxy.send_event(RuntimeEvent::CrawlerUpdate {
                                                    tab_id,
                                                    payload,
                                                    acknowledgement,
                                                }).is_ok() {
                                                    let _ = acknowledged.await;
                                                }
                                            }
                                        }
                                        running.store(false, Ordering::Release);
                                    });
                                    let payload = serde_json::json!({"kind":"status","message":"Crawl started. Results will stream in as pages are extracted."});
                                    if let Some(tab) = tabs.iter().find(|tab| tab.id == tab_id) {
                                        let _ = tab.engine.view.evaluate_script(&format!(
                                            "window.yukkiCrawler && window.yukkiCrawler.append({});", payload
                                        ));
                                    }
                                }
                                Err(error) => {
                                    crawler_running.store(false, Ordering::Release);
                                    let payload = serde_json::json!({"kind":"error","message":error});
                                    if let Some(tab) = tabs.iter().find(|tab| tab.id == tab_id) {
                                        let _ = tab.engine.view.evaluate_script(&format!(
                                            "window.yukkiCrawler && window.yukkiCrawler.append({});", payload
                                        ));
                                    }
                                }
                            }
                        }
                    }
                    "open_summary" => {
                        match crawler_summary_html(&message) {
                            Ok(document) => {
                                let target_id = tabs.iter()
                                    .find(|tab| tab.id == main_page_tab_id && tab.kind == TabKind::Page)
                                    .map(|tab| tab.id)
                                    .or_else(|| tabs.iter().find(|tab| tab.kind == TabKind::Page).map(|tab| tab.id));
                                if let Some(target_id) = target_id {
                                    if let Some(tab) = tabs.iter_mut().find(|tab| tab.id == target_id) {
                                        match tab.engine.view.load_html(&document) {
                                            Ok(()) => {
                                                tab.url = message.url.clone().unwrap_or_else(|| "yukki://crawler-summary".to_owned());
                                                tab.title = format!("Summary: {}", message.title.as_deref().unwrap_or("Untitled page"));
                                                selected_tab_id = target_id;
                                                main_page_tab_id = target_id;
                                                set_active_tab(&mut tabs, selected_tab_id);
                                            }
                                            Err(error) => {
                                                let _ = proxy.send_event(RuntimeEvent::Notice(format!("Could not open crawler summary: {error}")));
                                            }
                                        }
                                    }
                                }
                            }
                            Err(error) => {
                                let _ = proxy.send_event(RuntimeEvent::Notice(format!("Crawler summary rejected: {error}")));
                            }
                        }
                    }
                    _ => {}
                }
                sync_chrome(&toolbar, &window, &tabs, selected_tab_id, &browser_state, "Crawler utility");
            }
            #[cfg(target_os = "linux")]
            Event::UserEvent(RuntimeEvent::Exit) => {
                *control_flow = ControlFlow::Exit;
            }
            Event::UserEvent(RuntimeEvent::Ui(message)) => {
                let mut status = "Ready".to_owned();
                match message.action.as_str() {
                    "ready" => {}
                    "navigate" => {
                        let value = message.url.unwrap_or_default();
                        match resolve_address(&value) {
                            Ok(url) => {
                                if let Some(tab) = tabs.iter().find(|tab| tab.id == selected_tab_id) {
                                    match tab.engine.navigate(&url) {
                                        Ok(()) => status = format!("Navigating to {url}"),
                                        Err(error) => status = format!("Navigation failed: {error}"),
                                    }
                                }
                            }
                            Err(error) => status = error.to_string(),
                        }
                    }
                    "back" => {
                        if let Some(tab) = tabs.iter().find(|tab| tab.id == selected_tab_id) {
                            status = tab.engine.back().map(|_| "Back".to_owned()).unwrap_or_else(|error| error);
                        }
                    }
                    "forward" => {
                        if let Some(tab) = tabs.iter().find(|tab| tab.id == selected_tab_id) {
                            status = tab.engine.forward().map(|_| "Forward".to_owned()).unwrap_or_else(|error| error);
                        }
                    }
                    "reload" => {
                        if let Some(tab) = tabs.iter().find(|tab| tab.id == selected_tab_id) {
                            status = tab.engine.reload().map(|_| "Reloading".to_owned()).unwrap_or_else(|error| error);
                        }
                    }
                    "crawler_tab" => {
                        #[cfg(target_os = "linux")]
                        let result = add_crawler_tab(
                            &window, &page_host, &proxy, &mut tabs, &mut next_tab_id,
                            &mut selected_tab_id, window.inner_size(),
                        );
                        #[cfg(not(target_os = "linux"))]
                        let result = add_crawler_tab(
                            &window, &proxy, &mut tabs, &mut next_tab_id,
                            &mut selected_tab_id, window.inner_size(),
                        );
                        status = result.map(|_| "Crawler utility opened".to_owned()).unwrap_or_else(|error| error);
                    }
                    "new_tab" => {
                        let destination = message.url.as_deref().unwrap_or(DEFAULT_URL);
                        #[cfg(target_os = "linux")]
                        let result = add_tab(
                            &window,
                            &page_host,
                            &proxy,
                            &mut tabs,
                            &mut next_tab_id,
                            &mut selected_tab_id,
                            destination,
                            window.inner_size(),
                        );
                        #[cfg(not(target_os = "linux"))]
                        let result = add_tab(
                            &window,
                            &proxy,
                            &mut tabs,
                            &mut next_tab_id,
                            &mut selected_tab_id,
                            destination,
                            window.inner_size(),
                        );
                        status = result
                            .map(|_| "New tab".to_owned())
                            .unwrap_or_else(|error| error);
                        if let Some(tab) = tabs.iter().find(|tab| tab.id == selected_tab_id && tab.kind == TabKind::Page) {
                            main_page_tab_id = tab.id;
                        }
                    }
                    "close_tab" => {
                        let selected_kind = tabs.iter()
                            .find(|tab| tab.id == selected_tab_id)
                            .map(|tab| tab.kind);
                        let page_count = tabs.iter()
                            .filter(|tab| tab.kind == TabKind::Page)
                            .count();
                        if tabs.len() > 1
                            && !(selected_kind == Some(TabKind::Page) && page_count <= 1)
                        {
                            if let Some(index) = tabs.iter().position(|tab| tab.id == selected_tab_id) {
                                tabs.remove(index);
                            }
                            selected_tab_id = tabs.last().map(|tab| tab.id).unwrap_or(0);
                            if let Some(page) = tabs.iter().find(|tab| tab.kind == TabKind::Page) {
                                main_page_tab_id = page.id;
                            }
                            set_active_tab(&mut tabs, selected_tab_id);
                            status = "Tab closed".to_owned();
                        } else if selected_kind == Some(TabKind::Page) {
                            if let Some(tab) = tabs.iter().find(|tab| tab.kind == TabKind::Page) {
                                if let Ok(url) = resolve_address(DEFAULT_URL) {
                                    let _ = tab.engine.navigate(&url);
                                }
                            }
                            status = "The last page tab cannot be closed".to_owned();
                        } else {
                            status = "The last tab cannot be closed".to_owned();
                        }
                    }
                    "switch_tab" => {
                        if let Some(id) = message.tab_id {
                            if tabs.iter().any(|tab| tab.id == id) {
                                selected_tab_id = id;
                                if tabs.iter().any(|tab| tab.id == id && tab.kind == TabKind::Page) {
                                    main_page_tab_id = id;
                                }
                                set_active_tab(&mut tabs, selected_tab_id);
                                status = "Tab selected".to_owned();
                            }
                        }
                    }
                    "bookmark" => {
                        if let Some(tab) = tabs.iter().find(|tab| tab.id == selected_tab_id) {
                            let added = browser_state.add_bookmark(&tab.url);
                            persist_state(&state_path, &browser_state);
                            status = if added { "Bookmark saved".to_owned() } else { "Already bookmarked".to_owned() };
                        }
                    }
                    "graphics_test" => {
                        if graphics_test_running.swap(true, Ordering::AcqRel) {
                            status = "A synthetic graphics check is already running".to_owned();
                        } else {
                            status = "Running synthetic graphics check; website pixels are not sent".to_owned();
                            let scheduler = Arc::clone(&accelerator_scheduler);
                            let running = Arc::clone(&graphics_test_running);
                            let completion_proxy = proxy.clone();
                            async_runtime.spawn(async move {
                                // Deliberately synthetic test input. This diagnostic
                                // never reads from a WebView, canvas, page screenshot,
                                // or user-selected image.
                                let mut tile = vec![0u8; 128 * 128 * 4];
                                for (index, pixel) in tile.chunks_exact_mut(4).enumerate() {
                                    pixel[0] = (index.wrapping_mul(17) & 0xff) as u8;
                                    pixel[1] = (index.wrapping_mul(31) & 0xff) as u8;
                                    pixel[2] = ((index ^ (index >> 3)) & 0xff) as u8;
                                    pixel[3] = 255;
                                }
                                let result = match scheduler.as_ref() {
                                    Ok(scheduler) => match scheduler
                                        .run_rgba_gain("browser-ui-synthetic-graphics-check", &tile)
                                        .await
                                    {
                                        Ok(report) if report.output == rgba_gain_cpu(&tile) => {
                                            let location = report.execution_node_id
                                                .map(|node| format!("peer {node}"))
                                                .unwrap_or_else(|| "local node".to_owned());
                                            format!(
                                                "Synthetic graphics check passed: requested {:?}, ran on {:?} at {location}, {} ms",
                                                report.requested_backend,
                                                report.actual_backend,
                                                report.elapsed_ms,
                                            )
                                        }
                                        Ok(report) => {
                                            format!(
                                                "Synthetic graphics check failed CPU comparison (reported backend {:?}, output {} bytes)",
                                                report.actual_backend,
                                                report.output.len(),
                                            )
                                        }
                                        Err(error) => format!("Synthetic graphics check failed: {error}"),
                                    },
                                    Err(error) => format!("Graphics scheduler unavailable: {error}"),
                                };
                                running.store(false, Ordering::Release);
                                let _ = completion_proxy.send_event(RuntimeEvent::Notice(result));
                            });
                        }
                    }
                    _ => status = "Unknown browser command".to_owned(),
                }

                set_active_tab(&mut tabs, selected_tab_id);
                sync_chrome(&toolbar, &window, &tabs, selected_tab_id, &browser_state, &status);
            }
            _ => {}
        }

        #[cfg(target_os = "linux")]
        while gtk::events_pending() {
            gtk::main_iteration_do(false);
        }
    });
}

#[cfg(all(test, target_os = "linux"))]
mod linux_display_backend_tests {
    use super::{parse_linux_display_backend, LinuxDisplayBackend};

    #[test]
    fn display_backend_defaults_to_gtk_auto_selection() {
        assert_eq!(
            parse_linux_display_backend(None).unwrap(),
            LinuxDisplayBackend::Auto
        );
    }

    #[test]
    fn display_backend_distinguishes_x11_from_xwayland() {
        assert_eq!(
            parse_linux_display_backend(Some("wayland")).unwrap(),
            LinuxDisplayBackend::Wayland
        );
        assert_eq!(
            parse_linux_display_backend(Some("xwayland")).unwrap(),
            LinuxDisplayBackend::XWayland
        );
        assert_eq!(
            parse_linux_display_backend(Some("x11")).unwrap(),
            LinuxDisplayBackend::X11
        );
    }

    #[test]
    fn display_backend_resolves_native_wayland_x11_and_xwayland() {
        assert_eq!(
            super::resolve_linux_gdk_backend(Some("wayland"), Some("wayland-1"), None, None)
                .unwrap(),
            Some("wayland")
        );
        assert_eq!(
            super::resolve_linux_gdk_backend(Some("x11"), None, Some(":0"), Some("x11")).unwrap(),
            Some("x11")
        );
        assert_eq!(
            super::resolve_linux_gdk_backend(
                Some("xwayland"),
                Some("wayland-1"),
                Some(":1"),
                Some("wayland")
            )
            .unwrap(),
            Some("x11")
        );
        // Some launchers provide only the session marker alongside XWayland's
        // DISPLAY; the explicit session marker is a valid Wayland assertion.
        assert_eq!(
            super::resolve_linux_gdk_backend(Some("xwayland"), None, Some(":2"), Some("Wayland"))
                .unwrap(),
            Some("x11")
        );
    }

    #[test]
    fn display_backend_rejects_missing_or_empty_session_displays() {
        assert!(super::resolve_linux_gdk_backend(Some("wayland"), Some(" "), None, None).is_err());
        assert!(super::resolve_linux_gdk_backend(Some("x11"), None, Some(""), None).is_err());
        assert!(
            super::resolve_linux_gdk_backend(Some("xwayland"), None, Some(":1"), Some("x11"))
                .is_err()
        );
        assert!(
            super::resolve_linux_gdk_backend(Some("xwayland"), None, Some(":1"), None).is_err()
        );
    }

    #[test]
    fn auto_backend_leaves_gtk_session_selection_untouched() {
        assert_eq!(
            super::resolve_linux_gdk_backend(None, None, None, None).unwrap(),
            None
        );
    }

    #[test]
    fn display_backend_rejects_unknown_values() {
        assert!(parse_linux_display_backend(Some("nested")).is_err());
    }
}
