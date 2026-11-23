use serde::Deserialize;
use std::{env, error::Error, path::PathBuf};
use tao::{
    dpi::{LogicalSize, PhysicalSize},
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy},
    window::{Window, WindowBuilder},
};
use url::Url;
use wry::{
    dpi::{LogicalPosition, LogicalSize as WebViewLogicalSize},
    NewWindowResponse, PermissionResponse, Rect, WebView, WebViewBuilder,
};

use yukki_browser_runtime::{
    policy::{resolve_address, validate_navigation},
    store::{self, BrowserState},
    EngineAdapter, MAX_TABS,
};

const DEFAULT_URL: &str = "https://example.com";
const TOOLBAR_HEIGHT: f64 = 122.0;

#[derive(Debug, Deserialize)]
struct UiMessage {
    action: String,
    url: Option<String>,
    tab_id: Option<u64>,
}

enum RuntimeEvent {
    Ui(UiMessage),
    Visited { tab_id: u64, url: String },
    TitleChanged { tab_id: u64, title: String },
    Notice(String),
}

struct Tab {
    id: u64,
    engine: WryEngineAdapter,
    url: String,
    title: String,
}

struct WryEngineAdapter {
    view: WebView,
}

impl EngineAdapter for WryEngineAdapter {
    fn navigate(&self, url: &Url) -> Result<(), String> {
        self.view.load_url(url.as_str()).map_err(|error| error.to_string())
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
        self.view.can_go_forward().map_err(|error| error.to_string())
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
    logical_rect(logical.width, logical.height - TOOLBAR_HEIGHT, TOOLBAR_HEIGHT)
}

fn toolbar_rect(size: PhysicalSize<u32>, scale_factor: f64) -> Rect {
    let logical = size.to_logical::<f64>(scale_factor);
    logical_rect(logical.width, TOOLBAR_HEIGHT, 0.0)
}

fn build_page(
    window: &Window,
    proxy: &EventLoopProxy<RuntimeEvent>,
    tab_id: u64,
    url: &str,
    bounds: Rect,
    visible: bool,
) -> Result<WryEngineAdapter, Box<dyn Error>> {
    let navigation_proxy = proxy.clone();
    let title_proxy = proxy.clone();
    let popup_proxy = proxy.clone();

    let view = WebViewBuilder::new()
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
        .build_as_child(window)?;

    Ok(WryEngineAdapter { view })
}

fn build_toolbar(
    window: &Window,
    proxy: &EventLoopProxy<RuntimeEvent>,
    size: PhysicalSize<u32>,
    scale_factor: f64,
) -> Result<WebView, Box<dyn Error>> {
    let ipc_proxy = proxy.clone();
    let toolbar = WebViewBuilder::new()
        .with_html(include_str!("../assets/shell.html"))
        .with_bounds(toolbar_rect(size, scale_factor))
        .with_ipc_handler(move |request| {
            if let Ok(message) = serde_json::from_str::<UiMessage>(request.body()) {
                let _ = ipc_proxy.send_event(RuntimeEvent::Ui(message));
            }
        })
        .build_as_child(window)?;
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
                "title": if tab.title.is_empty() { tab.url.as_str() } else { tab.title.as_str() }
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
        let script = format!(
            "window.yukkiBrowser && window.yukkiBrowser.render({json});"
        );
        let _ = toolbar.evaluate_script(&script);
    }

    if let Some(tab) = active {
        let title = if tab.title.is_empty() { &tab.url } else { &tab.title };
        window.set_title(&format!("YuKKi Browser — {title}"));
    }
}

fn resize_views(
    toolbar: &WebView,
    tabs: &[Tab],
    size: PhysicalSize<u32>,
    scale_factor: f64,
) {
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
    proxy: &EventLoopProxy<RuntimeEvent>,
    tabs: &mut Vec<Tab>,
    next_tab_id: &mut u64,
    selected_tab_id: &mut u64,
    url: &str,
    size: PhysicalSize<u32>,
) -> Result<(), String> {
    if tabs.len() >= MAX_TABS {
        return Err(format!("The browser tab limit is {MAX_TABS}. Close a tab before opening another."));
    }
    let url = resolve_address(url).map_err(|error| error.to_string())?;
    let id = *next_tab_id;
    *next_tab_id += 1;
    let bounds = page_rect(size, window.scale_factor());
    let engine = build_page(window, proxy, id, url.as_str(), bounds, true)
        .map_err(|error| error.to_string())?;

    for tab in tabs.iter() {
        let _ = tab.engine.view.set_visible(false);
    }
    tabs.push(Tab {
        id,
        engine,
        url: url.to_string(),
        title: String::new(),
    });
    *selected_tab_id = id;
    Ok(())
}

fn persist_state(path: &PathBuf, state: &BrowserState) {
    if let Err(error) = store::save(path, state) {
        eprintln!("Unable to save YuKKi browser state: {error}");
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    #[cfg(target_os = "linux")]
    {
        if env::var_os("WAYLAND_DISPLAY").is_some() {
            if env::var_os("DISPLAY").is_none() {
                return Err("This first browser adapter supports Linux/X11 only; start an XWayland display or use the later GTK-container adapter for native Wayland.".into());
            }
            // Wry's child-window path is X11-only on Linux. Prefer XWayland when
            // a Wayland session also exposes an X11 display.
            env::remove_var("WAYLAND_DISPLAY");
            env::set_var("GDK_BACKEND", "x11");
        }
        gtk::init()?;
    }

    let requested = env::args().skip(1).next().unwrap_or_else(|| DEFAULT_URL.to_owned());
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
    let toolbar = build_toolbar(&window, &proxy, initial_size, scale_factor)?;
    let state_path = store::default_state_path();
    let mut browser_state = store::load(&state_path);
    let mut tabs = Vec::new();
    let mut next_tab_id = 1_u64;
    let mut selected_tab_id = 0_u64;
    add_tab(
        &window,
        &proxy,
        &mut tabs,
        &mut next_tab_id,
        &mut selected_tab_id,
        initial_url.as_str(),
        initial_size,
    )
    .map_err(std::io::Error::other)?;

    sync_chrome(
        &toolbar,
        &window,
        &tabs,
        selected_tab_id,
        &browser_state,
        "Ready · private page storage",
    );

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
            Event::UserEvent(RuntimeEvent::Notice(message)) => {
                sync_chrome(&toolbar, &window, &tabs, selected_tab_id, &browser_state, &message);
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
                    "new_tab" => {
                        let destination = message.url.as_deref().unwrap_or(DEFAULT_URL);
                        status = add_tab(
                            &window,
                            &proxy,
                            &mut tabs,
                            &mut next_tab_id,
                            &mut selected_tab_id,
                            destination,
                            window.inner_size(),
                        )
                        .map(|_| "New tab".to_owned())
                        .unwrap_or_else(|error| error);
                    }
                    "close_tab" => {
                        if tabs.len() > 1 {
                            if let Some(index) = tabs.iter().position(|tab| tab.id == selected_tab_id) {
                                tabs.remove(index);
                            }
                            selected_tab_id = tabs.last().map(|tab| tab.id).unwrap_or(0);
                            set_active_tab(&mut tabs, selected_tab_id);
                            status = "Tab closed".to_owned();
                        } else if let Some(tab) = tabs.first() {
                            if let Ok(url) = resolve_address(DEFAULT_URL) {
                                let _ = tab.engine.navigate(&url);
                            }
                            status = "The last tab cannot be closed".to_owned();
                        }
                    }
                    "switch_tab" => {
                        if let Some(id) = message.tab_id {
                            if tabs.iter().any(|tab| tab.id == id) {
                                selected_tab_id = id;
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
