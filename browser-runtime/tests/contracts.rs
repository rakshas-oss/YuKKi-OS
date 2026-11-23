use yukki_browser_runtime::{
    policy::{resolve_address, validate_navigation, NavigationError},
    store::BrowserState,
    MAX_TABS,
};

#[test]
fn runtime_limits_are_explicit_and_bounded() {
    assert_eq!(MAX_TABS, 8);
}

#[test]
fn browser_contract_rejects_active_and_local_schemes() {
    assert_eq!(
        validate_navigation("javascript:alert(1)"),
        Err(NavigationError::UnsupportedScheme)
    );
    assert_eq!(
        validate_navigation("file:///etc/passwd"),
        Err(NavigationError::UnsupportedScheme)
    );
    assert_eq!(
        validate_navigation("http://127.0.0.1"),
        Err(NavigationError::LocalAddress)
    );
}

#[test]
fn address_bar_supports_hosts_and_search_terms() {
    assert_eq!(resolve_address("example.org").unwrap().host_str(), Some("example.org"));
    assert_eq!(resolve_address("web engine design").unwrap().host_str(), Some("duckduckgo.com"));
}

#[test]
fn browser_state_has_separate_history_and_bookmarks() {
    let mut state = BrowserState::default();
    state.record_visit("https://example.org/");
    assert!(state.add_bookmark("https://example.org/"));
    assert_eq!(state.history.len(), 1);
    assert_eq!(state.bookmarks.len(), 1);
}

#[test]
fn local_chrome_exposes_navigation_and_graphics_capability_probe() {
    let shell = include_str!("../assets/shell.html");
    for action in [
        "back", "forward", "reload", "navigate", "bookmark",
        "new_tab", "close_tab", "switch_tab", "graphics_test",
    ] {
        assert!(shell.contains(&format!("\"action\": \"{action}\"")) ||
                shell.contains(&format!("action: \"{action}\"")),
                "missing browser action {action}");
    }
    assert!(shell.contains("id=\"graphics\""));
    assert!(shell.contains("id=\"graphics-test\""));
    assert!(shell.contains("never sends webpage pixels"));
    let native_host = include_str!("../src/main.rs");
    assert!(native_host.contains("graphics_test"));
    assert!(native_host.contains("run_rgba_gain"));
    assert!(native_host.contains("build_gtk"));
    assert!(native_host.contains("YUKKI_BROWSER_DISPLAY_BACKEND"));
    assert!(native_host.contains("xwayland"));
    assert!(!native_host.contains("WINIT_UNIX_BACKEND"));
    assert!(shell.contains("navigator.gpu"));
    assert!(shell.contains("getContext(\"webgl2\")"));
}
