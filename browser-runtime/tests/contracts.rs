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
