//! YuKKi-OS native browser runtime contracts.
//!
//! This crate is deliberately separate from browser-wasm: the WASM workspace
//! remains a portable gateway client, while this native crate hosts an OS
//! WebView engine for general page rendering.

pub mod accelerator;
pub mod policy;
pub mod store;

use url::Url;

/// Maximum simultaneously resident page views in the initial runtime.
pub const MAX_TABS: usize = 8;

/// Narrow contract implemented by a concrete page-rendering engine.
///
/// Host-side policy is applied before navigation. This interface intentionally
/// does not expose native handles, page JavaScript evaluation, or host services
/// to web content.
pub trait EngineAdapter {
    fn navigate(&self, url: &Url) -> Result<(), String>;
    fn back(&self) -> Result<(), String>;
    fn forward(&self) -> Result<(), String>;
    fn reload(&self) -> Result<(), String>;
    fn can_go_back(&self) -> Result<bool, String>;
    fn can_go_forward(&self) -> Result<bool, String>;
}
