//! Bounded browser history and bookmark persistence.
//!
//! Website storage remains private/incognito in the WebView. This file stores
//! only YuKKi's own URL history and bookmarks.

use serde::{Deserialize, Serialize};
use std::{
    env,
    fs,
    io,
    path::{Path, PathBuf},
};

const MAX_HISTORY: usize = 200;
const MAX_BOOKMARKS: usize = 200;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrowserState {
    pub history: Vec<String>,
    pub bookmarks: Vec<String>,
}

impl BrowserState {
    pub fn record_visit(&mut self, url: &str) {
        self.history.retain(|item| item != url);
        self.history.insert(0, url.to_owned());
        self.history.truncate(MAX_HISTORY);
    }

    pub fn add_bookmark(&mut self, url: &str) -> bool {
        if self.bookmarks.iter().any(|item| item == url) {
            return false;
        }
        self.bookmarks.insert(0, url.to_owned());
        self.bookmarks.truncate(MAX_BOOKMARKS);
        true
    }

    pub fn remove_bookmark(&mut self, url: &str) {
        self.bookmarks.retain(|item| item != url);
    }
}

pub fn default_state_path() -> PathBuf {
    let root = env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .unwrap_or_else(env::temp_dir);
    root.join("yukki-browser").join("browser-state.json")
}

pub fn load(path: &Path) -> BrowserState {
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

pub fn save(path: &Path, state: &BrowserState) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "state path has no parent directory")
    })?;
    fs::create_dir_all(parent)?;

    let temporary = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    fs::write(&temporary, bytes)?;

    // Rename is atomic on the supported Unix targets when source and target
    // are on the same filesystem.
    fs::rename(&temporary, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_is_deduplicated_newest_first_and_bounded() {
        let mut state = BrowserState::default();
        state.record_visit("https://a.example/");
        state.record_visit("https://b.example/");
        state.record_visit("https://a.example/");
        assert_eq!(state.history, ["https://a.example/", "https://b.example/"]);

        for index in 0..250 {
            state.record_visit(&format!("https://{index}.example/"));
        }
        assert_eq!(state.history.len(), MAX_HISTORY);
    }

    #[test]
    fn bookmarks_are_deduplicated_and_removable() {
        let mut state = BrowserState::default();
        assert!(state.add_bookmark("https://example.com/"));
        assert!(!state.add_bookmark("https://example.com/"));
        state.remove_bookmark("https://example.com/");
        assert!(state.bookmarks.is_empty());
    }
}
