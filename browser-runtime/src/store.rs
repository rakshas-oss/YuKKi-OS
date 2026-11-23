//! Bounded browser history and bookmark persistence.
//!
//! Website storage remains private/incognito in the WebView. This file stores
//! only YuKKi's own URL history and bookmarks.

use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    fs::OpenOptions,
    io,
    path::{Path, PathBuf},
};

const MAX_HISTORY: usize = 200;
const MAX_BOOKMARKS: usize = 200;
const MAX_URL_BYTES: usize = 2048;
const MAX_STATE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrowserState {
    pub history: Vec<String>,
    pub bookmarks: Vec<String>,
}

impl BrowserState {
    pub fn record_visit(&mut self, url: &str) {
        if !valid_stored_url(url) {
            return;
        }
        self.history.retain(|item| item != url);
        self.history.insert(0, url.to_owned());
        self.history.truncate(MAX_HISTORY);
    }

    pub fn add_bookmark(&mut self, url: &str) -> bool {
        if !valid_stored_url(url) || self.bookmarks.iter().any(|item| item == url) {
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

fn valid_stored_url(raw: &str) -> bool {
    if raw.len() > MAX_URL_BYTES {
        return false;
    }
    url::Url::parse(raw)
        .map(|url| {
            matches!(url.scheme(), "http" | "https")
                && url.username().is_empty()
                && url.password().is_none()
        })
        .unwrap_or(false)
}

pub fn default_state_path() -> PathBuf {
    let root = env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .unwrap_or_else(env::temp_dir);
    root.join("yukki-browser").join("browser-state.json")
}

pub fn load(path: &Path) -> BrowserState {
    let Ok(metadata) = fs::metadata(path) else {
        return BrowserState::default();
    };
    if metadata.len() > MAX_STATE_BYTES {
        return BrowserState::default();
    }

    let Ok(bytes) = fs::read(path) else {
        return BrowserState::default();
    };
    let Ok(mut state) = serde_json::from_slice::<BrowserState>(&bytes) else {
        return BrowserState::default();
    };

    state.history.retain(|url| valid_stored_url(url));
    state.history.dedup();
    state.history.truncate(MAX_HISTORY);
    state.bookmarks.retain(|url| valid_stored_url(url));
    state.bookmarks.sort();
    state.bookmarks.dedup();
    state.bookmarks.truncate(MAX_BOOKMARKS);
    state
}

pub fn save(path: &Path, state: &BrowserState) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "state path has no parent directory")
    })?;
    fs::create_dir_all(parent)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }

    let mut bounded = state.clone();
    bounded.history.retain(|url| valid_stored_url(url));
    bounded.history.truncate(MAX_HISTORY);
    bounded.bookmarks.retain(|url| valid_stored_url(url));
    bounded.bookmarks.truncate(MAX_BOOKMARKS);

    let bytes = serde_json::to_vec_pretty(&bounded)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "browser state exceeds the 1 MiB persistence limit",
        ));
    }

    let temporary = path.with_extension("json.tmp");
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    use std::io::Write;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);

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
        assert_eq!(
            state.history.iter().map(String::as_str).collect::<Vec<_>>(),
            vec!["https://a.example/", "https://b.example/"]
        );

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

    #[test]
    fn state_rejects_non_web_and_oversized_urls() {
        let mut state = BrowserState::default();
        state.record_visit("file:///etc/passwd");
        state.record_visit(&format!("https://{}.example/", "x".repeat(MAX_URL_BYTES)));
        assert!(state.history.is_empty());
        assert!(!state.add_bookmark("javascript:alert(1)"));
    }
}
