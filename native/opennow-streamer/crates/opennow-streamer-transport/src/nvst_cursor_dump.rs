//! Capture-only diagnostics for server cursor notifications.
//!
//! The native bitmap cursor (`0x0110`) pixel layout is not yet known. To recover it, this module
//! writes every *distinct* cursor-related data-channel message in full to
//! `diagnostics/cursor-capture.log`, next to `native-streamer.log`. The regular log truncates lines
//! at 2 KiB and the embedded runtime's `eprintln!` output never reaches a file, so neither can hold
//! a complete bitmap.
//!
//! Only cursor notifications (and a few messages right after a bitmap, in case its pixels are
//! split across messages) are written. The file is capped, and identical payloads are written once.

use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::fs::{File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Hard cap for the capture file. Enough for hundreds of 64x64 BGRA cursors as hex.
const MAX_CAPTURE_BYTES: u64 = 24 * 1024 * 1024;
/// Messages dumped after a bitmap notification, in case its pixels follow separately.
const FOLLOW_MESSAGES: u32 = 6;
/// Largest single message written in full; larger ones are truncated and flagged.
const MAX_MESSAGE_BYTES: usize = 256 * 1024;
const BITMAP_CURSOR_CODE: [u8; 2] = 0x0110_u16.to_le_bytes();

struct DumpState {
    file: Option<File>,
    opened_for: Option<String>,
    written: u64,
    seen: HashSet<u64>,
    follow_remaining: u32,
    sequence: u64,
}

fn state() -> &'static Mutex<DumpState> {
    static STATE: OnceLock<Mutex<DumpState>> = OnceLock::new();
    STATE.get_or_init(|| {
        Mutex::new(DumpState {
            file: None,
            opened_for: None,
            written: 0,
            seen: HashSet::new(),
            follow_remaining: 0,
            sequence: 0,
        })
    })
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

fn fingerprint(bytes: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(value, "{byte:02x}");
    }
    value
}

impl DumpState {
    /// Opens (or reopens after a log-path change) `cursor-capture.log` beside the streamer log.
    fn ensure_file(&mut self) -> bool {
        let Some(log_path) = opennow_streamer_protocol::log::log_file_path() else {
            return false;
        };
        if self.opened_for.as_deref() == Some(log_path.as_str()) && self.file.is_some() {
            return true;
        }
        let directory = Path::new(&log_path)
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        let path = directory.join("cursor-capture.log");
        let Ok(file) = OpenOptions::new().create(true).append(true).open(&path) else {
            return false;
        };
        self.written = file.metadata().map(|metadata| metadata.len()).unwrap_or(0);
        self.file = Some(file);
        self.opened_for = Some(log_path);
        let header = format!(
            "{} session-start build=cursor-capture-v1 os={} arch={}\n",
            now_ms(),
            std::env::consts::OS,
            std::env::consts::ARCH
        );
        self.write_raw(&header);
        true
    }

    fn write_raw(&mut self, line: &str) {
        if self.written + line.len() as u64 > MAX_CAPTURE_BYTES {
            return;
        }
        if let Some(file) = self.file.as_mut()
            && file.write_all(line.as_bytes()).is_ok()
        {
            self.written += line.len() as u64;
        }
    }

    fn record(&mut self, kind: &str, channel: &str, detail: &str, bytes: &[u8]) {
        if !self.seen.insert(fingerprint(bytes)) {
            return;
        }
        if !self.ensure_file() {
            return;
        }
        self.sequence += 1;
        let shown = &bytes[..bytes.len().min(MAX_MESSAGE_BYTES)];
        let line = format!(
            "{} seq={} kind={kind} channel={channel} {detail} bytes={}{} hex={}\n",
            now_ms(),
            self.sequence,
            bytes.len(),
            if shown.len() < bytes.len() {
                " truncated=1"
            } else {
                ""
            },
            hex(shown),
        );
        self.write_raw(&line);
    }
}

/// Records one inbound data-channel message.
///
/// * `cursor_commands` lists the `(command, offset)` pairs the cursor parser found in `bytes`.
/// * `is_cursor_channel` marks messages on the negotiated `cursor_channel`.
pub(crate) fn record_data_channel_message(
    channel: &str,
    bytes: &[u8],
    cursor_commands: &[(u16, usize)],
    is_cursor_channel: bool,
) {
    let mut guard = match state().lock() {
        Ok(guard) => guard,
        Err(_) => return,
    };
    let has_bitmap = cursor_commands
        .iter()
        .any(|(command, _)| *command == 0x0110);
    // A bitmap whose declared length overruns this message is not parsed at all, so also catch a
    // leading 0x0110 frame header here.
    let leading_partial_bitmap =
        !has_bitmap && bytes.len() >= 4 && bytes[..2] == BITMAP_CURSOR_CODE;

    if is_cursor_channel {
        guard.record("cursor-channel", channel, "", bytes);
    } else if has_bitmap || leading_partial_bitmap {
        let commands = cursor_commands
            .iter()
            .map(|(command, offset)| format!("0x{command:04x}@{offset}"))
            .collect::<Vec<_>>()
            .join(",");
        let kind = if has_bitmap {
            "bitmap"
        } else {
            "bitmap-partial"
        };
        guard.record(kind, channel, &format!("commands={commands}"), bytes);
        guard.follow_remaining = FOLLOW_MESSAGES;
        return;
    } else if !cursor_commands.is_empty() {
        let commands = cursor_commands
            .iter()
            .map(|(command, offset)| format!("0x{command:04x}@{offset}"))
            .collect::<Vec<_>>()
            .join(",");
        guard.record("system", channel, &format!("commands={commands}"), bytes);
    }

    if guard.follow_remaining > 0 {
        guard.follow_remaining -= 1;
        guard.record("follow", channel, "", bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encodes_every_byte() {
        assert_eq!(hex(&[0x00, 0x10, 0xff]), "0010ff");
    }

    #[test]
    fn bitmaps_are_written_in_full_once_with_following_messages() {
        let mut directory = std::env::temp_dir();
        directory.push(format!("opennow-cursor-dump-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let log = directory.join("native-streamer.log");
        opennow_streamer_protocol::log::set_log_file(log.to_str().unwrap()).unwrap();

        // 0x0110 frame with a payload far beyond the regular log's 2 KiB line limit.
        let mut bitmap = vec![0x10, 0x01, 0x00, 0x10];
        bitmap.extend((0..4096_u32).map(|value| value as u8));
        record_data_channel_message("control", &bitmap, &[(0x0110, 0)], false);
        record_data_channel_message("control", &bitmap, &[(0x0110, 0)], false);
        record_data_channel_message("control", &[0xaa, 0xbb], &[], false);
        record_data_channel_message("control", &[0x01, 0x02], &[], false);

        let body = std::fs::read_to_string(directory.join("cursor-capture.log")).unwrap();
        assert!(body.contains("session-start build=cursor-capture-v1"));
        assert_eq!(body.matches("kind=bitmap ").count(), 1, "{body}");
        assert!(body.contains(&hex(&bitmap)));
        assert!(body.contains("kind=follow channel=control  bytes=2 hex=aabb"));
        assert!(body.contains("hex=0102"));
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn identical_payloads_share_a_fingerprint() {
        assert_eq!(fingerprint(&[1, 2, 3]), fingerprint(&[1, 2, 3]));
        assert_ne!(fingerprint(&[1, 2, 3]), fingerprint(&[1, 2, 4]));
    }
}
