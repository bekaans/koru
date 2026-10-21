//! Persistent notification queue (ADR-0007).
//! The input is treated as the on-disk queue file's content: first the pure validator, then
//! `PersistentQueue::open` with a real file (an invalid file is set aside as `.corrupt`, a
//! valid file is loaded). Expected: no crash; if the pure validator passes, `open` loads the queue.
#![no_main]

use std::fs;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::sync::atomic::{AtomicU64, Ordering};

use koru_notify::{PersistentQueue, queue_content_valid};
use libfuzzer_sys::fuzz_target;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fuzz_target!(|data: &[u8]| {
    let valid = queue_content_valid(data);
    if data.len() > 256 * 1024 {
        return;
    }
    // On macOS /var is a symlink; the queue does not follow symlinks, so a canonical path is used.
    let base = fs::canonicalize(std::env::temp_dir()).expect("temp dir");
    let dir = base.join(format!("koru-fuzz-queue-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::Relaxed)));
    fs::DirBuilder::new().mode(0o700).create(&dir).expect("temp dir");
    let file = dir.join("ntfy.queue");
    {
        use std::io::Write;
        let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&file).expect("file");
        f.write_all(data).expect("write");
    }
    let outcome = PersistentQueue::open(&dir, "ntfy", 100);
    if valid {
        let k = outcome.expect("valid content must load");
        for record in k.records() {
            let _ = record.notification();
        }
    }
    let _ = fs::remove_dir_all(&dir);
});
