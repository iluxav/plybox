//! The session record: one JSON object per line, appended as things happen.
//! The proxy writes every allow/refuse; the supervisor writes start and
//! exit. This is the audit trail — the thing none of the compared tools
//! produce as a file you can keep.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

pub struct Record {
    file: Mutex<File>,
}

impl Record {
    pub fn open(path: &Path) -> std::io::Result<Record> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Record { file: Mutex::new(file) })
    }

    /// Append one event. `fields` must be a JSON object; `t` (unix seconds,
    /// ms precision) and `event` are added.
    pub fn event(&self, event: &str, mut fields: Value) {
        let t = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as f64 / 1000.0).unwrap_or(0.0);
        if let Value::Object(ref mut m) = fields {
            m.insert("t".into(), json!(t));
            m.insert("event".into(), json!(event));
        }
        if let Ok(mut f) = self.file.lock() {
            let _ = writeln!(f, "{fields}");
        }
    }
}
