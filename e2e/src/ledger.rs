// Copyright (c) 2026, NOFire AI
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

//! The event ledger a run wrote, read as plain JSON.
//!
//! The records are parsed into [`serde_json::Value`] rather than hvi's own
//! types, so a test fails when the wire format changes.

use std::path::Path;

use serde_json::Value;

/// The records of one run's `--events` ledger, in file order.
#[derive(Clone, Debug, Default)]
pub struct Ledger {
    /// One parsed record per line.
    records: Vec<Value>,
}

impl Ledger {
    /// Reads the ledger at `path`, or returns an empty ledger if the file does
    /// not exist.
    ///
    /// A last line without its newline is a write that a killed run cut short,
    /// and is left out rather than read as a record.
    ///
    /// # Panics
    ///
    /// Panics if the file cannot be read, or a whole line is not a JSON object,
    /// since every line hvi writes is one.
    pub fn read(path: &Path) -> Ledger {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => panic!("reading the ledger {}: {e}", path.display()),
        };
        let whole = text.rfind('\n').map_or("", |end| &text[..=end]);
        let records = whole
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| {
                let record: Value = serde_json::from_str(line)
                    .unwrap_or_else(|e| panic!("ledger line {line:?}: {e}"));
                assert!(record.is_object(), "ledger line {line:?} is not an object");
                record
            })
            .collect();
        Ledger { records }
    }

    /// Returns every record.
    pub fn records(&self) -> &[Value] {
        &self.records
    }

    /// Returns the records whose `source` is `source`.
    pub fn records_from<'a>(&'a self, source: &'a str) -> impl Iterator<Item = &'a Value> + 'a {
        self.records
            .iter()
            .filter(move |record| record["source"] == source)
    }

    /// Returns the payload of the `vmm.start` record, or `None` if there is
    /// none.
    pub fn start_record(&self) -> Option<&Value> {
        self.records_from("vmm.start")
            .next()
            .map(|record| &record["payload"])
    }

    /// Returns the payload of the `vmm.stop` record, or `None` if there is
    /// none.
    pub fn stop_record(&self) -> Option<&Value> {
        self.records_from("vmm.stop")
            .next()
            .map(|record| &record["payload"])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn torn_last_line_is_left_out() {
        let path = std::env::temp_dir().join(format!("hvi-e2e-ledger-{}", std::process::id()));
        std::fs::write(&path, "{\"source\":\"vmm.start\"}\n{\"source\":\"vmm.st").unwrap();
        let ledger = Ledger::read(&path);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(ledger.records().len(), 1);
        assert_eq!(ledger.records()[0]["source"], "vmm.start");
    }
}
