//! HPACK static table (RFC 7541, Appendix A) and dynamic table.

/// Static table entry: (index_1based, name, value).
/// Index 0 is unused; entries are 1-based per the spec.
pub(crate) static STATIC_TABLE: &[(&[u8], &[u8])] = &[
    (b":authority", b""),                   //  1
    (b":method", b"GET"),                   //  2
    (b":method", b"POST"),                  //  3
    (b":path", b"/"),                       //  4
    (b":path", b"/index.html"),             //  5
    (b":scheme", b"http"),                  //  6
    (b":scheme", b"https"),                 //  7
    (b":status", b"200"),                   //  8
    (b":status", b"204"),                   //  9
    (b":status", b"206"),                   // 10
    (b":status", b"304"),                   // 11
    (b":status", b"400"),                   // 12
    (b":status", b"404"),                   // 13
    (b":status", b"500"),                   // 14
    (b"accept-charset", b""),               // 15
    (b"accept-encoding", b"gzip, deflate"), // 16
    (b"accept-language", b""),              // 17
    (b"accept-ranges", b""),                // 18
    (b"accept", b""),                       // 19
    (b"access-control-allow-origin", b""),  // 20
    (b"age", b""),                          // 21
    (b"allow", b""),                        // 22
    (b"authorization", b""),                // 23
    (b"cache-control", b""),                // 24
    (b"content-disposition", b""),          // 25
    (b"content-encoding", b""),             // 26
    (b"content-language", b""),             // 27
    (b"content-length", b""),               // 28
    (b"content-location", b""),             // 29
    (b"content-range", b""),                // 30
    (b"content-type", b""),                 // 31
    (b"cookie", b""),                       // 32
    (b"date", b""),                         // 33
    (b"etag", b""),                         // 34
    (b"expect", b""),                       // 35
    (b"expires", b""),                      // 36
    (b"from", b""),                         // 37
    (b"host", b""),                         // 38
    (b"if-match", b""),                     // 39
    (b"if-modified-since", b""),            // 40
    (b"if-none-match", b""),                // 41
    (b"if-range", b""),                     // 42
    (b"if-unmodified-since", b""),          // 43
    (b"last-modified", b""),                // 44
    (b"link", b""),                         // 45
    (b"location", b""),                     // 46
    (b"max-forwards", b""),                 // 47
    (b"proxy-authenticate", b""),           // 48
    (b"proxy-authorization", b""),          // 49
    (b"range", b""),                        // 50
    (b"referer", b""),                      // 51
    (b"refresh", b""),                      // 52
    (b"retry-after", b""),                  // 53
    (b"server", b""),                       // 54
    (b"set-cookie", b""),                   // 55
    (b"strict-transport-security", b""),    // 56
    (b"transfer-encoding", b""),            // 57
    (b"user-agent", b""),                   // 58
    (b"vary", b""),                         // 59
    (b"via", b""),                          // 60
    (b"www-authenticate", b""),             // 61
];

const STATIC_TABLE_LEN: usize = 61;

/// Search result from table lookup.
#[derive(Debug, Clone, Copy)]
pub(crate) enum TableMatch {
    /// Full match (name + value). Carries the 1-based HPACK index.
    Full(usize),
    /// Name-only match. Carries the 1-based HPACK index of the name entry.
    NameOnly(usize),
}

/// Dynamic table (FIFO ring buffer).
pub(crate) struct DynamicTable {
    entries: std::collections::VecDeque<(Vec<u8>, Vec<u8>)>,
    size: usize,
    max_size: usize,
}

impl DynamicTable {
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: std::collections::VecDeque::new(),
            size: 0,
            max_size,
        }
    }

    fn entry_size(name: &[u8], value: &[u8]) -> usize {
        name.len() + value.len() + 32
    }

    pub fn insert(&mut self, name: Vec<u8>, value: Vec<u8>) {
        let entry_sz = Self::entry_size(&name, &value);
        if entry_sz > self.max_size {
            self.entries.clear();
            self.size = 0;
            return;
        }
        while self.size + entry_sz > self.max_size {
            if let Some((n, v)) = self.entries.pop_back() {
                self.size -= Self::entry_size(&n, &v);
            }
        }
        self.entries.push_front((name, value));
        self.size += entry_sz;
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn get(&self, idx: usize) -> Option<(&[u8], &[u8])> {
        self.entries
            .get(idx)
            .map(|(n, v)| (n.as_slice(), v.as_slice()))
    }

    pub fn set_max_size(&mut self, new_max: usize) {
        self.max_size = new_max;
        while self.size > self.max_size {
            if let Some((n, v)) = self.entries.pop_back() {
                self.size -= Self::entry_size(&n, &v);
            }
        }
    }
}

/// Find a header in the static table + dynamic table.
///
/// Returns `TableMatch::Full(idx)` if both name and value match,
/// `TableMatch::NameOnly(idx)` if only the name matches,
/// or `None` if the name is not found anywhere.
pub(crate) fn find_header(name: &[u8], value: &[u8], dynamic: &DynamicTable) -> Option<TableMatch> {
    let mut name_match: Option<usize> = None;

    // Search static table (1-based indices 1..=61)
    for (i, &(sn, sv)) in STATIC_TABLE.iter().enumerate() {
        if sn == name {
            if sv == value {
                return Some(TableMatch::Full(i + 1));
            }
            if name_match.is_none() {
                name_match = Some(i + 1);
            }
        }
    }

    // Search dynamic table (indices STATIC_TABLE_LEN+1 ..)
    for i in 0..dynamic.len() {
        if let Some((dn, dv)) = dynamic.get(i) {
            if dn == name {
                let idx = STATIC_TABLE_LEN + 1 + i;
                if dv == value {
                    return Some(TableMatch::Full(idx));
                }
                if name_match.is_none() {
                    name_match = Some(idx);
                }
            }
        }
    }

    name_match.map(TableMatch::NameOnly)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_table_method_get() {
        let dyn_table = DynamicTable::new(4096);
        match find_header(b":method", b"GET", &dyn_table) {
            Some(TableMatch::Full(idx)) => assert_eq!(idx, 2),
            other => panic!("expected Full(2), got {other:?}"),
        }
    }

    #[test]
    fn test_static_table_name_only() {
        let dyn_table = DynamicTable::new(4096);
        match find_header(b":method", b"PUT", &dyn_table) {
            Some(TableMatch::NameOnly(idx)) => assert_eq!(idx, 2),
            other => panic!("expected NameOnly(2), got {other:?}"),
        }
    }

    #[test]
    fn test_dynamic_table_insert_and_find() {
        let mut dyn_table = DynamicTable::new(4096);
        dyn_table.insert(b"x-custom".to_vec(), b"val1".to_vec());

        match find_header(b"x-custom", b"val1", &dyn_table) {
            Some(TableMatch::Full(idx)) => assert_eq!(idx, STATIC_TABLE_LEN + 1),
            other => panic!("expected Full(62), got {other:?}"),
        }
    }

    #[test]
    fn test_dynamic_table_eviction() {
        let mut dyn_table = DynamicTable::new(100);
        // Each entry: 32 + name.len + value.len
        // "aaaa" + "bbbb" = 32 + 4 + 4 = 40
        dyn_table.insert(b"aaaa".to_vec(), b"bbbb".to_vec());
        dyn_table.insert(b"cccc".to_vec(), b"dddd".to_vec());
        // 80 < 100, both fit
        assert_eq!(dyn_table.len(), 2);

        dyn_table.insert(b"eeee".to_vec(), b"ffff".to_vec());
        // 120 > 100, oldest evicted → 2 entries
        assert_eq!(dyn_table.len(), 2);
    }
}
