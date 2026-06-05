use std::fs;
use std::path::{Path, PathBuf};

const ASSERTION_TOKENS: &[&str] = &[
    "assert!",
    "assert_eq!",
    "assert_ne!",
    "debug_assert!",
    "debug_assert_eq!",
    "debug_assert_ne!",
    "prop_assert!",
    "prop_assert_eq!",
    "prop_assert_ne!",
    "expect_err(",
    "unwrap_err(",
    "panic!(",
    "unreachable!(",
];

#[derive(Debug)]
struct TestFailure {
    path: PathBuf,
    line: usize,
    name: String,
}

#[test]
fn all_workspace_tests_contain_explicit_assertions() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("lkrequest crate lives in the workspace root");

    let mut failures = Vec::new();
    let mut total_tests = 0usize;

    for path in rust_files_under(workspace_root) {
        let source = fs::read_to_string(&path).expect("read Rust source");
        let (file_total, file_failures) = scan_file_for_missing_assertions(&path, &source);
        total_tests += file_total;
        failures.extend(file_failures);
    }

    assert!(
        total_tests > 0,
        "test assertion scanner did not discover any test functions"
    );

    if !failures.is_empty() {
        let details = failures
            .iter()
            .map(|failure| {
                format!(
                    "{}:{}: {}",
                    failure.path.display(),
                    failure.line,
                    failure.name
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        panic!(
            "found {} test(s) without an explicit assertion:\n{}",
            failures.len(),
            details
        );
    }
}

fn rust_files_under(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir).expect("read directory");
        for entry in entries {
            let entry = entry.expect("read directory entry");
            let path = entry.path();
            if path.is_dir() {
                if should_skip_dir(&path) {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }

    files
}

fn should_skip_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(
                name,
                "target" | "deps" | ".cargo" | ".git" | ".cursor" | ".uv-cache"
            )
        })
}

fn scan_file_for_missing_assertions(path: &Path, source: &str) -> (usize, Vec<TestFailure>) {
    let lines = source.lines().collect::<Vec<_>>();
    let mut i = 0usize;
    let mut total = 0usize;
    let mut failures = Vec::new();

    while i < lines.len() {
        if !is_test_attr(lines[i]) {
            i += 1;
            continue;
        }

        let attr_start = i;
        let mut fn_line = i + 1;
        while fn_line < lines.len() && lines[fn_line].trim_start().starts_with("#[") {
            fn_line += 1;
        }
        if fn_line >= lines.len() {
            break;
        }

        let Some(name) = parse_fn_name(lines[fn_line]) else {
            i = fn_line + 1;
            continue;
        };

        let mut body_end = fn_line;
        let mut seen_open = false;
        let mut brace_depth = 0isize;
        while body_end < lines.len() {
            let line = lines[body_end];
            if line.contains('{') {
                seen_open = true;
            }
            brace_depth += line.matches('{').count() as isize;
            brace_depth -= line.matches('}').count() as isize;
            if seen_open && brace_depth == 0 {
                break;
            }
            body_end += 1;
        }

        total += 1;
        let attrs = lines[attr_start..fn_line].join("\n");
        let body = lines[fn_line..=body_end.min(lines.len() - 1)].join("\n");
        if !has_explicit_assertion(&attrs, &body) {
            failures.push(TestFailure {
                path: path.to_path_buf(),
                line: fn_line + 1,
                name,
            });
        }

        i = body_end + 1;
    }

    (total, failures)
}

fn is_test_attr(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("#[test") || trimmed.starts_with("#[tokio::test")
}

fn parse_fn_name(line: &str) -> Option<String> {
    let idx = line.find("fn ")? + 3;
    let rest = &line[idx..];
    let end = rest
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .unwrap_or(rest.len());
    (end > 0).then(|| rest[..end].to_string())
}

fn has_explicit_assertion(attrs: &str, body: &str) -> bool {
    attrs.contains("should_panic") || ASSERTION_TOKENS.iter().any(|token| body.contains(token))
}
