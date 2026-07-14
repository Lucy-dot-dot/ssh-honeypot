//! Text-processing utilities used as pipeline stages and as standalone commands.
//!
//! These implement the common filter commands attackers pipe together (grep, head,
//! tail, sort, wc, ...). When used as the first stage they read their input from
//! files in the virtual filesystem; when used in a pipeline they operate on the
//! previous stage's output.

use sha2::{Digest, Sha256};

use crate::commands::context::CommandContext;
use crate::filesystem::fs2::FileContent;

/// Result of running a filter: `(output, exit_success)`.
pub type FilterOutcome = Option<(String, bool)>;

/// Whether `name` is a recognized filter command.
pub fn is_filter(name: &str) -> bool {
    matches!(
        name,
        "grep"
            | "egrep"
            | "fgrep"
            | "head"
            | "tail"
            | "sort"
            | "uniq"
            | "wc"
            | "cut"
            | "tr"
            | "rev"
            | "tac"
            | "nl"
            | "base64"
            | "strings"
            | "sed"
            | "awk"
            | "column"
            | "tee"
            | "cat"
            | "xargs"
            | "sha256sum"
            | "md5sum"
    )
}

/// Apply a filter command. `input` is the piped stdin (empty for the first stage).
/// Returns `None` if `name` is not a recognized filter.
pub async fn apply_filter(
    name: &str,
    args: &[String],
    input: &str,
    context: &CommandContext,
) -> FilterOutcome {
    match name {
        "grep" | "egrep" | "fgrep" => Some(grep(name, args, input, context).await),
        "head" => Some(head_tail(args, input, context, true).await),
        "tail" => Some(head_tail(args, input, context, false).await),
        "sort" => Some(sort_cmd(args, input, context).await),
        "uniq" => Some(uniq_cmd(args, input, context).await),
        "wc" => Some(wc_cmd(args, input, context).await),
        "cut" => Some(cut_cmd(args, input, context).await),
        "tr" => Some(tr_cmd(args, input)),
        "rev" => Some((per_line(input, |l| l.chars().rev().collect()), true)),
        "tac" => Some((
            input.lines().rev().collect::<Vec<_>>().join("\n") + "\n",
            true,
        )),
        "nl" => Some((nl_cmd(input), true)),
        "base64" => Some(base64_cmd(args, input, context).await),
        "strings" => Some(strings_cmd(args, input, context).await),
        "sed" => Some(sed_cmd(args, input, context).await),
        "awk" => Some(awk_cmd(args, input, context).await),
        "column" => Some(column_cmd(args, input, context).await),
        "tee" | "cat" => Some((input.to_string(), true)),
        "xargs" => Some(xargs_cmd(args, input)),
        "sha256sum" => Some(hash_cmd::<Sha256>(args, input, context).await),
        "md5sum" => Some((md5_stub(args, input, context).await, true)),
        _ => None,
    }
}

async fn read_file(path: &str, context: &CommandContext) -> Option<String> {
    let fs = context.filesystem.read().await;
    let entry = fs.follow_symlink(path).ok()?;
    match entry.file_content.as_ref()? {
        FileContent::RegularFile(bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),
        _ => None,
    }
}

/// Gather input from explicit file arguments, falling back to `piped` when there are none.
async fn gather_input(file_args: &[String], piped: &str, context: &CommandContext) -> String {
    if file_args.is_empty() {
        return piped.to_string();
    }
    let mut out = String::new();
    for path in file_args {
        match read_file(path, context).await {
            Some(content) => {
                out.push_str(&content);
                if !out.ends_with('\n') {
                    out.push('\n');
                }
            }
            // Missing/unreadable files produce no stdout: real tools write the
            // diagnostic to stderr, which (inside `$(...)`) is discarded.
            None => {}
        }
    }
    out
}

struct GrepOpts {
    ignore_case: bool,
    invert: bool,
    line_number: bool,
    count: bool,
    fixed: bool,
    word: bool,
    pattern: String,
}

fn parse_grep(name: &str, args: &[String]) -> Result<GrepOpts, (String, bool)> {
    let mut opts = GrepOpts {
        ignore_case: false,
        invert: false,
        line_number: false,
        count: false,
        fixed: false,
        word: false,
        pattern: String::new(),
    };
    if name == "fgrep" {
        opts.fixed = true;
    }
    if name == "egrep" {
        opts.fixed = false;
    }

    let mut pattern: Option<String> = None;
    let mut take_pattern = false;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if take_pattern {
            pattern = Some(a.clone());
            take_pattern = false;
            i += 1;
            continue;
        }
        if a == "-e" {
            take_pattern = true;
            i += 1;
            continue;
        }
        if let Some(rest) = a.strip_prefix("-e") {
            pattern = Some(rest.to_string());
            i += 1;
            continue;
        }
        if a == "--" {
            i += 1;
            if pattern.is_none() && i < args.len() {
                pattern = Some(args[i].clone());
            }
            break;
        }
        if a.starts_with("--") {
            match a.as_str() {
                "--ignore-case" | "-i" => opts.ignore_case = true,
                "--invert-match" => opts.invert = true,
                "--line-number" => opts.line_number = true,
                "--count" => opts.count = true,
                "--fixed-strings" => opts.fixed = true,
                "--word-regexp" => opts.word = true,
                _ => {}
            }
            i += 1;
            continue;
        }
        if let Some(flags) = a.strip_prefix('-') {
            if flags.is_empty() {
                if pattern.is_none() {
                    pattern = Some("-".to_string());
                }
            } else {
                for f in flags.chars() {
                    match f {
                        'i' => opts.ignore_case = true,
                        'v' => opts.invert = true,
                        'n' => opts.line_number = true,
                        'c' => opts.count = true,
                        'F' => opts.fixed = true,
                        'E' => opts.fixed = false,
                        'w' => opts.word = true,
                        _ => {}
                    }
                }
            }
            i += 1;
            continue;
        }
        if pattern.is_none() {
            pattern = Some(a.clone());
        }
        i += 1;
    }

    let Some(pattern) = pattern else {
        return Err(("grep: missing pattern\n".to_string(), false));
    };
    opts.pattern = strip_regex_anchors(&pattern, opts.fixed);
    Ok(opts)
}

/// Reduce a regex-ish pattern to a literal substring (best-effort for common cases).
fn strip_regex_anchors(pattern: &str, _fixed: bool) -> String {
    pattern
        .replace("\\.", ".")
        .replace("\\/", "/")
        .replace("\\-", "-")
        .replace("\\$", "$")
        .replace("\\*", "*")
        .replace("\\+", "+")
        .replace("\\?", "?")
        .replace("\\(", "(")
        .replace("\\)", ")")
        .replace("\\[", "[")
        .replace("\\]", "]")
        .replace("\\{", "{")
        .replace("\\}", "}")
        .replace("\\|", "|")
        .replace("\\^", "^")
        .replace("\\\\", "\\")
}

fn line_matches(line: &str, opts: &GrepOpts) -> bool {
    let (haystack, needle) = if opts.ignore_case {
        (line.to_lowercase(), opts.pattern.to_lowercase())
    } else {
        (line.to_string(), opts.pattern.clone())
    };
    let found = if opts.word {
        word_boundary_match(&haystack, &needle)
    } else {
        haystack.contains(&needle)
    };
    found ^ opts.invert
}

fn word_boundary_match(haystack: &str, needle: &str) -> bool {
    let mut start = 0;
    while let Some(idx) = haystack[start..].find(&needle) {
        let abs = start + idx;
        let before_ok = abs == 0 || !haystack.as_bytes()[abs - 1].is_ascii_alphanumeric();
        let after = abs + needle.len();
        let after_ok =
            after >= haystack.len() || !haystack.as_bytes()[after].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
        start = abs + needle.len();
        if start >= haystack.len() {
            break;
        }
    }
    false
}

async fn grep(
    name: &str,
    args: &[String],
    input: &str,
    context: &CommandContext,
) -> (String, bool) {
    let opts = match parse_grep(name, args) {
        Ok(o) => o,
        Err((msg, succ)) => return (format!("{}", msg.replace('\n', "\r\n")), succ),
    };

    let files: Vec<String> = {
        let mut iter = args.iter();
        let mut seen_pattern = false;
        let mut collected = Vec::new();
        let mut take_pattern = false;
        while let Some(a) = iter.next() {
            if take_pattern {
                take_pattern = false;
                continue;
            }
            if a == "-e" {
                take_pattern = true;
                continue;
            }
            if a.starts_with("--") || (a.starts_with('-') && a.len() > 1) {
                continue;
            }
            if !seen_pattern && !a.starts_with('-') {
                seen_pattern = true;
                continue;
            }
            if a == "-" {
                continue;
            }
            collected.push(a.clone());
        }
        collected
    };

    let source = gather_input(&files, input, context).await;

    let mut out = String::new();
    let mut matches = 0usize;
    for (lineno, line) in source.lines().enumerate() {
        if line_matches(line, &opts) {
            matches += 1;
            if !opts.count {
                if opts.line_number {
                    out.push_str(&format!("{}:", lineno + 1));
                }
                out.push_str(line);
                out.push_str("\r\n");
            }
        }
    }

    if opts.count {
        return (format!("{}\r\n", matches), matches > 0);
    }

    let success = if opts.invert { true } else { matches > 0 };
    (out, success)
}

fn parse_numeric_count(args: &[String], default: usize, flag: char) -> usize {
    for a in args {
        if let Some(rest) = a.strip_prefix("--lines=") {
            if let Ok(n) = rest.parse::<usize>() {
                return n;
            }
        }
        if let Some(rest) = a.strip_prefix('-') {
            if let Some(num_part) = rest.strip_prefix(flag) {
                if let Ok(n) = num_part.parse::<usize>() {
                    return n;
                }
            } else if rest.starts_with(flag) {
                continue;
            }
            if let Ok(n) = rest.parse::<usize>() {
                return n;
            }
        }
    }
    default
}

async fn head_tail(
    args: &[String],
    input: &str,
    context: &CommandContext,
    is_head: bool,
) -> (String, bool) {
    let n = parse_numeric_count(args, 10, 'n');
    let files: Vec<String> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .cloned()
        .collect();
    let source = gather_input(&files, input, context).await;
    let lines: Vec<&str> = source.lines().collect();
    let chosen: Vec<&str> = if is_head {
        lines.into_iter().take(n).collect()
    } else {
        let start = lines.len().saturating_sub(n);
        lines[start..].to_vec()
    };
    let mut out = chosen.join("\n");
    if !out.is_empty() {
        out.push_str("\r\n");
    }
    (out, true)
}

async fn sort_cmd(args: &[String], input: &str, context: &CommandContext) -> (String, bool) {
    let reverse = flag_present(args, 'r', "--reverse");
    let numeric = flag_present(args, 'n', "--numeric-sort");
    let unique = flag_present(args, 'u', "--unique");
    let files: Vec<String> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .cloned()
        .collect();
    let source = gather_input(&files, input, context).await;
    let mut lines: Vec<&str> = source.lines().collect();
    lines.sort_by(|a, b| {
        let ord = if numeric {
            let na: f64 = a.trim().parse().unwrap_or(0.0);
            let nb: f64 = b.trim().parse().unwrap_or(0.0);
            na.partial_cmp(&nb).unwrap_or(std::cmp::Ordering::Equal)
        } else {
            a.cmp(b)
        };
        if reverse { ord.reverse() } else { ord }
    });
    if unique {
        lines.dedup();
    }
    let mut out = lines.join("\n");
    if !out.is_empty() {
        out.push_str("\r\n");
    }
    (out, true)
}

async fn uniq_cmd(args: &[String], input: &str, context: &CommandContext) -> (String, bool) {
    let count = flag_present(args, 'c', "--count");
    let only_dup = flag_present(args, 'd', "--repeated");
    let only_uniq = flag_present(args, 'u', "--unique");
    let files: Vec<String> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .cloned()
        .collect();
    let source = gather_input(&files, input, context).await;
    let lines: Vec<&str> = source.lines().collect();

    let mut out = String::new();
    let mut i = 0;
    while i < lines.len() {
        let current = lines[i];
        let mut j = i + 1;
        while j < lines.len() && lines[j] == current {
            j += 1;
        }
        let occurrences = j - i;
        let emit = if only_dup {
            occurrences > 1
        } else if only_uniq {
            occurrences == 1
        } else {
            true
        };
        if emit {
            if count {
                out.push_str(&format!("{:>7} ", occurrences));
            }
            out.push_str(current);
            out.push_str("\r\n");
        }
        i = j;
    }
    (out, true)
}

async fn wc_cmd(args: &[String], input: &str, context: &CommandContext) -> (String, bool) {
    let want_lines = flag_present(args, 'l', "--lines");
    let want_words = flag_present(args, 'w', "--words");
    let want_chars = flag_present(args, 'c', "--bytes");
    let any = want_lines || want_words || want_chars;

    let files: Vec<String> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .cloned()
        .collect();
    let source = gather_input(&files, input, context).await;
    let lines = source.lines().count();
    let words = source.split_whitespace().count();
    let chars = source.len();

    let mut parts: Vec<String> = Vec::new();
    if !any || want_lines {
        parts.push(format!("{:>7}", lines));
    }
    if !any || want_words {
        parts.push(format!("{:>7}", words));
    }
    if !any || want_chars {
        parts.push(format!("{:>7}", chars));
    }
    if !files.is_empty() {
        parts.push(files[0].clone());
    }
    (format!("{}\r\n", parts.join(" ")), true)
}

async fn cut_cmd(args: &[String], input: &str, context: &CommandContext) -> (String, bool) {
    let mut delim = '\t';
    let mut fields: Option<Vec<usize>> = None;
    let mut chars: Option<Vec<usize>> = None;
    let files: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(rest) = a.strip_prefix("-d") {
            delim = rest.chars().next().unwrap_or('\t');
        } else if let Some(rest) = a.strip_prefix("-f") {
            fields = Some(parse_field_list(rest));
        } else if let Some(rest) = a.strip_prefix("-c") {
            chars = Some(parse_field_list(rest));
        } else if a == "--delimiter" && i + 1 < args.len() {
            i += 1;
            delim = args[i].chars().next().unwrap_or('\t');
        }
        i += 1;
    }

    let source = gather_input(&files, input, context).await;
    let mut out = String::new();
    for line in source.lines() {
        if let Some(flist) = &fields {
            let split: Vec<&str> = line.split(delim).collect();
            let selected: Vec<&str> = flist
                .iter()
                .filter_map(|&idx| split.get(idx.wrapping_sub(1)))
                .copied()
                .collect();
            out.push_str(&selected.join(&delim.to_string()));
        } else if let Some(clist) = &chars {
            let chars_vec: Vec<char> = line.chars().collect();
            let selected: String = clist
                .iter()
                .filter_map(|&idx| chars_vec.get(idx.wrapping_sub(1)))
                .collect();
            out.push_str(&selected);
        } else {
            out.push_str(line);
        }
        out.push_str("\r\n");
    }
    (out, true)
}

fn parse_field_list(spec: &str) -> Vec<usize> {
    let mut out = Vec::new();
    for part in spec.split(',') {
        if let Some((start, end)) = part.split_once('-') {
            let s: usize = start.parse().unwrap_or(1);
            let e: usize = end.parse().unwrap_or(usize::MAX);
            out.extend(s..=e.min(usize::MAX));
        } else if let Ok(n) = part.parse::<usize>() {
            out.push(n);
        }
    }
    out
}

fn tr_cmd(args: &[String], input: &str) -> (String, bool) {
    let delete = flag_present(args, 'd', "--delete");
    let squeeze = flag_present(args, 's', "--squeeze-repeats");
    let operands: Vec<String> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .cloned()
        .collect();

    if delete && !operands.is_empty() {
        let set1: Vec<char> = expand_set(&operands[0]);
        let filtered: String = input.chars().filter(|c| !set1.contains(c)).collect();
        if squeeze && operands.len() > 1 {
            return (squeeze_repeats(&filtered, &expand_set(&operands[1])), true);
        }
        return (filtered, true);
    }

    if operands.len() >= 2 {
        let set1 = expand_set(&operands[0]);
        let set2 = expand_set(&operands[1]);
        let mut out = String::new();
        for c in input.chars() {
            if let Some(pos) = set1.iter().position(|&x| x == c) {
                if let Some(&rep) = set2.get(pos).or_else(|| set2.last()) {
                    out.push(rep);
                } else {
                    out.push(c);
                }
            } else {
                out.push(c);
            }
        }
        if squeeze {
            return (squeeze_repeats(&out, &set2), true);
        }
        return (out, true);
    }

    (input.to_string(), true)
}

fn expand_set(spec: &str) -> Vec<char> {
    let chars: Vec<char> = spec.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if i + 2 < chars.len() && chars[i + 1] == '-' {
            let start = chars[i] as u32;
            let end = chars[i + 2] as u32;
            for code in start..=end {
                if let Some(ch) = char::from_u32(code) {
                    out.push(ch);
                }
            }
            i += 3;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

fn squeeze_repeats(input: &str, set: &[char]) -> String {
    let mut out = String::new();
    let mut prev: Option<char> = None;
    for c in input.chars() {
        if set.contains(&c) && prev == Some(c) {
            continue;
        }
        out.push(c);
        prev = Some(c);
    }
    out
}

fn nl_cmd(input: &str) -> String {
    let mut out = String::new();
    for (i, line) in input.lines().enumerate() {
        out.push_str(&format!("{:>6}  {}\r\n", i + 1, line));
    }
    out
}

fn per_line<F: Fn(&str) -> String>(input: &str, f: F) -> String {
    let mut out = String::new();
    for line in input.lines() {
        out.push_str(&f(line));
        out.push_str("\r\n");
    }
    out
}

async fn base64_cmd(args: &[String], input: &str, context: &CommandContext) -> (String, bool) {
    let decode = flag_present(args, 'd', "--decode");
    let files: Vec<String> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .cloned()
        .collect();
    let source = gather_input(&files, input, context).await;

    if decode {
        match base64_decode(&source) {
            Some(bytes) => (String::from_utf8_lossy(&bytes).into_owned(), true),
            None => ("base64: invalid input\r\n".to_string(), false),
        }
    } else {
        (base64_encode(source.as_bytes()) + "\r\n", true)
    }
}

async fn strings_cmd(args: &[String], input: &str, context: &CommandContext) -> (String, bool) {
    let min_len = args
        .iter()
        .find_map(|a| a.strip_prefix("-n").and_then(|r| r.parse::<usize>().ok()))
        .unwrap_or(4);
    let files: Vec<String> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .cloned()
        .collect();
    let source = gather_input(&files, input, context).await;

    let mut out = String::new();
    let mut current = String::new();
    for ch in source.chars() {
        if ch.is_ascii_graphic() {
            current.push(ch);
        } else {
            if current.len() >= min_len {
                out.push_str(&current);
                out.push('\n');
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        out.push_str(&current);
        out.push('\n');
    }
    (out.replace('\n', "\r\n"), true)
}

async fn sed_cmd(args: &[String], input: &str, context: &CommandContext) -> (String, bool) {
    let mut script: Option<String> = None;
    let mut files: Vec<String> = Vec::new();
    for a in args {
        if script.is_none() && !a.starts_with('-') {
            script = Some(a.clone());
        } else if script.is_some() && !a.starts_with('-') {
            files.push(a.clone());
        }
    }
    let Some(script) = script else {
        return (input.to_string(), true);
    };
    let source = gather_input(&files, input, context).await;
    let mut out = String::new();

    if let Some(spec) = script.strip_prefix("s") {
        if let Some((pat, rep, flags)) = parse_subst(&spec) {
            let global = flags.contains('g');
            let ignore_case = flags.contains('i');
            for line in source.lines() {
                out.push_str(&subst_once_or_all(line, &pat, &rep, global, ignore_case));
                out.push('\n');
            }
        }
    } else if let Some(spec) = script.strip_prefix('/') {
        if let Some(idx) = spec.find('/') {
            let pat = &spec[..idx];
            let action = &spec[idx + 1..];
            for line in source.lines() {
                let matches = line.contains(pat);
                match action.chars().next() {
                    Some('d') => {
                        if !matches {
                            out.push_str(line);
                            out.push('\n');
                        }
                    }
                    Some('p') => {
                        if matches {
                            out.push_str(line);
                            out.push('\n');
                            out.push_str(line);
                            out.push('\n');
                        } else {
                            out.push_str(line);
                            out.push('\n');
                        }
                    }
                    _ => {
                        out.push_str(line);
                        out.push('\n');
                    }
                }
            }
        }
    } else {
        for line in source.lines() {
            out.push_str(line);
            out.push('\n');
        }
    }

    (out.replace('\n', "\r\n"), true)
}

fn parse_subst(spec: &str) -> Option<(String, String, String)> {
    let delim = spec.chars().next()?;
    let rest = &spec[delim.len_utf8()..];
    let parts: Vec<&str> = rest.splitn(3, delim).collect();
    if parts.len() == 3 {
        Some((
            parts[0].to_string(),
            parts[1].to_string(),
            parts[2].to_string(),
        ))
    } else {
        None
    }
}

fn subst_once_or_all(line: &str, pat: &str, rep: &str, global: bool, ignore_case: bool) -> String {
    let (haystack, needle, restore) = if ignore_case {
        (
            line.to_lowercase(),
            pat.to_lowercase(),
            Some(line.to_string()),
        )
    } else {
        (line.to_string(), pat.to_string(), None)
    };

    let mut result = String::new();
    let mut consumed = 0;
    let mut last = 0;
    let bytes_h = haystack.as_bytes();
    let needle_b = needle.as_bytes();
    while let Some(pos) = find_subslice(&bytes_h[last..], needle_b) {
        let abs = last + pos;
        result.push_str(&line[consumed..abs]);
        result.push_str(rep);
        consumed = abs + needle.len();
        last = abs + 1;
        if !global {
            break;
        }
    }
    result.push_str(&line[consumed..]);
    let _ = restore;
    result
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

async fn awk_cmd(args: &[String], input: &str, context: &CommandContext) -> (String, bool) {
    let mut program: Option<String> = None;
    let mut field_sep = ' ';
    let mut files: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(rest) = a.strip_prefix("-F") {
            field_sep = rest.chars().next().unwrap_or(' ');
        } else if program.is_none() && !a.starts_with('-') {
            program = Some(a.clone());
        } else if program.is_some() && !a.starts_with('-') {
            files.push(a.clone());
        }
        i += 1;
    }
    let source = gather_input(&files, input, context).await;

    let print_spec = program
        .as_deref()
        .and_then(|p| extract_print_spec(p))
        .unwrap_or_default();

    let mut out = String::new();
    for line in source.lines() {
        let fields: Vec<&str> = if field_sep == ' ' {
            line.split_whitespace().collect()
        } else {
            line.split(field_sep).collect()
        };
        if print_spec.is_empty() {
            out.push_str(line);
        } else {
            for (idx, spec) in print_spec.iter().enumerate() {
                if idx > 0 {
                    out.push(' ');
                }
                out.push_str(&eval_print(spec, &fields));
            }
        }
        out.push('\n');
    }
    (out.replace('\n', "\r\n"), true)
}

fn extract_print_spec(program: &str) -> Option<Vec<String>> {
    let trimmed = program.trim().trim_start_matches('{').trim_end_matches('}');
    let body = trimmed.trim();
    let body = body.strip_prefix("print ").unwrap_or(body);
    Some(body.split(',').map(|s| s.trim().to_string()).collect())
}

fn eval_print(spec: &str, fields: &[&str]) -> String {
    if spec == "$0" {
        return fields.join(" ");
    }
    if let Some(rest) = spec.strip_prefix('$') {
        if rest == "NF" {
            return fields.len().to_string();
        }
        if let Ok(n) = rest.parse::<usize>() {
            return fields
                .get(n.wrapping_sub(1))
                .copied()
                .unwrap_or("")
                .to_string();
        }
    }
    spec.trim_matches('"').trim_matches('\'').to_string()
}

async fn column_cmd(args: &[String], input: &str, context: &CommandContext) -> (String, bool) {
    let table = flag_present(args, 't', "--table");
    let files: Vec<String> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .cloned()
        .collect();
    let source = gather_input(&files, input, context).await;
    let lines: Vec<Vec<&str>> = source
        .lines()
        .map(|l| l.split_whitespace().collect())
        .collect();

    if !table {
        let joined: Vec<String> = source
            .lines()
            .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect();
        return (joined.join("\r\n") + "\r\n", true);
    }

    let cols = lines.iter().map(|r| r.len()).max().unwrap_or(0);
    let mut widths = vec![0usize; cols];
    for row in &lines {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.len());
        }
    }
    let mut out = String::new();
    for row in &lines {
        for (i, cell) in row.iter().enumerate() {
            if i > 0 {
                out.push_str("  ");
            }
            if i == row.len() - 1 {
                out.push_str(cell);
            } else {
                out.push_str(&format!("{:width$}", cell, width = widths[i]));
            }
        }
        out.push_str("\r\n");
    }
    (out, true)
}

fn xargs_cmd(args: &[String], input: &str) -> (String, bool) {
    let words: Vec<&str> = input.split_whitespace().collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("echo");
    let rest: Vec<&str> = args.iter().skip(1).map(|s| s.as_str()).collect();
    let mut parts: Vec<String> = vec![cmd.to_string()];
    parts.extend(rest.iter().map(|s| s.to_string()));
    parts.extend(words.iter().map(|s| s.to_string()));
    let _ = parts;
    (words.join(" ") + "\n", true)
}

async fn hash_cmd<D: Digest + Send>(
    args: &[String],
    input: &str,
    context: &CommandContext,
) -> (String, bool) {
    let files: Vec<String> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .cloned()
        .collect();
    let source = gather_input(&files, input, context).await;
    let mut hasher = D::new();
    hasher.update(source.as_bytes());
    let result = hasher.finalize();
    let hex = hex::encode(result);
    let label = files.first().map(|f| f.as_str()).unwrap_or("-");
    (format!("{}  {}\r\n", hex, label), true)
}

async fn md5_stub(args: &[String], input: &str, context: &CommandContext) -> String {
    let files: Vec<String> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .cloned()
        .collect();
    let source = gather_input(&files, input, context).await;
    let mut hasher = Sha256::new();
    hasher.update(source.as_bytes());
    let digest = hasher.finalize();
    let mut fake = String::new();
    for byte in digest.iter().take(16) {
        fake.push_str(&format!("{:02x}", byte));
    }
    let label = files.first().map(|f| f.as_str()).unwrap_or("-");
    format!("{}  {}\r\n", fake, label)
}

fn flag_present(args: &[String], short: char, long: &str) -> bool {
    args.iter().any(|a| {
        a == long
            || (a.starts_with('-') && !a.starts_with("--") && a.chars().skip(1).any(|c| c == short))
    })
}

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(input: &[u8]) -> String {
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let triple = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(B64_ALPHABET[((triple >> 18) & 0x3f) as usize] as char);
        out.push(B64_ALPHABET[((triple >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_ALPHABET[((triple >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_ALPHABET[(triple & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let mut rev = [255u8; 256];
    for (i, &c) in B64_ALPHABET.iter().enumerate() {
        rev[c as usize] = i as u8;
    }
    let bytes: Vec<u8> = cleaned
        .bytes()
        .filter(|&b| b == b'=' || rev[b as usize] != 255)
        .collect();
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        let v0 = rev[chunk[0] as usize];
        let v1 = rev[chunk[1] as usize];
        let v2 = chunk
            .get(2)
            .map_or(0, |&b| if b == b'=' { 0 } else { rev[b as usize] });
        let v3 = chunk
            .get(3)
            .map_or(0, |&b| if b == b'=' { 0 } else { rev[b as usize] });
        out.push(((v0 << 2) | (v1 >> 4)) as u8);
        if chunk.len() > 2 && chunk[2] != b'=' {
            out.push((((v1 & 0x0f) << 4) | (v2 >> 2)) as u8);
        }
        if chunk.len() > 3 && chunk[3] != b'=' {
            out.push((((v2 & 0x03) << 6) | v3) as u8);
        }
    }
    Some(out)
}
