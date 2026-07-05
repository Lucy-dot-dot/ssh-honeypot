//! Bash/sh-compatible command line parser.
//!
//! Produces an AST of command lists -> and-or items -> pipelines -> simple commands.
//! Handles quote-aware operator splitting (`;`, `&&`, `||`, `|`, `&`), redirection
//! capture (`>`, `>>`, `<`, `2>`, `&>`, `2>&1`), subshell unwrapping (`(` `)`),
//! comments (`#`), variable expansion (`$VAR`, `${VAR}`, `$?`), tilde expansion (`~`)
//! and word tokenization via `shlex`.
//!
//! Command substitution (`$(...)`) and arithmetic (`$((...))`) are resolved by the
//! dispatcher (which can run sub-commands); this module provides the pure helpers
//! (`eval_arithmetic`, `parse_assignment`, `looks_like_command`) used there.

use std::collections::HashMap;

/// A separator/operator discovered while scanning the raw line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sep {
    Pipe,
    Semi,
    AndAnd,
    OrOr,
    /// `&` (treated like `;` - no real backgrounding)
    Amp,
}

/// Where a redirection sends its file descriptor.
#[derive(Debug, Clone)]
pub enum RedirTarget {
    DevNull,
    File(String),
    /// Duplicate another file descriptor, e.g. `2>&1`.
    Fd(u8),
}

/// A single redirection attached to a simple command.
#[derive(Debug, Clone)]
pub struct Redirect {
    pub fd: u8,
    pub append: bool,
    pub target: RedirTarget,
}

/// A scanned span: raw text, an operator, or a complete redirection.
#[derive(Debug, Clone)]
enum Span {
    Text(String),
    Sep(Sep),
    Redir(Redirect),
}

/// A token after word-splitting + expansion, a carried-over operator, or a redirection.
#[derive(Debug, Clone)]
enum Tok {
    Word(String),
    Sep(Sep),
    Redir(Redirect),
}

/// A simple command: name + tokenized, expanded arguments + redirections.
#[derive(Debug, Clone)]
pub struct SimpleCommand {
    pub name: String,
    pub args: Vec<String>,
    pub redirects: Vec<Redirect>,
}

/// How an and-or item connects to the next item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AndOp {
    /// `;` / `&` / end: next item always runs.
    Then,
    /// `&&`: next item runs only if this one succeeded.
    And,
    /// `||`: next item runs only if this one failed.
    Or,
}

/// A pipeline of simple commands connected by `|`.
#[derive(Debug, Clone)]
pub struct Pipeline {
    pub commands: Vec<SimpleCommand>,
}

/// One and-or item: a pipeline plus the operator connecting it to the following item.
#[derive(Debug, Clone)]
pub struct AndOrItem {
    pub pipeline: Pipeline,
    pub op: AndOp,
}

/// A full parsed command line: a list of and-or items.
#[derive(Debug, Clone, Default)]
pub struct CommandList {
    pub items: Vec<AndOrItem>,
}

impl CommandList {
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// Reserved shell keywords that introduce or delimit compound commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keyword {
    If,
    Then,
    Elif,
    Else,
    Fi,
    For,
    In,
    Do,
    Done,
    While,
    Until,
    Case,
    Esac,
}

fn keyword_of(word: &str) -> Option<Keyword> {
    Some(match word {
        "if" => Keyword::If,
        "then" => Keyword::Then,
        "elif" => Keyword::Elif,
        "else" => Keyword::Else,
        "fi" => Keyword::Fi,
        "for" => Keyword::For,
        "in" => Keyword::In,
        "do" => Keyword::Do,
        "done" => Keyword::Done,
        "while" => Keyword::While,
        "until" => Keyword::Until,
        "case" => Keyword::Case,
        "esac" => Keyword::Esac,
        _ => return None,
    })
}

/// A parsed statement: a regular command sequence or a control structure.
#[derive(Debug, Clone)]
pub enum Node {
    /// A plain sequence of and-or items (`;`, `&&`, `||`, `|`).
    Seq(CommandList),
    /// `if COND; then BODY; [elif COND2; then BODY2;]...[else ELSE_BODY;] fi`
    If {
        branches: Vec<(Vec<Node>, Vec<Node>)>,
        else_body: Option<Vec<Node>>,
    },
    /// `for VAR [in WORDS...]; do BODY; done`
    For {
        var: String,
        words: Vec<String>,
        body: Vec<Node>,
    },
    /// `while/until COND; do BODY; done`
    While {
        cond: Vec<Node>,
        body: Vec<Node>,
        until: bool,
    },
}

/// A full parsed script: a sequence of nodes.
#[derive(Debug, Clone, Default)]
pub struct Script {
    pub nodes: Vec<Node>,
}

fn is_op_char(c: char) -> bool {
    matches!(c, '|' | '&' | ';' | '>' | '<' | '(' | ')')
}

/// Read a single redirection target word starting at `start`, skipping leading
/// whitespace and honouring quotes. Returns the word and the index of the first
/// unconsumed char.
fn read_word(chars: &[char], start: usize) -> (String, usize) {
    let mut i = start;
    while i < chars.len() && chars[i].is_whitespace() {
        i += 1;
    }
    let mut s = String::new();
    if i < chars.len() && (chars[i] == '"' || chars[i] == '\'') {
        let q = chars[i];
        i += 1;
        while i < chars.len() && chars[i] != q {
            s.push(chars[i]);
            i += 1;
        }
        if i < chars.len() {
            i += 1;
        }
    } else {
        while i < chars.len()
            && !chars[i].is_whitespace()
            && !is_op_char(chars[i])
            && chars[i] != '"'
            && chars[i] != '\''
        {
            s.push(chars[i]);
            i += 1;
        }
    }
    (s, i)
}

/// Remove and return trailing digits glued to a redirection (e.g. the `2` in `2>file`).
fn take_trailing_fd(cur: &mut String) -> Option<u8> {
    let end = cur.len();
    if end == 0 {
        return None;
    }
    let mut cut = end;
    for (idx, ch) in cur.char_indices().rev() {
        if ch.is_ascii_digit() {
            cut = idx;
        } else if ch.is_whitespace() {
            break;
        } else {
            if cut < end {
                let digits = &cur[cut..end];
                let n = digits.parse::<u8>().ok();
                cur.truncate(cut);
                return n;
            }
            return None;
        }
    }
    if cut < end {
        let digits = &cur[cut..end];
        let n = digits.parse::<u8>().ok();
        cur.truncate(cut);
        n
    } else {
        None
    }
}

/// Quote-aware scan of the raw line into text spans, operators and redirections.
fn scan(input: &str) -> Vec<Span> {
    let chars: Vec<char> = input.chars().collect();
    let mut spans: Vec<Span> = Vec::new();
    let mut cur = String::new();
    let mut i = 0usize;
    let mut in_single = false;
    let mut in_double = false;

    while i < chars.len() {
        let c = chars[i];

        if in_single {
            cur.push(c);
            if c == '\'' {
                in_single = false;
            }
            i += 1;
            continue;
        }
        if in_double {
            cur.push(c);
            if c == '"' {
                in_double = false;
            }
            i += 1;
            continue;
        }

        match c {
            '\'' => {
                in_single = true;
                cur.push(c);
                i += 1;
                continue;
            }
            '"' => {
                in_double = true;
                cur.push(c);
                i += 1;
            }
            '\\' => {
                if i + 1 < chars.len() {
                    cur.push('\\');
                    cur.push(chars[i + 1]);
                    i += 2;
                    continue;
                } else {
                    cur.push('\\');
                    i += 1;
                    continue;
                }
            }
            '#' if cur.trim().is_empty() => {
                break;
            }
            '(' => {
                // Subshell unwrap: treat like a separator. Keep `$(` intact if it survived.
                if cur.ends_with('$') {
                    cur.push(c);
                    i += 1;
                    continue;
                }
                flush_text(&mut spans, &mut cur);
                i += 1;
                continue;
            }
            ')' => {
                flush_text(&mut spans, &mut cur);
                i += 1;
                continue;
            }
            '|' => {
                flush_text(&mut spans, &mut cur);
                if chars.get(i + 1) == Some(&'|') {
                    spans.push(Span::Sep(Sep::OrOr));
                    i += 2;
                } else {
                    spans.push(Span::Sep(Sep::Pipe));
                    i += 1;
                }
                continue;
            }
            '&' => {
                if chars.get(i + 1) == Some(&'>') {
                    // &> redirects both stdout and stderr to a file.
                    flush_text(&mut spans, &mut cur);
                    let (target, next) = read_word(&chars, i + 2);
                    let tgt = target_to_enum(target);
                    spans.push(Span::Redir(Redirect {
                        fd: 1,
                        append: false,
                        target: tgt.clone(),
                    }));
                    spans.push(Span::Redir(Redirect {
                        fd: 2,
                        append: false,
                        target: tgt,
                    }));
                    i = next;
                    continue;
                }
                flush_text(&mut spans, &mut cur);
                if chars.get(i + 1) == Some(&'&') {
                    spans.push(Span::Sep(Sep::AndAnd));
                    i += 2;
                } else {
                    spans.push(Span::Sep(Sep::Amp));
                    i += 1;
                }
                continue;
            }
            ';' => {
                flush_text(&mut spans, &mut cur);
                spans.push(Span::Sep(Sep::Semi));
                i += 1;
                continue;
            }
            '>' | '<' => {
                let is_out = c == '>';
                let fd = take_trailing_fd(&mut cur).unwrap_or(if is_out { 1 } else { 0 });
                flush_text(&mut spans, &mut cur);
                let mut k = i;
                let mut append = false;
                if is_out && chars.get(i + 1) == Some(&'>') {
                    append = true;
                    k = i + 1;
                }
                // fd merge: N>&M  or  N<&M
                if chars.get(k + 1) == Some(&'&') {
                    let mut d = k + 2;
                    let mut num = String::new();
                    while d < chars.len() && chars[d].is_ascii_digit() {
                        num.push(chars[d]);
                        d += 1;
                    }
                    if !num.is_empty() {
                        let m: u8 = num.parse().unwrap_or(0);
                        spans.push(Span::Redir(Redirect {
                            fd,
                            append,
                            target: RedirTarget::Fd(m),
                        }));
                        i = d;
                        continue;
                    }
                }
                let (target, next) = read_word(&chars, k + 1);
                let tgt = target_to_enum(target);
                spans.push(Span::Redir(Redirect {
                    fd,
                    append,
                    target: tgt,
                }));
                i = next;
                continue;
            }
            _ => {
                cur.push(c);
                i += 1;
                continue;
            }
        }
    }

    flush_text(&mut spans, &mut cur);
    spans
}

fn target_to_enum(target: String) -> RedirTarget {
    if target == "/dev/null" {
        RedirTarget::DevNull
    } else {
        RedirTarget::File(target)
    }
}

fn flush_text(spans: &mut Vec<Span>, cur: &mut String) {
    if !cur.trim().is_empty() {
        let text = std::mem::take(cur);
        spans.push(Span::Text(text));
    } else {
        cur.clear();
    }
}

/// Expand a single, already-unquoted word: tilde then variables.
fn expand_word(word: &str, env: &HashMap<String, String>, home: &str) -> String {
    let tilde = expand_tilde(word, home);
    expand_vars(&tilde, env)
}

fn expand_tilde(word: &str, home: &str) -> String {
    if word == "~" {
        return home.to_string();
    }
    if let Some(rest) = word.strip_prefix("~/") {
        return format!("{}/{}", home.trim_end_matches('/'), rest);
    }
    word.to_string()
}

fn expand_vars(s: &str, env: &HashMap<String, String>) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if c != '$' {
            out.push(c);
            i += 1;
            continue;
        }
        let Some(&nc) = chars.get(i + 1) else {
            out.push('$');
            i += 1;
            continue;
        };
        // Leave command substitution / arithmetic intact for the dispatcher.
        if nc == '(' {
            out.push('$');
            i += 1;
            continue;
        }
        if nc == '{' {
            // Find the matching closing brace (allowing nested ${...}).
            let mut depth = 1i32;
            let mut end_rel: Option<usize> = None;
            for (rel, &ch) in chars[i + 2..].iter().enumerate() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end_rel = Some(rel);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(rel) = end_rel else {
                out.push('$');
                i += 1;
                continue;
            };
            let end = i + 2 + rel;
            let inner: String = chars[i + 2..end].iter().collect();
            out.push_str(&expand_brace(&inner, env));
            i = end + 1;
            continue;
        }
        if nc == '?' {
            out.push('0');
            i += 2;
            continue;
        }
        if nc == '$' {
            out.push_str("1234");
            i += 2;
            continue;
        }
        if nc == '#' {
            out.push('0');
            i += 2;
            continue;
        }
        if nc.is_ascii_alphabetic() || nc == '_' {
            let mut j = i + 1;
            while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') {
                j += 1;
            }
            let name: String = chars[i + 1..j].iter().collect();
            let val = env.get(&name).cloned().unwrap_or_default();
            out.push_str(&val);
            i = j;
            continue;
        }
        out.push('$');
        i += 1;
    }
    out
}

/// Evaluate the contents of `${...}` (the part between the braces) including
/// all parameter-expansion operators (`:-`, `:+`, `:=`, `:?`, `-`, `+`, `#`,
/// `##`, `%`, `%%`, `/`, `//`, and length `${#var}`).
fn expand_brace(inner: &str, env: &HashMap<String, String>) -> String {
    // `${#NAME}` -> string length of NAME's value.
    if let Some(rest) = inner.strip_prefix('#') {
        if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return env
                .get(rest)
                .map(|v| v.chars().count().to_string())
                .unwrap_or_else(|| "0".to_string());
        }
    }

    // Extract the variable name (leading identifier).
    let mut name_end = 0usize;
    for (idx, b) in inner.bytes().enumerate() {
        if b.is_ascii_alphanumeric() || b == b'_' {
            name_end = idx + 1;
        } else {
            break;
        }
    }
    if name_end == 0 {
        return String::new();
    }
    let name = &inner[..name_end];
    let rest = &inner[name_end..];
    let is_set = env.contains_key(name);
    let val = env.get(name).cloned().unwrap_or_default();

    if rest.is_empty() {
        return val;
    }

    // Two-char operators prefixed with ':'.
    if let Some(word) = rest.strip_prefix(":-") {
        return if val.is_empty() {
            expand_vars(word, env)
        } else {
            val
        };
    }
    if let Some(word) = rest.strip_prefix(":+") {
        return if !val.is_empty() {
            expand_vars(word, env)
        } else {
            String::new()
        };
    }
    if let Some(word) = rest.strip_prefix(":=") {
        return if val.is_empty() {
            expand_vars(word, env)
        } else {
            val
        };
    }
    if rest.starts_with(":?") {
        return if val.is_empty() { String::new() } else { val };
    }
    // Single-char operators (no colon).
    if let Some(word) = rest.strip_prefix('-') {
        return if !is_set { expand_vars(word, env) } else { val };
    }
    if let Some(word) = rest.strip_prefix('+') {
        return if is_set {
            expand_vars(word, env)
        } else {
            String::new()
        };
    }
    if let Some(word) = rest.strip_prefix('=') {
        return if !is_set { expand_vars(word, env) } else { val };
    }
    // Prefix/suffix removal (literal patterns; longest vs shortest is the same
    // for literals).
    if let Some(pat) = rest.strip_prefix("##").or_else(|| rest.strip_prefix('#')) {
        return val.strip_prefix(pat).unwrap_or(&val).to_string();
    }
    if let Some(pat) = rest.strip_prefix("%%").or_else(|| rest.strip_prefix('%')) {
        return val.strip_suffix(pat).unwrap_or(&val).to_string();
    }
    // Search-and-replace: `/old/new` or `//old/new`.
    if let Some(body) = rest.strip_prefix('/') {
        let (all, body) = if let Some(b) = body.strip_prefix('/') {
            (true, b)
        } else {
            (false, body)
        };
        let (old, new) = match body.find('/') {
            Some(idx) => (&body[..idx], &body[idx + 1..]),
            None => (body, ""),
        };
        if old.is_empty() {
            return val;
        }
        return if all {
            val.replace(old, new)
        } else {
            val.replacen(old, new, 1)
        };
    }
    val
}

/// Turn scanned spans into tokens (expanded words + operators + redirects).
fn tokenize(spans: &[Span], env: &HashMap<String, String>, home: &str) -> Vec<Tok> {
    let mut tokens: Vec<Tok> = Vec::new();

    for span in spans {
        match span {
            Span::Sep(sep) => {
                tokens.push(Tok::Sep(*sep));
            }
            Span::Redir(r) => {
                tokens.push(Tok::Redir(r.clone()));
            }
            Span::Text(text) => {
                let words = shlex::split(text).unwrap_or_default();
                for w in words {
                    tokens.push(Tok::Word(expand_word(&w, env, home)));
                }
            }
        }
    }
    tokens
}

/// Assemble a flat token stream into a command list.
fn assemble(tokens: Vec<Tok>) -> CommandList {
    assemble_until(&tokens, &[]).0
}

/// Assemble tokens (starting at index 0) into a command list, stopping when a
/// command-start word matches one of `terms`. Returns the list, the number of
/// tokens consumed, and the matching terminator word (if any).
fn assemble_until(tokens: &[Tok], terms: &[&str]) -> (CommandList, usize, Option<String>) {
    let mut list = CommandList::default();
    let mut current: Option<SimpleCommand> = None;
    let mut pipeline: Vec<SimpleCommand> = Vec::new();
    let mut cmd_start = true;
    let mut i = 0usize;

    while i < tokens.len() {
        // Detect a terminator keyword at command-start position.
        let terminator = if cmd_start {
            if let Tok::Word(w) = &tokens[i] {
                if terms.iter().any(|t| t == w) {
                    Some(w.clone())
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        if let Some(term) = terminator {
            if let Some(c) = current.take() {
                pipeline.push(c);
            }
            if !pipeline.is_empty() {
                list.items.push(AndOrItem {
                    pipeline: Pipeline {
                        commands: std::mem::take(&mut pipeline),
                    },
                    op: AndOp::Then,
                });
            }
            return (list, i, Some(term));
        }

        match &tokens[i] {
            Tok::Word(w) => {
                let cmd = current.get_or_insert_with(|| SimpleCommand {
                    name: String::new(),
                    args: Vec::new(),
                    redirects: Vec::new(),
                });
                if cmd.name.is_empty() {
                    cmd.name = w.clone();
                } else {
                    cmd.args.push(w.clone());
                }
                cmd_start = false;
            }
            Tok::Redir(r) => {
                let cmd = current.get_or_insert_with(|| SimpleCommand {
                    name: String::new(),
                    args: Vec::new(),
                    redirects: Vec::new(),
                });
                cmd.redirects.push(r.clone());
            }
            Tok::Sep(Sep::Pipe) => {
                if let Some(c) = current.take() {
                    pipeline.push(c);
                }
                cmd_start = true;
            }
            Tok::Sep(sep) => {
                if let Some(c) = current.take() {
                    pipeline.push(c);
                }
                if !pipeline.is_empty() {
                    let op = match sep {
                        Sep::AndAnd => AndOp::And,
                        Sep::OrOr => AndOp::Or,
                        _ => AndOp::Then,
                    };
                    list.items.push(AndOrItem {
                        pipeline: Pipeline {
                            commands: std::mem::take(&mut pipeline),
                        },
                        op,
                    });
                }
                cmd_start = true;
            }
        }
        i += 1;
    }

    if let Some(c) = current.take() {
        pipeline.push(c);
    }
    if !pipeline.is_empty() {
        list.items.push(AndOrItem {
            pipeline: Pipeline { commands: pipeline },
            op: AndOp::Then,
        });
    }

    (list, i, None)
}

/// Keywords that terminate a plain command sequence (they begin or end a
/// compound command).
const STRUCTURE_TERMS: &[&str] = &[
    "if", "then", "elif", "else", "fi", "for", "in", "do", "done", "while", "until", "case", "esac",
];

/// Build a script (list of nodes) from a token stream, recognising compound
/// command keywords (`if`/`for`/`while`/`until`).
fn build_script(tokens: &[Tok]) -> Vec<Node> {
    let mut parser = ScriptBuilder { tokens, pos: 0 };
    let mut nodes = Vec::new();

    while parser.pos < tokens.len() {
        // Skip leading separators.
        if matches!(parser.tokens[parser.pos], Tok::Sep(_)) {
            parser.pos += 1;
            continue;
        }
        let cmd_start_word = match &parser.tokens[parser.pos] {
            Tok::Word(w) => w.as_str(),
            _ => "",
        };
        match keyword_of(cmd_start_word) {
            Some(Keyword::If) => {
                if let Some(node) = parser.parse_if() {
                    nodes.push(node);
                }
            }
            Some(Keyword::For) => {
                if let Some(node) = parser.parse_for() {
                    nodes.push(node);
                }
            }
            Some(Keyword::While | Keyword::Until) => {
                let until = keyword_of(cmd_start_word) == Some(Keyword::Until);
                if let Some(node) = parser.parse_while(until) {
                    nodes.push(node);
                }
            }
            Some(_) => {
                // Stray structural delimiter (then/do/done/fi/else/elif/esac/in):
                // skip it.
                parser.pos += 1;
            }
            None => {
                // A regular command: parse a plain sequence up to the next
                // structural keyword.
                let (list, consumed, _term) =
                    assemble_until(&parser.tokens[parser.pos..], STRUCTURE_TERMS);
                parser.pos += consumed;
                if !list.items.is_empty() {
                    nodes.push(Node::Seq(list));
                }
            }
        }
    }

    nodes
}

/// Scan `tokens` (from index 0) tracking nesting depth of compound commands
/// (`if`/`for`/`while`/`until`/`case` open, `fi`/`done`/`esac` close). Returns
/// the index and word of the first command-start word at depth 0 that matches
/// one of `terms`. Used to split off condition / body / branch regions.
fn find_terminator(tokens: &[Tok], terms: &[&str]) -> Option<(usize, String)> {
    let mut depth = 0i32;
    let mut cmd_start = true;
    for (i, tok) in tokens.iter().enumerate() {
        match tok {
            Tok::Word(w) => {
                if cmd_start {
                    if depth == 0 && terms.iter().any(|t| t == w) {
                        return Some((i, w.clone()));
                    }
                    match w.as_str() {
                        "if" | "for" | "while" | "until" | "case" | "select" => depth += 1,
                        "fi" | "done" | "esac" => {
                            if depth > 0 {
                                depth -= 1;
                            }
                        }
                        _ => {}
                    }
                }
                cmd_start = false;
            }
            Tok::Redir(_) => {
                cmd_start = false;
            }
            Tok::Sep(_) => {
                cmd_start = true;
            }
        }
    }
    None
}

struct ScriptBuilder<'a> {
    tokens: &'a [Tok],
    pos: usize,
}

impl<'a> ScriptBuilder<'a> {
    fn skip_seps(&mut self) {
        while self.pos < self.tokens.len() && matches!(self.tokens[self.pos], Tok::Sep(_)) {
            self.pos += 1;
        }
    }

    fn at_word(&self, w: &str) -> bool {
        matches!(self.tokens.get(self.pos), Some(Tok::Word(x)) if x == w)
    }

    /// Parse `if ...; then ...; [elif ...; then ...;]...[else ...;] fi`.
    fn parse_if(&mut self) -> Option<Node> {
        self.pos += 1; // consume `if`
        let mut branches = Vec::new();
        let mut else_body = None;

        loop {
            // Condition: up to `then` at depth 0.
            let cond_slice_end = find_terminator(&self.tokens[self.pos..], &["then"]);
            let cond_end = cond_slice_end
                .map(|(i, _)| i)
                .unwrap_or(self.tokens.len() - self.pos);
            let cond_nodes = build_script(&self.tokens[self.pos..self.pos + cond_end]);
            self.pos += cond_end;
            if self.at_word("then") {
                self.pos += 1; // consume `then`
            }
            // Body: up to `elif`/`else`/`fi` at depth 0.
            let body_terms = ["elif", "else", "fi"];
            let body_slice_end = find_terminator(&self.tokens[self.pos..], &body_terms);
            let body_end = body_slice_end
                .map(|(i, _)| i)
                .unwrap_or(self.tokens.len() - self.pos);
            let body_nodes = build_script(&self.tokens[self.pos..self.pos + body_end]);
            self.pos += body_end;
            branches.push((cond_nodes, body_nodes));
            match self.tokens.get(self.pos) {
                Some(Tok::Word(w)) if w == "elif" => {
                    self.pos += 1;
                    continue;
                }
                Some(Tok::Word(w)) if w == "else" => {
                    self.pos += 1;
                    let els_end = find_terminator(&self.tokens[self.pos..], &["fi"])
                        .map(|(i, _)| i)
                        .unwrap_or(self.tokens.len() - self.pos);
                    let els_nodes = build_script(&self.tokens[self.pos..self.pos + els_end]);
                    self.pos += els_end;
                    else_body = Some(els_nodes);
                    if self.at_word("fi") {
                        self.pos += 1;
                    }
                    break;
                }
                Some(Tok::Word(w)) if w == "fi" => {
                    self.pos += 1;
                    break;
                }
                _ => break, // unterminated; bail out
            }
        }

        Some(Node::If {
            branches,
            else_body,
        })
    }

    /// Parse `for VAR [in WORDS...]; do BODY; done`.
    fn parse_for(&mut self) -> Option<Node> {
        self.pos += 1; // consume `for`
        self.skip_seps();
        let var = match &self.tokens.get(self.pos) {
            Some(Tok::Word(w)) => {
                let v = w.clone();
                self.pos += 1;
                v
            }
            _ => return None,
        };
        // Optional `in WORDS...`.
        let mut words = Vec::new();
        self.skip_seps();
        if self.at_word("in") {
            self.pos += 1;
            while let Some(Tok::Word(w)) = self.tokens.get(self.pos) {
                if w == "do" {
                    break;
                }
                words.push(w.clone());
                self.pos += 1;
            }
        }
        // Skip to `do`.
        while self.pos < self.tokens.len() && !self.at_word("do") {
            self.pos += 1;
        }
        if self.at_word("do") {
            self.pos += 1;
        }
        let body_end = find_terminator(&self.tokens[self.pos..], &["done"])
            .map(|(i, _)| i)
            .unwrap_or(self.tokens.len() - self.pos);
        let body_nodes = build_script(&self.tokens[self.pos..self.pos + body_end]);
        self.pos += body_end;
        if self.at_word("done") {
            self.pos += 1;
        }
        Some(Node::For {
            var,
            words,
            body: body_nodes,
        })
    }

    /// Parse `while/until COND; do BODY; done`.
    fn parse_while(&mut self, until: bool) -> Option<Node> {
        self.pos += 1; // consume `while`/`until`
        let cond_end = find_terminator(&self.tokens[self.pos..], &["do"])
            .map(|(i, _)| i)
            .unwrap_or(self.tokens.len() - self.pos);
        let cond_nodes = build_script(&self.tokens[self.pos..self.pos + cond_end]);
        self.pos += cond_end;
        if self.at_word("do") {
            self.pos += 1;
        }
        let body_end = find_terminator(&self.tokens[self.pos..], &["done"])
            .map(|(i, _)| i)
            .unwrap_or(self.tokens.len() - self.pos);
        let body_nodes = build_script(&self.tokens[self.pos..self.pos + body_end]);
        self.pos += body_end;
        if self.at_word("done") {
            self.pos += 1;
        }
        Some(Node::While {
            cond: cond_nodes,
            body: body_nodes,
            until,
        })
    }
}

/// Parse a full command line into an executable AST.
pub fn parse_command_line(input: &str, env: &HashMap<String, String>, home: &str) -> CommandList {
    let spans = scan(input);
    let tokens = tokenize(&spans, env, home);
    assemble(tokens)
}

/// Normalise a multi-line script into a single logical line: handle backslash
/// line-continuations, convert newlines to `;` (suppressing the separator when
/// the previous non-whitespace character is a binary operator like `|` or `&`).
fn normalize_newlines(input: &str) -> String {
    // Backslash-newline continuation: just join the lines.
    let joined = input.replace("\\\n", " ");
    let chars: Vec<char> = joined.chars().collect();
    let mut out = String::new();
    let mut in_s = false;
    let mut in_d = false;
    for &c in &chars {
        if in_s {
            out.push(c);
            if c == '\'' {
                in_s = false;
            }
            continue;
        }
        if in_d {
            out.push(c);
            if c == '"' {
                in_d = false;
            }
            continue;
        }
        match c {
            '\'' => {
                in_s = true;
                out.push(c);
            }
            '"' => {
                in_d = true;
                out.push(c);
            }
            '\n' => {
                let trimmed = out.trim_end();
                if trimmed.ends_with('|') || trimmed.ends_with('&') {
                    // Continuation after a binary operator: drop the newline.
                } else {
                    out.push(';');
                }
            }
            '\r' => {} // drop carriage returns
            _ => out.push(c),
        }
    }
    out
}

/// Parse a (possibly multi-line) script into a sequence of nodes, recognising
/// compound commands (`if`, `for`, `while`, `until`).
pub fn parse_script(input: &str, env: &HashMap<String, String>, home: &str) -> Script {
    let normalised = normalize_newlines(input);
    let spans = scan(&normalised);
    let tokens = tokenize(&spans, env, home);
    Script {
        nodes: build_script(&tokens),
    }
}

/// Analyse `text` for block balance: counts compound-command keywords
/// (`if`/`for`/`while`/`until`/`case` open, `fi`/`done`/`esac` close) and
/// parentheses, plus unclosed quotes. Returns `(balance, unclosed_quote)`.
fn analyze_block(text: &str) -> (i32, bool) {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut depth = 0i32;
    let mut paren = 0i32;
    let mut in_s = false;
    let mut in_d = false;
    let mut in_comment = false;
    let mut i = 0usize;
    let mut word = String::new();

    fn account(word: &mut String, depth: &mut i32) {
        match word.as_str() {
            "if" | "for" | "while" | "until" | "case" | "select" => *depth += 1,
            "fi" | "done" | "esac" => *depth -= 1,
            _ => {}
        }
        word.clear();
    }

    while i < n {
        let c = chars[i];
        if in_comment {
            if c == '\n' {
                in_comment = false;
            }
            i += 1;
            continue;
        }
        if in_s {
            word.push(c);
            if c == '\'' {
                in_s = false;
            }
            i += 1;
            continue;
        }
        if in_d {
            word.push(c);
            if c == '"' {
                in_d = false;
            }
            i += 1;
            continue;
        }
        match c {
            '#' if word.is_empty() => {
                in_comment = true;
                i += 1;
            }
            '\'' => {
                account(&mut word, &mut depth);
                in_s = true;
                i += 1;
            }
            '"' => {
                account(&mut word, &mut depth);
                in_d = true;
                i += 1;
            }
            '(' => {
                account(&mut word, &mut depth);
                paren += 1;
                i += 1;
            }
            ')' => {
                account(&mut word, &mut depth);
                paren -= 1;
                i += 1;
            }
            '\\' => {
                if i + 1 < n {
                    word.push(chars[i + 1]);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            ch if ch.is_alphanumeric() || ch == '_' => {
                word.push(ch);
                i += 1;
            }
            _ => {
                account(&mut word, &mut depth);
                i += 1;
            }
        }
    }
    account(&mut word, &mut depth);
    (depth + paren, in_s || in_d)
}

/// Returns true if `text` opens a block (compound command, subshell, or quote)
/// that has not yet been closed - i.e. more input is needed before executing.
pub fn is_incomplete_block(text: &str) -> bool {
    let (balance, open_quote) = analyze_block(text);
    balance != 0 || open_quote
}

/// If `word` is a variable assignment (`IDENT=...`), return `(name, value)`.
pub fn parse_assignment(word: &str) -> Option<(String, String)> {
    let bytes = word.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let first = bytes[0];
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return None;
    }
    let eq = word.find('=')?;
    let name = &word[..eq];
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return None;
    }
    Some((name.to_string(), word[eq + 1..].to_string()))
}

/// Heuristic: does the body of `$((...))` look like a command (pipes/redirects/etc.)
/// rather than a pure arithmetic expression?
pub fn looks_like_command(expr: &str) -> bool {
    expr.contains('|')
        || expr.contains('&')
        || expr.contains(';')
        || expr.contains('>')
        || expr.contains('<')
        || expr.contains('`')
}

/// Lenient integer arithmetic evaluation for `$((...))`. Returns 0 on anything
/// unparseable; unknown identifiers resolve to 0.
pub fn eval_arithmetic(expr: &str, env: &HashMap<String, String>) -> i64 {
    let tokens = arith_tokens(expr);
    if tokens.is_empty() {
        return 0;
    }
    let mut p = ArithParser { tokens, pos: 0 };
    let v = p.parse_expr(env);
    if v.is_none() {
        return 0;
    }
    v.unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq)]
enum ATok {
    Num(i64),
    Ident(String),
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    LParen,
    RParen,
}

fn arith_tokens(expr: &str) -> Vec<ATok> {
    let chars: Vec<char> = expr.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        match c {
            '+' => out.push(ATok::Plus),
            '-' => out.push(ATok::Minus),
            '*' => out.push(ATok::Star),
            '/' => out.push(ATok::Slash),
            '%' => out.push(ATok::Percent),
            '(' => out.push(ATok::LParen),
            ')' => out.push(ATok::RParen),
            d if d.is_ascii_digit() => {
                let mut n = String::new();
                while i < chars.len() && chars[i].is_ascii_digit() {
                    n.push(chars[i]);
                    i += 1;
                }
                out.push(ATok::Num(n.parse::<i64>().unwrap_or(0)));
                continue;
            }
            a if a.is_ascii_alphabetic() || a == '_' => {
                let mut name = String::new();
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    name.push(chars[i]);
                    i += 1;
                }
                out.push(ATok::Ident(name));
                continue;
            }
            // Anything else aborts arithmetic; signal by returning empty.
            _ => return Vec::new(),
        }
        i += 1;
    }
    out
}

struct ArithParser {
    tokens: Vec<ATok>,
    pos: usize,
}

impl ArithParser {
    fn peek(&self) -> Option<&ATok> {
        self.tokens.get(self.pos)
    }

    fn parse_expr(&mut self, env: &HashMap<String, String>) -> Option<i64> {
        let mut left = self.parse_term(env)?;
        while let Some(t) = self.peek() {
            match t {
                ATok::Plus => {
                    self.pos += 1;
                    left = left.checked_add(self.parse_term(env)?)?;
                }
                ATok::Minus => {
                    self.pos += 1;
                    left = left.checked_sub(self.parse_term(env)?)?;
                }
                _ => break,
            }
        }
        Some(left)
    }

    fn parse_term(&mut self, env: &HashMap<String, String>) -> Option<i64> {
        let mut left = self.parse_factor(env)?;
        while let Some(t) = self.peek() {
            match t {
                ATok::Star => {
                    self.pos += 1;
                    left = left.checked_mul(self.parse_factor(env)?)?;
                }
                ATok::Slash => {
                    self.pos += 1;
                    let r = self.parse_factor(env)?;
                    if r == 0 {
                        left = 0;
                    } else {
                        left = left.checked_div(r)?;
                    }
                }
                ATok::Percent => {
                    self.pos += 1;
                    let r = self.parse_factor(env)?;
                    if r == 0 {
                        left = 0;
                    } else {
                        left = left.checked_rem(r)?;
                    }
                }
                _ => break,
            }
        }
        Some(left)
    }

    fn parse_factor(&mut self, env: &HashMap<String, String>) -> Option<i64> {
        match self.peek()? {
            ATok::Num(n) => {
                let v = *n;
                self.pos += 1;
                Some(v)
            }
            ATok::Ident(name) => {
                let name = name.clone();
                self.pos += 1;
                let v = env
                    .get(&name)
                    .and_then(|s| s.trim().parse::<i64>().ok())
                    .unwrap_or(0);
                Some(v)
            }
            ATok::Minus => {
                self.pos += 1;
                Some(-self.parse_factor(env)?)
            }
            ATok::Plus => {
                self.pos += 1;
                self.parse_factor(env)
            }
            ATok::LParen => {
                self.pos += 1;
                let v = self.parse_expr(env)?;
                if self.peek() == Some(&ATok::RParen) {
                    self.pos += 1;
                }
                Some(v)
            }
            ATok::RParen => None,
            ATok::Star | ATok::Slash | ATok::Percent => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("HOME".to_string(), "/home/root".to_string());
        m.insert("USER".to_string(), "root".to_string());
        m
    }

    fn names(list: &CommandList) -> Vec<(String, Vec<String>)> {
        list.items
            .iter()
            .flat_map(|item| {
                item.pipeline
                    .commands
                    .iter()
                    .map(|c| (c.name.clone(), c.args.clone()))
            })
            .collect()
    }

    #[test]
    fn semicolon_sequences() {
        let list = parse_command_line("ls; echo hi; pwd", &env(), "/home/root");
        let cmds = names(&list);
        assert_eq!(
            cmds,
            vec![
                ("ls".to_string(), vec![]),
                ("echo".to_string(), vec!["hi".to_string()]),
                ("pwd".to_string(), vec![]),
            ]
        );
        assert!(list.items.iter().all(|i| i.op == AndOp::Then));
    }

    #[test]
    fn pipe_splits_into_pipeline() {
        let list = parse_command_line("ls -la | grep foo", &env(), "/home/root");
        assert_eq!(list.items.len(), 1);
        assert_eq!(list.items[0].pipeline.commands.len(), 2);
        assert_eq!(list.items[0].pipeline.commands[0].name, "ls");
        assert_eq!(list.items[0].pipeline.commands[1].name, "grep");
    }

    #[test]
    fn and_or_operators() {
        let list = parse_command_line("true && echo yes || echo no", &env(), "/home/root");
        assert_eq!(list.items.len(), 3);
        assert_eq!(list.items[0].op, AndOp::And);
        assert_eq!(list.items[1].op, AndOp::Or);
        assert_eq!(list.items[2].op, AndOp::Then);
    }

    #[test]
    fn quoting_preserves_spaces() {
        let list = parse_command_line("echo \"hello   world\" 'a|b'", &env(), "/home/root");
        let cmds = names(&list);
        assert_eq!(cmds.len(), 1);
        assert_eq!(
            cmds[0].1,
            vec!["hello   world".to_string(), "a|b".to_string()]
        );
    }

    #[test]
    fn pipe_inside_quotes_is_literal() {
        let list = parse_command_line("echo \"a|b\" | grep x", &env(), "/home/root");
        assert_eq!(list.items[0].pipeline.commands.len(), 2);
        assert_eq!(list.items[0].pipeline.commands[0].args[0], "a|b");
    }

    #[test]
    fn env_var_expansion() {
        let list = parse_command_line("echo $HOME ${USER} $MISSING", &env(), "/home/root");
        let cmds = names(&list);
        assert_eq!(
            cmds[0].1,
            vec!["/home/root".to_string(), "root".to_string(), "".to_string()]
        );
    }

    #[test]
    fn tilde_expansion() {
        let list = parse_command_line("cd ~/dir", &env(), "/home/root");
        let cmds = names(&list);
        assert_eq!(cmds[0].1, vec!["/home/root/dir".to_string()]);
    }

    #[test]
    fn redirection_is_captured() {
        let list = parse_command_line("echo hi > /tmp/out 2>&1 < in", &env(), "/home/root");
        let cmds = names(&list);
        assert_eq!(cmds[0].0, "echo");
        assert_eq!(cmds[0].1, vec!["hi".to_string()]);
        let r = &list.items[0].pipeline.commands[0].redirects;
        assert_eq!(r.len(), 3);
        assert!(matches!(&r[0].target, RedirTarget::File(f) if f == "/tmp/out"));
        assert!(matches!(&r[1].target, RedirTarget::Fd(1)));
        assert!(matches!(&r[2].target, RedirTarget::File(f) if f == "in"));
    }

    #[test]
    fn devnull_redirection() {
        let list = parse_command_line("cmd 2>/dev/null", &env(), "/home/root");
        let r = &list.items[0].pipeline.commands[0].redirects;
        assert!(matches!(&r[0].target, RedirTarget::DevNull));
    }

    #[test]
    fn comment_is_ignored() {
        let list = parse_command_line("ls -la # this is a comment", &env(), "/home/root");
        let cmds = names(&list);
        assert_eq!(cmds[0].1, vec!["-la".to_string()]);
    }

    #[test]
    fn empty_line() {
        let list = parse_command_line("   ", &env(), "/home/root");
        assert!(list.items.is_empty());
    }

    #[test]
    fn background_amp_treated_as_separator() {
        let list = parse_command_line("sleep 5 & echo done", &env(), "/home/root");
        assert_eq!(list.items.len(), 2);
        assert_eq!(list.items[0].op, AndOp::Then);
    }

    #[test]
    fn subshell_is_unwrapped() {
        let list = parse_command_line("(nproc || grep -c x /f) | head -1", &env(), "/home/root");
        // `||` inside the subshell creates an and-or boundary, so nproc and head
        // end up in different items/pipelines after unwrapping.
        let all_names: Vec<String> = list
            .items
            .iter()
            .flat_map(|item| item.pipeline.commands.iter().map(|c| c.name.clone()))
            .collect();
        assert!(
            all_names.iter().any(|n| n == "nproc"),
            "names: {:?}",
            all_names
        );
        assert!(
            all_names.iter().any(|n| n == "head"),
            "names: {:?}",
            all_names
        );
    }

    #[test]
    fn assignment_detection() {
        assert_eq!(
            parse_assignment("FOO=bar"),
            Some(("FOO".into(), "bar".into()))
        );
        assert_eq!(parse_assignment("_x=1"), Some(("_x".into(), "1".into())));
        assert_eq!(parse_assignment("9k=v"), None);
        assert_eq!(parse_assignment("echo"), None);
    }

    #[test]
    fn arithmetic_eval() {
        let e = env();
        assert_eq!(eval_arithmetic("2 + 3 * 4", &e), 14);
        assert_eq!(eval_arithmetic("(2 + 3) * 4", &e), 20);
        assert_eq!(eval_arithmetic("10 % 3", &e), 1);
        assert_eq!(eval_arithmetic("-5 + 2", &e), -3);
        assert_eq!(eval_arithmetic("7 / 0", &e), 0);
        assert_eq!(eval_arithmetic("foo + 1", &e), 1); // unknown ident -> 0
    }

    #[test]
    fn looks_like_command_heuristic() {
        assert!(looks_like_command("cat --help | tr"));
        assert!(!looks_like_command("(seconds%86400)/3600"));
    }

    #[test]
    fn param_expansion_plus() {
        let mut e = env();
        e.insert("x".to_string(), "5".to_string());
        assert_eq!(expand_vars("${x:+set}", &e), "set");
        assert_eq!(expand_vars("${y:+set}", &e), ""); // unset -> empty
        assert_eq!(expand_vars("${x:-def}", &e), "5");
        assert_eq!(expand_vars("${y:-def}", &e), "def");
        assert_eq!(expand_vars("${#x}", &e), "1"); // length of "5"
    }

    /// Extract the first command name from a node list (descending into Seq).
    fn first_cmd_name(nodes: &[Node]) -> Option<String> {
        for n in nodes {
            if let Node::Seq(list) = n {
                if let Some(item) = list.items.first() {
                    if let Some(cmd) = item.pipeline.commands.first() {
                        return Some(cmd.name.clone());
                    }
                }
            }
        }
        None
    }

    #[test]
    fn parse_if_structure() {
        let e = env();
        let script = parse_script("if true; then echo a; fi", &e, "/home/root");
        assert_eq!(script.nodes.len(), 1);
        match &script.nodes[0] {
            Node::If {
                branches,
                else_body,
            } => {
                assert_eq!(branches.len(), 1);
                assert!(else_body.is_none());
                assert_eq!(first_cmd_name(&branches[0].0), Some("true".to_string()));
                assert_eq!(first_cmd_name(&branches[0].1), Some("echo".to_string()));
            }
            other => panic!("expected If, got {:?}", other),
        }
    }

    #[test]
    fn parse_if_else_structure() {
        let e = env();
        let script = parse_script("if false; then echo a; else echo b; fi", &e, "/home/root");
        match &script.nodes[0] {
            Node::If {
                branches,
                else_body,
            } => {
                assert_eq!(branches.len(), 1);
                assert!(else_body.is_some());
                assert_eq!(
                    first_cmd_name(else_body.as_ref().unwrap()),
                    Some("echo".to_string())
                );
            }
            other => panic!("expected If, got {:?}", other),
        }
    }

    #[test]
    fn parse_multiline_if() {
        let e = env();
        let script = parse_script("if [ -z \"$x\" ]; then\necho hi\nfi", &e, "/home/root");
        assert_eq!(script.nodes.len(), 1);
        assert!(matches!(script.nodes[0], Node::If { .. }));
    }

    #[test]
    fn parse_for_structure() {
        let e = env();
        let script = parse_script("for i in a b c; do echo $i; done", &e, "/home/root");
        match &script.nodes[0] {
            Node::For { var, words, body } => {
                assert_eq!(var, "i");
                assert_eq!(words, &["a".to_string(), "b".to_string(), "c".to_string()]);
                assert_eq!(first_cmd_name(body), Some("echo".to_string()));
            }
            other => panic!("expected For, got {:?}", other),
        }
    }

    #[test]
    fn incomplete_block_detection() {
        assert!(is_incomplete_block("if [ -z x ]; then"));
        assert!(is_incomplete_block("if true; then\nif false; then"));
        assert!(!is_incomplete_block("if true; then echo a; fi"));
        assert!(is_incomplete_block("for i in a; do echo $i"));
        assert!(!is_incomplete_block("for i in a; do echo $i; done"));
        assert!(is_incomplete_block("x=$(uname"));
        assert!(!is_incomplete_block("echo hello"));
        assert!(is_incomplete_block("echo \"unclosed"));
    }
}
