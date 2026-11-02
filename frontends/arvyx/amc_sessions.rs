//! Local AMC presentation extension. No protocol, runtime or provider input changes.
use super::*;
#[path = "amc_session_rpc.rs"]
mod rpc;
use crossterm::event::{KeyEventKind, MouseButton, MouseEvent, MouseEventKind};

fn terminal_text(text: &str, limit: usize) -> String {
    // Rust's Unicode debug table also identifies non-printable format,
    // separator and private-use characters, unlike char::is_control (Cc only).
    // Keep printable Unicode intact; use Python terminal_text-style visible
    // ASCII escapes only at presentation, never in route/workspace values.
    let mut result = String::new();
    for c in text.chars().take(limit) {
        if c.is_control() || (!c.is_ascii() && c.escape_debug().next() == Some('\\')) {
            let value = u32::from(c);
            result.push_str(&if value <= 0xff {
                format!("\\x{value:02x}")
            } else if value <= 0xffff {
                format!("\\u{value:04x}")
            } else {
                format!("\\U{value:08x}")
            });
        } else {
            result.push(c);
        }
    }
    result
}

#[derive(Clone, serde::Deserialize)]
pub(super) struct Session {
    pane: String,
    title: String,
    conversation: String,
}
pub(super) struct Chooser {
    sessions: Vec<Session>,
    open: bool,
    swallow_up: bool,
    all: bool,
    query: String,
    scroll: usize,
    hits: Vec<(Rect, String)>,
    area: Rect,
    header_y: u16,
    shared: bool,
    rpc: Option<rpc::Model<rpc::Client>>,
    notice: String,
    header_actions: Vec<(Rect, String)>,
    new_mode: Option<String>,
    environment: String,
    root_acknowledged: bool,
    harness: String,
    provider_acknowledged: bool,
    roots: Vec<serde_json::Value>,
    root_index: usize,
    review: Option<serde_json::Value>,
    search_dirty: bool,
}
impl Chooser {
    pub(super) fn is_open(&self) -> bool {
        self.open
    }
    pub(super) fn search_text(&mut self, text: &str) {
        self.query.extend(
            text.chars()
                .take(256usize.saturating_sub(self.query.chars().count())),
        );
        self.search_dirty = true;
        self.review = None;
        self.scroll = 0;
    }
    fn new(sessions: Vec<Session>) -> Self {
        Self {
            sessions,
            open: false,
            swallow_up: false,
            all: false,
            query: String::new(),
            scroll: 0,
            hits: vec![],
            area: Rect::default(),
            header_y: 33,
            shared: false,
            rpc: None,
            notice: String::new(),
            header_actions: vec![],
            new_mode: None,
            environment: "metadata".into(),
            root_acknowledged: false,
            harness: "shell".into(),
            provider_acknowledged: false,
            roots: vec![],
            root_index: 0,
            review: None,
            search_dirty: false,
        }
    }
    pub(super) fn from_environment() -> Option<Self> {
        if let Ok(raw) = std::env::var("AMC_ONBOARDING_RPC") {
            let mut value = Self::new(vec![]);
            value.shared = true;
            match rpc::Client::parse(&raw) {
                Ok(client) => {
                    value.rpc = Some(rpc::Model::new(client));
                    value.notice =
                        "Choose an exact connected agent; no session opens automatically".into();
                }
                Err(_) => value.notice = "Shared setup configuration invalid; no fallback".into(),
            }
            return Some(value);
        }
        let raw = std::env::var("AMC_NATIVE_SESSIONS").ok()?;
        Some(Self::new(serde_json::from_str(&raw).ok()?))
    }
    fn action(&mut self, action: &str) {
        self.open = true;
        if action == "close" {
            self.review = None;
            self.open = false;
            return;
        }
        if !self.shared {
            if action == "all" {
                self.all = true;
            }
            if action == "recent" {
                self.all = false;
            }
            self.scroll = 0;
            return;
        }
        let Some(model) = self.rpc.as_mut() else {
            return;
        };
        let result: Result<(), String> = (|| {
            match action {
                "agent" => {
                    self.sessions.clear();
                    self.hits.clear();
                    self.roots.clear();
                    self.root_index = 0;
                    self.query.clear();
                    self.search_dirty = false;
                    self.all = false;
                    self.scroll = 0;
                    self.new_mode = None;
                    self.review = None;
                    model.cycle_target()?;
                }
                "recent" => {
                    self.review = None;
                    self.new_mode = None;
                    model.recent()?;
                    self.all = false;
                }
                "all" => {
                    self.review = None;
                    self.new_mode = None;
                    model.search(&self.query)?;
                    self.all = true;
                    self.search_dirty = false;
                }
                "next" => {
                    self.review = None;
                    model.next()?;
                }
                "present" => {
                    let sid = self
                        .sessions
                        .get(self.scroll)
                        .ok_or("Select an exact listed native session")?
                        .conversation
                        .clone();
                    self.review = Some(model.present(&sid)?);
                }
                "new" => {
                    self.environment = "metadata".into();
                    self.root_acknowledged = false;
                    self.harness = "shell".into();
                    self.provider_acknowledged = false;
                    self.roots = model.roots()?;
                    self.root_index = 0;
                    self.new_mode = Some("existing".into());
                    self.review = None;
                    self.query.clear();
                }
                "root" => {
                    if !self.roots.is_empty() {
                        self.root_index = (self.root_index + 1) % self.roots.len();
                    }
                    self.review = None;
                }
                "existing" | "create" | "current" => {
                    self.new_mode = Some(action.into());
                    self.review = None;
                    self.query.clear();
                }
                "shell" | "hermes" => {
                    self.harness = action.into();
                    self.provider_acknowledged = false;
                    self.review = None;
                }
                "provider-risk" => {
                    if self.harness == "hermes" {
                        self.provider_acknowledged = true;
                    }
                    self.review = None;
                }
                "metadata" | "sandbox" | "host" | "admin" => {
                    self.environment = if action == "admin" { "root" } else { action }.into();
                    self.root_acknowledged = false;
                    self.review = None;
                }
                "risk" => {
                    if self.environment == "root" {
                        self.root_acknowledged = true;
                    }
                    self.review = None;
                }
                "review" => {
                    let mode = self.new_mode.as_deref().ok_or("Choose workspace mode")?;
                    let root = self
                        .roots
                        .get(self.root_index)
                        .ok_or("No authorized workspace roots")?["id"]
                        .clone();
                    let mut workspace = serde_json::json!({"mode":mode,"root_id":root});
                    workspace[if mode == "current" {
                        "session_id"
                    } else {
                        "path"
                    }] = serde_json::json!(self.query);
                    self.review = Some(if self.environment == "metadata" {
                        model.review(workspace)?
                    } else {
                        model.review_native(
                            workspace,
                            &self.environment,
                            self.root_acknowledged,
                            &self.harness,
                            self.provider_acknowledged,
                        )?
                    });
                }
                "confirm" => {
                    let review = self
                        .review
                        .take()
                        .ok_or("Review the exact workspace first")?;
                    let result = model.commit(&review)?;
                    self.notice = if review["action"] == "native/present" {
                        "Exact native pane focus observed.".into()
                    } else if review["execution"] == true {
                        format!(
                            "Created and focused exact native conversation: {}.",
                            result["conversation"].as_str().unwrap_or("")
                        )
                    } else if review["action"] == "sessions/select" {
                        "Exact session metadata inspected. No native input or launch.".into()
                    } else {
                        format!(
                            "Workspace ready: {}. No native session or process created.",
                            result["workspace"].as_str().unwrap_or("")
                        )
                    };
                    self.new_mode = None;
                    if result["native_focus_observed"] == true {
                        self.open = false;
                    }
                    return Ok(());
                }
                _ => {}
            }
            self.sessions = model
                .items
                .iter()
                .map(|r| Session {
                    pane: String::new(),
                    title: r["title"].as_str().unwrap_or("").into(),
                    conversation: r["route"]["session_id"].as_str().unwrap_or("").into(),
                })
                .collect();
            self.scroll = 0;
            self.notice = if self.new_mode.is_some() {
                format!(
                    "Workspace root: {} | {} | Enter reviews; explicit Confirm prepares only",
                    self.roots
                        .get(self.root_index)
                        .and_then(|r| r["label"].as_str())
                        .unwrap_or("unavailable"),
                    self.new_mode.as_deref().unwrap_or("")
                )
            } else {
                format!(
                    "{} matching metadata records | {} | no native launch",
                    model.total,
                    model
                        .exact()
                        .ok()
                        .and_then(|t| t["agent_id"].as_str().map(str::to_string))
                        .unwrap_or_default()
                )
            };
            Ok(())
        })();
        if let Err(message) = result {
            model.invalidate();
            self.sessions.clear();
            self.hits.clear();
            self.roots.clear();
            self.root_index = 0;
            self.new_mode = None;
            self.query.clear();
            self.search_dirty = false;
            self.scroll = 0;
            self.all = false;
            self.review = None;
            self.notice = message;
        }
    }
    fn select_metadata(&mut self, sid: &str) {
        if let Some(model) = self.rpc.as_ref() {
            match model.select(sid) {
                Ok(review) => {
                    self.review = Some(review);
                    self.notice = "Review the exact session, then Confirm action".into();
                }
                Err(message) => {
                    self.review = None;
                    self.notice = message;
                }
            }
        }
    }
    fn display_notice(&self) -> String {
        let text = if let Some(review) = self.review.as_ref() {
            if review["action"] == "native/present" {
                format!(
                    "Review opening exact native conversation {} | Confirm opens its native pane",
                    review["request"]["session_id"].as_str().unwrap_or("")
                )
            } else if review["execution"] == true {
                format!("Review New local shell: {} in {} | Confirm starts a process with these permissions",review["request"]["environment"].as_str().unwrap_or(""),review["snapshot"]["workspace"]["path"].as_str().unwrap_or(""))
            } else if review["action"] == "sessions/select" {
                format!(
                    "Review exact session: {} | Confirm action inspects metadata",
                    review["request"]["route"]["session_id"]
                        .as_str()
                        .unwrap_or("unavailable")
                )
            } else {
                format!(
                "Review exact workspace: {} | Confirm prepares this workspace only; no session or process",
                review["workspace"].as_str().unwrap_or("unavailable")
            )
            }
        } else {
            self.notice.clone()
        };
        terminal_text(&text, 1024)
    }
    fn filtered(&self) -> Vec<Session> {
        let query = self.query.to_lowercase();
        self.sessions
            .iter()
            .filter(|s| {
                format!("{} {}", s.title, s.conversation)
                    .to_lowercase()
                    .contains(if self.shared { "" } else { &query })
            })
            .take(if self.all { usize::MAX } else { 5 })
            .cloned()
            .collect()
    }
}
impl ClientShellState {
    pub(super) fn render_amc_sessions(&mut self, frame: &mut FrameData) -> Option<Rect> {
        let chooser = self.amc_sessions.as_mut()?;
        if !chooser.open {
            chooser.header_actions.clear();
            chooser.hits.clear();
            chooser.area = Rect::default();
            return None;
        }
        let mut buffer = frame.to_ratatui_buffer()?;
        let width = buffer.area.width;
        if width < 8 || buffer.area.height < 8 {
            return None;
        }
        let height = if chooser.open {
            buffer.area.height.saturating_sub(5).min(20)
        } else {
            0
        };
        let left = self
            .sidebar_width
            .saturating_add(2)
            .min(width.saturating_sub(4));
        chooser.header_y = 2;
        chooser.area = Rect::new(left, 2, width.saturating_sub(left + 2), height);
        let style = Style::default()
            .fg(self.config.palette.text)
            .bg(self.config.palette.panel_bg);
        for y in chooser.area.y..chooser.area.bottom() {
            for x in chooser.area.x..chooser.area.right() {
                buffer[(x, y)].set_symbol(" ").set_style(style);
            }
        }
        for x in chooser.area.x..chooser.area.right() {
            buffer[(x, chooser.header_y)]
                .set_symbol(" ")
                .set_style(style);
        }
        let labels: Vec<(&str, &str)> = if chooser.shared {
            if chooser.new_mode.is_some() {
                vec![
                    ("[Agent]", "agent"),
                    ("[Root]", "root"),
                    ("[Existing]", "existing"),
                    ("[Create]", "create"),
                    ("[Current]", "current"),
                    ("[Shell]", "shell"),
                    ("[Hermes]", "hermes"),
                    ("[Allow provider start]", "provider-risk"),
                    ("[Metadata]", "metadata"),
                    ("[Sandbox]", "sandbox"),
                    ("[Host]", "host"),
                    ("[Admin]", "admin"),
                    ("[Accept root risk]", "risk"),
                    ("[Review]", "review"),
                    ("[Confirm action]", "confirm"),
                    ("[Close]", "close"),
                ]
            } else {
                vec![
                    ("[Choose agent]", "agent"),
                    ("[Last 5]", "recent"),
                    ("[All / search]", "all"),
                    ("[Next page]", "next"),
                    ("[New session]", "new"),
                    ("[Open native]", "present"),
                    ("[Confirm action]", "confirm"),
                    ("[Close]", "close"),
                    ("[Detach]", "detach"),
                ]
            }
        } else {
            vec![
                ("[Hermes sessions]", "recent"),
                ("[Last 5]", "recent"),
                ("[All]", "all"),
                ("[New unavailable]", ""),
                ("[Close]", "close"),
                ("[Detach]", "detach"),
            ]
        };
        chooser.header_actions.clear();
        let mut x = left.saturating_add(1);
        let mut header_row = chooser.header_y;
        for (label, action) in labels {
            let length = label.len() as u16;
            if x.saturating_add(length) > chooser.area.right() {
                x = left.saturating_add(1);
                header_row += 1;
                if header_row + 4 >= chooser.area.bottom() {
                    break;
                }
            }
            buffer.set_stringn(x, header_row, label, usize::from(length), style);
            chooser
                .header_actions
                .push((Rect::new(x, header_row, length, 1), action.into()));
            x = x.saturating_add(length + 1);
        }
        chooser.hits.clear();
        if chooser.open && height > 5 {
            buffer.set_stringn(
                left + 2,
                header_row + 1,
                format!(
                    "{}: {}",
                    if chooser.new_mode.is_some() {
                        "Workspace path or exact current-session ID"
                    } else {
                        "Search title / exact ID (Enter)"
                    },
                    terminal_text(&chooser.query, 256)
                ),
                usize::from(chooser.area.width.saturating_sub(4)),
                style,
            );
            let notice = chooser.display_notice();
            buffer.set_stringn(left+2,header_row+2,if chooser.shared {notice.as_str()} else {"Existing exact owner only | New / cold resume unavailable | wheel scroll | Esc close"},usize::from(chooser.area.width.saturating_sub(4)),style);
            let sessions = chooser.filtered();
            chooser.scroll = chooser.scroll.min(sessions.len().saturating_sub(1));
            for (i, session) in sessions
                .iter()
                .skip(chooser.scroll)
                .take(usize::from(
                    chooser.area.bottom().saturating_sub(header_row + 4),
                ))
                .enumerate()
            {
                let y = header_row + 4 + i as u16;
                let live = chooser.shared
                    || self
                        .snapshot
                        .as_ref()
                        .is_some_and(|s| s.panes.iter().any(|p| p.pane_id == session.pane));
                let selected = !chooser.shared
                    && self.snapshot.as_ref().is_some_and(|s| {
                        s.panes
                            .iter()
                            .any(|p| p.pane_id == session.pane && p.focused)
                    });
                let label = format!(
                    "{} {} | {}{}",
                    if selected { "●" } else { " " },
                    session.title,
                    session.conversation,
                    if live { "" } else { " [unavailable]" }
                );
                let label = terminal_text(&label, 4096);
                buffer.set_stringn(
                    left + 2,
                    y,
                    label,
                    usize::from(chooser.area.width.saturating_sub(4)),
                    style,
                );
                if live {
                    chooser.hits.push((
                        Rect::new(left, y, chooser.area.width, 1),
                        if chooser.shared {
                            session.conversation.clone()
                        } else {
                            session.pane.clone()
                        },
                    ));
                }
            }
        }
        frame.replace_from_ratatui_buffer_preserving_effects(&buffer, None);
        Some(chooser.area)
    }
    pub(super) fn amc_mouse(&mut self, mouse: MouseEvent, outcome: &mut ClientShellInput) -> bool {
        let Some(chooser) = self.amc_sessions.as_mut() else {
            return false;
        };
        if chooser.swallow_up {
            if matches!(mouse.kind, MouseEventKind::Up(_)) {
                chooser.swallow_up = false;
            }
            return true;
        }
        let point = (mouse.column, mouse.row);
        if chooser.open
            && super::contains(chooser.area, point)
            && mouse.kind == MouseEventKind::Down(MouseButton::Left)
            && chooser
                .header_actions
                .iter()
                .any(|(area, _)| super::contains(*area, point))
        {
            let action = chooser
                .header_actions
                .iter()
                .find(|(area, _)| super::contains(*area, point))
                .map(|(_, action)| action.clone());
            if let Some(action) = action {
                if action == "detach" {
                    outcome.detach = true;
                } else {
                    chooser.action(&action);
                }
            }
            outcome.repaint = true;
            return true;
        }
        if chooser.open
            && super::contains(chooser.area, point)
            && chooser
                .header_actions
                .iter()
                .any(|(area, _)| super::contains(*area, point))
        {
            return true;
        }
        if mouse.kind == MouseEventKind::Down(MouseButton::Left)
            && self.hits.agents.iter().any(|(area, pane)| {
                super::contains(*area, point) && chooser.sessions.iter().any(|s| &s.pane == pane)
            })
        {
            chooser.open = true;
            chooser.query.clear();
            chooser.scroll = 0;
            chooser.swallow_up = true;
            outcome.repaint = true;
            return true;
        }
        if !chooser.open {
            return false;
        }
        if !super::contains(chooser.area, point) {
            // Preserve the original native agent rail, tabs and pane interactions.
            if matches!(mouse.kind, MouseEventKind::Down(_)) {
                chooser.open = false;
                outcome.repaint = true;
            }
            return false;
        }
        match mouse.kind {
            MouseEventKind::ScrollDown => chooser.scroll = chooser.scroll.saturating_add(3),
            MouseEventKind::ScrollUp => chooser.scroll = chooser.scroll.saturating_sub(3),
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some((_, pane)) = chooser
                    .hits
                    .iter()
                    .find(|(area, _)| super::contains(*area, point))
                {
                    let pane = pane.clone();
                    chooser.swallow_up = true;
                    if chooser.shared {
                        chooser.select_metadata(&pane);
                    } else {
                        chooser.open = false;
                        self.push_endpoint_method(
                            crate::api::schema::Method::PaneFocus(crate::api::schema::PaneTarget {
                                pane_id: pane,
                            }),
                            outcome,
                        );
                    }
                }
            }
            _ => {}
        }
        outcome.repaint = true;
        true
    }
    pub(super) fn amc_key(
        &mut self,
        key: &crate::input::TerminalKey,
        outcome: &mut ClientShellInput,
    ) -> bool {
        let Some(chooser) = self.amc_sessions.as_mut() else {
            return false;
        };
        if key.code == KeyCode::F(6) {
            if key.kind == KeyEventKind::Press {
                chooser.open = !chooser.open;
                outcome.repaint = true;
            }
            return true;
        }
        if !chooser.open {
            return false;
        }
        if key.kind == KeyEventKind::Press {
            match key.code {
                KeyCode::Esc => chooser.open = false,
                KeyCode::Char(c) if !c.is_control() && chooser.query.chars().count() < 256 => {
                    chooser.search_dirty = true;
                    chooser.review = None;
                    chooser.query.push(c);
                    chooser.scroll = 0;
                }
                KeyCode::Backspace => {
                    chooser.search_dirty = true;
                    chooser.review = None;
                    chooser.query.pop();
                    chooser.scroll = 0;
                }
                KeyCode::Tab if chooser.shared => chooser.action(if chooser.new_mode.is_some() {
                    "root"
                } else {
                    "agent"
                }),
                KeyCode::PageDown if chooser.shared => chooser.action("next"),
                KeyCode::Down => chooser.scroll = chooser.scroll.saturating_add(1),
                KeyCode::Up => chooser.scroll = chooser.scroll.saturating_sub(1),
                KeyCode::Enter if !chooser.shared => {
                    if let Some(item) = chooser.filtered().get(chooser.scroll) {
                        let pane = item.pane.clone();
                        if self
                            .snapshot
                            .as_ref()
                            .is_some_and(|s| s.panes.iter().any(|p| p.pane_id == pane))
                        {
                            chooser.open = false;
                            self.push_endpoint_method(
                                crate::api::schema::Method::PaneFocus(
                                    crate::api::schema::PaneTarget { pane_id: pane },
                                ),
                                outcome,
                            );
                        }
                    }
                }
                KeyCode::Enter if chooser.shared => {
                    if chooser.new_mode.is_some() {
                        chooser.action(if chooser.review.is_some() {
                            "confirm"
                        } else {
                            "review"
                        });
                    } else if chooser.search_dirty {
                        chooser.action("all");
                    } else if let Some(item) = chooser.filtered().get(chooser.scroll) {
                        let sid = item.conversation.clone();
                        chooser.select_metadata(&sid);
                    }
                }
                _ => {}
            }
            outcome.repaint = true;
        }
        true // Search keystrokes never reach the native pane/provider.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_chooser_does_not_occlude_or_consume_bottom_row() {
        let mut state = ClientShellState::new(ClientShellConfig::from_config(&Config::default()));
        state.amc_sessions = Some(Chooser::new(vec![]));
        let mut buffer = Buffer::empty(Rect::new(0, 0, 80, 20));
        buffer.set_stringn(0, 19, "native bottom row", 80, Style::default());
        let mut frame = FrameData::from_ratatui_buffer_with_hyperlinks(&buffer, None, &[]);
        assert!(state.render_amc_sessions(&mut frame).is_none());
        assert_eq!(frame.to_ratatui_buffer().unwrap()[(0, 19)].symbol(), "n");
        let mut output = ClientShellInput::default();
        assert!(!state.amc_mouse(
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: 70,
                row: 19,
                modifiers: crossterm::event::KeyModifiers::NONE,
            },
            &mut output
        ));
        let key = crate::input::TerminalKey::new(
            KeyCode::Char('x'),
            crossterm::event::KeyModifiers::NONE,
        );
        assert!(!state.amc_key(&key, &mut output));
    }

    #[test]
    fn hostile_metadata_is_visible_in_the_actual_terminal_buffer() {
        let hostile = "pay\u{202e}\u{2066}\u{200d}\u{2028}\u{a0}\u{e000}\x1b[31m";
        let mut state = ClientShellState::new(ClientShellConfig::from_config(&Config::default()));
        let mut chooser = Chooser::new(vec![Session {
            pane: "unavailable".into(),
            title: hostile.into(),
            conversation: "exact-id".into(),
        }]);
        chooser.shared = true;
        chooser.open = true;
        chooser.notice = hostile.into();
        chooser.search_text(hostile);
        // Store/query/route identifiers stay exact; escaping is presentation only.
        state.amc_sessions = Some(chooser);
        let buffer = Buffer::empty(Rect::new(0, 0, 220, 20));
        let mut frame = FrameData::from_ratatui_buffer_with_hyperlinks(&buffer, None, &[]);
        assert!(state.render_amc_sessions(&mut frame).is_some());
        assert_eq!(state.amc_sessions.as_ref().unwrap().query, hostile);
        let output = frame.to_ratatui_buffer().unwrap();
        for y in [3, 4, 6] {
            let row: String = (0..220).map(|x| output[(x, y)].symbol()).collect();
            for visible in [
                "\\u202e", "\\u2066", "\\u200d", "\\u2028", "\\xa0", "\\ue000", "\\x1b",
            ] {
                assert!(
                    row.contains(visible),
                    "missing {visible:?} in row {y}: {row:?}"
                );
            }
            for c in hostile.chars().filter(|c| !c.is_ascii()) {
                assert!(!row.contains(c));
            }
        }
        assert_eq!(
            state.amc_sessions.as_ref().unwrap().sessions[0].conversation,
            "exact-id"
        );
    }

    #[test]
    fn shared_server_activity_order_is_preserved_for_last_five() {
        let chooser = Chooser::new(
            (0..8)
                .rev()
                .map(|i| Session {
                    pane: format!("p{i}"),
                    title: format!("Session {i}"),
                    conversation: format!("c{i}"),
                })
                .collect(),
        );
        assert_eq!(
            chooser
                .filtered()
                .iter()
                .map(|s| s.conversation.clone())
                .collect::<Vec<_>>(),
            vec!["c7", "c6", "c5", "c4", "c3"]
        );
    }
    #[test]
    fn query_is_bounded_and_never_produces_native_input() {
        let mut chooser = Chooser::new(vec![]);
        chooser.search_text(&"x".repeat(5000));
        assert_eq!(chooser.query.len(), 256);
        assert!(chooser.search_dirty);
        assert!(chooser.review.is_none());
    }
    #[test]
    fn workspace_review_displays_exact_effect_and_sanitizes_controls() {
        let mut chooser = Chooser::new(vec![]);
        chooser.review = Some(serde_json::json!({"workspace":"/approved/exact"}));
        assert!(chooser.display_notice().contains("/approved/exact"));
        assert!(chooser.display_notice().contains("no session or process"));
        chooser.review = None;
        chooser.notice = "unsafe\x1b[31m".into();
        assert!(!chooser.display_notice().contains('\x1b'));
    }
    #[test]
    fn chooser_repeat_and_release_never_forward_input() {
        let mut state = ClientShellState::new(ClientShellConfig::from_config(&Config::default()));
        let mut chooser = Chooser::new(vec![]);
        chooser.open = true;
        state.amc_sessions = Some(chooser);
        let mut output = ClientShellInput::default();
        let mut key = crate::input::TerminalKey::new(
            KeyCode::Char('x'),
            crossterm::event::KeyModifiers::NONE,
        );
        key.kind = KeyEventKind::Repeat;
        assert!(state.amc_key(&key, &mut output));
        key.kind = KeyEventKind::Release;
        assert!(state.amc_key(&key, &mut output));
        assert!(output.requests.is_empty());
        assert!(state.amc_sessions.as_ref().unwrap().query.is_empty());
    }
}
