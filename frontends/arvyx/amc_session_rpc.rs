//! AMC client of the SAME authenticated onboarding API used by web/text clients.
//! No runtime protocol, provider input, process launch, credential persistence or
//! role provisioning. Network work occurs only on explicit input, never render.
use serde_json::{json, Value};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};
const MAX: usize = 1024 * 1024;
pub(super) trait Transport {
    fn call(&self, operation: &str, body: Option<Value>) -> Result<Value, String>;
}
pub(super) struct Client {
    address: SocketAddr,
    origin: String,
    capability: String,
}
impl Client {
    pub(super) fn parse(raw: &str) -> Result<Self, String> {
        let value: Value =
            serde_json::from_str(raw).map_err(|_| "Invalid shared service configuration")?;
        let origin = value["origin"]
            .as_str()
            .ok_or("Missing origin")?
            .trim_end_matches('/');
        let port = origin
            .strip_prefix("http://127.0.0.1:")
            .ok_or("Literal loopback origin required")?;
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err("Canonical loopback port required".into());
        }
        let number: u16 = port.parse().map_err(|_| "Invalid loopback port")?;
        if number == 0 || number.to_string() != port {
            return Err("Canonical loopback port required".into());
        }
        let capability = value["capability"].as_str().ok_or("Missing capability")?;
        if capability.is_empty()
            || capability.len() > 256
            || !capability.bytes().all(|b| (33..=126).contains(&b))
        {
            return Err("Invalid capability".into());
        }
        Ok(Self {
            address: ([127, 0, 0, 1], number).into(),
            origin: origin.into(),
            capability: capability.into(),
        })
    }
}
fn decode_response(raw: &[u8]) -> Result<Value, String> {
    if raw.len() > MAX {
        return Err("Shared service response exceeds limit".into());
    }
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("Invalid HTTP framing")?;
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| "Invalid HTTP header")?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .ok_or("Missing HTTP status")?
        .split_whitespace()
        .nth(1)
        .ok_or("Missing HTTP status")?;
    let mut length = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or("Invalid HTTP header")?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("Unsupported HTTP framing".into());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err("Duplicate HTTP length".into());
            }
            length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| "Invalid HTTP length")?,
            );
        }
    }
    let body = &raw[split + 4..];
    if length != Some(body.len()) {
        return Err("Incomplete HTTP response".into());
    }
    if status != "200" && status != "201" {
        return Err(format!(
            "Shared service refused request ({status}); nothing retried"
        ));
    }
    serde_json::from_slice(body).map_err(|_| "Invalid shared service JSON".into())
}
impl Transport for Client {
    fn call(&self, operation: &str, body: Option<Value>) -> Result<Value, String> {
        if !matches!(
            operation,
            "targets"
                | "sessions/recent"
                | "sessions/all"
                | "sessions/select"
                | "actions/prepare"
                | "actions/commit"
                | "sessions/workspaces"
                | "sessions/prepare"
                | "sessions/commit"
                | "native/prepare"
                | "native/commit"
        ) {
            return Err("Operation outside native client scope".into());
        }
        let method = if body.is_some() { "POST" } else { "GET" };
        let payload = body.map(|b| b.to_string()).unwrap_or_default();
        if payload.len() > 16384 {
            return Err("Shared request exceeds limit".into());
        }
        let deadline = Instant::now() + Duration::from_millis(900);
        let mut stream = TcpStream::connect_timeout(&self.address, Duration::from_millis(900))
            .map_err(|_| "Shared service unavailable")?;
        stream
            .set_read_timeout(Some(Duration::from_millis(900)))
            .map_err(|_| "Read deadline unavailable")?;
        stream
            .set_write_timeout(Some(Duration::from_millis(900)))
            .map_err(|_| "Write deadline unavailable")?;
        let request = format!(
            concat!("{method} /api/public-onboarding/{operation} HTTP/1.0\r\n", "Host: {}\r\nOrigin: {}\r\nAuthorization: Bearer {}\r\n", "Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}"),
            self.address,
            self.origin,
            self.capability,
            payload.len(),
            method = method, operation = operation, payload = payload
        );
        let mut sent = 0;
        while sent < request.len() {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or("Shared deadline exceeded; delivery uncertain; nothing retried")?;
            stream
                .set_write_timeout(Some(remaining))
                .map_err(|_| "Write deadline unavailable")?;
            let count = stream
                .write(&request.as_bytes()[sent..])
                .map_err(|_| "Shared request delivery uncertain; nothing retried")?;
            if count == 0 {
                return Err("Shared request closed; delivery uncertain; nothing retried".into());
            }
            sent += count;
        }
        let mut raw = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or("Shared response deadline exceeded; nothing retried")?;
            stream
                .set_read_timeout(Some(remaining))
                .map_err(|_| "Read deadline unavailable")?;
            let count = stream
                .read(&mut buffer)
                .map_err(|_| "Shared response unavailable; nothing retried")?;
            if count == 0 {
                break;
            }
            if raw.len() + count > MAX {
                return Err("Shared response exceeds limit; nothing retried".into());
            }
            raw.extend_from_slice(&buffer[..count]);
        }
        decode_response(&raw)
    }
}
fn target(value: &Value) -> Result<Value, String> {
    let mut result = serde_json::Map::new();
    for key in ["machine_id", "agent_id", "workspace_id", "connection_id"] {
        let text = value[key]
            .as_str()
            .filter(|v| !v.is_empty())
            .ok_or("Incomplete exact destination")?;
        result.insert(key.into(), json!(text));
    }
    Ok(Value::Object(result))
}
pub(super) struct Model<T: Transport> {
    transport: T,
    pub(super) targets: Vec<Value>,
    pub(super) selected: Option<usize>,
    pub(super) items: Vec<Value>,
    pub(super) total: usize,
    pub(super) next_cursor: Option<String>,
    query: String,
}
impl<T: Transport> Model<T> {
    pub(super) fn new(transport: T) -> Self {
        Self {
            transport,
            targets: vec![],
            selected: None,
            items: vec![],
            total: 0,
            next_cursor: None,
            query: String::new(),
        }
    }
    pub(super) fn exact(&self) -> Result<Value, String> {
        self.selected
            .and_then(|i| self.targets.get(i))
            .cloned()
            .ok_or("Choose an exact connected agent first".into())
    }
    pub(super) fn invalidate(&mut self) {
        self.items.clear();
        self.total = 0;
        self.next_cursor = None;
        self.query.clear();
    }
    pub(super) fn cycle_target(&mut self) -> Result<(), String> {
        self.invalidate();
        // Refresh on every explicit Agent action. Connection incarnations and
        // consent can change while this process is alive; never retain stale
        // routes if fetching or validating the replacement catalog fails.
        let previous = self.exact().ok();
        self.targets.clear();
        self.selected = None;
        let response = self.transport.call("targets", None)?;
        self.targets = response["items"]
            .as_array()
            .ok_or("Invalid target catalog")?
            .iter()
            .map(target)
            .collect::<Result<_, _>>()?;
        if self.targets.is_empty() {
            return Err("No consented metadata profile is connected".into());
        }
        self.selected = Some(
            previous
                .and_then(|old| self.targets.iter().position(|value| value == &old))
                .map_or(0, |i| (i + 1) % self.targets.len()),
        );
        self.recent()
    }
    fn accept(&mut self, response: Value, recent: bool) -> Result<(), String> {
        let exact = self.exact()?;
        let items = response["items"]
            .as_array()
            .ok_or("Invalid metadata page")?;
        if items.len() > if recent { 5 } else { 20 } {
            return Err("Metadata page exceeds requested limit".into());
        }
        let mut seen = HashSet::new();
        for row in items {
            let sid = row["route"]["session_id"]
                .as_str()
                .ok_or("Missing session identity")?;
            if target(&row["route"]["target"])? != exact
                || !seen.insert(sid)
                || row["title"].as_str().is_none()
            {
                return Err("Metadata destination mismatch; reload".into());
            }
        }
        let next = response.get("next_cursor").filter(|v| !v.is_null());
        if next.is_some_and(|v| v.as_str().is_none_or(|s| s.is_empty() || s.len() > 1024)) {
            return Err("Invalid metadata cursor".into());
        }
        let total = if recent {
            items.len()
        } else {
            usize::try_from(response["total"].as_u64().ok_or("Missing total")?)
                .map_err(|_| "Metadata total exceeds platform limit")?
        };
        if total < items.len() || (next.is_some() && (items.is_empty() || total <= items.len())) {
            return Err("Inconsistent metadata page total or continuation".into());
        }
        self.items = items.clone();
        self.total = total;
        self.next_cursor = next.and_then(|v| v.as_str()).map(str::to_string);
        Ok(())
    }
    pub(super) fn recent(&mut self) -> Result<(), String> {
        self.invalidate();
        let response = self
            .transport
            .call("sessions/recent", Some(json!({"target":self.exact()?})))?;
        self.accept(response, true)
    }
    pub(super) fn search(&mut self, query: &str) -> Result<(), String> {
        if query.chars().count() > 256 {
            self.invalidate();
            return Err("Search exceeds limit".into());
        }
        self.query = query.into();
        self.page(None)
    }
    fn page(&mut self, cursor: Option<String>) -> Result<(), String> {
        let result = (|| {
            let response = self.transport.call(
                "sessions/all",
                Some(json!({"target":self.exact()?,"query":self.query,"limit":20,"cursor":cursor})),
            )?;
            self.accept(response, false)
        })();
        if result.is_err() {
            self.invalidate();
        }
        result
    }
    pub(super) fn next(&mut self) -> Result<(), String> {
        let cursor = self.next_cursor.clone().ok_or("No next page")?;
        self.page(Some(cursor))
    }
    pub(super) fn select(&self, sid: &str) -> Result<Value, String> {
        let route = self
            .items
            .iter()
            .find(|r| r["route"]["session_id"] == sid)
            .ok_or("Select a listed exact session")?["route"]
            .clone();
        if route["target"] != self.exact()? {
            return Err("Selection destination changed; reload".into());
        }
        let response = self.transport.call(
            "actions/prepare",
            Some(json!({"action":"sessions/select","request":{"route":route,"confirmed":true}})),
        )?;
        if response["action"] != "sessions/select" || response["request"]["route"] != route {
            return Err("Selection destination mismatch".into());
        }
        Ok(response)
    }
    pub(super) fn present(&self, sid: &str) -> Result<Value, String> {
        if !self.items.iter().any(|r| r["route"]["session_id"] == sid) {
            return Err("Select a listed exact native session".into());
        }
        let request = json!({"target":self.exact()?,"session_id":sid,"confirmed":true});
        let review = self.transport.call(
            "actions/prepare",
            Some(json!({"action":"native/present","request":request})),
        )?;
        if review["action"] != "native/present" || review["request"] != request {
            return Err("Exact native presentation review mismatch".into());
        }
        Ok(review)
    }
    pub(super) fn roots(&self) -> Result<Vec<Value>, String> {
        let response = self
            .transport
            .call("sessions/workspaces", Some(json!({"target":self.exact()?})))?;
        response["roots"]
            .as_array()
            .cloned()
            .ok_or("No authorized workspace roots".into())
    }
    pub(super) fn review(&self, workspace: Value) -> Result<Value, String> {
        let response = self.transport.call(
            "sessions/prepare",
            Some(json!({"target":self.exact()?,"workspace":workspace,"environment":"metadata"})),
        )?;
        if response["request"]["target"] != self.exact()?
            || response["execution"] != false
            || response["native_session_creation"] != false
        {
            return Err("Unrecognized preparation effect; refused".into());
        }
        Ok(response)
    }
    pub(super) fn review_native(
        &self,
        workspace: Value,
        environment: &str,
        root_acknowledged: bool,
        harness: &str,
        provider_acknowledged: bool,
    ) -> Result<Value, String> {
        if !matches!(environment, "sandbox" | "host" | "root")
            || (environment == "root" && !root_acknowledged)
        {
            return Err("Explicit executor choice and root risk acknowledgement required".into());
        }
        if !matches!(harness, "shell" | "hermes") || (harness == "hermes" && !provider_acknowledged)
        {
            return Err(
                "Separate configured Hermes provider-start acknowledgement required".into(),
            );
        }
        let request = json!({"target":self.exact()?,"workspace":workspace,"environment":environment,"harness":harness,"root_acknowledged":root_acknowledged,"provider_start_acknowledged":provider_acknowledged,"presentation":"native"});
        let review = self
            .transport
            .call("native/prepare", Some(request.clone()))?;
        if review["request"] != request || review["execution"] != true {
            return Err("Exact native effect review mismatch".into());
        }
        Ok(review)
    }
    pub(super) fn commit(&self, review: &Value) -> Result<Value, String> {
        if review["action"] == "native/present" {
            if review["request"]["target"] != self.exact()? {
                return Err("Native destination changed".into());
            }
            let response=self.transport.call("actions/commit",Some(json!({"consent_id":review["consent_id"],"consent_sha256":review["sha256"],"confirmed":true})))?;
            if response["target"] != self.exact()?
                || response["conversation"] != review["request"]["session_id"]
                || response["native_focus_observed"] != true
                || response["pane_id"]
                    .as_str()
                    .filter(|v| !v.is_empty())
                    .is_none()
            {
                return Err("Exact native focus not acknowledged; do not recreate".into());
            }
            return Ok(response);
        }

        if review["execution"] == true {
            if review["request"]["target"] != self.exact()?
                || !matches!(
                    review["request"]["harness"].as_str(),
                    Some("shell" | "hermes")
                )
            {
                return Err("Native review target changed".into());
            }
            let result=self.transport.call("native/commit",Some(json!({"consent_id":review["consent_id"],"consent_sha256":review["sha256"],"confirmed":true})))?;
            if result["target"] != self.exact()?
                || result["native_session_created"] != true
                || result["tool"] != review["request"]["harness"]
                || result["owner_session"]
                    .as_str()
                    .filter(|v| !v.is_empty())
                    .is_none()
                || result["environment"] != review["request"]["environment"]
                || result["native_focus_observed"] != true
                || result["pane_id"]
                    .as_str()
                    .filter(|v| !v.is_empty())
                    .is_none()
            {
                return Err("Native creation outcome uncertain; reconcile without replay".into());
            }
            return Ok(result);
        }

        if review["action"] == "sessions/select" {
            let route = &review["request"]["route"];
            if route["target"] != self.exact()? {
                return Err("Review destination changed".into());
            }
            let response=self.transport.call("actions/commit",Some(json!({"consent_id":review["consent_id"],"consent_sha256":review["sha256"],"confirmed":true})))?;
            if response["route"] != *route {
                return Err("Selection destination mismatch".into());
            }
            return Ok(response);
        }
        if review["request"]["target"] != self.exact()? {
            return Err("Review destination changed".into());
        }
        let response=self.transport.call("sessions/commit",Some(json!({"consent_id":review["consent_id"],"consent_sha256":review["sha256"],"confirmed":true})))?;
        if response["target"] != self.exact()?
            || response["native_session_created"] != false
            || response["execution"] != false
            || response["status"] != "workspace_ready"
        {
            return Err("Workspace preparation not confirmed; reconcile, never retry".into());
        }
        Ok(response)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    fn exact() -> Value {
        json!({"machine_id":"m","agent_id":"a","workspace_id":"w","connection_id":"c"})
    }
    struct Fake {
        calls: RefCell<Vec<(String, Option<Value>)>>,
    }
    impl Transport for Fake {
        fn call(&self, operation: &str, body: Option<Value>) -> Result<Value, String> {
            self.calls
                .borrow_mut()
                .push((operation.into(), body.clone()));
            match operation {
                "targets" => Ok(json!({"items":[exact()]})),
                "sessions/recent" => Ok(
                    json!({"items":(1200..1205).rev().map(|i|json!({"route":{"target":exact(),"session_id":i.to_string()},"title":format!("Session {i}")})).collect::<Vec<_>>() }),
                ),
                "sessions/all" => {
                    let b = body.unwrap();
                    let start = b["cursor"]
                        .as_str()
                        .unwrap_or("0")
                        .parse::<usize>()
                        .unwrap();
                    let end = (start + 20).min(1205);
                    Ok(
                        json!({"items":(start..end).map(|i|json!({"route":{"target":exact(),"session_id":i.to_string()},"title":"Stored"})).collect::<Vec<_>>(),"total":1205,"next_cursor":if end<1205 {Some(end.to_string())}else{None}}),
                    )
                }
                "actions/prepare" => {
                    let b = body.unwrap();
                    Ok(
                        json!({"action":"sessions/select","request":b["request"],"consent_id":"fixture","sha256":"fixture-digest"}),
                    )
                }
                "actions/commit" => Ok(
                    json!({"route":{"target":exact(),"session_id":"1204"},"result":{"metadata_only":true}}),
                ),
                _ => Err("Not configured".into()),
            }
        }
    }
    #[test]
    fn native_presentation_requires_fresh_review_and_observed_exact_focus() {
        struct Present {
            observed: bool,
        }
        impl Transport for Present {
            fn call(&self, op: &str, body: Option<Value>) -> Result<Value, String> {
                match op {
                    "actions/prepare" => {
                        let b = body.unwrap();
                        Ok(
                            json!({"action":"native/present","request":b["request"],"consent_id":"id","sha256":"digest"}),
                        )
                    }
                    "actions/commit" => Ok(
                        json!({"target":exact(),"conversation":"native","pane_id":"pane-exact","native_focus_observed":self.observed}),
                    ),
                    _ => Err("unexpected".into()),
                }
            }
        }
        let mut model = Model::new(Present { observed: false });
        model.targets = vec![exact()];
        model.selected = Some(0);
        model.items = vec![json!({"route":{"target":exact(),"session_id":"native"}})];
        assert!(model.present("other").is_err());
        let review = model.present("native").unwrap();
        assert!(model.commit(&review).is_err());
        model.transport.observed = true;
        assert!(model.commit(&review).is_ok());
    }

    #[test]
    fn native_new_requires_review_exact_target_and_root_risk() {
        struct Native {
            calls: RefCell<Vec<String>>,
        }
        impl Transport for Native {
            fn call(&self, op: &str, body: Option<Value>) -> Result<Value, String> {
                self.calls.borrow_mut().push(op.into());
                match op {
                    "native/prepare" => Ok(
                        json!({"execution":true,"request":body.unwrap(),"consent_id":"id","sha256":"digest"}),
                    ),
                    "native/commit" => Ok(
                        json!({"target":exact(),"owner_session":"immutable-owner-id","conversation":"immutable-owner-id","tool":"shell","environment":"host","native_session_created":true,"native_focus_observed":true,"pane_id":"exact-pane"}),
                    ),
                    _ => Err("unexpected".into()),
                }
            }
        }
        let mut model = Model::new(Native {
            calls: RefCell::new(vec![]),
        });
        model.targets = vec![exact()];
        model.selected = Some(0);
        assert!(model
            .review_native(json!({}), "root", false, "shell", false)
            .is_err());
        assert!(model.transport.calls.borrow().is_empty());
        let review = model
            .review_native(
                json!({"mode":"existing","root_id":"work","path":"folder"}),
                "host",
                false,
                "shell",
                false,
            )
            .unwrap();
        assert_eq!(*model.transport.calls.borrow(), vec!["native/prepare"]);
        let result = model.commit(&review).unwrap();
        assert_eq!(result["owner_session"], "immutable-owner-id");
        let mut changed = review;
        changed["request"]["target"]["connection_id"] = json!("stale");
        assert!(model.commit(&changed).is_err());
        assert_eq!(
            *model.transport.calls.borrow(),
            vec!["native/prepare", "native/commit"]
        );
    }

    #[test]
    fn catalog_refresh_replaces_incarnation_and_clears_on_failure() {
        struct Reconnect {
            generation: RefCell<usize>,
        }
        impl Transport for Reconnect {
            fn call(&self, operation: &str, body: Option<Value>) -> Result<Value, String> {
                let generation = *self.generation.borrow();
                let mut current = exact();
                current["connection_id"] = json!(format!("c{generation}"));
                match operation {
                    "targets" if generation == 2 => Err("revoked".into()),
                    "targets" => Ok(json!({"items":[current]})),
                    "sessions/recent" => {
                        assert_eq!(body.unwrap()["target"], current);
                        Ok(json!({"items":[]}))
                    }
                    _ => Err("unexpected operation".into()),
                }
            }
        }
        let mut model = Model::new(Reconnect {
            generation: RefCell::new(0),
        });
        model.cycle_target().unwrap();
        assert_eq!(model.exact().unwrap()["connection_id"], "c0");
        *model.transport.generation.borrow_mut() = 1;
        model.cycle_target().unwrap();
        assert_eq!(model.exact().unwrap()["connection_id"], "c1");
        *model.transport.generation.borrow_mut() = 2;
        assert!(model.cycle_target().is_err());
        assert!(model.exact().is_err());
        assert!(model.items.is_empty());
        assert!(model.next_cursor.is_none());
    }

    #[test]
    fn profile_history_last5_and_all_1205_pages_use_shared_api() {
        let mut model = Model::new(Fake {
            calls: RefCell::new(vec![]),
        });
        assert!(model.recent().is_err());
        model.cycle_target().unwrap();
        assert_eq!(model.items[0]["route"]["session_id"], "1204");
        model.search("").unwrap();
        let mut count = model.items.len();
        while model.next_cursor.is_some() {
            model.next().unwrap();
            count += model.items.len();
        }
        assert_eq!(count, 1205);
        assert_eq!(model.total, 1205);
        let review = model.select("1204").unwrap();
        assert!(!model
            .transport
            .calls
            .borrow()
            .iter()
            .any(|(op, _)| op == "actions/commit"));
        assert!(model.commit(&review).is_ok());
        assert!(model.select("not-listed").is_err());
        assert!(!model
            .transport
            .calls
            .borrow()
            .iter()
            .any(|(op, _)| op.contains("execute") || op.contains("launch")));
    }
    // Focus75 REV-0026 regressions: NOT_EXECUTED. No native acceptance implied.
    #[test]
    fn focus75_rejects_inconsistent_history_pages() {
        struct Page(Value);
        impl Transport for Page {
            fn call(&self, _: &str, _: Option<Value>) -> Result<Value, String> {
                Ok(self.0.clone())
            }
        }
        let row = json!({"route":{"target":exact(),"session_id":"one"},"title":"Stored"});
        for response in [
            json!({"items":[row.clone()],"total":0,"next_cursor":null}),
            json!({"items":[row.clone()],"total":1,"next_cursor":"next"}),
            json!({"items":[],"total":2,"next_cursor":"next"}),
            json!({"items":[row.clone()],"total":2,"next_cursor":""}),
        ] {
            let mut model = Model::new(Page(response));
            model.targets = vec![exact()];
            model.selected = Some(0);
            model.items = vec![row.clone()];
            model.next_cursor = Some("old".into());
            assert!(model.search("").is_err());
            assert!(model.items.is_empty());
            assert!(model.next_cursor.is_none());
            assert_eq!(model.total, 0);
        }
    }
    #[test]
    fn focus75_overlong_search_clears_old_selection() {
        let mut model = Model::new(Fake {
            calls: RefCell::new(vec![]),
        });
        model.cycle_target().unwrap();
        assert!(!model.items.is_empty());
        assert!(model.search(&"x".repeat(257)).is_err());
        assert!(model.items.is_empty());
        assert!(model.next_cursor.is_none());
    }
    #[test]
    fn real_client_posts_exact_json_content_type() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let header = String::from_utf8(request).unwrap();
            assert_eq!(
                header
                    .lines()
                    .filter(|line| *line == "Content-Type: application/json")
                    .count(),
                1
            );
            assert!(header.contains("Origin: http://127.0.0.1:"));
            assert!(header.contains("Authorization: Bearer fixture"));
            let length: usize = header
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .unwrap()
                .parse()
                .unwrap();
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap(),
                json!({"target":exact()})
            );
            stream
                .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                .unwrap();
        });
        let client = Client::parse(
            &json!({"origin":format!("http://{address}"),"capability":"fixture"}).to_string(),
        )
        .unwrap();
        assert_eq!(
            client
                .call("sessions/recent", Some(json!({"target":exact()})))
                .unwrap(),
            json!({})
        );
        server.join().unwrap();
    }
    #[test]
    fn malformed_origin_and_header_injection_are_refused() {
        for origin in [
            "https://127.0.0.1:1",
            "http://localhost:1",
            "http://127.0.0.1:1/private",
            "http://127.0.0.1:1?x=1",
            "http://127.0.0.1:0001",
        ] {
            assert!(
                Client::parse(&json!({"origin":origin,"capability":"fixture"}).to_string())
                    .is_err()
            );
        }
        assert!(Client::parse(
            &json!({"origin":"http://127.0.0.1:1","capability":"x\r\nInjected: yes"}).to_string()
        )
        .is_err());
    }
    #[test]
    fn response_framing_and_failures_do_not_fallback() {
        assert!(decode_response(b"HTTP/1.0 403 Forbidden\r\nContent-Length: 2\r\n\r\n{}").is_err());
        assert!(decode_response(
            b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}"
        )
        .is_err());
        assert!(decode_response(b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\n{}").is_err());
        assert_eq!(
            decode_response(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}").unwrap(),
            json!({})
        );
    }
}
#[cfg(test)]
mod deadline_regressions {
    #[test]
    fn native_client_total_deadline_is_not_renewable() {
        use super::{Client, Transport};
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::time::{Duration, Instant};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 100\r\n\r\n");
            for _ in 0..30 {
                if stream.write_all(b" ").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let config=serde_json::json!({"origin":format!("http://{address}"),"capability":"synthetic-local-review-marker-only"}).to_string();
        let client = Client::parse(&config).unwrap();
        let start = Instant::now();
        assert!(client.call("targets", None).is_err());
        let elapsed = start.elapsed();
        server.join().unwrap();
        assert!(elapsed < Duration::from_millis(1600), "elapsed {elapsed:?}");
    }
}
