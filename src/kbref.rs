//! Reference knowledge base for AWS edge services.
//!
//! The diagnostics engine ([`crate::diagnose`]) answers *why did this probe
//! fail*. This module answers *what does this response mean*: it explains the
//! HTTP status codes, response headers, canonical error sentences and API
//! exceptions of Amazon CloudFront and Amazon API Gateway, plus longer
//! topics such as viewer mTLS modes and origin mTLS requirements.
//!
//! The content lives in `kb/reference.yaml` (embedded at build time). It is
//! used in two ways:
//!
//! * [`annotate`] turns the evidence captured by a probe into context notes
//!   that are printed under the diagnosis and carried in JSON output.
//! * [`explain`] backs `dcert kb explain <query>` and the MCP
//!   `explain_edge_term` tool, so an operator or an AI agent can look up a
//!   status code, header, error name or topic without leaving the terminal.
//!
//! Like the diagnostics engine, everything here is pure: no I/O, no network.

use anyhow::{Context, Result};
use regex_lite::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::diagnose::Evidence;

/// The reference base compiled into the binary.
pub const BUILTIN_REFERENCE: &str = include_str!("../kb/reference.yaml");

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

/// The whole reference file.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReferenceBase {
    pub version: u32,
    pub services: Vec<Service>,
}

/// One AWS service and everything dcert knows about its responses.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Service {
    /// Stable identifier, e.g. `cloudfront` or `api_gateway`.
    pub id: String,
    pub name: String,
    pub summary: String,
    /// How a probe recognises that a response came from this service.
    #[serde(default)]
    pub detect: Detect,
    #[serde(default)]
    pub statuses: Vec<StatusNote>,
    #[serde(default)]
    pub headers: Vec<HeaderNote>,
    #[serde(default)]
    pub bodies: Vec<BodyNote>,
    /// Control plane (API) exceptions, for `kb explain <ExceptionName>`.
    #[serde(default)]
    pub errors: Vec<ErrorNote>,
    #[serde(default)]
    pub topics: Vec<Topic>,
}

/// Signals that identify the service in a captured response.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Detect {
    /// Any of these response headers matching marks the service as present.
    #[serde(default)]
    pub headers: Vec<HeaderMatch>,
    /// Any of these patterns matching the target host marks the service as present.
    #[serde(default)]
    pub hosts: Vec<String>,
}

/// A header name and a pattern its value must match.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HeaderMatch {
    pub name: String,
    pub pattern: String,
}

/// What one HTTP status code means when this service returns it.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StatusNote {
    pub code: u16,
    pub title: String,
    pub summary: String,
    /// `edge`, `origin` or `either`: which hop usually generates it.
    #[serde(default)]
    pub generated_by: Option<String>,
    #[serde(default)]
    pub causes: Vec<String>,
    #[serde(default)]
    pub checks: Vec<String>,
    #[serde(default)]
    pub references: Vec<String>,
}

/// What one header means, with optional per value meanings.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HeaderNote {
    pub name: String,
    /// `request` (added or removed on the way to the origin), `response`
    /// (visible to the viewer) or `both`.
    pub direction: String,
    pub summary: String,
    #[serde(default)]
    pub values: Vec<ValueMeaning>,
    #[serde(default)]
    pub references: Vec<String>,
}

/// A value pattern and what it means.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ValueMeaning {
    pub pattern: String,
    pub meaning: String,
}

/// A canonical sentence in an error body and what it means.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BodyNote {
    pub pattern: String,
    pub meaning: String,
    /// The status the sentence normally accompanies, when it is fixed.
    #[serde(default)]
    pub status: Option<u16>,
    #[serde(default)]
    pub references: Vec<String>,
}

/// One control plane exception.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ErrorNote {
    pub name: String,
    pub http_status: u16,
    pub summary: String,
}

/// A longer explanation on one subject (mTLS modes, limits, ciphers).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Topic {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Paragraphs or bullet lines, printed in order.
    pub text: Vec<String>,
    #[serde(default)]
    pub references: Vec<String>,
}

impl ReferenceBase {
    /// Parse and validate the embedded reference base.
    pub fn builtin() -> Result<Self> {
        Self::parse(BUILTIN_REFERENCE).context("built in reference knowledge base is invalid")
    }

    /// Parse and validate a YAML document.
    pub fn parse(yaml: &str) -> Result<Self> {
        let rb: Self = serde_yaml_ng::from_str(yaml).context("failed to parse reference YAML")?;
        rb.validate()?;
        Ok(rb)
    }

    /// Structural validation: unique ids, compiling regexes, sane codes.
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            anyhow::bail!("unsupported reference knowledge base version {}", self.version);
        }
        let mut ids = BTreeSet::new();
        for svc in &self.services {
            if svc.id.trim().is_empty() || !ids.insert(svc.id.as_str()) {
                anyhow::bail!("service id '{}' is empty or duplicated", svc.id);
            }
            let check = |p: &str, what: &str| -> Result<()> {
                Regex::new(p).with_context(|| format!("service '{}': invalid {what} regex '{p}'", svc.id))?;
                Ok(())
            };
            for h in &svc.detect.headers {
                check(&h.pattern, "detect header")?;
            }
            for h in &svc.detect.hosts {
                check(h, "detect host")?;
            }
            let mut codes = BTreeSet::new();
            for s in &svc.statuses {
                if !(100..=599).contains(&s.code) {
                    anyhow::bail!("service '{}': status code {} is out of range", svc.id, s.code);
                }
                if !codes.insert(s.code) {
                    anyhow::bail!("service '{}': status code {} is listed twice", svc.id, s.code);
                }
                if s.summary.trim().is_empty() {
                    anyhow::bail!("service '{}': status {} has no summary", svc.id, s.code);
                }
                if let Some(g) = &s.generated_by
                    && !matches!(g.as_str(), "edge" | "origin" | "either")
                {
                    anyhow::bail!(
                        "service '{}': status {} generated_by must be edge, origin or either",
                        svc.id,
                        s.code
                    );
                }
            }
            let mut names = BTreeSet::new();
            for h in &svc.headers {
                if !names.insert(h.name.to_ascii_lowercase()) {
                    anyhow::bail!("service '{}': header '{}' is listed twice", svc.id, h.name);
                }
                if !matches!(h.direction.as_str(), "request" | "response" | "both") {
                    anyhow::bail!(
                        "service '{}': header '{}' direction must be request, response or both",
                        svc.id,
                        h.name
                    );
                }
                for v in &h.values {
                    check(&v.pattern, "header value")?;
                }
            }
            for b in &svc.bodies {
                check(&b.pattern, "body")?;
            }
            let mut topics = BTreeSet::new();
            for t in &svc.topics {
                if !topics.insert(t.id.as_str()) {
                    anyhow::bail!("service '{}': topic '{}' is listed twice", svc.id, t.id);
                }
                if t.text.is_empty() {
                    anyhow::bail!("service '{}': topic '{}' has no text", svc.id, t.id);
                }
            }
        }
        Ok(())
    }

    pub fn service(&self, id: &str) -> Option<&Service> {
        self.services.iter().find(|s| s.id.eq_ignore_ascii_case(id))
    }

    /// JSON schema for the YAML file, for editor validation.
    pub fn json_schema() -> serde_json::Value {
        serde_json::to_value(schemars::schema_for!(ReferenceBase)).unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Annotation of probe evidence
// ---------------------------------------------------------------------------

/// What a note is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NoteKind {
    Status,
    Body,
    Header,
}

/// One piece of context derived from a response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Note {
    /// Service id the note comes from.
    pub service: String,
    pub kind: NoteKind,
    /// The status code, header name or matched body sentence.
    pub subject: String,
    pub text: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

fn re(pattern: &str) -> Option<Regex> {
    Regex::new(pattern).ok()
}

fn header_value<'a>(ev: &'a Evidence, name: &str) -> Option<&'a str> {
    ev.http_headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}

impl Service {
    /// `true` when the evidence carries this service's fingerprints.
    pub fn detected(&self, ev: &Evidence) -> bool {
        let by_header = self
            .detect
            .headers
            .iter()
            .any(|h| header_value(ev, &h.name).is_some_and(|v| re(&h.pattern).is_some_and(|r| r.is_match(v))));
        let by_host = self
            .detect
            .hosts
            .iter()
            .any(|p| re(p).is_some_and(|r| r.is_match(&ev.target_host)));
        by_header || by_host
    }
}

fn short(value: &str) -> String {
    let one_line: String = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if one_line.chars().count() > 100 {
        let cut: String = one_line.chars().take(97).collect();
        format!("{cut}...")
    } else {
        one_line
    }
}

/// Explain the status, body sentences and headers of a captured response.
/// Returns nothing when no known service is detected, so probes of
/// unrelated hosts stay quiet.
pub fn annotate(rb: &ReferenceBase, ev: &Evidence) -> Vec<Note> {
    let mut notes = Vec::new();
    for svc in rb.services.iter().filter(|s| s.detected(ev)) {
        if let Some(code) = ev.http_status
            && let Some(s) = svc.statuses.iter().find(|s| s.code == code)
        {
            let mut text = format!("{}: {}", s.title, s.summary.trim());
            if let Some(g) = &s.generated_by {
                let hint = match g.as_str() {
                    "edge" => "generated at the edge",
                    "origin" => "generated by the origin",
                    _ => "generated at the edge or by the origin",
                };
                text.push_str(&format!(" (usually {hint})"));
            }
            notes.push(Note {
                service: svc.id.clone(),
                kind: NoteKind::Status,
                subject: code.to_string(),
                text,
                references: s.references.clone(),
            });
        }
        if let Some(body) = ev.http_body.as_deref() {
            for b in &svc.bodies {
                if let Some(r) = re(&b.pattern)
                    && let Some(m) = r.find(body)
                {
                    notes.push(Note {
                        service: svc.id.clone(),
                        kind: NoteKind::Body,
                        subject: short(m.as_str()),
                        text: b.meaning.trim().to_string(),
                        references: b.references.clone(),
                    });
                }
            }
        }
        for h in svc.headers.iter().filter(|h| h.direction != "request") {
            let Some(value) = header_value(ev, &h.name) else {
                continue;
            };
            let mut text = h.summary.trim().to_string();
            if let Some(v) = h
                .values
                .iter()
                .find(|v| re(&v.pattern).is_some_and(|r| r.is_match(value)))
            {
                text.push(' ');
                text.push_str(v.meaning.trim());
            }
            notes.push(Note {
                service: svc.id.clone(),
                kind: NoteKind::Header,
                subject: format!("{}: {}", h.name, short(value)),
                text,
                references: h.references.clone(),
            });
        }
    }
    notes
}

// ---------------------------------------------------------------------------
// Look ups for `dcert kb explain`
// ---------------------------------------------------------------------------

/// One answer to a look up.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Explanation {
    pub service: String,
    /// `status`, `header`, `body`, `error` or `topic`.
    pub kind: String,
    pub subject: String,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_ascii_lowercase().contains(needle)
}

/// Find everything that matches `query` in the services selected by
/// `service` (all services when `None`). A numeric query matches status
/// codes; otherwise header names, error names, topic ids, titles and tags,
/// and canonical body sentences are searched case insensitively.
pub fn explain(rb: &ReferenceBase, query: &str, service: Option<&str>) -> Vec<Explanation> {
    let q = query.trim().to_ascii_lowercase();
    let code: Option<u16> = q.parse().ok();
    let mut out = Vec::new();
    for svc in rb
        .services
        .iter()
        .filter(|s| service.is_none_or(|id| s.id.eq_ignore_ascii_case(id)))
    {
        if let Some(code) = code {
            for s in svc.statuses.iter().filter(|s| s.code == code) {
                let mut details: Vec<String> = s.causes.iter().map(|c| format!("cause: {c}")).collect();
                details.extend(s.checks.iter().map(|c| format!("check: {c}")));
                if let Some(g) = &s.generated_by {
                    details.insert(0, format!("generated by: {g}"));
                }
                out.push(Explanation {
                    service: svc.id.clone(),
                    kind: "status".into(),
                    subject: format!("{} {}", s.code, s.title),
                    summary: s.summary.trim().to_string(),
                    details,
                    references: s.references.clone(),
                });
            }
            for e in svc.errors.iter().filter(|e| e.http_status == code) {
                out.push(Explanation {
                    service: svc.id.clone(),
                    kind: "error".into(),
                    subject: e.name.clone(),
                    summary: format!("HTTP {}: {}", e.http_status, e.summary.trim()),
                    details: Vec::new(),
                    references: Vec::new(),
                });
            }
            continue;
        }
        for h in svc.headers.iter().filter(|h| contains_ci(&h.name, &q)) {
            out.push(Explanation {
                service: svc.id.clone(),
                kind: "header".into(),
                subject: format!("{} ({})", h.name, h.direction),
                summary: h.summary.trim().to_string(),
                details: h
                    .values
                    .iter()
                    .map(|v| format!("{} => {}", v.pattern, v.meaning))
                    .collect(),
                references: h.references.clone(),
            });
        }
        for e in svc
            .errors
            .iter()
            .filter(|e| e.name.eq_ignore_ascii_case(&q) || (q.len() >= 4 && contains_ci(&e.name, &q)))
        {
            out.push(Explanation {
                service: svc.id.clone(),
                kind: "error".into(),
                subject: e.name.clone(),
                summary: format!("HTTP {}: {}", e.http_status, e.summary.trim()),
                details: Vec::new(),
                references: Vec::new(),
            });
        }
        for t in svc.topics.iter().filter(|t| {
            contains_ci(&t.id, &q) || contains_ci(&t.title, &q) || t.tags.iter().any(|tag| contains_ci(tag, &q))
        }) {
            out.push(Explanation {
                service: svc.id.clone(),
                kind: "topic".into(),
                subject: format!("{} ({})", t.title, t.id),
                summary: t.text.first().cloned().unwrap_or_default(),
                details: t.text.iter().skip(1).cloned().collect(),
                references: t.references.clone(),
            });
        }
        for b in svc
            .bodies
            .iter()
            .filter(|b| q.len() >= 4 && (contains_ci(&b.pattern, &q) || contains_ci(&b.meaning, &q)))
        {
            out.push(Explanation {
                service: svc.id.clone(),
                kind: "body".into(),
                subject: b.pattern.clone(),
                summary: b.meaning.trim().to_string(),
                details: b.status.map(|s| vec![format!("status: {s}")]).unwrap_or_default(),
                references: b.references.clone(),
            });
        }
    }
    out
}

/// A compact index of what `explain` can answer, for `dcert kb topics`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TopicIndex {
    pub service: String,
    pub name: String,
    pub statuses: Vec<u16>,
    pub headers: Vec<String>,
    pub error_count: usize,
    pub topics: Vec<String>,
}

pub fn index(rb: &ReferenceBase) -> Vec<TopicIndex> {
    rb.services
        .iter()
        .map(|s| TopicIndex {
            service: s.id.clone(),
            name: s.name.clone(),
            statuses: s.statuses.iter().map(|x| x.code).collect(),
            headers: s.headers.iter().map(|h| h.name.clone()).collect(),
            error_count: s.errors.len(),
            topics: s.topics.iter().map(|t| t.id.clone()).collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::HttpHeader;

    fn header(name: &str, value: &str) -> HttpHeader {
        HttpHeader {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    fn rb() -> ReferenceBase {
        ReferenceBase::builtin().expect("built in reference base parses")
    }

    #[test]
    fn builtin_reference_is_valid_and_substantial() {
        let rb = rb();
        let cf = rb.service("cloudfront").expect("cloudfront service");
        let gw = rb.service("api_gateway").expect("api gateway service");
        assert!(cf.statuses.len() >= 10, "cloudfront statuses");
        assert!(cf.headers.len() >= 20, "cloudfront headers");
        assert!(cf.errors.len() >= 150, "cloudfront api exceptions");
        assert!(gw.statuses.len() >= 8, "api gateway statuses");
        assert!(gw.errors.len() >= 10, "api gateway api exceptions");
        for s in &rb.services {
            for st in &s.statuses {
                assert!(!st.references.is_empty(), "{}/{} has no references", s.id, st.code);
            }
            for t in &s.topics {
                assert!(!t.references.is_empty(), "{}/{} has no references", s.id, t.id);
            }
        }
    }

    #[test]
    fn schema_file_is_current() {
        let expected = serde_json::to_string_pretty(&ReferenceBase::json_schema()).unwrap();
        let on_disk = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/kb/reference.schema.json"))
            .unwrap_or_default();
        assert_eq!(
            on_disk.trim(),
            expected.trim(),
            "kb/reference.schema.json is stale; run `dcert kb schema --reference > kb/reference.schema.json`"
        );
    }

    #[test]
    fn rejects_bad_documents() {
        let bad_regex =
            "version: 1\nservices:\n  - {id: x, name: X, summary: s, bodies: [{pattern: '(', meaning: m}]}\n";
        assert!(
            ReferenceBase::parse(bad_regex)
                .unwrap_err()
                .to_string()
                .contains("invalid body regex")
        );
        let dup_status = "version: 1\nservices:\n  - {id: x, name: X, summary: s, statuses: [{code: 403, title: t, summary: s}, {code: 403, title: t, summary: s}]}\n";
        assert!(
            ReferenceBase::parse(dup_status)
                .unwrap_err()
                .to_string()
                .contains("listed twice")
        );
        let bad_direction = "version: 1\nservices:\n  - {id: x, name: X, summary: s, headers: [{name: h, direction: sideways, summary: s}]}\n";
        assert!(
            ReferenceBase::parse(bad_direction)
                .unwrap_err()
                .to_string()
                .contains("direction")
        );
        let unknown_field = "version: 1\nservices:\n  - {id: x, name: X, summary: s, bogus: 1}\n";
        assert!(ReferenceBase::parse(unknown_field).is_err());
    }

    #[test]
    fn cloudfront_error_page_is_annotated() {
        let ev = Evidence {
            target_host: "www.example.com".into(),
            http_status: Some(502),
            http_headers: vec![
                header("Server", "CloudFront"),
                header("X-Cache", "Error from cloudfront"),
                header("Via", "1.1 abc.cloudfront.net (CloudFront)"),
                header("X-Amz-Cf-Pop", "LHR62-P1"),
                header("X-Amz-Cf-Id", "abc=="),
            ],
            http_body: Some("<p>CloudFront wasn't able to resolve the origin domain name.</p>".into()),
            ..Default::default()
        };
        let notes = annotate(&rb(), &ev);
        let kinds: Vec<(NoteKind, &str)> = notes.iter().map(|n| (n.kind, n.subject.as_str())).collect();
        assert!(matches!(kinds.first(), Some((NoteKind::Status, "502"))), "{kinds:?}");
        assert!(
            notes.iter().any(|n| n.kind == NoteKind::Body && n.text.contains("DNS")),
            "{notes:#?}"
        );
        let xcache = notes
            .iter()
            .find(|n| n.kind == NoteKind::Header && n.subject.starts_with("X-Cache"))
            .expect("x-cache note");
        assert!(xcache.text.contains("edge"), "{}", xcache.text);
        assert!(notes.iter().any(|n| n.subject.starts_with("X-Amz-Cf-Pop")));
        assert!(notes.iter().all(|n| n.service == "cloudfront"));
    }

    #[test]
    fn api_gateway_response_is_annotated() {
        let ev = Evidence {
            target_host: "abc123.execute-api.eu-west-2.amazonaws.com".into(),
            http_status: Some(403),
            http_headers: vec![
                header("x-amzn-RequestId", "1111-2222"),
                header("x-amzn-ErrorType", "MissingAuthenticationTokenException"),
                header("x-amz-apigw-id", "abcdef="),
            ],
            http_body: Some(r#"{"message":"Missing Authentication Token"}"#.into()),
            ..Default::default()
        };
        let notes = annotate(&rb(), &ev);
        assert!(
            notes
                .iter()
                .any(|n| n.service == "api_gateway" && n.kind == NoteKind::Status)
        );
        assert!(notes.iter().any(|n| n.kind == NoteKind::Header
            && n.subject.starts_with("x-amzn-ErrorType")
            && n.text.contains("resource")));
        assert!(notes.iter().any(|n| n.kind == NoteKind::Body));
    }

    #[test]
    fn unknown_hosts_produce_no_notes() {
        let ev = Evidence {
            target_host: "intranet.corp".into(),
            http_status: Some(403),
            http_headers: vec![header("Server", "nginx")],
            ..Default::default()
        };
        assert!(annotate(&rb(), &ev).is_empty());
    }

    #[test]
    fn explain_finds_statuses_headers_errors_and_topics() {
        let rb = rb();
        let by_code = explain(&rb, "504", None);
        assert!(by_code.iter().any(|e| e.service == "cloudfront" && e.kind == "status"));
        assert!(by_code.iter().any(|e| e.service == "api_gateway" && e.kind == "status"));
        let only_gw = explain(&rb, "504", Some("api_gateway"));
        assert!(only_gw.iter().all(|e| e.service == "api_gateway"));
        let header = explain(&rb, "x-cache", None);
        assert!(header.iter().any(|e| e.kind == "header" && !e.details.is_empty()));
        let error = explain(&rb, "NoSuchDistribution", None);
        assert_eq!(error.len(), 1);
        assert!(error[0].summary.starts_with("HTTP 404"));
        let topic = explain(&rb, "passthrough", None);
        assert!(topic.iter().any(|e| e.kind == "topic"), "{topic:#?}");
        let body = explain(&rb, "key-pair-id", None);
        assert!(body.iter().any(|e| e.kind == "body"), "{body:#?}");
        assert!(explain(&rb, "zzzz-no-such-thing", None).is_empty());
    }

    #[test]
    fn index_lists_every_service() {
        let idx = index(&rb());
        assert!(idx.iter().any(|i| i.service == "cloudfront" && i.error_count > 100));
        assert!(idx.iter().any(|i| i.service == "api_gateway" && !i.topics.is_empty()));
    }
}
