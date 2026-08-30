//! SSE event stream bridging runtime events to the browser.
//!
//! Every subscriber gets its own broadcast receiver; payloads are the
//! JSON-serialized [`OrchestratorEvent`]s (status and summaries only, never
//! untrusted raw text). Axum's `KeepAlive` emits a heartbeat comment every
//! 15 seconds to keep connections from timing out.
//!
//! The stream adapter below is hand-rolled because `tokio-stream` /
//! `futures-util` are not on the allowed dependency list: a small
//! `Stream` impl over an `mpsc::Receiver` using its public `poll_recv`.

use std::pin::Pin;
use std::task::{Context, Poll};

use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use tokio::sync::{broadcast, mpsc};

use super::AppState;

/// GET /api/events — server-sent events of the orchestration pipeline.
pub async fn events(
    State(state): State<AppState>,
) -> Sse<axum::response::sse::KeepAliveStream<SseStream>> {
    let mut receiver = state.events.subscribe();
    let (tx, rx) = mpsc::channel::<Result<Event, axum::Error>>(64);
    // Forward broadcast events into the per-connection channel; the task
    // ends when the client disconnects (send fails) or the server stops.
    tokio::spawn(async move {
        loop {
            match receiver.recv().await {
                Ok(event) => {
                    if tx.send(Ok(event_to_sse(&event))).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    let comment =
                        Event::default().comment(format!("lagged: skipped {skipped} events"));
                    if tx.send(Ok(comment)).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });
    Sse::new(SseStream { rx }).keep_alive(KeepAlive::default())
}

/// `Stream` adapter over an mpsc receiver of SSE events.
pub struct SseStream {
    rx: mpsc::Receiver<Result<Event, axum::Error>>,
}

impl futures_core::Stream for SseStream {
    type Item = Result<Event, axum::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

fn event_to_sse(event: &crate::runtime::orchestrator::OrchestratorEvent) -> Event {
    use crate::runtime::orchestrator::OrchestratorEvent;
    let (name, payload): (&str, serde_json::Value) = match event {
        OrchestratorEvent::ScanStarted {
            session_id,
            mode,
            total_changes,
        } => (
            "scan_started",
            serde_json::json!({"session_id": session_id, "mode": mode, "total_changes": total_changes}),
        ),
        OrchestratorEvent::ScanProgress { session_id, state } => (
            "scan_progress",
            serde_json::json!({"session_id": session_id, "state": state}),
        ),
        OrchestratorEvent::GuardVerdict {
            session_id,
            verdict,
            risk_level,
        } => (
            "guard_verdict",
            serde_json::json!({"session_id": session_id, "verdict": verdict, "risk_level": risk_level}),
        ),
        OrchestratorEvent::AuditAppended { session_id, event } => (
            "audit_appended",
            serde_json::json!({"session_id": session_id, "event": event}),
        ),
        OrchestratorEvent::ScanCompleted {
            session_id,
            verdict,
            risk_level,
        } => (
            "scan_completed",
            serde_json::json!({"session_id": session_id, "verdict": verdict, "risk_level": risk_level}),
        ),
    };
    Event::default().event(name).data(payload.to_string())
}
