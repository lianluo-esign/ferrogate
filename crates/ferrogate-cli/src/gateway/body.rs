use bytes::Bytes;
use pingora::{proxy::Session, Result as PingoraResult};

pub(super) async fn read_request_body(
    session: &mut Session,
    max_bytes: usize,
) -> PingoraResult<Bytes> {
    let mut body = Vec::new();
    while let Some(chunk) = session.as_downstream_mut().read_request_body().await? {
        if body.len() + chunk.len() > max_bytes {
            break;
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(body))
}
