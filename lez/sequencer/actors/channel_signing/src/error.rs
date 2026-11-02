#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Channel signing actor failed")]
    Actor,
}
