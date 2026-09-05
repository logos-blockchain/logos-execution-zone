#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Channel config actor failed")]
    Actor,
}
