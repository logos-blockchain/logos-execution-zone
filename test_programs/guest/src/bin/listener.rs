use lee_core::program::{ReceiveInput, Response};

lee_core::actor_entrypoint!(raw listen);

const fn listen(_input: &ReceiveInput) -> Response {
    Response::keep_state()
}
