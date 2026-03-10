use anyhow::Result;
use sequencer_service::main_runner;

pub const NUM_THREADS: usize = 4;

// TODO: Why it requires config as a directory and not as a file?
fn main() -> Result<()> {
    actix::System::with_tokio_rt(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(NUM_THREADS)
            .enable_all()
            .build()
            .unwrap()
    })
    .block_on(main_runner())
}
