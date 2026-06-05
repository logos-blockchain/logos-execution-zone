pub mod fixtures;
pub use fixtures::PpeFixture;

include!(concat!(env!("OUT_DIR"), "/methods.rs"));
