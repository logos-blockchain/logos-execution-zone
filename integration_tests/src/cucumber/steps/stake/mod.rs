/// `When` steps submitting stake lifecycle transactions.
pub mod actions;
/// `Then` steps asserting stake lifecycle outcomes.
pub mod assertions;
/// Chain access shared by the stake lifecycle steps.
mod helpers;
/// `Given` steps preparing the node-level stake lifecycle scenario.
pub mod setup;
