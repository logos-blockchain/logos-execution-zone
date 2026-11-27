use sequencer_bedrock_actor::protocol::Slot;

/// Whose turn it is to write to the channel, as Bedrock last told us.
#[derive(Debug)]
pub struct Turn {
    ours: bool,
    /// Slot our current turn started at, once Bedrock has told us.
    starting_slot: Option<Slot>,
}

impl Turn {
    pub const fn new(ours: bool) -> Self {
        Self {
            ours,
            starting_slot: None,
        }
    }

    pub const fn is_ours(&self) -> bool {
        self.ours
    }

    /// Applies a turn notification, returning whether a new turn of ours
    /// started.
    pub fn update(&mut self, ours: bool, starting_slot: Option<Slot>) -> bool {
        let was_ours = std::mem::replace(&mut self.ours, ours);
        if !ours {
            return false;
        }

        let started = match (self.starting_slot, starting_slot) {
            (Some(current), Some(new)) => current != new,
            _ => !was_ours,
        };
        if started || starting_slot.is_some() {
            self.starting_slot = starting_slot;
        }
        started
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(slot: u64) -> Slot {
        Slot::from(slot)
    }

    #[test]
    fn a_turn_starts_when_it_becomes_ours() {
        let mut turn = Turn::new(false);
        assert!(turn.update(true, Some(slot(60))));
        assert!(turn.is_ours());
    }

    #[test]
    fn a_turn_starts_once_however_often_it_is_notified() {
        let mut turn = Turn::new(false);
        assert!(turn.update(true, None));
        assert!(!turn.update(true, Some(slot(60))));
        assert!(!turn.update(true, Some(slot(60))));
    }

    #[test]
    fn a_turn_moving_on_to_a_new_starting_slot_is_a_new_turn() {
        let mut turn = Turn::new(false);
        assert!(turn.update(true, Some(slot(60))));
        assert!(turn.update(true, Some(slot(120))));
    }

    #[test]
    fn losing_the_turn_ends_it() {
        let mut turn = Turn::new(false);
        assert!(turn.update(true, Some(slot(60))));
        assert!(!turn.update(false, Some(slot(120))));
        assert!(!turn.is_ours());
        assert!(turn.update(true, Some(slot(180))));
    }

    #[test]
    fn a_turn_reported_again_after_a_reconnect_does_not_start_again() {
        let mut turn = Turn::new(false);
        assert!(turn.update(true, Some(slot(60))));
        assert!(!turn.update(false, Some(slot(60))));
        assert!(!turn.is_ours());
        assert!(!turn.update(true, Some(slot(60))));
        assert!(turn.is_ours());
    }

    #[test]
    fn a_turn_without_a_slot_forgets_the_previous_turns_slot() {
        let mut turn = Turn::new(false);
        assert!(turn.update(true, Some(slot(60))));
        assert!(!turn.update(false, Some(slot(120))));
        assert!(turn.update(true, None));
        assert!(!turn.update(true, Some(slot(180))));
    }

    #[test]
    fn a_turn_whose_slot_comes_later_starts_once() {
        let mut turn = Turn::new(false);
        assert!(!turn.update(false, Some(slot(60))));
        assert!(turn.update(true, None));
        assert!(!turn.update(true, Some(slot(120))));
    }

    #[test]
    fn the_turn_held_at_startup_does_not_start_again_once_its_slot_is_known() {
        let mut turn = Turn::new(true);
        assert!(!turn.update(true, Some(slot(60))));
    }
}
