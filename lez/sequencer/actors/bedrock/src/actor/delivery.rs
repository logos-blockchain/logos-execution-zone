use std::collections::VecDeque;

use anyhow::anyhow;
use futures::future::BoxFuture;
use kameo::error::SendError;
use tracing::{Instrument as _, Span};

use crate::{
    Result,
    error::Error,
    protocol::{
        ChannelEvent, ChannelEventKind, ChannelEventRecipient, ChannelId, ChannelUpdate,
        SequencerCheckpoint,
    },
};

/// Channel events on their way to the recipient, each asked of it once it handled the one before.
pub struct Deliveries {
    channel_id: ChannelId,
    /// Where events go, [`None`] to send none.
    recipient: Option<ChannelEventRecipient>,
    /// Events waiting for [`Self::in_flight`] to finish, in order.
    queue: VecDeque<Delivery>,
    /// The event the recipient is handling.
    in_flight: Option<DeliveryFuture>,
    /// Updates in [`Self::queue`] or [`Self::in_flight`]. Publishes are refused while any is left,
    /// as the recipient has not applied it yet.
    undelivered_updates: usize,
}

/// An event waiting to be asked of the recipient.
struct Delivery {
    event: ChannelEventKind,
    /// The checkpoint to store once the recipient applied the event, set by
    /// [`Deliveries::push_update`] only.
    checkpoint: Option<SequencerCheckpoint>,
    /// The span the event was queued in, which the ask runs in.
    span: Span,
}

/// Resolves to the checkpoint of the delivered event, once the recipient handled it.
type DeliveryFuture = BoxFuture<'static, Result<Option<SequencerCheckpoint>>>;

impl Deliveries {
    /// Deliveries of `channel_id`'s events to `recipient`, [`None`] for none.
    pub const fn new(channel_id: ChannelId, recipient: Option<ChannelEventRecipient>) -> Self {
        Self {
            channel_id,
            recipient,
            queue: VecDeque::new(),
            in_flight: None,
            undelivered_updates: 0,
        }
    }

    /// Queues `event` for the recipient. An update is queued with [`Self::push_update`] instead.
    pub fn push(&mut self, event: ChannelEventKind) {
        debug_assert!(
            !matches!(event, ChannelEventKind::Update(_)),
            "Updates are queued with `push_update`"
        );
        self.push_delivery(event, None);
    }

    /// Queues `update` for the recipient, with the checkpoint to store once it is applied.
    /// Publishes are refused until it is.
    pub fn push_update(&mut self, update: ChannelUpdate, checkpoint: SequencerCheckpoint) {
        if self.recipient.is_some() {
            self.undelivered_updates = self.undelivered_updates.saturating_add(1);
        }
        self.push_delivery(ChannelEventKind::Update(Box::new(update)), Some(checkpoint));
    }

    fn push_delivery(&mut self, event: ChannelEventKind, checkpoint: Option<SequencerCheckpoint>) {
        if self.recipient.is_none() {
            return;
        }
        self.queue.push_back(Delivery {
            event,
            checkpoint,
            span: Span::current(),
        });
    }

    /// Asks the recipient the next queued event unless it is handling one already. Returns
    /// whether it is handling one, which [`Self::delivered`] then waits for.
    pub fn start_next(&mut self) -> bool {
        if self.in_flight.is_none()
            && let Some(delivery) = self.queue.pop_front()
        {
            self.in_flight = Some(self.ask(delivery));
        }
        self.in_flight.is_some()
    }

    /// Waits for the recipient to handle the event [`Self::start_next`] asked it, returning the
    /// checkpoint to store now. Cancel safe.
    pub async fn delivered(&mut self) -> Result<Option<SequencerCheckpoint>> {
        let in_flight = self
            .in_flight
            .as_mut()
            .expect("A delivery is started first");
        let delivered = in_flight.await;
        self.in_flight = None;
        // Only an update carries a checkpoint.
        if matches!(delivered, Ok(Some(_))) {
            self.undelivered_updates = self.undelivered_updates.saturating_sub(1);
        }
        delivered
    }

    /// Refuses a publish while an update the recipient has not applied yet moved the channel.
    pub const fn check_not_moved(&self) -> Result<()> {
        if self.undelivered_updates > 0 {
            return Err(Error::ChannelMoved);
        }
        Ok(())
    }

    /// Asks the recipient to handle `delivery`.
    fn ask(&self, delivery: Delivery) -> DeliveryFuture {
        let recipient = self
            .recipient
            .clone()
            .expect("Events are queued only for a recipient");
        let event = ChannelEvent {
            channel_id: self.channel_id,
            event: delivery.event,
        };
        Box::pin(
            async move {
                recipient.ask(event).await.map_err(|err| {
                    Error::ChannelEventDeliveryFailed(if let SendError::HandlerError(err) = err {
                        err.0
                    } else {
                        anyhow!("{err}")
                    })
                })?;
                Ok(delivery.checkpoint)
            }
            .instrument(delivery.span),
        )
    }
}
