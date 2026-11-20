use common::transaction::LeeTransaction;
use kameo::{Actor, message::Message};

use crate::{
    Result,
    error::Error,
    protocol::{Approval, Propose, Report, SetApprovalPublisher, SetCommittee},
};

pub trait SlasherActorTrait:
    Actor<Error = Error>
    + Message<Report, Reply = Result<()>>
    + Message<Propose, Reply = Vec<LeeTransaction>>
    + Message<SetCommittee, Reply = ()>
    + Message<Approval, Reply = ()>
    + Message<SetApprovalPublisher, Reply = ()>
{
}
