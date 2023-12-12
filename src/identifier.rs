use frost_core::Ciphersuite;
use serde::{Deserialize, Serialize};

/// A FROST participant identifier.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Copy, Deserialize, Serialize)]
#[repr(transparent)]
pub struct ParticipantIdentifier(pub u8);

impl<C: Ciphersuite> From<frost_core::Identifier<C>> for ParticipantIdentifier {
    fn from(s: frost_core::Identifier<C>) -> Self {
        Self::from(&s)
    }
}

impl<C: Ciphersuite> From<&frost_core::Identifier<C>> for ParticipantIdentifier {
    fn from(s: &frost_core::Identifier<C>) -> Self {
        Self(*s.serialize().as_ref().iter().last().unwrap())
    }
}

impl<C: Ciphersuite> From<ParticipantIdentifier> for frost_core::Identifier<C> {
    fn from(s: ParticipantIdentifier) -> Self {
        Self::from(&s)
    }
}

impl<C: Ciphersuite> From<&ParticipantIdentifier> for frost_core::Identifier<C> {
    fn from(s: &ParticipantIdentifier) -> Self {
        frost_core::Identifier::<C>::try_from(s.0 as u16).unwrap()
    }
}
