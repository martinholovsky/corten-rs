//! Corten's exchange gateway (`docs/gates/gateway-proposal.md`): the OpenID
//! Connect relying party that accepts only phishing-resistant sign-ins and
//! issues short-lived Corten tokens. Being built in steps; today ID-token
//! validation, the authorization-code flow, token minting and the
//! session store exist.

pub mod flow;
pub mod idtoken;
#[cfg(unix)]
pub mod mint;
pub mod session;
