//! Corten's exchange gateway (`docs/gates/gateway-proposal.md`): the OpenID
//! Connect relying party that accepts only phishing-resistant sign-ins and
//! issues short-lived Corten tokens. Being built in steps; today ID-token
//! validation, the authorization-code flow, token minting, the
//! session store, the HTTPS client, the browser-facing rules and
//! the server that wires them together exist.

#[cfg(unix)]
pub mod cli;
pub mod client;
pub mod config;
pub mod edge;
pub mod flow;
pub mod idtoken;
#[cfg(unix)]
pub mod keyfile;
#[cfg(unix)]
pub mod mint;
#[cfg(unix)]
pub mod server;
pub mod session;
