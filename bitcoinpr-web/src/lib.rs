#![warn(clippy::unwrap_used)]

pub mod api;
pub mod auth;
pub mod server;
pub mod state;
pub mod ws;

pub use server::WebServer;
pub use state::{PeerEntry, ServiceEntry, WebState};
