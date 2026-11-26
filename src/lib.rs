//! tcptui — a cross-platform terminal UI for TCP and UDP endpoints.
//!
//! The crate is organized so the terminal-free logic is testable:
//! - [`model`] holds data types and snapshot diffing,
//! - [`net`], [`proc`], [`services`], [`dns`] and [`actions`] wrap Windows
//!   and Unix APIs and system information sources,
//! - [`app`] owns application state and the background collector,
//! - [`events`] and [`ui`] render and drive the terminal interface.

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
compile_error!("tcptui supports Windows, Linux and macOS.");

pub mod actions;
pub mod app;
pub mod args;
pub mod clipboard;
pub mod config;
pub mod dns;
#[cfg(windows)]
pub mod etw;
pub mod events;
pub mod export;
pub mod filter;
pub mod geoip;
pub mod model;
pub mod net;
pub mod proc;
pub mod services;
pub mod trace;
pub mod ui;
#[cfg(feature = "virustotal")]
pub mod vt;
