//! tcptui — a terminal UI clone of Sysinternals TCPView for Windows.
//!
//! The crate is organized so the terminal-free logic is testable:
//! - [`model`] holds data types and snapshot diffing,
//! - [`net`], [`proc`], [`services`], [`dns`] and [`actions`] wrap Windows
//!   APIs and system information sources,
//! - [`app`] owns application state and the background collector,
//! - [`events`] and [`ui`] render and drive the terminal interface.

pub mod actions;
pub mod app;
pub mod args;
pub mod clipboard;
pub mod config;
pub mod dns;
pub mod events;
pub mod export;
pub mod filter;
pub mod model;
pub mod net;
pub mod proc;
pub mod services;
pub mod ui;
