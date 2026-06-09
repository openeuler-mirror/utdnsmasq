/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

//! utdnsmasq - A Rust implementation of dnsmasq
//!
//! This library provides DNS and DHCP server functionality with full
//! compatibility with the original dnsmasq project.

pub mod cache;
pub mod cli;
pub mod config;
pub mod dhcp;
pub mod dnsmasq;
pub mod forward;
pub mod lease;
pub mod logs;
pub mod network;
pub mod rfc1035;
pub mod rfc2131;
pub mod util;

use thiserror::Error;

/// Custom error type for DNSMasq operations
#[derive(Error, Debug)]
pub enum DnsmasqError {
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    ParseError(String),
}

/// Result type alias for DNSMasq operations
pub type Result<T> = std::result::Result<T, DnsmasqError>;
