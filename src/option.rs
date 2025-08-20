/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
#[derive(Default, Clone)]
pub struct Resolv {
    file: Option<String>,
    valid: u8,
    serial: u32,
    filename: &'static str,
}

#[repr(C)]
#[derive(Debug)]
pub struct InAddr {
    s_addr: u32,
}

#[derive(Debug)]
pub struct BogusAddr {
    addr: InAddr,
    next: Option<Box<BogusAddr>>,
}

#[derive(Debug)]
pub struct Iname {
    name: Option<String>,
    addr: SocketAddr,
    found: bool,
    next: Option<Box<Iname>>,
}

#[derive(Debug)]
pub enum MySockAddr {
    V4(SocketAddr),
    V6(SocketAddr),
}

#[derive(Debug)]
pub struct ServerFd {
    fd: i32,
    source_addr: MySockAddr,
    next: Option<Arc<ServerFd>>,
}

#[derive(Debug)]
pub struct Server {
    addr: MySockAddr,
    source_addr: MySockAddr,
    sfd: Option<ServerFd>,
    domain: Option<String>,
    flags: u32,
    next: Option<Box<Server>>,
}

#[derive(Debug)]
pub struct ResolvC {
    next: Option<Box<ResolvC>>,
    is_default: bool,
    logged: bool,
    name: Option<String>,
}

const ETHER_ADDR_LEN: usize = 6;
#[derive(Debug)]
pub struct DhcpContext {
    pub fd: isize,
    pub rawfd: isize,
    pub ifindex: isize,
    pub iface: String,
    pub hwaddr: [u8; ETHER_ADDR_LEN],
    pub lease_time: u32,
    pub serv_addr: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub broadcast: Ipv4Addr,
    pub start: Ipv4Addr,
    pub end: Ipv4Addr,
    pub last: Ipv4Addr,
    pub next: Option<Box<DhcpContext>>,
}

#[derive(Debug)]
pub struct DhcpConfig {
    pub clid_len: usize,
    pub clid: Vec<u8>,
    pub hwaddr: [u8; ETHER_ADDR_LEN],
    pub hostname: Option<String>,
    pub addr: Ipv4Addr,
    pub lease_time: u32,
    pub next: Option<Box<DhcpConfig>>,
}

#[derive(Debug)]
pub struct DhcpOpt {
    pub opt: u8,
    pub len: u8,
    pub val: Vec<u8>,
    pub next: Option<Box<DhcpOpt>>,
}

pub fn read_opts(
    argc: usize,
    argv: Vec<String>,
    buff: &mut [u8],
    resolv_file: Option<&mut Resolv>,
    mxname: Option<&mut String>,
    mxtarget: Option<&mut String>,
    lease_file: &Option<&mut String>,
    username: &str,
    groupname: &str,
    domain_suffix: Option<String>,
    runfile: Option<&str>,
    if_names: &Option<&mut Vec<Iname>>,
    if_addrs: &Option<&mut Vec<Iname>>,
    if_except: &Option<&mut Vec<Iname>>,
    bogus_addr: Option<&mut BogusAddr>,
    serv_addrs: Option<&mut Vec<Server>>,
    cachesize: Option<&mut usize>,
    port: Option<&mut u16>,
    query_port: Option<&mut i32>,
    local_ttl: Option<&mut u64>,
    addn_hosts: Option<&mut String>,
    dhcp: &Option<Box<DhcpContext>>,
    dhcp_conf: Option<Box<DhcpConfig>>,
    opts: Option<Box<DhcpOpt>>,
    dhcp_file: Option<&mut String>,
    dhcp_sname: Option<&mut String>,
    dhcp_next_server: Ipv4Addr,
) -> u32 {
    0
}
