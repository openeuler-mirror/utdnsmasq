/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

pub type SaFamilyT = u16;
pub type InPortT = u16;
pub type InAddrT = u32;

#[derive(Clone)]
pub struct BogusAddr {
    pub addr: InAddr,
    pub next: Option<Box<BogusAddr>>,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct InAddr {
    pub s_addr: InAddrT,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct In6Addr {
    pub(crate) s6_addr: [u8; 16],
}

#[derive(PartialEq, Copy, Clone)]
#[repr(C)]
pub struct SockAddr {
    pub sa_family: SaFamilyT,
    pub sa_data: [u8; 14],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct SockAddrIn {
    pub sin_family: SaFamilyT,
    pub sin_port: InPortT,
    pub sin_addr: InAddr,
    pub sin_zero: [u8; 8],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct SockAddrIn6 {
    pub sin6_family: SaFamilyT,
    pub sin6_port: InPortT,
    pub sin6_flowinfo: u32,
    pub sin6_addr: In6Addr,
    pub sin6_scope_id: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union MySockAddr {
    pub sa: SockAddr,
    pub in_: SockAddrIn,
    pub in6: SockAddrIn6,
}

#[derive(Clone)]
pub struct Iname {
    pub name: Option<String>,
    pub addr: MySockAddr,
    pub found: bool,
    pub next: Option<Box<Iname>>,
}

#[derive(Clone)]
pub struct ServerFd {
    pub fd: i32,
    pub source_addr: MySockAddr,
    pub next: Option<Box<ServerFd>>,
}

#[derive(Clone)]
pub struct Server {
    pub addr: MySockAddr,
    pub source_addr: MySockAddr,
    pub sfd: Option<ServerFd>,
    pub domain: Option<String>,
    pub flags: u32,
    pub next: Option<Box<Server>>,
}

#[derive(Debug, Clone)]
pub struct ResolvC {
    pub next: Option<Box<ResolvC>>,
    pub is_default: bool,
    pub logged: bool,
    pub name: Option<String>,
}

pub const ETHER_ADDR_LEN: usize = 6;
#[derive(Debug)]
pub struct DhcpContext {
    pub fd: i32,
    pub rawfd: i32,
    pub ifindex: i32,
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

#[derive(Debug, Clone)]
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
    resolv_file: &Option<Box<ResolvC>>,
    mxname: &Option<&mut String>,
    mxtarget: &Option<&mut String>,
    lease_file: &Option<&str>,
    username: &str,
    groupname: &str,
    domain_suffix: &Option<String>,
    runfile: Option<&str>,
    if_names: &Option<Box<Iname>>,
    if_addrs: &Option<Box<Iname>>,
    if_except: &Option<Box<Iname>>,
    bogus_addr: &Option<Box<BogusAddr>>,
    serv_addrs: &Option<Box<Server>>,
    cachesize: Option<&mut usize>,
    port: Option<&mut u16>,
    query_port: Option<&mut i32>,
    local_ttl: Option<&mut u64>,
    addn_hosts: &Option<&mut String>,
    dhcp: &Option<Box<DhcpContext>>,
    dhcp_conf: &Option<Box<DhcpConfig>>,
    opts: Option<Box<DhcpOpt>>,
    dhcp_file: Option<&mut String>,
    dhcp_sname: Option<&mut String>,
    dhcp_next_server: Ipv4Addr,
) -> u32 {
    0
}
