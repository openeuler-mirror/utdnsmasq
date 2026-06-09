/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

//! Rust implementation of dnsmasq DNS and DHCP server
//!
//! This is a safe Rust conversion of the original dnsmasq C code,
//! maintaining the same logic while using Rust's safe APIs for networking.

use crate::{DnsmasqError::ParseError, Result};
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::udp::MutableUdpPacket;
use socket2::Socket;
use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::rc::{Rc, Weak};
use std::time::SystemTime;

// 操作标志
pub const OPT_ERROR: u32 = 0xffff; // 错误
pub const OPT_BOGUSPRIV: u32 = 1; // 处理某些邮件类型
pub const OPT_FILTER: u32 = 2; // 过滤功能
pub const OPT_LOG: u32 = 4; // 日志功能
pub const OPT_SELFMX: u32 = 8; // 邮件服务器
pub const OPT_NO_HOSTS: u32 = 16; // 禁用主机相关
pub const OPT_NO_POLL: u32 = 32; // 禁用轮询模式
pub const OPT_DEBUG: u32 = 64; // 开启调试模式
pub const OPT_ORDER: u32 = 128; // 排序
pub const OPT_NO_RESOLV: u32 = 256; // 禁用域名解析
pub const OPT_EXPAND: u32 = 512; // 扩展
pub const OPT_LOCALMX: u32 = 1024; // 本地邮件服务器相关选项
pub const OPT_NO_NEG: u32 = 2048; //
pub const OPT_NODOTS_LOCAL: u32 = 4096; // 禁止使用 '.'

// Constants
pub const MAXDNAME: usize = 1024;
pub const SMALLDNAME: usize = 256;
pub const PACKETSZ: usize = 512;
pub const RRFIXEDSZ: usize = 10;
pub const ETHER_ADDR_LEN: usize = 6;
pub const CACHESIZ: usize = 150;
pub const NAMESERVER_PORT: u16 = 53;
pub const RESOLVFILE: &str = "/etc/resolv.conf";
pub const CHUSER: &str = "nobody";
pub const CHGRP: &str = "dip";

/// Represents an IP address (IPv4 or IPv6)
pub type AllAddr = IpAddr;

/// Bogus address entry for handling non-existent domains
#[derive(Debug, Clone)]
pub struct BogusAddr {
    pub addr: Ipv4Addr,
    pub next: Option<Box<BogusAddr>>,
}

impl Default for BogusAddr {
    fn default() -> Self {
        Self {
            addr: Ipv4Addr::UNSPECIFIED,
            next: None,
        }
    }
}

/// DNS cache entry
#[derive(Debug, Clone)]
pub struct Crec {
    pub prev: Option<Weak<RefCell<Crec>>>,
    pub next: Option<Rc<RefCell<Crec>>>,
    pub ttd: SystemTime, // Time to die
    pub addr: Option<AllAddr>,
    pub flags: u16,
    pub name: String,
}

impl Default for Crec {
    fn default() -> Self {
        Self {
            next: None,
            prev: None,
            ttd: SystemTime::now(),
            addr: None,
            flags: 0,
            name: String::new(),
        }
    }
}

// Cache entry flags
pub const F_IMMORTAL: u16 = 1; // 表示缓存条目永不过期
pub const F_CONFIG: u16 = 2; // 来自配置文件的条目
pub const F_REVERSE: u16 = 4; // 反向DNS查询相关
pub const F_FORWARD: u16 = 8; // 与DNS转发相关的操作
pub const F_DHCP: u16 = 16; // 来自DHCP分配的条目
pub const F_NEG: u16 = 32; // 表示否定缓存（negative caching）条目
pub const F_HOSTS: u16 = 64; // 来自/etc/hosts文件的条目
pub const F_IPV4: u16 = 128; // IPv4地址相关
pub const F_IPV6: u16 = 256; // IPv6地址相关
pub const F_BIGNAME: u16 = 512; // 使用大域名存储（超过SMALLDNAME长度）
pub const F_UPSTREAM: u16 = 1024; // 上游服务器相关
pub const F_SERVER: u16 = 2048; // 服务器相关操作
pub const F_NXDOMAIN: u16 = 4096; // 表示NXDOMAIN响应（域名不存在）
pub const F_QUERY: u16 = 8192; // 查询操作相关
pub const F_ADDN: u16 = 16384; // 附加主机文件(addn-hosts)相关
pub const F_NOERR: u16 = 32768; // 表示NOERROR响应（查询成功但无数据）

pub type MySockAddr = SocketAddr;

// Server flags
pub const SERV_FROM_RESOLV: u32 = 1; // 1用于解析服务器，0用于命令行
pub const SERV_NO_ADDR: u32 = 2; // 没有服务器，这个域只是本地的
pub const SERV_LITERAL_ADDRESS: u32 = 4; // 地址是应答，而不是服务器
pub const SERV_HAS_SOURCE: u32 = 8; // 指定源地址
pub const SERV_HAS_DOMAIN: u32 = 16; // 仅用于一个域的服务器
pub const SERV_FOR_NODOTS: u32 = 32; // 仅用于没有域部分的名称的服务器
pub const SERV_TYPE: u32 = SERV_HAS_DOMAIN | SERV_FOR_NODOTS; // 服务器类型掩码

/// Server file descriptor
#[derive(Debug)]
pub struct ServerFd {
    pub socket: Socket,
    pub source_addr: MySockAddr,
}

impl Clone for ServerFd {
    fn clone(&self) -> Self {
        // 使用try_clone()来克隆现有的socket
        let cloned_socket = self.socket.try_clone().expect("Failed to clone socket");

        Self {
            socket: cloned_socket, // 使用克隆的socket，保持绑定状态
            source_addr: self.source_addr,
        }
    }
}

impl Default for ServerFd {
    fn default() -> Self {
        Self {
            socket: Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )
            .unwrap_or_else(|_| panic!("Failed to create default socket")),
            source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        }
    }
}

/// DNS server configuration
#[derive(Debug, Clone)]
pub struct Server {
    pub addr: MySockAddr,
    pub source_addr: MySockAddr,
    pub sfd: Option<ServerFd>, // Non-NULL if server has its own fd
    pub domain: String,        // Set if server only handles a domain
    pub flags: u32,
    pub next: Option<Box<Server>>,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            sfd: None,
            domain: String::new(),
            flags: 0,
            next: None,
        }
    }
}

/// Network interface record   InterfaceRecord
#[derive(Debug)]
pub struct Irec {
    pub addr: MySockAddr, // 接口的IP地址和端口信息
    pub socket: Socket,   // 绑定到该接口的socket文件 socket 本质是文件描述符
    pub valid: bool,      // 接口是否有效（用于接口扫描）
                          // pub next: Option<Box<Irec>>, // 下一个
}

impl Clone for Irec {
    fn clone(&self) -> Self {
        // 创建一个新的socket而不是克隆现有的socket
        let new_socket = Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap_or_else(|_| panic!("Failed to create socket for clone"));

        Self {
            addr: self.addr,
            socket: new_socket,
            valid: self.valid,
        }
    }
}

impl Default for Irec {
    fn default() -> Self {
        Self {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            // fd: 0,
            socket: Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )
            .unwrap_or_else(|_| panic!("Failed to create default socket")),
            valid: false,
        }
    }
}
/// Interface name parameters from command line  
#[derive(Debug, Clone)]
pub struct Iname {
    pub name: String,
    pub addr: MySockAddr,
    pub found: bool, // 找到发现 1：在
}

impl Default for Iname {
    fn default() -> Self {
        Self {
            name: String::new(),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            found: false,
        }
    }
}

/// Resolv-file parameters from command line
#[derive(Debug, Clone, Default)]
pub struct ResolvC {
    pub is_default: bool, // 是否为默认配置文件标志
    pub logged: bool,     // 是否已记录日志标志
    pub name: String,     // 配置文件路径名
}

/// Forward query record  ForwardRecord
#[derive(Debug)]
pub struct Frec {
    pub source: MySockAddr,           // 原始客户端地址信息     查询来源
    pub sent_to: Option<Box<Server>>, //  目标上游服务器      // 转发到的上游DNS服务器
    pub orig_id: u16,                 // 原始查询的DNS ID
    pub new_id: u16,                  // 转发时生成的新DNS ID
    pub socket: Socket,               // 原始客户端套接字socket文件描述符
    pub time: SystemTime,             // 记录创建时间
                                      // pub next: Option<Box<Frec>>,
}

impl Clone for Frec {
    fn clone(&self) -> Self {
        // 创建一个新的socket而不是克隆现有的socket
        let new_socket = Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap_or_else(|_| panic!("Failed to create socket for clone"));

        Self {
            source: self.source,
            sent_to: self.sent_to.clone(),
            orig_id: self.orig_id,
            new_id: self.new_id,
            socket: new_socket,
            time: self.time,
        }
    }
}

impl Default for Frec {
    fn default() -> Self {
        Self {
            source: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            sent_to: None,
            orig_id: 0,
            new_id: 0,
            socket: Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )
            .unwrap_or_else(|_| panic!("Failed to create default socket")),
            time: SystemTime::now(),
        }
    }
}

/// DHCP lease information
#[derive(Debug, Clone)]
pub struct DhcpLease {
    pub clid_len: usize,              // 客户端标识符长度
    pub clid: Vec<u8>,                // 客户端id
    pub hostname: Option<String>,     // 客户端主机名
    pub fqdn: Option<String>,         // 完全限定域名
    pub expires: SystemTime,          // 租约到期时间
    pub hwaddr: [u8; ETHER_ADDR_LEN], // 硬件地址
    pub addr: Ipv4Addr,               // IP地址
                                      // pub next: Option<Box<DhcpLease>>,
}

/// DHCP configuration
#[derive(Debug, Clone)]
pub struct DhcpConfig {
    pub clid_len: usize,
    pub clid: Vec<u8>,
    pub hwaddr: [u8; ETHER_ADDR_LEN],
    pub hostname: Option<String>,
    pub addr: Ipv4Addr,
    pub lease_time: u32,
    // pub next: Option<Box<DhcpConfig>>,
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            clid_len: 0,
            clid: Vec::new(),
            hwaddr: [0; ETHER_ADDR_LEN],
            hostname: None,
            addr: Ipv4Addr::UNSPECIFIED,
            lease_time: 0,
            // next: None,
        }
    }
}

/// DHCP option
#[derive(Debug, Clone, Default)]
pub struct DhcpOpt {
    pub opt: u8,
    pub len: u8,
    pub val: Vec<u8>,
    // pub next: Option<Box<DhcpOpt>>,
}

/// DHCP context
#[derive(Debug)]
pub struct DhcpContext {
    pub fd_socket: Option<Socket>,
    pub rawfd: Option<Socket>,
    pub ifindex: u32,
    pub iface: String,
    pub hwaddr: [u8; ETHER_ADDR_LEN],
    pub lease_time: u32,
    pub serv_addr: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub broadcast: Ipv4Addr,
    pub start: Ipv4Addr,
    pub end: Ipv4Addr,
    pub last: Ipv4Addr, // 上次使用的
                        // pub next: Option<Box<DhcpContext>>,
}

impl Default for DhcpContext {
    fn default() -> Self {
        Self {
            fd_socket: None,
            rawfd: None,
            ifindex: 0,
            iface: String::new(),
            hwaddr: [0; ETHER_ADDR_LEN],
            lease_time: 0,
            serv_addr: Ipv4Addr::new(0, 0, 0, 0),
            netmask: Ipv4Addr::new(0, 0, 0, 0),
            broadcast: Ipv4Addr::new(0, 0, 0, 0),
            start: Ipv4Addr::new(0, 0, 0, 0),
            end: Ipv4Addr::new(0, 0, 0, 0),
            last: Ipv4Addr::new(0, 0, 0, 0),
            // next: None,
        }
    }
}

/// DNS header structure (simplified)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Header {
    pub id: u16, // 事务ID

    pub qr: bool,   // 查询/响应标志
    pub opcode: u8, // 操作码
    pub aa: bool,   // 授权回答
    pub tc: bool,   // 截断标志
    pub rd: bool,   // 递归期望

    pub ra: bool,     // 递归可用
    pub unused: bool, // 保留字段
    pub ad: bool,
    pub cd: bool,
    pub rcode: u8, // 响应码

    pub qdcount: u16, // 问题数
    pub ancount: u16, // 回答记录数
    pub nscount: u16, // 授权记录数
    pub arcount: u16, // 附加记录数
}

// 响应码
pub const NOERROR: u8 = 0; // 没有错误
pub const FORMERR: u8 = 1; // 格式错误
pub const SERVFAIL: u8 = 2; // 服务器失败
pub const NXDOMAIN: u8 = 3; // 域名不存在
pub const NOTIMP: u8 = 4; // 未实现
pub const REFUSED: u8 = 5; // 拒绝
pub const YXDOMAIN: u8 = 6; // 域名已存在
pub const YXRRSET: u8 = 7; // RR 集合已存在
pub const NXRRSET: u8 = 8; // RR 集合不存在
pub const NOTAUTH: u8 = 9; // 未授权
pub const NOTZONE: u8 = 10; // 不在区域中

pub const QUERY: u8 = 0;

pub const C_IN: u16 = 1;
pub const C_CHAOS: u16 = 3;
pub const C_ANY: u16 = 255;

pub const T_A: u16 = 1;
pub const T_AAAA: u16 = 28;
pub const T_ANY: u16 = 255;
pub const T_TXT: u16 = 16;
pub const T_SOA: u16 = 6;
pub const T_SRV: u16 = 33;
pub const T_PTR: u16 = 12;
pub const T_MX: u16 = 15;
pub const T_MAILB: u16 = 253;
pub const T_CNAME: u16 = 5;

impl Header {
    pub fn new() -> Self {
        Header {
            id: 0,
            qr: false,
            opcode: 0,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            unused: false,
            ad: false,
            cd: false,
            rcode: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    /// 从字节数组解析 DNS 头部
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 12 {
            return Err(ParseError("DNS header parsr error".to_string()));
        }

        let id = u16::from_be_bytes([data[0], data[1]]);
        // 解析标志字段
        let flags1 = data[2];
        let flags2 = data[3];

        let qr = (flags1 & 0x80) != 0;
        let opcode = (flags1 & 0x78) >> 3;
        let aa = (flags1 & 0x04) != 0;
        let tc = (flags1 & 0x02) != 0;
        let rd = (flags1 & 0x01) != 0;

        let ra = (flags2 & 0x80) != 0;
        let unused = (flags2 & 0x40) != 0;
        let ad = (flags2 & 0x40) != 0;
        let cd = (flags2 & 0x10) != 0;
        let rcode = flags2 & 0x0F;

        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        let ancount = u16::from_be_bytes([data[6], data[7]]);
        let nscount = u16::from_be_bytes([data[8], data[9]]);
        let arcount = u16::from_be_bytes([data[10], data[11]]);

        Ok(Header {
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            unused,
            ad,
            cd,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        })
    }

    /// 将 DNS 头部转换为字节数组
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12);

        // ID
        bytes.extend_from_slice(&self.id.to_be_bytes());

        // 标志字段 1
        let mut flags1: u8 = 0;
        if self.qr {
            flags1 |= 0x80;
        }
        flags1 |= (self.opcode << 3) & 0x78;
        if self.aa {
            flags1 |= 0x04;
        }
        if self.tc {
            flags1 |= 0x02;
        }
        if self.rd {
            flags1 |= 0x01;
        }
        bytes.push(flags1);

        // 标志字段 2
        let mut flags2: u8 = 0;
        if self.ra {
            flags2 |= 0x80;
        }
        if self.unused {
            flags2 |= 0x40;
        }
        if self.ad {
            flags2 |= 0x20;
        }
        if self.cd {
            flags2 |= 0x10;
        }
        flags2 |= self.rcode & 0x0F;
        bytes.push(flags2);

        // 计数字段
        bytes.extend_from_slice(&self.qdcount.to_be_bytes());
        bytes.extend_from_slice(&self.ancount.to_be_bytes());
        bytes.extend_from_slice(&self.nscount.to_be_bytes());
        bytes.extend_from_slice(&self.arcount.to_be_bytes());

        bytes
    }
}

pub const IPVERSION: u8 = 4; /* IP version number */
/// IP header structure (equivalent to struct ip from netinet/ip.h)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Ip {
    // Bit fields for version and header length (endian-dependent)
    pub version_header_len: u8, // Combined version (4 bits) and header length (4 bits)
    pub tos: u8,                // Type of service
    pub tot_len: u16,           // Total length
    pub id: u16,                // Identification
    pub frag_off: u16,          // Fragment offset field
    pub ttl: u8,                // Time to live
    pub protocol: u8,           // Protocol
    pub check: u16,             // Checksum
    pub saddr: Ipv4Addr,        // Source address
    pub daddr: Ipv4Addr,        // Destination address
}

impl Default for Ip {
    fn default() -> Self {
        Self::new()
    }
}

impl Ip {
    pub fn new() -> Self {
        Self {
            version_header_len: 0x45, // IPv4, 5 words (20 bytes) header
            tos: 0,
            tot_len: 0,
            id: 0,
            frag_off: 0,
            ttl: 64,      // Default TTL
            protocol: 17, // UDP protocol
            check: 0,
            saddr: Ipv4Addr::UNSPECIFIED,
            daddr: Ipv4Addr::UNSPECIFIED,
        }
    }
}

/// DHCP packet structure (equivalent to struct dhcp_packet)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct DhcpPacket {
    pub op: u8,             // Operation code
    pub htype: u8,          // Hardware type
    pub hlen: u8,           // Hardware address length
    pub hops: u8,           // Hops
    pub xid: u32,           // Transaction ID
    pub secs: u16,          // Seconds elapsed
    pub flags: u16,         // Flags
    pub ciaddr: Ipv4Addr,   // Client IP address        客户端ip
    pub yiaddr: Ipv4Addr,   // Your (client) IP address 你的ip
    pub siaddr: Ipv4Addr,   // Server IP address        服务器ip
    pub giaddr: Ipv4Addr,   // Gateway IP address       中继代理ip
    pub chaddr: [u8; 16],   // Client hardware address  客户端硬件地址
    pub sname: [u8; 64],    // Server host name         服务器名称，
    pub file: [u8; 128],    // Boot file name
    pub cookie: u32,        // Magic cookie
    pub options: [u8; 308], // DHCP options
}

impl Default for DhcpPacket {
    fn default() -> Self {
        Self::new()
    }
}

impl DhcpPacket {
    pub fn new() -> Self {
        Self {
            op: 0,
            htype: 0,
            hlen: 0,
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0; 16],
            sname: [0; 64],
            file: [0; 128],
            cookie: 0x63825363, // DHCP magic cookie
            options: [0; 308],
        }
    }

    /// Convert DhcpPacket to byte vector (Vec<u8>)
    pub fn to_vec(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(std::mem::size_of::<Self>());

        // Serialize basic fields
        bytes.push(self.op);
        bytes.push(self.htype);
        bytes.push(self.hlen);
        bytes.push(self.hops);

        // Serialize xid (big-endian)
        bytes.extend_from_slice(&self.xid.to_be_bytes());

        // Serialize secs (big-endian)
        bytes.extend_from_slice(&self.secs.to_be_bytes());

        // Serialize flags (big-endian)
        bytes.extend_from_slice(&self.flags.to_be_bytes());

        // Serialize IP addresses
        bytes.extend_from_slice(&self.ciaddr.octets());
        bytes.extend_from_slice(&self.yiaddr.octets());
        bytes.extend_from_slice(&self.siaddr.octets());
        bytes.extend_from_slice(&self.giaddr.octets());

        // Serialize chaddr
        bytes.extend_from_slice(&self.chaddr);

        // Serialize sname
        bytes.extend_from_slice(&self.sname);

        // Serialize file
        bytes.extend_from_slice(&self.file);

        // Serialize cookie (big-endian)
        bytes.extend_from_slice(&self.cookie.to_be_bytes());

        // Serialize options
        bytes.extend_from_slice(&self.options);

        bytes
    }

    /// # Arguments
    /// * `data` - Byte array containing DHCP packet data
    ///
    /// # Returns
    /// * `Result<DhcpPacket>` - Parsed DHCP packet or error if data is invalid
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < std::mem::size_of::<DhcpPacket>() - 308 {
            return Err(ParseError("DHCP packet data too short".to_string()));
        }

        let mut packet = DhcpPacket::new();
        let mut pos = 0;

        // Parse basic fields
        packet.op = data[pos];
        pos += 1;
        packet.htype = data[pos];
        pos += 1;
        packet.hlen = data[pos];
        pos += 1;
        packet.hops = data[pos];
        pos += 1;

        // Parse xid (4 bytes)
        packet.xid = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;

        // Parse secs (2 bytes)
        packet.secs = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        // Parse flags (2 bytes)
        packet.flags = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        // Parse IP addresses (each 4 bytes)
        packet.ciaddr = Ipv4Addr::new(data[pos], data[pos + 1], data[pos + 2], data[pos + 3]);
        pos += 4;
        packet.yiaddr = Ipv4Addr::new(data[pos], data[pos + 1], data[pos + 2], data[pos + 3]);
        pos += 4;
        packet.siaddr = Ipv4Addr::new(data[pos], data[pos + 1], data[pos + 2], data[pos + 3]);
        pos += 4;
        packet.giaddr = Ipv4Addr::new(data[pos], data[pos + 1], data[pos + 2], data[pos + 3]);
        pos += 4;

        // Parse chaddr (16 bytes)
        packet.chaddr.copy_from_slice(&data[pos..pos + 16]);
        pos += 16;

        // Parse sname (64 bytes)
        packet.sname.copy_from_slice(&data[pos..pos + 64]);
        pos += 64;

        // Parse file (128 bytes)
        packet.file.copy_from_slice(&data[pos..pos + 128]);
        pos += 128;

        // Parse cookie (4 bytes)
        packet.cookie =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;

        // Parse options - 只复制剩余的数据，不足308字节时只复制实际数据
        let remaining_data = &data[pos..];
        let copy_len = std::cmp::min(remaining_data.len(), packet.options.len());
        packet.options[..copy_len].copy_from_slice(&remaining_data[..copy_len]);

        Ok(packet)
    }
}

/// Complete UDP DHCP packet structure (equivalent to struct udp_dhcp_packet)
#[derive(Debug)]
#[repr(C)]
pub struct UdpDhcpPacket<'a> {
    pub ip: MutableIpv4Packet<'a>, // IP header
    pub udp: MutableUdpPacket<'a>, // UDP header
    pub data: DhcpPacket,          // DHCP packet data
}
