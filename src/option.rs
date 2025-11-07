/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use hostname;
use std::fmt;
use std::fs::File;
use std::io::{self, BufRead};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::util::canonicalise;
use crate::{die, CONFILE};

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
impl InAddr {
    pub fn new(addr: InAddrT) -> Self {
        InAddr { s_addr: addr }
    }
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct In6Addr {
    pub(crate) s6_addr: [u8; 16],
}

impl In6Addr {
    pub fn new(addr: [u8; 16]) -> Self {
        In6Addr { s6_addr: addr }
    }
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
impl fmt::Debug for MySockAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe { write!(f, "MySockAddr {{ sa_family: {} }}", self.sa.sa_family) }
    }
}

impl Default for MySockAddr {
    fn default() -> Self {
        MySockAddr {
            sa: SockAddr {
                sa_family: 0, // 默认值先置为0
                sa_data: [0; 14],
            },
        }
    }
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

#[derive(Clone, Default)]
pub struct Server {
    pub addr: MySockAddr,
    pub source_addr: MySockAddr,
    pub sfd: Option<ServerFd>,
    pub domain: Option<String>,
    pub flags: u32,
    pub next: Option<Box<Server>>,
}

#[derive(Debug, Clone, Default)]
pub struct ResolvC {
    pub next: Option<Box<ResolvC>>,
    pub is_default: bool,
    pub logged: bool,
    pub name: Option<String>,
}

pub const ETHER_ADDR_LEN: usize = 6;
#[derive(Debug, Clone)]
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

impl Default for DhcpContext {
    fn default() -> Self {
        DhcpContext {
            fd: 0,
            rawfd: 0,
            ifindex: 0,
            iface: "".to_string(),
            hwaddr: [0; ETHER_ADDR_LEN],
            lease_time: 0,
            // 地址先默认给0  0.0.0.0 有特殊用途 目前不知道这样给会不会有问题 待测试
            serv_addr: Ipv4Addr::new(0, 0, 0, 0),
            netmask: Ipv4Addr::new(0, 0, 0, 0),
            broadcast: Ipv4Addr::new(0, 0, 0, 0),
            start: Ipv4Addr::new(0, 0, 0, 0),
            end: Ipv4Addr::new(0, 0, 0, 0),
            last: Ipv4Addr::new(0, 0, 0, 0),
            next: None,
        }
    }
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
impl Default for DhcpConfig {
    fn default() -> Self {
        DhcpConfig {
            clid_len: 0,
            clid: Vec::new(),
            hwaddr: [0; ETHER_ADDR_LEN],
            hostname: None,
            addr: Ipv4Addr::new(0, 0, 0, 0),
            lease_time: DEFLEASE,
            next: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DhcpOpt {
    pub opt: u8,
    pub len: u8,
    pub val: Vec<u8>,
    pub next: Option<Box<DhcpOpt>>,
}

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const NAMESERVER_PORT: u16 = 53;
// 定义为32位  最多4,294,967,295s 约49,710天
const DEFLEASE: u32 = 3600; /* default lease time, 1 hour */

pub const SERV_FROM_RESOLV: u32 = 1; /* 1 for servers from resolv, 0 for command line. */
pub const SERV_NO_ADDR: u32 = 2; /* no server, this domain is local only */
pub const SERV_LITERAL_ADDRESS: u32 = 4; /* addr is the answer, not the server */
pub const SERV_HAS_SOURCE: u32 = 8; /* source address specified */
pub const SERV_HAS_DOMAIN: u32 = 16; /* server for one domain only */
pub const SERV_FOR_NODOTS: u32 = 32; /* server for names with no domain part only */
pub const SERV_TYPE: u32 = SERV_HAS_DOMAIN | SERV_FOR_NODOTS;

pub const OPT_BOGUSPRIV: u32 = 1;
const OPT_FILTER: u32 = 2;
const OPT_LOG: u32 = 4;
pub const OPT_SELFMX: u32 = 8;
const OPT_NO_HOSTS: u32 = 16;
const OPT_NO_POLL: u32 = 32;
const OPT_DEBUG: u32 = 64;
pub const OPT_ORDER: u32 = 128;
const OPT_NO_RESOLV: u32 = 256;
const OPT_EXPAND: u32 = 512;
pub const OPT_LOCALMX: u32 = 1024;
const OPT_NO_NEG: u32 = 2048;
pub const OPT_NODOTS_LOCAL: u32 = 4096;

struct Optflags<'a> {
    pub c: &'a str,
    pub flag: u32,
}

const OPTMAP: [Optflags; 15] = [
    (Optflags {
        c: "bogus-priv",
        flag: OPT_BOGUSPRIV,
    }),
    (Optflags {
        c: "filterwin2k",
        flag: OPT_FILTER,
    }),
    (Optflags {
        c: "log-queries",
        flag: OPT_LOG,
    }),
    (Optflags {
        c: "selfmx",
        flag: OPT_SELFMX,
    }),
    (Optflags {
        c: "no-hosts",
        flag: OPT_NO_HOSTS,
    }),
    (Optflags {
        c: "no-poll",
        flag: OPT_NO_POLL,
    }),
    (Optflags {
        c: "no-daemon",
        flag: OPT_DEBUG,
    }),
    (Optflags {
        c: "strict-order",
        flag: OPT_ORDER,
    }),
    (Optflags {
        c: "no-resolv",
        flag: OPT_NO_RESOLV,
    }),
    (Optflags {
        c: "expand-hosts",
        flag: OPT_EXPAND,
    }),
    (Optflags {
        c: "localmx",
        flag: OPT_LOCALMX,
    }),
    (Optflags {
        c: "no-negcache",
        flag: OPT_NO_NEG,
    }),
    (Optflags {
        c: "domain-needed",
        flag: OPT_NODOTS_LOCAL,
    }),
    (Optflags { c: "help", flag: 0 }),
    (Optflags {
        c: "version",
        flag: 0,
    }),
];

pub fn read_opts(
    resolv_files: &mut Option<Box<ResolvC>>,
    mxname: &mut Option<String>,
    mxtarget: &mut Option<String>,
    lease_file: &mut Option<String>,
    username: &mut String,
    groupname: &mut String,
    domain_suffix: &mut Option<String>,
    runfile: &mut Option<String>,
    if_names: &mut Option<Box<Iname>>,
    if_addrs: &mut Option<Box<Iname>>,
    if_except: &mut Option<Box<Iname>>,
    bogus_addr: &mut Option<Box<BogusAddr>>,
    serv_addrs: &mut Option<Box<Server>>,
    cachesize: &mut usize,
    port: &mut u16,
    query_port: &mut i32,
    local_ttl: &mut u64,
    addn_hosts: &mut Option<String>,
    dhcp: &mut Option<Box<DhcpContext>>,
    dhcp_conf: &mut Option<Box<DhcpConfig>>,
    dhcp_opts: &mut Option<Box<DhcpOpt>>,
    dhcp_file: &mut Option<String>,
    dhcp_sname: &mut Option<String>,
    dhcp_next_server: &mut Ipv4Addr,
) -> u32 {
    let mut flags: u32 = 0;
    let mut conffile: &str = CONFILE;
    let mut conffile_set: bool = false;
    let mut option_flag: &str = "";

    let c_collection: Vec<&'static str> = OPTMAP
        .iter()
        .map(|optflags| optflags.c) // 提取每个 Optflags 结构体的 c 字段
        .collect();

    /* 打开配置文件 */
    let file = File::open(conffile);
    let file = match file {
        Ok(file) => Some(file),
        Err(error) => {
            if conffile_set {
                let str = format!("cannot read the config file {}", conffile);
                die(&str, "");
            } else {
                println!("{:?}", error);
                return 0;
            }
            None
        }
    };

    /* 逐行读取 */
    let reader = io::BufReader::new(file.unwrap());
    for line in reader.lines() {
        let line = line.unwrap();

        if line.starts_with('#') || line.is_empty() {
            continue;
        }

        /* 去除注释、空格、等多余字符 */
        let re = regex::Regex::new(r"[ |\t]").unwrap();
        let line_vec: Vec<&str> = re.split(&line).filter(|s| !s.is_empty()).collect();
        let line_val = line_vec[0];

        /* 获取option 和 value */
        let (mut option, mut optarg) = if line_val.contains('=') {
            let val: Vec<&str> = line_val.split('=').collect();
            (val[0], val[1])
        } else {
            (line_val, "")
        };

        /* 配置项缺少参数 */
        if !c_collection.contains(&option) {
            if optarg.is_empty() {
                let string = format!("missing parameter for {} in config file.", option);
                die(&string, "");
            }
        } else {
            // 配置项参数多余
            if !optarg.is_empty() {
                let string = format!("extraneous parameter for {} in config file.", option);
                die(&string, "");
            }
        }

        for i in OPTMAP.iter() {
            if option == i.c {
                flags |= i.flag;
                option = "";
                break;
            }
        }

        if option != "" {
            match option {
                // C
                "conf-file" => {
                    conffile = optarg;
                    conffile_set = true;
                }
                // x
                "pid-file" => {
                    *runfile = Some(optarg.to_string());
                }
                // r
                "resolv-file" => {
                    // 全部clone可能会有问题  先这样 可以解析
                    let name: Option<String> = Some(optarg.to_string());
                    let mut new: ResolvC = ResolvC::default();
                    let mut list: Option<Box<ResolvC>> = resolv_files.clone();

                    if list.clone().is_some() && list.clone().unwrap().is_default {
                        if name.is_some() {
                            list.clone().unwrap().is_default = false;
                            list.clone().unwrap().name = name;
                        } else {
                            list = None;
                        }
                    } else if name.clone().is_some() {
                        new.next = list.clone();
                        new.name = name;
                        new.is_default = false;
                        new.logged = false;
                        list = Some(Box::new(new.clone()));
                    }
                    *resolv_files = list.clone();
                }
                // m
                "mx-host" => {
                    if canonicalise(optarg).is_none() {
                        option_flag = "?";
                    } else {
                        *mxname = Some(optarg.to_string());
                    }
                }
                // c
                "cache-size" => {
                    let mut size: i32 = optarg.parse().unwrap();
                    if size < 0 {
                        size = 0;
                    } else if size > 10000 {
                        size = 10000;
                    }

                    *cachesize = size as usize;
                }
                // t
                "mx-target" => {
                    if canonicalise(optarg).is_none() {
                        option_flag = "?";
                    } else {
                        *mxtarget = Some(optarg.to_string());
                    }
                }
                // l
                "dhcp-leasefile" => {
                    *lease_file = Some(optarg.to_string());
                }
                // H
                "addn-hosts" => {
                    if addn_hosts.is_some() {
                        option_flag = "?";
                    } else {
                        *addn_hosts = Some(optarg.to_string());
                    }
                }

                // s
                "domain" => {
                    if canonicalise(optarg).is_none() {
                        option_flag = "?";
                    } else {
                        *domain_suffix = Some(optarg.to_string());
                    }
                }

                // u
                "user" => {
                    *username = optarg.to_string();
                }
                // g
                "group" => {
                    *groupname = optarg.to_string();
                }
                // i
                "interface" => {
                    let mut new = Iname {
                        found: false,
                        addr: MySockAddr::default(),
                        name: None,
                        next: if_names.clone(),
                    };

                    new.name = Some(optarg.to_string());
                    new.found = false;
                    *if_names = Some(Box::new(new.clone()));
                }
                // I
                "except-interface" => {
                    let mut new = Iname {
                        found: false, // C端没有赋值  暂时默认为flase
                        addr: MySockAddr::default(),
                        name: None,
                        next: if_except.clone(),
                    };

                    new.name = Some(optarg.to_string());
                    *if_except = Some(Box::new(new.clone()));
                }
                // B
                "bogus-nxdomain" => {
                    let mut addr: InAddr = InAddr { s_addr: 0 }; // 默认值 暂定为0
                    let ret = inet_addr(&optarg);
                    match ret {
                        Some(in_addr) => {
                            addr.s_addr = in_addr;
                            let baddr: BogusAddr = BogusAddr {
                                addr: addr,
                                next: bogus_addr.clone(),
                            };
                            *bogus_addr = Some(Box::new(baddr.clone()));
                        }

                        None => option_flag = "?",
                    }
                }
                // a
                "listen-address" => {
                    let mut new: Iname = Iname {
                        found: false,
                        addr: MySockAddr::default(),
                        name: None,
                        next: if_addrs.clone(),
                    };
                    // 将配置文件地址转为换ip地址
                    let ipaddr = inet_pton(&optarg);
                    match ipaddr {
                        // 解析地址类型
                        Some(ip) => {
                            match ip {
                                IpAddr::V4(ipv4) => {
                                    // 将 IPv4 地址转换为网络字节序的 u32
                                    let binary_format = u32::from(ipv4).to_be();
                                    new.addr.in_.sin_addr = InAddr::new(binary_format);
                                    new.addr.sa.sa_family = 2; // AF_INET
                                }
                                IpAddr::V6(ipv6) => {
                                    let binary_format = ipv6.octets();
                                    new.addr.in6.sin6_addr = In6Addr::new(binary_format);
                                    new.addr.sa.sa_family = 10; // AF_INET6
                                    new.addr.in6.sin6_flowinfo = 0;
                                }
                            }
                        }
                        None => {
                            option_flag = "?";
                        }
                    }

                    *if_addrs = Some(Box::new(new.clone()));
                }

                // S A
                "server" | "address" => {
                    let mut serv: Server = Server::default();
                    let mut newlist: Server = Server::default();

                    if optarg.starts_with("/") {
                        let mut end: &str;
                        while optarg.contains("/") {
                            let ret: Vec<&str> = optarg.splitn(2, "/").collect();
                            optarg = ret[0];
                            end = ret[1];

                            let domain = canonicalise(optarg);
                            if domain.is_none() {
                                option_flag = "?";
                                break;
                            }

                            serv.next = Some(Box::new(newlist.clone()));
                            serv.sfd = None;
                            serv.domain = domain.clone();
                            serv.flags = if domain.is_some() {
                                SERV_HAS_DOMAIN
                            } else {
                                SERV_FOR_NODOTS
                            };
                            newlist = serv.clone();

                            optarg = end;
                        }

                        if Some(newlist.clone()).is_none() {
                            let string = format!("bad argument for option {}", option);
                            die(&string, "");
                        }
                    } else {
                        newlist.next = None;
                        newlist.flags = 0;
                        newlist.sfd = None;
                        newlist.domain = None;
                    }

                    if option == "address" {
                        newlist.flags |= SERV_LITERAL_ADDRESS;
                        if newlist.flags & SERV_TYPE == 0 {
                            let string = format!("bad argument for option {}", option);
                            die(&string, "");
                        }
                    }

                    if optarg.is_empty() {
                        newlist.flags |= SERV_NO_ADDR;
                        if newlist.flags & SERV_LITERAL_ADDRESS != 0 {
                            option_flag = "?";
                        }
                    } else {
                        let mut source_port: u16 = 0;
                        let mut serv_port: u16 = NAMESERVER_PORT;
                        // let mut portno: i32 = 0;
                        let mut source: &str = "";
                        // let mut temp: &str = "";

                        if optarg.contains("@") {
                            let split: Vec<&str> = optarg.split("@").collect();
                            optarg = split[0];
                            source = split[1];

                            if source.contains("#") {
                                let split: Vec<&str> = source.split("#").collect();
                                source = split[0];
                                if let Ok(port) = split[1].parse::<u16>() {
                                    source_port = port;
                                } else {
                                    option_flag = "?";
                                }
                            }
                        }

                        if optarg.contains("#") {
                            let split: Vec<&str> = optarg.split("#").collect();
                            optarg = split[0];

                            if let Ok(port) = split[1].parse::<u16>() {
                                serv_port = port;
                            } else {
                                option_flag = "?";
                            }
                        }

                        let ipaddr = inet_pton(&optarg);
                        match ipaddr {
                            Some(ip) => {
                                match ip {
                                    IpAddr::V4(ipv4) => {
                                        // 将 IPv4 地址转换为网络字节序的 u32
                                        let binary_format = u32::from(ipv4).to_be();
                                        newlist.addr.in_.sin_addr = InAddr::new(binary_format);
                                        newlist.addr.in_.sin_port = serv_port.to_be();
                                        newlist.source_addr.in_.sin_port = source_port.to_be();
                                        newlist.addr.sa.sa_family = AF_INET;
                                        newlist.source_addr.sa.sa_family = AF_INET;

                                        if !source.is_empty() {
                                            let ret = inet_pton(source);
                                            match ret {
                                                Some(ip) => match ip {
                                                    IpAddr::V4(ipv4) => {
                                                        let binary_format = u32::from(ipv4).to_be();
                                                        newlist.source_addr.in_.sin_addr =
                                                            InAddr::new(binary_format);
                                                        newlist.flags |= SERV_HAS_SOURCE;
                                                    }
                                                    _ => option_flag = "?",
                                                },
                                                None => {}
                                            }
                                        } else {
                                            newlist.source_addr.in_.sin_addr.s_addr = 0;
                                            // INADDR_ANY
                                        }
                                    }
                                    IpAddr::V6(ipv6) => {
                                        let binary_format = ipv6.octets();
                                        newlist.addr.in6.sin6_addr = In6Addr::new(binary_format);

                                        newlist.addr.in6.sin6_port = serv_port.to_be();
                                        newlist.source_addr.in6.sin6_port = source_port.to_be();
                                        newlist.addr.sa.sa_family = AF_INET6;
                                        newlist.source_addr.sa.sa_family = AF_INET6;
                                        newlist.addr.in6.sin6_flowinfo = 0;
                                        newlist.source_addr.in6.sin6_flowinfo = 0;

                                        if !source.is_empty() {
                                            let ret = inet_pton(source);
                                            match ret {
                                                Some(ip) => match ip {
                                                    IpAddr::V6(ipv6) => {
                                                        let binary_format = ipv6.octets();
                                                        newlist.source_addr.in6.sin6_addr =
                                                            In6Addr::new(binary_format);
                                                        newlist.flags |= SERV_HAS_SOURCE;
                                                    }
                                                    _ => option_flag = "?",
                                                },
                                                None => {}
                                            }
                                        } else {
                                            newlist.source_addr.in6.sin6_addr =
                                                In6Addr::new([0; 16]);
                                            // in6addr_any
                                        }
                                    }
                                }
                            }
                            None => {}
                        }
                    }

                    serv = newlist.clone();
                    while serv.next.is_some() {
                        match serv.next {
                            Some(ref mut next) => {
                                next.flags = serv.flags;
                                next.addr = serv.addr;
                                next.source_addr = serv.source_addr;
                                serv = *next.clone();
                            }
                            None => {}
                        }
                    }

                    serv.next = serv_addrs.take();
                    *serv_addrs = Some(Box::new(newlist.clone()));
                }

                // p
                "port" => {
                    let ret = optarg.parse::<u16>();
                    match ret {
                        Ok(num) => {
                            *port = num;
                        }
                        Err(_) => {
                            // 参数类型不正确  直接退出
                            die("port must be an integer", "");
                        }
                    }
                }

                // Q
                "query-port" => {
                    let ret = optarg.parse::<i32>();
                    match ret {
                        Ok(num) => {
                            *query_port = num;
                        }
                        Err(_) => {
                            // 参数类型不正确  直接退出
                            die("query_port must be an integer", "");
                        }
                    }
                }

                // T
                "local-ttl" => {
                    let ret = optarg.parse::<u64>();
                    match ret {
                        Ok(num) => {
                            *local_ttl = num;
                        }
                        Err(_) => {
                            // 参数类型不正确  直接退出
                            die("local_ttl must be an integer", "");
                        }
                    }
                }

                // F
                "dhcp-range" => {
                    let mut new: DhcpContext = DhcpContext::default();

                    // 将dhcp值赋值给new.next 并将dhcp置为空
                    new.next = std::mem::replace(dhcp, None);

                    new.lease_time = DEFLEASE; // 默认租约时间

                    if optarg.contains(",") {
                        let mut iter: Vec<&str> = optarg.split(',').collect();
                        // 如果只分出来两个字段 则将第三个字段置为空
                        // 字段1：起始地址 字段2：结束地址 字段3：租约时间
                        if iter.len() == 2 {
                            iter.push("");
                        }

                        // 获取ip范围起始地址
                        match Ipv4Addr::from_str(iter[0]) {
                            Ok(ip) => {
                                new.start = ip;
                            }
                            Err(_) => {
                                option_flag = "?";
                            }
                        }

                        // 获取ip范围结束地址
                        match Ipv4Addr::from_str(iter[1]) {
                            Ok(ip) => {
                                new.end = ip;
                            }
                            Err(_) => {
                                option_flag = "?";
                            }
                        }

                        // 解析租约时间
                        if iter[2] != "" {
                            let opt = iter[2];
                            if opt == "infinite" {
                                new.lease_time = 0xffffffff;
                            } else {
                                let mut fac: u32 = 1;
                                if opt.len() > 0 {
                                    match opt.chars().last() {
                                        Some('h') | Some('H') => fac *= 60 * 60,
                                        Some('m') | Some('M') => fac *= 60,
                                        _ => {
                                            println!("时间格式错误");
                                        }
                                    }
                                    // 解析时间
                                    let ret = opt[..opt.len() - 1].parse::<u32>();
                                    match ret {
                                        Ok(time) => {
                                            new.lease_time = time * fac;
                                        }
                                        Err(_) => {
                                            println!("时间格式错误");
                                        }
                                    }
                                }
                            }
                        }

                        new.last = new.start;
                        new.iface = String::from("");
                    } else {
                        option_flag = "?";
                    }

                    *dhcp = Some(Box::new(new.clone()));
                }

                // G
                "dhcp-host" => {
                    let mut new: DhcpConfig = DhcpConfig::default();

                    new.next = dhcp_conf.clone();

                    // ","分割参数
                    let a: Vec<&str> = optarg.split(',').collect();

                    // 遍历参数
                    for temp in a {
                        if temp.contains(":") {
                            let mut args: Vec<&str> = temp.split(":").collect();
                            // arg[0] 属于["id", "ID", "iD", "Id"]中的一个
                            if ["id", "ID", "iD", "Id"]
                                .iter()
                                .any(|&x| args[0].contains(x))
                            {
                                args = args[1..].to_owned();
                                // 剩余的参数长度大于1  是id：1a:2b:3c:4d类型的id
                                if args.len() > 1 {
                                    for arg in args {
                                        new.clid.push(u32::from_str_radix(arg, 16).unwrap() as u8);
                                    }
                                } else {
                                    // id:marjorie 类型id
                                    new.clid = args[0].to_owned().into();
                                }
                                new.clid_len = new.clid.len();
                            } else if args.len() == 6 {
                                // mac地址
                                new.hwaddr[0] = u32::from_str_radix(args[0], 16).unwrap() as u8;
                                new.hwaddr[1] = u32::from_str_radix(args[1], 16).unwrap() as u8;
                                new.hwaddr[2] = u32::from_str_radix(args[2], 16).unwrap() as u8;
                                new.hwaddr[3] = u32::from_str_radix(args[3], 16).unwrap() as u8;
                                new.hwaddr[4] = u32::from_str_radix(args[4], 16).unwrap() as u8;
                                new.hwaddr[5] = u32::from_str_radix(args[5], 16).unwrap() as u8;
                            } else {
                                option_flag = "?";
                            }
                        } else if temp.contains(".") {
                            // ip地址
                            match Ipv4Addr::from_str(temp) {
                                Ok(ip) => {
                                    new.addr = ip;
                                }
                                Err(_) => {
                                    println!("ip parse error");
                                }
                            }
                        } else {
                            // 租约时间
                            let last: Option<char>;
                            let mut fac: u32 = 1;

                            if temp.len() > 1 {
                                last = temp.chars().last();
                                match last {
                                    Some('h') | Some('H') => fac *= 60 * 60,
                                    Some('m') | Some('M') => fac *= 60,
                                    _ => {}
                                }

                                match is_decimal::<u32>(&temp[..temp.len() - 1]) {
                                    Some(num) => {
                                        new.lease_time = num * fac;
                                    }
                                    None => {
                                        // 不是数字
                                        if temp == "infinite" {
                                            new.lease_time = 0xffffffff;
                                        } else {
                                            // 不是时间 设置主机名
                                            new.hostname = Some(temp.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }

                    *dhcp_conf = Some(Box::new(new.clone()));
                }

                // O
                "dhcp-option" => {
                    let mut new: DhcpOpt = DhcpOpt::default();
                    let comma: &str;

                    new.next = dhcp_opts.clone();

                    if let Some((first, rest)) = optarg.split_once(',') {
                        match is_decimal::<u8>(first) {
                            Some(num) => {
                                new.opt = num;
                            }
                            None => option_flag = "?",
                        }
                        comma = rest;
                    } else {
                        comma = "";
                    }

                    if comma.is_empty() {
                        option_flag = "?";
                    }

                    // 检查非地址列表字符
                    let mut text_flag: bool = false;
                    let rests: Vec<&str> = comma.split(",").collect();
                    for rest in rests {
                        for char in rest.chars() {
                            if is_valid_char(char) {
                                continue;
                            } else {
                                text_flag = true;
                                break;
                            }
                        }
                    }

                    // 文本
                    if text_flag {
                        new.len = comma.len() as u8;
                        new.val = comma.to_owned().into();
                    } else {
                        // 地址
                        let ip_addrs: Vec<&str> = comma.split(",").collect();
                        for ip_addr in ip_addrs {
                            match inet_addr(ip_addr) {
                                Some(ip) => {
                                    // 地址解析出的数据有可能是反向的，需要进一步验证
                                    // 小端续
                                    let temp = ip.to_le_bytes();
                                    // 大端序
                                    // let temp = ip.to_be_bytes();
                                    for i in 0..4 {
                                        new.val.push(temp[i]); // 添加ip地址
                                    }
                                }
                                None => {
                                    option_flag = "?";
                                }
                            }
                        }
                        new.len = new.val.len() as u8;
                    }

                    *dhcp_opts = Some(Box::new(new.clone()));
                }

                // M
                "dhcp-boot" => {
                    let mut comma: &str;

                    if let Some((first, rest)) = optarg.split_once(',') {
                        *dhcp_file = Some(first.to_string());
                        comma = rest;
                    } else {
                        comma = "";
                    }
                    // comma非空
                    if !comma.is_empty() {
                        if let Some((first, rest)) = comma.split_once(',') {
                            *dhcp_sname = Some(first.to_string());
                            comma = rest;
                        } else {
                            comma = "";
                        }

                        if !comma.is_empty() {
                            match Ipv4Addr::from_str(comma) {
                                Ok(ip) => {
                                    *dhcp_next_server = ip;
                                }
                                Err(_) => {
                                    option_flag = "?";
                                }
                            }
                        }
                    }
                }

                _ => {}
            }
        }

        if option_flag == "?" {
            let string = format!("bad argument for option {}", option);
            die(&string, "");
        }
    }

    /* port might no be known when the address is parsed - fill in here */
    if serv_addrs.clone().is_some() {
        let mut tmp = serv_addrs.as_mut();

        while let Some(current) = tmp {
            unsafe {
                if current.flags & SERV_HAS_SOURCE == 0 {
                    if current.addr.sa.sa_family == AF_INET as u16 {
                        current.source_addr.in_.sin_port = query_port.to_be() as u16;
                    } else if current.addr.sa.sa_family == AF_INET6 as u16 {
                        current.source_addr.in6.sin6_port = query_port.to_be() as u16;
                    }
                }
            }
            tmp = current.next.as_mut();
        }
    }

    if if_addrs.clone().is_some() {
        let mut tmp = if_addrs.as_mut();

        while let Some(current) = tmp {
            unsafe {
                if current.addr.sa.sa_family == AF_INET as u16 {
                    current.addr.in_.sin_port = port.to_be();
                } else if current.addr.sa.sa_family == AF_INET6 as u16 {
                    current.addr.in6.sin6_port = port.to_be();
                }
            }
            tmp = current.next.as_mut();
        }
    }

    if flags & OPT_LOCALMX != 0 || mxname.is_some() || mxtarget.is_some() {
        match hostname::get() {
            Ok(hostname) => {
                if mxname.is_none() {
                    *mxname = Some(hostname.to_string_lossy().into_owned());
                }
                if mxtarget.is_none() {
                    *mxtarget = Some(hostname.to_string_lossy().into_owned());
                }
            }
            Err(_) => {
                die("can't get hostname", "");
            }
        }
    }

    // 无resolv文件
    if flags & OPT_NO_RESOLV != 0 {
        *resolv_files = None;
    } else if resolv_files.clone().is_some() {
        // 禁止轮询
        if let Some(temp) = resolv_files {
            if temp.next.is_some() && flags & OPT_NO_POLL != 0 {
                die("only one resolv.conf file allowed in no-poll mode.", "");
            }
        }
    }

    flags
}

// 将点分十进制转换为u32类型   成功返回true，失败返回false
fn inet_addr(ip_str: &str) -> Option<u32> {
    match Ipv4Addr::from_str(ip_str) {
        Ok(ip) => Some(u32::from(ip).to_be()),
        Err(_) => None,
    }
}
// 点分十进制 转成IP地址
fn inet_pton(ip_str: &str) -> Option<IpAddr> {
    if let Ok(ipv4_addr) = ip_str.parse::<Ipv4Addr>() {
        return Some(IpAddr::V4(ipv4_addr));
    }

    if let Ok(ipv6_addr) = ip_str.parse::<Ipv6Addr>() {
        return Some(IpAddr::V6(ipv6_addr));
    }

    None
}

// 判断是否能转换为数字
fn is_decimal<T: std::str::FromStr>(s: &str) -> Option<T> {
    match s.parse::<T>() {
        Ok(num) => Some(num),
        Err(_) => None,
    }
}

fn is_valid_char(c: char) -> bool {
    c == '.' || c.is_whitespace() || c.is_ascii_digit()
}
