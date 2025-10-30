/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use std::fs::File;
use std::io::{self, BufRead};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;
use std::{default, process};

use users::cache;

use crate::util::canonicalise;
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

#[derive(Clone)]
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

#[derive(Debug, Clone)]
pub struct DhcpOpt {
    pub opt: u8,
    pub len: u8,
    pub val: Vec<u8>,
    pub next: Option<Box<DhcpOpt>>,
}

const CONFILE: &str = "/etc/utdnsmasq.conf";
const OPT_BOGUSPRIV: u32 = 1;
const OPT_FILTER: u32 = 2;
const OPT_LOG: u32 = 4;
const OPT_SELFMX: u32 = 8;
const OPT_NO_HOSTS: u32 = 16;
const OPT_NO_POLL: u32 = 32;
const OPT_DEBUG: u32 = 64;
const OPT_ORDER: u32 = 128;
const OPT_NO_RESOLV: u32 = 256;
const OPT_EXPAND: u32 = 512;
const OPT_LOCALMX: u32 = 1024;
const OPT_NO_NEG: u32 = 2048;
const OPT_NODOTS_LOCAL: u32 = 4096;

const OPTMAP: [&str; 15] = [
    "bogus-priv",
    "filterwin2k",
    "log-queries",
    "selfmx",
    "no-hosts",
    "no-poll",
    "no-daemon",
    "strict-order",
    "no-resolv",
    "expand-hosts",
    "localmx",
    "no-negcache",
    "domain-needed",
    "help",
    "version",
];

pub fn read_opts(
    argc: usize,
    argv: Vec<String>,
    buff: &mut [u8],
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
    serv_addrs: &Option<Box<Server>>,
    cachesize: &mut usize,
    port: Option<&mut u16>,
    query_port: Option<&mut i32>,
    local_ttl: Option<&mut u64>,
    addn_hosts: &mut Option<String>,
    dhcp: &Option<Box<DhcpContext>>,
    dhcp_conf: &Option<Box<DhcpConfig>>,
    opts: &Option<Box<DhcpOpt>>,
    dhcp_file: &Option<&mut String>,
    dhcp_sname: &Option<&mut String>,
    dhcp_next_server: Ipv4Addr,
) -> u32 {
    let mut flags: u32 = 0;
    let mut conffile: &str = CONFILE;
    let mut conffile_set: bool = false;

    /* 打开配置文件 */
    let file = File::open(conffile);
    let file = match file {
        Ok(file) => Some(file),
        Err(error) => {
            if conffile_set {
                println!("cannot read the config file {}", conffile);
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
        let re = regex::Regex::new(r"[#| |\t]").unwrap();
        let line_vec: Vec<&str> = re.split(&line).filter(|s| !s.is_empty()).collect();
        let line_val = line_vec[0];

        /* 获取option 和 value */
        let (mut option, optarg) = if line_val.contains('=') {
            let val: Vec<&str> = line_val.split('=').collect();
            (val[0], val[1])
        } else {
            (line_val, "")
        };

        /* 配置文件缺少参数 */
        if !OPTMAP.contains(&option) && optarg.is_empty() {
            println!("missing parameter for {} in config file.", option);
            process::exit(1);
        }

        match option {
            "conf-file" => {
                conffile = optarg;
                conffile_set = true;
            }

            "pid-file" => {
                *runfile = Some(optarg.to_string());
            }

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

            "mx-host" => {
                if canonicalise(optarg).is_none() {
                    option = "?";
                } else {
                    *mxname = Some(optarg.to_string());
                }
            }

            "cache-size" => {
                let mut size: i32 = optarg.parse().unwrap();
                if size < 0 {
                    size = 0;
                } else if size > 10000 {
                    size = 10000;
                }

                *cachesize = size as usize;
            }

            "mx-target" => {
                if canonicalise(optarg).is_none() {
                    option = "?";
                } else {
                    *mxtarget = Some(optarg.to_string());
                }
            }

            "dhcp-leasefile" => {
                *lease_file = Some(optarg.to_string());
            }
            // H
            "addn-hosts" => {
                if addn_hosts.is_some() {
                    option = "?";
                } else {
                    *addn_hosts = Some(optarg.to_string());
                }
            }

            // s
            "domain" => {
                if canonicalise(optarg).is_none() {
                    option = "?";
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
                let (ret, in_addr) = inet_addr(&optarg);
                if ret {
                    addr.s_addr = in_addr;
                    let mut baddr: BogusAddr = BogusAddr {
                        addr: addr,
                        next: bogus_addr.clone(),
                    };
                    *bogus_addr = Some(Box::new(baddr.clone()));
                } else {
                    option = "?";
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
                            _ => {
                                option = "?";
                            }
                        }
                    }
                    None => {
                        option = "?";
                    }
                }

                *if_addrs = Some(Box::new(new.clone()));
            }

            _ => {
                println!("bad argument for option {}", option);
            }
        }
    }

    0
}

// 将点分十进制转换为u32类型   成功返回true，失败返回false
fn inet_addr(ip_str: &str) -> (bool, u32) {
    // 将点分十进制形式的 IP 地址字符串转换为 Ipv4Addr 类型
    let ip_addr: Ipv4Addr = match Ipv4Addr::from_str(ip_str) {
        Ok(addr) => addr,
        Err(_) => return (false, 0),
    };

    // 获取网络字节序表示的IP地址
    let network_byte_order: u32 = u32::from(ip_addr).to_be();
    (true, network_byte_order)
}

fn inet_pton(ip_str: &str) -> Option<IpAddr> {
    if let Ok(ipv4_addr) = ip_str.parse::<Ipv4Addr>() {
        return Some(IpAddr::V4(ipv4_addr));
    }

    if let Ok(ipv6_addr) = ip_str.parse::<Ipv6Addr>() {
        return Some(IpAddr::V6(ipv6_addr));
    }

    None
}
