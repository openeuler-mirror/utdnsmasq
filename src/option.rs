/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use std::fs::File;
use std::io::{self, BufRead};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process;
use std::str::FromStr;

// use users::cache;

use crate::die;
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

#[derive(Debug, Clone)]
pub struct DhcpOpt {
    pub opt: u8,
    pub len: u8,
    pub val: Vec<u8>,
    pub next: Option<Box<DhcpOpt>>,
}

// 定义为32位  最多4,294,967,295s 约49,710天
const DEFLEASE: u32 = 3600; /* default lease time, 1 hour */

const SERV_FROM_RESOLV: u32 = 1; /* 1 for servers from resolv, 0 for command line. */
const SERV_NO_ADDR: u32 = 2; /* no server, this domain is local only */
const SERV_LITERAL_ADDRESS: u32 = 4; /* addr is the answer, not the server */
const SERV_HAS_SOURCE: u32 = 8; /* source address specified */
const SERV_HAS_DOMAIN: u32 = 16; /* server for one domain only */
const SERV_FOR_NODOTS: u32 = 32; /* server for names with no domain part only */
const SERV_TYPE: u32 = (SERV_HAS_DOMAIN | SERV_FOR_NODOTS);

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
    port: &mut u16,
    query_port: &mut i32,
    local_ttl: &mut u64,
    addn_hosts: &mut Option<String>,
    dhcp: &mut Option<Box<DhcpContext>>,
    dhcp_conf: &Option<Box<DhcpConfig>>,
    opts: &Option<Box<DhcpOpt>>,
    dhcp_file: &Option<String>,
    dhcp_sname: &Option<String>,
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
                    option = "?";
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
                    option = "?";
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

            // S A   暂未完成
            "server" | "address" => {
                let mut serv: Server = Server::default();
                let mut newlist: Server = Server::default();

                if optarg.starts_with("/") {
                    let mut end: String = String::new();
                    let domains: Vec<&str> = optarg.split('/').filter(|s| !s.is_empty()).collect();

                    for domain in domains {
                        let domain = canonicalise(domain);
                        if domain.is_none() {
                            option = "?";
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
                    }

                    if Some(newlist.clone()).is_none() {
                        option = "?";
                        break;
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
                        option = "?";
                        break;
                    }
                }
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
                let mut comma: String = String::new();
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
                            option = "?";
                        }
                    }

                    // 获取ip范围结束地址
                    match Ipv4Addr::from_str(iter[1]) {
                        Ok(ip) => {
                            new.end = ip;
                        }
                        Err(_) => {
                            option = "?";
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
                    option = "?";
                }

                *dhcp = Some(Box::new(new.clone()));
            }

            _ => {
                println!("bad argument for option {}", option);
            }
        }

        // if option == "?" {
        //     die!("bad argument for option {:#?}", buff);
        // }
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
