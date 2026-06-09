/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use crate::cli::Args;
use crate::dnsmasq::*;
use crate::logs::{die, LOG_ERR};
use crate::syslog;
use crate::util::{canonicalise, is_decimal, is_valid_char};
use crate::{DnsmasqError::ConfigError, Result};
use hostname;
use std::fs::File;
use std::io::{self, BufRead};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const FTABSIZ: u32 = 150; // 最大未完成请求数目
pub const TIMEOUT: u32 = 40; // 查询超时时间（秒）
pub const LOGRATE: i64 = 120; // 日志表溢出记录间隔（秒）
pub const CACHESIZ: usize = 150; // 默认缓存大小
pub const SMALLDNAME: usize = 40; // 大多数域名小于此长度
pub const NAMESERVER_PORT: u16 = 53; // Default DNS server port

// 配置文件路径
pub const CONFFILE: &str = "/etc/utdnsmasq.conf";
pub const HOSTSFILE: &str = "/etc/hosts";
pub const RESOLVFILE: &str = "/etc/resolv.conf"; // 解析文件路径
pub const RUNFILE: &str = "/var/run/utdnsmasq.pid"; // 运行文件路径（用于管理 dnsmasq 进程）
pub const LEASEFILE: &str = "/var/lib/misc/utdnsmasq.leases"; // 租约文件路径

pub const DEFLEASE: u32 = 3600; // 默认租约时间，1小时

// 运行用户和组
pub const CHUSER: &str = "nobody";
pub const CHGRP: &str = "dip";

// IPv6 接口信息文件
pub const IP6INTERFACES: &str = "/proc/net/if_inet6";

// DHCP 端口号
pub const DHCP_SERVER_PORT: u16 = 67;
pub const DHCP_CLIENT_PORT: u16 = 68;

/// 主配置结构
#[derive(Debug)]
pub struct Config {
    pub cache_size: usize, // 缓存条目
    pub port: u16,         // 监听端口号
    pub query_port: u16,   // 强制上游查询的发起端口
    pub local_ttl: u32,
    pub options: u32,
    pub runfile: PathBuf,      // 用来管理dnsmasq进程
    pub interfaces: Vec<Irec>, // 网络接口
    pub mxname: String,
    pub mxtarget: String,
    pub lease_file: PathBuf,
    pub addn_hosts: Vec<String>, // 附加的host文件
    pub domain_suffix: Option<String>,
    pub username: String,
    pub groupname: String,
    pub if_names: Vec<Iname>,            // 网络接口白名单
    pub if_addrs: Vec<Iname>,            // 地址白名单
    pub if_except: Vec<Iname>,           // 网络接口黑名单
    pub serv_addrs: Option<Box<Server>>, // 是一个链表
    pub resolv: Vec<ResolvC>,            // 设置上游服务器文件
    pub bogus_addr: Vec<BogusAddr>,      // ip地址为不存在的域
    pub dhcp: Vec<DhcpContext>,
    pub dhcp_configs: Vec<DhcpConfig>,
    pub dhcp_options: Vec<DhcpOpt>,
    pub dhcp_file: PathBuf,
    pub dhcp_sname: Option<String>,
    pub dhcp_next_server: Ipv4Addr,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            cache_size: CACHESIZ,
            port: NAMESERVER_PORT,
            query_port: 0,
            local_ttl: 0,
            options: 0,
            runfile: PathBuf::from(RUNFILE),
            interfaces: Vec::new(),
            mxname: String::new(),
            mxtarget: String::new(),
            lease_file: PathBuf::new(),
            addn_hosts: Vec::new(),
            domain_suffix: None,
            username: CHUSER.to_string(),
            groupname: CHGRP.to_string(),
            if_names: Vec::new(),
            if_addrs: Vec::new(),
            if_except: Vec::new(),
            serv_addrs: None,
            resolv: Vec::new(),
            bogus_addr: Vec::new(),
            dhcp: Vec::new(),
            dhcp_configs: Vec::new(),
            dhcp_options: Vec::new(),
            dhcp_file: PathBuf::new(),
            dhcp_sname: None,
            dhcp_next_server: Ipv4Addr::new(0, 0, 0, 0),
        }
    }
}

impl Config {
    pub fn get_cache_size(&mut self) -> usize {
        self.cache_size
    }

    /// 从文件加载配置
    pub fn load(args: &Args) -> Result<Self> {
        let path = args.conf_file.clone();
        let config_file = match path {
            Some(path) => path,
            None => CONFFILE.to_string(),
        };
        let mut config: Self = parse_config(&config_file)?;

        // 合并命令行参数到配置中
        config.merge_args(args);

        Ok(config)
    }

    /// 从命令行参数加载配置
    pub fn from_args() -> Result<Self> {
        // 这里会实现命令行参数解析
        // 暂时返回默认配置
        Ok(Self::default())
    }

    /// 合并命令行参数到配置中
    pub fn merge_args(&mut self, args: &crate::cli::Args) {
        // 监听地址
        if let Some(ref listen_addresses) = args.listen_address {
            for addr_str in listen_addresses {
                if let Ok(socket_addr) = parse_socket_addr(addr_str) {
                    let new = crate::dnsmasq::Iname {
                        found: false,
                        addr: socket_addr,
                        ..Default::default()
                    };
                    self.if_addrs.push(new);
                }
            }
        }

        // 地址映射 (address=/domain/ipaddr)
        if let Some(ref addresses) = args.address {
            for addr_spec in addresses {
                self.parse_address_or_server_or_local_domain_option("address", addr_spec);
            }
        }

        // 标志选项
        if args.bogus_priv {
            self.options |= crate::dnsmasq::OPT_BOGUSPRIV;
        }
        if args.no_daemon {
            self.options |= crate::dnsmasq::OPT_DEBUG;
        }
        if args.domain_needed {
            self.options |= crate::dnsmasq::OPT_NODOTS_LOCAL;
        }
        if args.selfmx {
            self.options |= crate::dnsmasq::OPT_SELFMX;
        }
        if args.expand_hosts {
            self.options |= crate::dnsmasq::OPT_EXPAND;
        }
        // if args.filterwin2k {
        //     self.options |= crate::dnsmasq::OPT_FILTER;
        // }
        if args.no_hosts {
            self.options |= crate::dnsmasq::OPT_NO_HOSTS;
        }
        if args.localmx {
            self.options |= crate::dnsmasq::OPT_LOCALMX;
        }
        if args.no_poll {
            self.options |= crate::dnsmasq::OPT_NO_POLL;
        }
        if args.no_negcache {
            self.options |= crate::dnsmasq::OPT_NO_NEG;
        }
        if args.strict_order {
            self.options |= crate::dnsmasq::OPT_ORDER;
        }
        if args.no_resolv {
            self.options |= crate::dnsmasq::OPT_NO_RESOLV;
        }
        if args.log_queries {
            self.options |= crate::dnsmasq::OPT_LOG;
        }

        // 缓存大小
        if let Some(cache_size) = args.cache_size {
            self.cache_size = cache_size as usize;
        }

        // 端口设置
        if let Some(port) = args.port {
            self.port = port;
        }

        // 查询端口
        if let Some(query_port) = args.query_port {
            self.query_port = query_port;
        }

        // 本地TTL
        if let Some(local_ttl) = args.local_ttl {
            self.local_ttl = local_ttl;
        }

        // 用户和组
        if let Some(ref user) = args.user {
            self.username = user.clone();
        }
        if let Some(ref group) = args.group {
            self.groupname = group.clone();
        }

        // 接口设置
        if let Some(ref interfaces) = args.interface {
            for iface in interfaces {
                let new = crate::dnsmasq::Iname {
                    name: iface.clone(),
                    found: false,
                    ..Default::default()
                };
                self.if_names.push(new);
            }
        }

        // 排除接口
        if let Some(ref except_interfaces) = args.except_interface {
            for iface in except_interfaces {
                let new = crate::dnsmasq::Iname {
                    name: iface.clone(),
                    ..Default::default()
                };
                self.if_except.push(new);
            }
        }

        // 附加hosts文件
        if let Some(ref hosts) = args.hosts {
            for host_file in hosts {
                self.addn_hosts.push(host_file.clone());
            }
        }

        // MX设置
        if let Some(ref mx_host) = args.mx_host {
            self.mxname = mx_host.clone();
        }
        if let Some(ref mx_target) = args.mx_target {
            self.mxtarget = mx_target.clone();
        }

        // 域名后缀
        if let Some(ref domain) = args.local_domain {
            self.domain_suffix = Some(domain.clone());
        }

        // 服务器设置
        if let Some(ref servers) = args.server {
            for server_spec in servers {
                self.parse_address_or_server_or_local_domain_option("server", server_spec);
            }
        }

        // 本地域名 (不转发查询)
        if let Some(ref local_domain) = args.local {
            self.parse_address_or_server_or_local_domain_option("local", local_domain);
        }

        // 虚假NXDOMAIN
        if let Some(ref bogus_nxdomains) = args.bogus_nxdomain {
            for ip_str in bogus_nxdomains {
                if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                    let new = crate::dnsmasq::BogusAddr {
                        addr: ip,
                        next: None,
                    };
                    self.bogus_addr.push(new);
                }
            }
        }

        // 解析文件
        if let Some(ref resolv_files) = args.resolv_file {
            for resolv_file in resolv_files {
                let new: ResolvC = ResolvC {
                    name: resolv_file.clone(),
                    is_default: false,
                    logged: false,
                };
                self.resolv.push(new);
            }
        }

        if let Some(query_port) = args.query_port {
            self.query_port = query_port;
        }
        // PID文件
        if let Some(ref pid_file) = args.pid_file {
            self.runfile = std::path::PathBuf::from(pid_file);
        }

        // 租约文件
        if let Some(ref leasefile) = args.leasefile {
            self.lease_file = std::path::PathBuf::from(leasefile);
        }

        if let Some(ref resolvs) = args.resolv_file {
            for resolv in resolvs {
                let name = resolv.to_string();
                let mut new = ResolvC::default();
                let list = &mut self.resolv;
                if !list.is_empty() && list[0].is_default {
                    list[0].is_default = false;
                    list[0].name = name.to_string();
                } else {
                    new.name = name.to_string();
                    new.is_default = false;
                    new.logged = false;
                    self.resolv.push(new);
                }
            }
        }
        // DHCP范围
        if let Some(ref dhcp_range) = args.dhcp_range {
            for range in dhcp_range {
                self.parse_dhcp_range_option(range);
            }
        }

        // DHCP主机
        if let Some(ref dhcp_host) = args.dhcp_host {
            self.parse_dhcp_host_option(dhcp_host);
        }

        // DHCP选项
        if let Some(ref dhcp_option) = args.dhcp_option {
            for option in dhcp_option {
                self.parse_dhcp_option_option(option);
            }
        }

        // DHCP启动
        if let Some(ref dhcp_boot) = args.dhcp_boot {
            self.parse_dhcp_boot_option(dhcp_boot);
        }


        // 解析地址时可能不知道端口，请在这里填写
        if let Some(ref mut serv) = self.serv_addrs {
            let mut current: &mut Server = serv;
            loop {
                if current.flags & SERV_HAS_SOURCE == 0 {
                    current.source_addr.set_port(self.query_port);
                }
                if let Some(ref mut next) = current.next {
                    current = next;
                } else {
                    break;
                }
            }
        }

        // 更新端口设置
        if !self.if_addrs.is_empty() {
            for tmp in self.if_addrs.iter_mut() {
                tmp.addr.set_port(self.port);
            }
        }

        if self.options & OPT_LOCALMX != 0 || !self.mxname.is_empty() || !self.mxtarget.is_empty()
        {
            match hostname::get() {
                Ok(hostname) => {
                    if self.mxname.is_empty() {
                        self.mxname = hostname.to_string_lossy().into_owned();
                    }
                    if self.mxtarget.is_empty() {
                        self.mxtarget = hostname.to_string_lossy().into_owned();
                    }
                }
                Err(_) => {
                    die("can't get hostname", "");
                }
            }
        }

        if self.options & OPT_NO_RESOLV != 0 {
            // 如果设置了OPT_NO_RESOLV标志，则清空解析文件列表
            self.resolv.clear();
        } else if self.resolv.len() > 1 && self.options & OPT_NO_POLL != 0 {
            // 如果解析文件列表存在多个文件并且设置了OPT_NO_POLL标志
            die("only one resolv.conf file allowed in no-poll mode.", "");
        }
    }

    /// 解析地址选项 (address=/domain/ipaddr)
    fn parse_address_or_server_or_local_domain_option(&mut self, option: &str, arg: &str) {
        let mut newlist: Server = Server::default();
        let mut optarg = arg;
        if optarg.starts_with("/") {
            // 处理多个域名
            let mut end: &str;
            optarg = &optarg[1..]; // 去除第一个 '/'
            while optarg.contains("/") {
                let ret: Vec<&str> = optarg.splitn(2, "/").collect();
                optarg = ret[0];
                end = ret[1];

                if !canonicalise(optarg) {
                    // 域名合法性检查
                    self.options = OPT_ERROR;
                    break;
                }

                let domain = optarg;
                let serv: Server = Server {
                    next: Some(Box::new(newlist.clone())),
                    sfd: None,
                    domain: domain.to_string(),
                    flags: if !domain.is_empty() {
                        SERV_HAS_DOMAIN
                    } else {
                        SERV_FOR_NODOTS
                    },
                    ..Default::default()
                };
                newlist = serv.clone();

                optarg = end;
            }

            if Some(newlist.clone()).is_none() {
                let string = format!("bad argument for option {}", option);
                die(&string, "");
            }
        } else {
            // 只有ip地址，没有多个域名对应一个IP地址的情况
            newlist.next = None;
            newlist.flags = 0;
            newlist.sfd = None;
            newlist.domain = String::new();
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
                self.options = OPT_ERROR;
            }
        } else {
            let mut source_port: u16 = 0;
            let mut serv_port: u16 = NAMESERVER_PORT;
            let mut source: &str = "";

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
                        self.options = OPT_ERROR;
                    }
                }
            }

            if optarg.contains("#") {
                let split: Vec<&str> = optarg.split("#").collect();
                optarg = split[0];

                if let Ok(port) = split[1].parse::<u16>() {
                    serv_port = port;
                } else {
                    self.options = OPT_ERROR;
                }
            }

            match parse_ip_address(optarg) {
                Ok(IpAddr::V4(ip)) => {
                    newlist.addr = SocketAddr::new(IpAddr::V4(ip), serv_port);
                    if !source.is_empty() {
                        match parse_ip_address(source) {
                            Ok(IpAddr::V4(ip)) => {
                                newlist.source_addr = SocketAddr::new(IpAddr::V4(ip), source_port);
                                newlist.flags |= SERV_HAS_SOURCE;
                            }
                            Ok(IpAddr::V6(ip)) => {
                                newlist.source_addr = SocketAddr::new(IpAddr::V6(ip), source_port);
                                newlist.flags |= SERV_HAS_SOURCE;
                            }
                            Err(_) => {
                                syslog!(LOG_ERR, "serve or address 解析ip地址错误",);
                            }
                        }
                    } else {
                        let ip = Ipv4Addr::new(0, 0, 0, 0);
                        newlist.source_addr = SocketAddr::new(IpAddr::V4(ip), source_port);
                    }
                }
                Ok(IpAddr::V6(ip)) => {
                    newlist.addr = SocketAddr::new(IpAddr::V6(ip), serv_port);
                    if !source.is_empty() {
                        match parse_ip_address(source) {
                            Ok(IpAddr::V4(ip)) => {
                                newlist.source_addr = SocketAddr::new(IpAddr::V4(ip), source_port);
                                newlist.flags |= SERV_HAS_SOURCE;
                            }
                            Ok(IpAddr::V6(ip)) => {
                                newlist.source_addr = SocketAddr::new(IpAddr::V6(ip), source_port);
                                newlist.flags |= SERV_HAS_SOURCE;
                            }
                            Err(_) => {
                                syslog!(LOG_ERR, "serve or address 解析ip地址错误",);
                            }
                        }
                    } else {
                        let ip = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);
                        newlist.source_addr = SocketAddr::new(IpAddr::V6(ip), source_port);
                    }
                }
                Err(_) => {
                    syslog!(LOG_ERR, "serve or address 解析ip地址错误",);
                }
            }
        }

        let mut serv = newlist.clone();
        while serv.next.is_some() {
            if let Some(ref mut next) = serv.next {
                next.flags = serv.flags;
                next.addr = serv.addr;
                next.source_addr = serv.source_addr;
                next.domain = serv.domain.clone();
                serv = *next.clone();
            }
        }
        serv.next = self.serv_addrs.clone();
        self.serv_addrs = Some(Box::new(serv.clone()));
    }

    /// 解析DHCP范围选项
    fn parse_dhcp_range_option(&mut self, dhcp_range: &str) {
        let mut new: DhcpContext = DhcpContext {
            lease_time: DEFLEASE, // 租约时间
            ..Default::default()
        };

        if dhcp_range.contains(",") {
            let mut iter: Vec<&str> = dhcp_range.split(',').collect();
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
                    syslog!(LOG_ERR, "dhcp range 开始ip错误");
                }
            }

            // 获取ip范围结束地址
            match Ipv4Addr::from_str(iter[1]) {
                Ok(ip) => {
                    new.end = ip;
                }
                Err(_) => {
                    syslog!(LOG_ERR, "dhcp range 结束ip错误");
                }
            }

            // 解析租约时间
            if !iter[2].is_empty() {
                let mut opt = iter[2];
                if opt == "infinite" {
                    new.lease_time = 0xffffffff;
                } else {
                    let mut fac: u32 = 1;
                    if !opt.is_empty() {
                        match opt.chars().last() {
                            Some('h') | Some('H') => {
                                fac *= 60 * 60;
                                opt = &opt[..opt.len() - 1];
                            }
                            Some('m') | Some('M') => {
                                fac *= 60;
                                opt = &opt[..opt.len() - 1];
                            }
                            _ => {}
                        }
                        // 解析时间
                        let ret = opt.parse::<u32>();
                        match ret {
                            Ok(time) => {
                                new.lease_time = time * fac;
                            }
                            Err(_) => {
                                syslog!(LOG_ERR, "dhcp range 时间格式错误");
                            }
                        }
                    }
                }
            }

            new.last = new.start;
            new.iface = String::from("");
        } else {
            syslog!(LOG_ERR, "dhcp-range 设置错误",);
        }
        self.dhcp.push(new);
    }

    /// 解析DHCP主机选项
    fn parse_dhcp_host_option(&mut self, dhcp_host: &str) {
        let mut new: DhcpConfig = DhcpConfig {
            lease_time: DEFLEASE,
            ..Default::default()
        };

        // ","分割参数
        let a: Vec<&str> = dhcp_host.split(',').collect();
        // 遍历参数
        for temp in a {
            if temp.contains(":") {
                if temp.to_lowercase().contains("id") {
                    if let Some((_, b)) = temp.split_once(':') {
                        new.clid_len = b.len();
                        new.clid = b.as_bytes().to_vec();
                    }
                } else {
                    let args: Vec<&str> = temp.split(":").collect();
                    if args.len() == 6 {
                        // mac地址
                        new.hwaddr[0] = u32::from_str_radix(args[0], 16).unwrap() as u8;
                        new.hwaddr[1] = u32::from_str_radix(args[1], 16).unwrap() as u8;
                        new.hwaddr[2] = u32::from_str_radix(args[2], 16).unwrap() as u8;
                        new.hwaddr[3] = u32::from_str_radix(args[3], 16).unwrap() as u8;
                        new.hwaddr[4] = u32::from_str_radix(args[4], 16).unwrap() as u8;
                        new.hwaddr[5] = u32::from_str_radix(args[5], 16).unwrap() as u8;
                    } else {
                        syslog!(LOG_ERR, "dhcp-host MAC地址错误",);
                    }
                }
            } else if temp.contains(".") {
                // ip地址
                match Ipv4Addr::from_str(temp) {
                    Ok(ip) => {
                        new.addr = ip;
                    }
                    Err(_) => {
                        syslog!(LOG_ERR, "ip parse error");
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
        self.dhcp_configs.push(new);
    }

    /// 解析DHCP选项
    fn parse_dhcp_option_option(&mut self, dhcp_option: &str) {
        let mut new = DhcpOpt::default();
        let mut comma: &str = "";

        if let Some((first, rest)) = dhcp_option.split_once(',') {
            match is_decimal::<u8>(first) {
                Some(num) => {
                    new.opt = num;
                }
                None => {
                    syslog!(LOG_ERR, "dhcp option 选项名称不是数字");
                }
            }
            comma = rest;
        } else {
            syslog!(LOG_ERR, "dhcp option 设置格式错误");
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
            new.val.extend_from_slice(comma.as_bytes());
        } else {
            // 地址
            let ip_addrs: Vec<&str> = comma.split(",").collect();
            for ip_addr in ip_addrs {
                new.val.extend_from_slice(ip_addr.as_bytes());
            }
            new.len = new.val.len() as u8;
        }
        self.dhcp_options.push(new);
    }

    /// 解析DHCP启动选项
    fn parse_dhcp_boot_option(&mut self, dhcp_boot: &str) {
        if let Some(comma_pos) = dhcp_boot.find(',') {
            // 分割字符串，第一部分给 dhcp_file
            let (first_part, remainder) = dhcp_boot.split_at(comma_pos);
            self.dhcp_file = PathBuf::from(first_part);

            // 处理剩余部分（跳过逗号）
            let remaining_str = &remainder[1..];

            if let Some(second_comma_pos) = remaining_str.find(',') {
                // 分割第二部分
                let (second_part, third_part) = remaining_str.split_at(second_comma_pos);
                self.dhcp_sname = Some(second_part.to_string());

                // 解析 IP 地址
                let ip_str = &third_part[1..]; // 跳过第二个逗号
                match ip_str.parse::<Ipv4Addr>() {
                    Ok(ip) => {
                        self.dhcp_next_server = ip;
                    }
                    Err(_) => {
                        syslog!(LOG_ERR, "dhcp boot ip地址设置错误");
                    }
                }
            } else {
                // 只有两个部分，没有 IP 地址
                self.dhcp_sname = Some(remaining_str.to_string());
            }
        } else {
            // 只有一个部分
            self.dhcp_file = PathBuf::from(dhcp_boot);
        }
    }
}

pub fn config_default(config: &mut Config) {
    let resolv = ResolvC {
        // next: None,
        is_default: true,
        logged: false,
        name: RESOLVFILE.to_string(),
    };
    config.resolv.push(resolv);
}

/// 解析utdnsmasq格式的配置文件
pub fn parse_config(path: &str) -> Result<Config> {
    let conffile_set: bool = false;
    let mut config = Config::default();

    // 默认配置
    config_default(&mut config);

    /* 打开配置文件 */
    let file = File::open(path);
    let file = match file {
        Ok(file) => file,
        Err(error) => {
            if conffile_set {
                return Err(ConfigError("conffile_set参数问题".to_string()));
            } else {
                return Err(ConfigError(format!("配置文件打开错误: {}", error)));
            }
        }
    };

    // Read file content
    let reader = io::BufReader::new(file);
    let _content = String::new();
    for line in reader.lines() {
        let line = line.unwrap();

        // 跳过空行和注释
        if line.trim_start().starts_with('#') || line.is_empty() {
            continue;
        }
        parse_line(&line, &mut config)?;
    }

    Ok(config)
}

fn parse_line(line: &str, config: &mut Config) -> Result<()> {
    /* 去除注释、空格、等多余字符 */
    let re = regex::Regex::new(r"[ |\t]").unwrap();
    let line_vec: Vec<&str> = re.split(line).filter(|s| !s.is_empty()).collect();
    if line_vec.is_empty() {
        return Err(ConfigError(format!(
            "配置文件空行中存在空格或参数解析有误: {}",
            line
        )));
    }

    let line_val = line_vec[0];

    /* 获取option 和 value */
    let (option, mut optarg) = if line_val.contains('=') {
        let val: Vec<&str> = line_val.split('=').collect();
        (val[0], val[1])
    } else {
        (line_val, "")
    };

    match option {
        // 标志类
        "bogus-priv" => {
            config.options |= OPT_BOGUSPRIV;
        }
        // "filter-win2k" => {
        //     config.options |= OPT_FILTER;
        // }
        "log-queries" => {
            config.options |= OPT_LOG;
        }
        "selfmx" => {
            config.options |= OPT_SELFMX;
        }
        "no-hosts" => {
            config.options |= OPT_NO_HOSTS;
        }
        "no-poll" => {
            config.options |= OPT_NO_POLL;
        }
        "no-daemon" => {
            config.options |= OPT_DEBUG;
        }
        "strict-order" => {
            config.options |= OPT_ORDER;
        }
        "no-resolv" => {
            config.options |= OPT_NO_RESOLV;
        }
        "expand-hosts" => {
            config.options |= OPT_EXPAND;
        }
        "localmx" => {
            config.options |= OPT_LOCALMX;
        }
        "no-negcache" => {
            config.options |= OPT_NO_NEG;
        }
        "domain-needed" => {
            config.options |= OPT_NODOTS_LOCAL;
        }

        // 字符串选项
        // x  指定pid文件的路径  默认为RUNFILE
        "pid-file" => {
            config.runfile = PathBuf::from(optarg);
        }
        // r  指定resolv.conf文件的路径
        "resolv-file" => {
            let name = optarg;
            let mut new = ResolvC::default();
            let list = &mut config.resolv;
            if !list.is_empty() && list[0].is_default {
                list[0].is_default = false;
                list[0].name = name.to_string();
            } else {
                new.name = name.to_string();
                new.is_default = false;
                new.logged = false;
                config.resolv.push(new);
            }
        }
        // m  指定回复MX记录时使用的主机名。
        "mx-host" => {
            if canonicalise(optarg) {
                config.mxname = optarg.to_string();
            } else {
                config.options = OPT_ERROR;
            }
        }
        // c
        "cache-size" => {
            let size: usize = optarg
                .parse()
                .map_err(|_| ConfigError("Invalid cache size".to_string()))?;
            config.cache_size = size.clamp(0, 10000);
        }
        // t  指定MX回复中的目标主机名
        "mx-target" => {
            if canonicalise(optarg) {
                config.mxtarget = optarg.to_string();
            } else {
                config.options = OPT_ERROR;
            }
        }
        // l  指定存储DHCP租约的文件路径，默认为LEASEFILE。
        "dhcp-leasefile" => {
            config.lease_file = PathBuf::from(optarg);
        }
        // H  指定额外的hosts文件，除了默认的HOSTSFILE （目前不允许对addn_hosts进行多次设置）
        "addn-hosts" => {
            if !config.addn_hosts.is_empty() {
                // addn_hosts是除HOSTSFILE以外的hosts文件，所以在最初不应该有值
                config.options = OPT_ERROR;
            } else {
                config.addn_hosts.push(optarg.to_string());
            }
        }
        // s   域名后缀
        "domain" => {
            if canonicalise(optarg) {
                config.domain_suffix = Some(optarg.to_string());
            } else {
                config.options = OPT_ERROR;
            }
        }
        // u  启动后更改到指定的用户，默认为CHUSER。
        "user" => {
            config.username = optarg.to_string();
        }
        // g  启动后更改到指定的用户组，默认为CHGRP。
        "group" => {
            config.groupname = optarg.to_string();
        }
        // i  只监听指定监听的网络接口（网卡名称）。 例如 eth0
        "interface" => {
            let new: Iname = Iname {
                name: optarg.to_string(),
                found: false,
                ..Default::default()
            };
            config.if_names.push(new);
        }
        // I 指定不监听的网络接口。
        "except-interface" => {
            let new: Iname = Iname {
                name: optarg.to_string(),
                ..Default::default()
            };
            config.if_except.push(new);
        }
        // B  将给定IP地址视为不存在的域
        "bogus-nxdomain" => match Ipv4Addr::from_str(optarg) {
            Ok(ip) => {
                let new = BogusAddr {
                    addr: ip,
                    next: None,
                };
                config.bogus_addr.push(new);
            }
            Err(_) => {
                config.options = OPT_ERROR;
            }
        },
        // a 指定本地监听的IP地址
        "listen-address" => {
            for ip in optarg.split(',') {
                let new = Iname {
                    found: false,
                    addr: parse_socket_addr(ip)
                        .map_err(|_| ConfigError(format!("Invalid listen address: {}", ip)))?,
                    ..Default::default()
                };
                config.if_addrs.push(new);
            }
        }
        // S A
        "server" | "local" | "address" => {
            // let mut newlist: Vec<Server> = Vec::new();
            let mut newlist: Server = Server::default();

            if optarg.starts_with("/") {
                // 处理多个域名
                let mut end: &str;
                optarg = &optarg[1..]; // 去除第一个 '/'
                while optarg.contains("/") {
                    let ret: Vec<&str> = optarg.splitn(2, "/").collect();
                    optarg = ret[0];
                    end = ret[1];

                    if !canonicalise(optarg) {
                        // 域名合法性检查
                        config.options = OPT_ERROR;
                        break;
                    }

                    let domain = optarg;
                    let serv: Server = Server {
                        next: Some(Box::new(newlist.clone())),
                        sfd: None,
                        domain: domain.to_string(),
                        flags: if !domain.is_empty() {
                            SERV_HAS_DOMAIN
                        } else {
                            SERV_FOR_NODOTS
                        },
                        ..Default::default()
                    };
                    newlist = serv.clone();

                    optarg = end;
                }

                if Some(newlist.clone()).is_none() {
                    let string = format!("bad argument for option {}", option);
                    die(&string, "");
                }
            } else {
                // 只有ip地址，没有多个域名对应一个IP地址的情况
                newlist.next = None;
                newlist.flags = 0;
                newlist.sfd = None;
                newlist.domain = String::new();
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
                    config.options = OPT_ERROR;
                }
            } else {
                let mut source_port: u16 = 0;
                let mut serv_port: u16 = NAMESERVER_PORT;
                let mut source: &str = "";

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
                            config.options = OPT_ERROR;
                        }
                    }
                }

                if optarg.contains("#") {
                    let split: Vec<&str> = optarg.split("#").collect();
                    optarg = split[0];

                    if let Ok(port) = split[1].parse::<u16>() {
                        serv_port = port;
                    } else {
                        config.options = OPT_ERROR;
                    }
                }

                match parse_ip_address(optarg) {
                    Ok(IpAddr::V4(ip)) => {
                        newlist.addr = SocketAddr::new(IpAddr::V4(ip), serv_port);
                        if !source.is_empty() {
                            match parse_ip_address(source) {
                                Ok(IpAddr::V4(ip)) => {
                                    newlist.source_addr =
                                        SocketAddr::new(IpAddr::V4(ip), source_port);
                                    newlist.flags |= SERV_HAS_SOURCE;
                                }
                                Ok(IpAddr::V6(ip)) => {
                                    newlist.source_addr =
                                        SocketAddr::new(IpAddr::V6(ip), source_port);
                                    newlist.flags |= SERV_HAS_SOURCE;
                                }
                                Err(_) => {
                                    return Err(ConfigError(
                                        "serve or address 解析ip地址错误".to_string(),
                                    ));
                                }
                            }
                        } else {
                            let ip = Ipv4Addr::new(0, 0, 0, 0);
                            newlist.source_addr = SocketAddr::new(IpAddr::V4(ip), source_port);
                        }
                    }
                    Ok(IpAddr::V6(ip)) => {
                        newlist.addr = SocketAddr::new(IpAddr::V6(ip), serv_port);
                        if !source.is_empty() {
                            match parse_ip_address(source) {
                                Ok(IpAddr::V4(ip)) => {
                                    newlist.source_addr =
                                        SocketAddr::new(IpAddr::V4(ip), source_port);
                                    newlist.flags |= SERV_HAS_SOURCE;
                                }
                                Ok(IpAddr::V6(ip)) => {
                                    newlist.source_addr =
                                        SocketAddr::new(IpAddr::V6(ip), source_port);
                                    newlist.flags |= SERV_HAS_SOURCE;
                                }
                                Err(_) => {
                                    return Err(ConfigError(
                                        "serve or address 解析ip地址错误".to_string(),
                                    ));
                                }
                            }
                        } else {
                            let ip = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);
                            newlist.source_addr = SocketAddr::new(IpAddr::V6(ip), source_port);
                        }
                    }
                    Err(_) => {
                        return Err(ConfigError("serve or address 解析ip地址错误".to_string()));
                    }
                }
            }

            let mut serv = newlist.clone();
            while serv.next.is_some() {
                if let Some(ref mut next) = serv.next {
                    next.flags = serv.flags;
                    next.addr = serv.addr;
                    next.source_addr = serv.source_addr;
                    next.domain = serv.domain.clone();
                    serv = *next.clone();
                }
            }
            serv.next = config.serv_addrs.clone();
            config.serv_addrs = Some(Box::new(serv.clone()));
        }
        // p
        "port" => {
            config.port = optarg
                .parse()
                .map_err(|_| ConfigError("Invalid port".to_string()))?;
        }
        // Q
        "query-port" => {
            config.query_port = optarg
                .parse()
                .map_err(|_| ConfigError("Invalid query port".to_string()))?;
        }
        // T
        "local-ttl" => {
            config.local_ttl = optarg
                .parse()
                .map_err(|_| ConfigError("Invalid local TTL".to_string()))?;
        }
        // F
        "dhcp-range" => {
            let mut new: DhcpContext = DhcpContext {
                lease_time: DEFLEASE, // 租约时间
                ..Default::default()
            };

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
                        config.options = OPT_ERROR;
                    }
                }

                // 获取ip范围结束地址
                match Ipv4Addr::from_str(iter[1]) {
                    Ok(ip) => {
                        new.end = ip;
                    }
                    Err(_) => {
                        config.options = OPT_ERROR;
                    }
                }

                // 解析租约时间
                if !iter[2].is_empty() {
                    let mut opt = iter[2];
                    if opt == "infinite" {
                        new.lease_time = 0xffffffff;
                    } else {
                        let mut fac: u32 = 1;
                        if !opt.is_empty() {
                            match opt.chars().last() {
                                Some('h') | Some('H') => {
                                    fac *= 60 * 60;
                                    opt = &opt[..opt.len() - 1];
                                }
                                Some('m') | Some('M') => {
                                    fac *= 60;
                                    opt = &opt[..opt.len() - 1];
                                }
                                _ => {}
                            }
                            // 解析时间
                            let ret = opt.parse::<u32>();
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
                config.options = OPT_ERROR;
            }
            config.dhcp.push(new);
        }
        // G
        "dhcp-host" => {
            let mut new: DhcpConfig = DhcpConfig {
                lease_time: DEFLEASE,
                ..Default::default()
            };

            // ","分割参数
            let a: Vec<&str> = optarg.split(',').collect();
            // 遍历参数
            for temp in a {
                if temp.contains(":") {
                    if temp.to_lowercase().contains("id") {
                        if let Some((_, b)) = temp.split_once(':') {
                            new.clid_len = b.len();
                            new.clid = b.as_bytes().to_vec();
                        }
                    } else {
                        let args: Vec<&str> = temp.split(":").collect();
                        if args.len() == 6 {
                            // mac地址
                            new.hwaddr[0] = u32::from_str_radix(args[0], 16).unwrap() as u8;
                            new.hwaddr[1] = u32::from_str_radix(args[1], 16).unwrap() as u8;
                            new.hwaddr[2] = u32::from_str_radix(args[2], 16).unwrap() as u8;
                            new.hwaddr[3] = u32::from_str_radix(args[3], 16).unwrap() as u8;
                            new.hwaddr[4] = u32::from_str_radix(args[4], 16).unwrap() as u8;
                            new.hwaddr[5] = u32::from_str_radix(args[5], 16).unwrap() as u8;
                        } else {
                            config.options = OPT_ERROR;
                        }
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
            config.dhcp_configs.push(new);
        }
        // O - dhcp-option
        "dhcp-option" => {
            let mut new = DhcpOpt::default();
            let mut comma: &str = "";

            if let Some((first, rest)) = optarg.split_once(',') {
                match is_decimal::<u8>(first) {
                    Some(num) => {
                        new.opt = num;
                    }
                    None => config.options = OPT_ERROR,
                }
                comma = rest;
            } else {
                config.options = OPT_ERROR;
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
                new.val.extend_from_slice(comma.as_bytes());
            } else {
                // 地址
                let ip_addrs: Vec<&str> = comma.split(",").collect();
                for ip_addr in ip_addrs {
                    new.val.extend_from_slice(ip_addr.as_bytes());
                }
                new.len = new.val.len() as u8;
            }
            config.dhcp_options.push(new);
        }
        // M
        "dhcp-boot" => {
            if let Some(comma_pos) = optarg.find(',') {
                // 分割字符串，第一部分给 dhcp_file
                let (first_part, remainder) = optarg.split_at(comma_pos);
                config.dhcp_file = PathBuf::from(first_part);

                // 处理剩余部分（跳过逗号）
                let remaining_str = &remainder[1..];

                if let Some(second_comma_pos) = remaining_str.find(',') {
                    // 分割第二部分
                    let (second_part, third_part) = remaining_str.split_at(second_comma_pos);
                    config.dhcp_sname = Some(second_part.to_string());

                    // 解析 IP 地址
                    let ip_str = &third_part[1..]; // 跳过第二个逗号
                    match ip_str.parse::<Ipv4Addr>() {
                        Ok(ip) => {
                            config.dhcp_next_server = ip;
                        }
                        Err(_) => {
                            config.options = OPT_ERROR;
                        }
                    }
                } else {
                    // 只有两个部分，没有 IP 地址
                    config.dhcp_sname = Some(remaining_str.to_string());
                }
            } else {
                // 只有一个部分
                config.dhcp_file = PathBuf::from(optarg);
            }
        }
        _ => {
            // 忽略未知配置项
        }
    }

    if config.options == OPT_ERROR {
        let string = format!("bad argument for option {}", option);
        die(&string, "");
    }

    Ok(())
}

/// Parse a socket address string into a MySockAddr
/// Supports formats like:
/// - "192.168.1.1" (IP address only, uses default DNS port 53)
/// - "192.168.1.1:53" (IP address with port)
/// - "[::1]:53" (IPv6 address with port)
fn parse_socket_addr(addr_str: &str) -> Result<MySockAddr> {
    // Try to parse as SocketAddr first (with port)
    if let Ok(socket_addr) = addr_str.parse::<SocketAddr>() {
        return Ok(socket_addr);
    }

    // If that fails, try parsing as just an IP address and use default DNS port
    if let Ok(ip_addr) = addr_str.parse::<std::net::IpAddr>() {
        let socket_addr = SocketAddr::new(ip_addr, NAMESERVER_PORT);
        return Ok(socket_addr);
    }

    // If both fail, return an error
    Err(ConfigError(format!(
        "Invalid socket address format: {}",
        addr_str
    )))
}

fn parse_ip_address(ip_str: &str) -> Result<IpAddr> {
    match ip_str.parse() {
        Ok(ip) => Ok(ip),
        Err(e) => Err(ConfigError(format!("ip地址解析错误: {}", e))),
    }
}
