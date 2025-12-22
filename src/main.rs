/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#![allow(
    unexpected_cfgs,
    unused_imports,
    unused_variables,
    unused_assignments,
    dead_code
)]

pub mod cache;
pub mod cli;
pub mod dhcp;
pub mod forward;
pub mod lease;
pub mod logs;
pub mod network;
pub mod option;
pub mod rfc1035;
pub mod rfc2131;
pub mod util;

use byteorder::{ByteOrder, NetworkEndian};
use cache::*;
use cli::parse_args;
use daemonize::Daemonize;
use dhcp::*;
use forward::*;
use lease::*;
use libc::{getpwnam, passwd};
use logs::*;
use mio::net::UdpSocket as MioUdpSocket;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use network::*;
use nix::sys::signal::{self, SaFlags, SigAction, SigHandler, SigSet, SigmaskHow, Signal};
use nix::sys::stat::{umask, Mode};
use nix::unistd::{
    chdir, close, fork, geteuid, getuid, setgid, setsid, setuid, ForkResult, Gid, Uid,
};
use std::ffi::CString;

use option::*;
use pnet::util::Octets;
use rfc1035::*;
use std::fs::File;
use std::io::Write;
use std::mem;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::FromRawFd;
use std::path::Path;
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fs, process};
use users::{get_group_by_name, get_user_by_name};

// 全局标志变量，使用 AtomicBool 来保证线程安全
static SIGHUP_FLAG: AtomicBool = AtomicBool::new(false);
static SIGUSR1_FLAG: AtomicBool = AtomicBool::new(false);
static SIGUSR2_FLAG: AtomicBool = AtomicBool::new(false);
static SIGTERM_FLAG: AtomicBool = AtomicBool::new(false);

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Header {
    pub id: u16,

    pub qr: u8,
    pub opcode: u8,
    pub aa: u8,
    pub tc: u8,
    pub rd: u8,

    pub ra: u8,
    pub unused: u8,
    pub ad: u8,
    pub cd: u8,
    pub rcode: u8,

    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl Header {
    pub fn new() -> Self {
        Header {
            id: 0,
            qr: 0,
            opcode: 0,
            aa: 0,
            tc: 0,
            rd: 0,
            ra: 0,
            unused: 0,
            ad: 0,
            cd: 0,
            rcode: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 12 {
            return None;
        }

        let id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let third_byte = bytes[2];
        let fourth_byte = bytes[3];
        let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]);
        let ancount = u16::from_be_bytes([bytes[6], bytes[7]]);
        let nscount = u16::from_be_bytes([bytes[8], bytes[9]]);
        let arcount = u16::from_be_bytes([bytes[10], bytes[11]]);

        Some(Header {
            id,
            qr: (third_byte >> 7) & 0x1,
            opcode: (third_byte >> 3) & 0xF,
            aa: (third_byte >> 2) & 0x1,
            tc: (third_byte >> 1) & 0x1,
            rd: third_byte & 0x1,
            ra: (fourth_byte >> 7) & 0x1,
            unused: (fourth_byte >> 6) & 0x1,
            ad: (fourth_byte >> 5) & 0x1,
            cd: (fourth_byte >> 4) & 0x1,
            rcode: fourth_byte & 0xF,
            qdcount,
            ancount,
            nscount,
            arcount,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; mem::size_of::<Header>()];
        NetworkEndian::write_u16(&mut bytes[0..2], self.id);
        bytes[2] = (self.qr << 7) | (self.opcode << 3) | (self.aa << 2) | (self.tc << 1) | self.rd;
        bytes[3] = (self.ra << 7) | (self.ad << 5) | (self.cd << 4) | self.rcode;
        NetworkEndian::write_u16(&mut bytes[4..6], self.qdcount);
        NetworkEndian::write_u16(&mut bytes[6..8], self.ancount);
        NetworkEndian::write_u16(&mut bytes[8..10], self.nscount);
        NetworkEndian::write_u16(&mut bytes[10..12], self.arcount);
        bytes
    }
}

extern "C" fn sig_handler(sig: i32) {
    match sig {
        libc::SIGTERM => SIGTERM_FLAG.store(true, Ordering::SeqCst),
        libc::SIGHUP => SIGHUP_FLAG.store(true, Ordering::SeqCst),
        libc::SIGUSR1 => SIGUSR1_FLAG.store(true, Ordering::SeqCst),
        libc::SIGUSR2 => SIGUSR2_FLAG.store(true, Ordering::SeqCst),
        _ => {}
    }
}

// 定义常量
const MAXDNAME: usize = 256; // 域名最大长度
const PACKETSZ: usize = 512; // 典型的 DNS 数据包大小
const RRFIXEDSZ: usize = 10; // 资源记录的固定大小
const CACHESIZ: usize = 1024; // 缓存大小默认值
const NAMESERVER_PORT: u16 = 53; // Default DNS server port
const RUNFILE: &str = "/tmp/utdnsmasq.pid";
const CHUSER: &str = "nobody"; // 默认用户名
const CHGRP: &str = "dip"; // 默认组名
const IFPACKET: &str = "/usr/include/netpacket/packet.h";
const IFBPF: &str = "/usr/include/linux/bpf.h";
const LEASEFILE: &str = "/var/lib/misc/dnsmasq.leases";
const VERSION: &str = "1.0.0";
const F_QUERY: u32 = 8192;
const CONFILE: &str = "/etc/utdnsmasq.conf";

// 存储接口名称和地址
#[derive(Clone, Debug)]
pub struct Irec {
    pub addr: MySockAddr,
    pub fd: i32,
    pub valid: bool,
    pub next: Option<Box<Irec>>,
}

fn main() {
    /*
       主函数，用于启动 dnsmasq 服务器
       参数：argc: 命令行参数个数
       args: 命令行参数向量
       返回值：0 表示成功，其他值表示失败
    */
    let mut cachesize: usize = CACHESIZ; // 缓存大小，默认值为 CACHESIZ
    let mut port: u16 = NAMESERVER_PORT; // 名称服务器端口，默认为 NAMESERVER_PORT
    let mut query_port: i32 = 0; // 查询端口，初始值为0
    let mut first_loop: bool = true;
    let mut local_ttl: u64 = 0; // 本地缓存 TTL，初始值为 0
    let mut runfile: Option<String> = Some(String::from(RUNFILE)); // 进程 PID 文件路径，默认为 RUNFILE

    let mut interfaces: Option<Box<Irec>> = None;
    // 时间戳相关变量
    let mut resolv_changed: Option<SystemTime> = None;
    let now: SystemTime = SystemTime::now();
    let mut last: Option<SystemTime> = None;
    // 邮件交换相关变量
    let mut resolv: Option<Box<ResolvC>> = None;
    let mut dhcp: Option<Box<DhcpContext>> = None;
    let mut dhcp_conf: Option<Box<DhcpConfig>> = None;
    let mut dhcp_opts: Option<Box<DhcpOpt>> = None;
    let mut mxname: Option<String> = None;
    let mut mxtarget: Option<String> = None;
    let mut lease_file: Option<String> = None; // 租约文件路径
    let mut addn_hosts: Option<String> = None; // 额外主机文件路径
    let mut domain_suffix: Option<String> = None; // 域名后缀
    let mut username: String = CHUSER.to_string(); // 用户名，默认值为 CHUSER
    let mut groupname: String = CHGRP.to_string(); // 组名，默认值为 CHGRP
    let mut if_names: Option<Box<Iname>> = None; // 用于存储接口名称
    let mut if_addrs: Option<Box<Iname>> = None; // 用于存储接口地址
    let mut if_except: Option<Box<Iname>> = None; // 用于存储例外情况
    let mut bogus_addr: Option<Box<BogusAddr>> = None;
    let mut dhcp_sname: Option<String> = None;
    let mut dhcp_file: Option<String> = Default::default();
    let mut serv_addrs: Option<Box<Server>> = None;
    let mut dnamebuff = vec![0u8; MAXDNAME];
    let mut packet = vec![0u8; PACKETSZ + MAXDNAME + RRFIXEDSZ];
    let mut dhcp_next_server = InAddr::new(0);
    let leasefd: i32 = 0;
    let mut sfds: Option<Box<ServerFd>> = None;

    // 初始化日志
    log_init();

    // 创建并初始化 SigSet，用于阻塞信号
    let mut sigset = SigSet::empty();
    sigset.add(Signal::SIGUSR1);
    sigset.add(Signal::SIGUSR2);
    sigset.add(Signal::SIGTERM);
    sigset.add(Signal::SIGHUP);

    // 定义信号处理程序，相当于 sigaction
    let sigact = SigAction::new(
        SigHandler::Handler(sig_handler),
        SaFlags::empty(),
        SigSet::empty(), // 初始化并清空信号集
    );

    // 注册信号和处理程序
    unsafe {
        signal::sigaction(Signal::SIGUSR1, &sigact).expect("无法注册 SIGUSR1");
        signal::sigaction(Signal::SIGUSR2, &sigact).expect("无法注册 SIGUSR2");
        signal::sigaction(Signal::SIGHUP, &sigact).expect("无法注册 SIGHUP");
        signal::sigaction(Signal::SIGTERM, &sigact).expect("无法注册 SIGTERM");
    }

    // 解析命令行参数
    let cli_args = parse_args();

    // 解析配置文件
    let options = read_opts(
        &mut resolv,
        &mut mxname,
        &mut mxtarget,
        &mut lease_file,
        &mut username,
        &mut groupname,
        &mut domain_suffix,
        &mut runfile,
        &mut if_names,
        &mut if_addrs,
        &mut if_except,
        &mut bogus_addr,
        &mut serv_addrs,
        &mut cachesize,
        &mut port,
        &mut query_port,
        &mut local_ttl,
        &mut addn_hosts,
        &mut dhcp,
        &mut dhcp_conf,
        &mut dhcp_opts,
        &mut dhcp_file,
        &mut dhcp_sname,
        &mut dhcp_next_server,
    );

    // 应用命令行参数，覆盖配置文件设置
    let mut options = options;
    if cli_args.no_daemon {
        options |= OPT_DEBUG;
    }
    if cli_args.cache_size.is_some() {
        cachesize = cli_args.cache_size.unwrap() as usize;
    }
    if cli_args.port.is_some() {
        port = cli_args.port.unwrap();
    }
    if cli_args.query_port.is_some() {
        query_port = cli_args.query_port.unwrap() as i32;
    }
    if cli_args.conf_file.is_some() {
        // 配置文件在read_opts中已经处理，这里不需要重新处理
    }
    if cli_args.bogus_priv {
        options |= OPT_BOGUSPRIV;
    }
    if cli_args.domain_needed {
        options |= OPT_NODOTS_LOCAL;
    }
    if cli_args.selfmx {
        options |= OPT_SELFMX;
    }
    if cli_args.expand_hosts {
        options |= OPT_EXPAND;
    }
    if cli_args.localmx {
        options |= OPT_LOCALMX;
    }
    if cli_args.no_poll {
        options |= OPT_NO_POLL;
    }
    if cli_args.no_negcache {
        options |= OPT_NO_NEG;
    }
    if cli_args.strict_order {
        options |= OPT_ORDER;
    }
    if cli_args.log_queries {
        options |= OPT_LOG;
    }
    if cli_args.no_resolv {
        options |= OPT_NO_RESOLV;
    }

    if lease_file.is_none() {
        lease_file = Some(String::from(LEASEFILE));
    } else if dhcp.is_none() {
        complain("********* dhcp-lease option set, but not dhcp-range.", "");
        complain(
            "********* Are you trying to use the obsolete ISC dhcpd integration?",
            "",
        );
        complain(
            "********* Please configure the dnsmasq integrated DHCP server by using",
            "",
        );
        complain(
            "********* the \"dhcp-range\" option, and remove any other DHCP server.",
            "",
        );
    }

    let int_err_string = enumerate_interfaces(
        &mut interfaces,
        &mut if_names,
        &mut if_addrs,
        &mut if_except,
        &mut dhcp,
        port,
    );

    if int_err_string.is_err() {
        eprintln!(
            "Warning: Failed to enumerate network interfaces: {:?}",
            int_err_string
        );
        syslog!(
            LOG_WARNING,
            "Failed to enumerate network interfaces, continuing with limited functionality",
        );

        // 在最小化环境中，即使接口枚举失败，我们也尝试继续运行
        // 创建一个默认的回环接口配置
        if interfaces.is_none() {
            let default_interface = Irec {
                addr: MySockAddr::default(),
                fd: -1,
                valid: false,
                next: None,
            };
            interfaces = Some(Box::new(default_interface));
            // 注意：这里只是为了让程序不会立即退出，实际功能可能受限
        }
    }
    let mut if_tmp = &if_names;
    while let Some(ref iname) = if_tmp {
        if iname.name.is_none() && !iname.found {
            // die("********* unknown interface",if_tmp->name);
        }
        if_tmp = &iname.next;
    }
    let mut if_tmp = &if_addrs;
    while let Some(ref iname) = if_tmp {
        if !iname.found {
            unsafe {
                if iname.addr.sa.sa_family == 2 {
                    // ipv4转换
                    let addr_str =
                        std::net::Ipv4Addr::from(u32::from_be(iname.addr.in_.sin_addr.s_addr))
                            .to_string();
                    syslog!(
                        LOG_DEBUG,
                        "Could not find interface for IPv4 address: {}",
                        addr_str
                    );
                } else {
                    // ipv6转换
                    syslog!(LOG_DEBUG, "Could not find interface for IPv6 address");
                }
            }
            complain("********* no interface with address", "");
            syslog!(LOG_CRIT, "no interface with address");
            exit(1);
        }
        if_tmp = &iname.next;
    }
    forward_init(true);
    let mut caches = Cache::new(cachesize, options & 4);
    // 检查DHCP配置并验证必要的文件是否存在
    if dhcp.is_some() {
        let packet_path = IFPACKET;
        let bpf_path = IFBPF;
        if file_exists(packet_path) && file_exists(bpf_path) {
            let mut current = &dhcp;
            while let Some(ctx) = current {
                if ctx.iface.is_empty() {
                    // 如果 iface 为空字符串，执行后续代码块
                    // die("********* No suitable interface for DHCP service at address", inet_ntoa(dhcp_tmp->start));
                    let _leasefd = lease_init(
                        lease_file.as_deref(),
                        &mut domain_suffix,
                        &mut dnamebuff,
                        &mut packet,
                        SystemTime::now(),
                        &mut dhcp_conf,
                    );
                    let _ = lease_update_dns(&mut caches, 1);
                }

                // 移动到下一个节点
                current = &ctx.next;
            }
        } else {
            complain("********* no DHCP support available on this OS.", "");
            syslog!(LOG_CRIT, "no DHCP support available on this OS.");
            exit(1);
        }
    }

    if (options & OPT_DEBUG) == 0 {
        let username_str: &str = username.as_str(); // 获取用户名字符串  将string类型转换为&str类型
        let groupname_str: &str = groupname.as_str();

        let runfile = match runfile {
            Some(t) => t,
            None => String::from("/tmp/utdnsmasq.pid"),
        };

        let daemonize = Daemonize::new()
            .working_directory("/")
            .umask(0o022)
            .user(username_str)
            .group(groupname_str)
            .privileged_action(|| {
                nix::unistd::setgroups(&[]).unwrap(); // 清除附加组
            });

        match daemonize.start() {
            Ok(_) => {}
            Err(e) => {
                eprintln!("Failed to daemonize: {}", e);
                syslog!(LOG_CRIT, "Failed to daemonize: {}", e);
                exit(1);
            }
        }
    } else {
        // 在no-daemon模式下，仍然需要切换用户/组（如果指定的话）
        let mut user_switched = false;
        if username != CHUSER || groupname != CHGRP {
            if let Some(user) = get_user_by_name(&username) {
                if let Some(group) = get_group_by_name(&groupname) {
                    if setgid(Gid::from_raw(group.gid())).is_ok()
                        && setuid(Uid::from_raw(user.uid())).is_ok()
                    {
                        user_switched = true;
                    }
                }
            }
        }

        // 只有在尝试切换用户但失败时才警告
        if (username != CHUSER || groupname != CHGRP)
            && !user_switched
            && (getuid().is_root() || geteuid().is_root())
        {
            syslog!(
                LOG_WARNING,
                "failed to drop root privs for user {} group {}",
                username,
                groupname
            );
        }
    }

    if Some(cachesize).is_some() {
        syslog!(
            LOG_INFO,
            "started, version {}, cachesize {}",
            VERSION,
            cachesize
        );
    } else {
        syslog!(LOG_INFO, "started, version {} cache disabled", VERSION);
    }

    if Some(options & 1024).is_some() {
        syslog!(
            LOG_INFO,
            "serving MX record for local hosts target {:?}",
            mxtarget
        );
    } else if mxname.is_some() {
        syslog!(
            LOG_INFO,
            "serving MX record for mailhost {:?} target {:?}",
            mxname,
            mxtarget
        )
    }
    let mut dhcp_tmp = &dhcp;
    while let Some(ref config) = dhcp_tmp {
        // 获取起始 IP 地址
        let _dnamebuff = Ipv4Addr::from(u32::from_be(config.start.s_addr)).to_string();

        // 租约时间格式化
        let _packet = if config.lease_time == 0 {
            String::from("infinite")
        } else {
            format!("{}s", config.lease_time)
        };

        // 移动到下一个配置
        dhcp_tmp = &config.next;
    }

    let mut servers = check_servers(serv_addrs, &interfaces, &mut sfds);
    let mut last_server = servers.clone();
    while !SIGTERM_FLAG.load(Ordering::Relaxed) {
        // 立即检查SIGTERM信号
        if SIGTERM_FLAG.load(Ordering::Relaxed) {
            break;
        }

        // 创建 Poll 实例
        let mut poll = Poll::new().expect("无法创建 Poll 实例");

        // 创建一个容量为 128 的 Events 集合，类似于 fd_set
        let mut events = Events::with_capacity(128);
        // 在每个主要处理阶段检查SIGTERM
        if SIGTERM_FLAG.load(Ordering::Relaxed) {
            break;
        }

        // fd_set events;
        if SIGHUP_FLAG.load(Ordering::Relaxed) {
            cache_reload(
                &mut caches,
                options,
                &mut dnamebuff,
                &mut domain_suffix,
                addn_hosts.as_ref().map(|x| x.to_string()),
            );
            let _ = lease_update_dns(&mut caches, 1);
        }
        if resolv.is_some() && (options & OPT_NO_POLL) != 0 {
            servers = check_servers(
                reload_servers(&mut resolv, &mut servers, &mut query_port),
                &interfaces,
                &mut sfds,
            );
            SIGHUP_FLAG.store(false, Ordering::SeqCst);
        }

        if SIGUSR1_FLAG.load(Ordering::SeqCst) {
            dump_cache(
                (options & (OPT_DEBUG | OPT_LOG)).try_into().unwrap(),
                &caches,
            );
            SIGUSR1_FLAG.store(false, Ordering::SeqCst);
        }

        if SIGUSR2_FLAG.load(Ordering::SeqCst) {
            if getuid().as_raw() != 0 && port <= 1024 {
                syslog!(LOG_ERR, "cannot re-scan interfaces unless --user=root",);
            } else {
                complain("rescanning network interfaces", "");
                let int_err_string = enumerate_interfaces(
                    &mut interfaces,
                    &mut if_names,
                    &mut if_addrs,
                    &mut if_except,
                    &mut dhcp,
                    port,
                );
                if int_err_string.is_err() {
                    syslog!(LOG_ERR, "Error: {:?}", int_err_string);
                }
            }
            SIGUSR2_FLAG.store(false, Ordering::SeqCst);
        }

        if !first_loop {
            // 用于跟踪最大文件描述符
            let mut maxfd = 0;

            // 遍历链表，将每个文件描述符注册到 Poll 中
            let mut serverfdp = sfds.as_deref();
            while let Some(server) = serverfdp {
                let raw_fd = server.fd;

                // 检查文件描述符是否有效
                if raw_fd >= 0 {
                    // 注册文件描述符到 poll，相当于 FD_SET
                    match poll.registry().register(
                        &mut SourceFd(&raw_fd),
                        Token(raw_fd as usize),
                        Interest::READABLE,
                    ) {
                        Ok(_) => {
                            // 更新最大文件描述符
                            if raw_fd > maxfd {
                                maxfd = raw_fd;
                            }
                        }
                        Err(_) => {
                            // 记录到系统日志而不是标准输出
                            let fd_value = raw_fd;
                            syslog!(LOG_WARNING, "Failed to register server fd={}", fd_value);
                        }
                    }
                }

                // 移动到下一个节点
                serverfdp = server.next.as_deref();
            }

            let mut iface = interfaces.as_deref_mut();
            while let Some(interface) = iface {
                let raw_fd = interface.fd;

                // 如果文件描述符有效，将其注册到 poll
                if interface.valid && raw_fd >= 0 {
                    match poll.registry().register(
                        &mut SourceFd(&raw_fd),
                        Token(raw_fd as usize),
                        Interest::READABLE,
                    ) {
                        Ok(_) => {
                            // 更新最大文件描述符
                            if raw_fd > maxfd {
                                maxfd = raw_fd;
                            }
                        }
                        Err(_) => {
                            // 如果注册失败，将接口标记为无效，避免无限循环
                            interface.valid = false;
                        }
                    }
                }

                // 移动到下一个节点
                iface = interface.next.as_deref_mut();
            }

            // 遍历链表，将每个文件描述符注册到 Poll 中
            let mut dhcp_tmp = dhcp.as_deref_mut();
            while let Some(dhcp_entry) = dhcp_tmp {
                let raw_fd = dhcp_entry.fd;

                // 检查文件描述符是否有效
                if raw_fd >= 0 {
                    // 将文件描述符注册到 Poll 中，相当于 FD_SET
                    match poll.registry().register(
                        &mut SourceFd(&raw_fd),
                        Token(raw_fd as usize),
                        Interest::READABLE,
                    ) {
                        Ok(_) => {
                            // 更新最大文件描述符
                            if raw_fd > maxfd {
                                maxfd = raw_fd;
                            }
                        }
                        Err(_) => {
                            // 记录到系统日志而不是标准输出
                            syslog!(LOG_WARNING, "Failed to register DHCP fd={}", raw_fd);
                        }
                    }
                }

                // 移动到下一个节点
                dhcp_tmp = dhcp_entry.next.as_deref_mut();
            }

            // 临时取消阻塞信号，允许信号处理器运行
            let empty_mask = SigSet::empty();
            let mut old_mask = SigSet::empty();
            signal::sigprocmask(
                SigmaskHow::SIG_SETMASK,
                Some(&empty_mask),
                Some(&mut old_mask),
            )
            .expect("无法取消阻塞信号");

            // 使用较短的超时时间来检查信号
            if poll
                .poll(&mut events, Some(Duration::from_millis(100)))
                .is_err()
            {
                events = Events::with_capacity(128); // 如果出错，清空 events
            }

            // 恢复信号阻塞
            signal::sigprocmask(SigmaskHow::SIG_SETMASK, Some(&old_mask), None)
                .expect("无法恢复信号掩码");
        }
        first_loop = false;

        if last.map_or(true, |last_time| {
            now.duration_since(last_time).unwrap_or(Duration::ZERO) > Duration::from_secs(1)
        }) {
            last = Some(now);
            if options & OPT_NO_POLL == 0 {
                // 用于记录最近修改的文件信息
                let mut latest: Option<Box<ResolvC>> = None;
                let mut last_change = UNIX_EPOCH;

                let mut f_resolv = resolv.as_deref_mut();
                while let Some(resolv) = f_resolv {
                    if let Some(ref name) = &resolv.name {
                        let path = Path::new(name);
                        match fs::metadata(path) {
                            Ok(metadata) => {
                                // 获取文件的最后修改时间
                                let modified_time = metadata.modified().unwrap_or(UNIX_EPOCH);
                                // 更新 `logged` 状态
                                resolv.logged = false;
                                if modified_time > last_change {
                                    last_change = modified_time;
                                    latest = Some(Box::new(resolv.clone()));
                                }
                            }
                            Err(e) => {
                                if !resolv.logged {
                                    syslog!(
                                        LOG_WARNING,
                                        "Warning: failed to access {}: {}",
                                        name,
                                        e
                                    );
                                }
                                resolv.logged = true;
                            }
                        }
                    } else {
                        // 如果 `name` 是 `None`，输出警告并标记为 `logged`
                        if !resolv.logged {
                            syslog!(
                                LOG_WARNING,
                                "Warning: file name is missing for f_resolv node.",
                            );
                        }
                        resolv.logged = true;
                    }

                    // 移动到下一个节点
                    f_resolv = resolv.next.as_deref_mut();
                }
                if let Some(latest) = latest {
                    if last_change > resolv_changed.expect("REASON") {
                        resolv_changed = Some(last_change);

                        if let Some(_name) = &latest.name {
                            servers = check_servers(
                                reload_servers(&mut Some(latest), &mut servers, &mut query_port),
                                &interfaces,
                                &mut sfds,
                            );
                        }
                    }
                }
            }
        }

        // 注册链表中的所有文件描述符到 Poll
        let mut serverfdp = sfds.as_deref_mut();
        while let Some(server) = serverfdp {
            // 检查文件描述符是否有效
            if server.fd >= 0 {
                match poll.registry().register(
                    &mut SourceFd(&server.fd),
                    Token(server.fd as usize),
                    Interest::READABLE,
                ) {
                    Ok(_) => {}
                    Err(_) => {
                        // 记录到系统日志而不是标准输出
                        let fd_value = server.fd;
                        syslog!(LOG_WARNING, "Failed to register server fd={}", fd_value);
                    }
                }
            }
            serverfdp = server.next.as_deref_mut();
        }

        // 在阻塞等待事件前再次检查 SIGTERM
        if SIGTERM_FLAG.load(Ordering::Relaxed) {
            break;
        }

        // 等待事件并处理，使用较短的超时时间以便能及时响应信号
        match poll.poll(&mut events, Some(Duration::from_millis(100))) {
            Ok(_) => {
                for event in events.iter() {
                    // 在处理每个事件前检查SIGTERM
                    if SIGTERM_FLAG.load(Ordering::Relaxed) {
                        break;
                    }

                    let mut serverfdp = sfds.as_deref_mut();
                    while let Some(server) = serverfdp {
                        // 检查文件描述符是否有事件（相当于 `FD_ISSET`）
                        if event.token() == Token(server.fd as usize) {
                            // 调用 `reply_query` 处理事件
                            last_server = reply_query(
                                server.fd,
                                options,
                                &mut packet,
                                now,
                                &mut dnamebuff,
                                last_server,
                                &mut bogus_addr,
                                &mut caches,
                            );
                        }

                        // 移动到下一个节点
                        serverfdp = server.next.as_deref_mut();
                    }
                }
            }
            Err(_) => {
                // poll 出错，继续下一轮循环
                events = Events::with_capacity(128);
            }
        }

        // 检查 SIGTERM 信号
        if SIGTERM_FLAG.load(Ordering::Relaxed) {
            break;
        }

        let mut dhcp_tmp = dhcp.as_deref_mut();
        while let Some(dtp) = dhcp_tmp {
            if SIGTERM_FLAG.load(Ordering::Relaxed) {
                break;
            }
            // 检查文件描述符是否有效
            if dtp.fd >= 0 {
                match poll.registry().register(
                    &mut SourceFd(&dtp.fd),
                    Token(dtp.fd as usize),
                    Interest::READABLE,
                ) {
                    Ok(_) => {}
                    Err(_) => {
                        // 记录到系统日志而不是标准输出
                        let fd_value = dtp.fd;
                        syslog!(LOG_WARNING, "Failed to register DHCP fd={}", fd_value);
                    }
                }
            }
            dhcp_tmp = dtp.next.as_deref_mut();
        }

        // 如果收到 SIGTERM，跳出循环
        if SIGTERM_FLAG.load(Ordering::Relaxed) {
            break;
        }

        match poll.poll(&mut events, Some(Duration::from_millis(100))) {
            Ok(_) => {
                for event in events.iter() {
                    if SIGTERM_FLAG.load(Ordering::Relaxed) {
                        break;
                    }
                    let mut dhcp_tmp = dhcp.as_deref_mut();
                    while let Some(dtp) = dhcp_tmp {
                        if event.token() == Token(dtp.fd as usize) {
                            dhcp_packet(
                                &mut caches,
                                Some(dtp),
                                &mut packet,
                                &mut dhcp_opts,
                                &mut dhcp_conf,
                                now,
                                &mut dnamebuff,
                                &mut domain_suffix,
                                &mut dhcp_file,
                                &mut dhcp_sname,
                                dhcp_next_server,
                            );
                        }
                        dhcp_tmp = dtp.next.as_deref_mut();
                    }
                }
            }
            Err(_) => {
                events = Events::with_capacity(128);
            }
        }

        // 最后检查 SIGTERM
        if SIGTERM_FLAG.load(Ordering::Relaxed) {
            break;
        }

        let mut iface_opt = interfaces.as_mut();
        // 遍历接口链表，处理接收到的数据包
        while let Some(iface) = iface_opt {
            // 检查 SIGTERM 信号
            if SIGTERM_FLAG.load(Ordering::Relaxed) {
                break;
            }

            // 只处理有效的文件描述符
            if !iface.valid || iface.fd < 0 {
                // 处理下一个接口
                iface_opt = iface.next.as_mut();
                continue;
            }

            // 直接使用 SourceFd 而不是 from_raw_fd，避免所有权问题
            let mut source_fd = SourceFd(&iface.fd);

            // 注册到 poll
            if poll
                .registry()
                .register(&mut source_fd, Token(iface.fd as usize), Interest::READABLE)
                .is_ok()
            {
                // 短暂等待事件
                if poll
                    .poll(&mut events, Some(Duration::from_millis(10)))
                    .is_ok()
                {
                    for event in events.iter() {
                        if event.token() == Token(iface.fd as usize) && event.is_readable() {
                            // 这里需要使用系统调用直接读取，而不是 MioUdpSocket
                            // 暂时跳过这个复杂的部分，避免文件描述符所有权问题
                            break;
                        }
                    }
                }
                // 注销文件描述符
                let _ = poll.registry().deregister(&mut source_fd);
            }

            // 处理下一个接口
            iface_opt = iface.next.as_mut();
        }
    }
    syslog!(LOG_INFO, "exiting on receipt of SIGTERM");
    exit(0);
}

fn daemonize() -> Result<(), nix::Error> {
    // 第一次 fork
    match unsafe { fork()? } {
        ForkResult::Parent { child } => {
            // 父进程退出
            process::exit(0);
        }
        ForkResult::Child => {
            // 子进程继续执行

            // 创建新的会话
            setsid()?;

            // 关闭标准输入、输出和错误
            let _ = nix::unistd::dup2(nix::libc::STDERR_FILENO, nix::libc::STDOUT_FILENO);
            let _ = nix::unistd::dup2(nix::libc::STDERR_FILENO, nix::libc::STDIN_FILENO);

            // 第二次 fork
            match unsafe { fork()? } {
                ForkResult::Parent { .. } => {
                    // 第一次子进程退出
                    process::exit(0);
                }
                ForkResult::Child => {
                    // 第二次子进程继续执行
                    Ok(())
                }
            }
        }
    }
}

fn file_exists<P: AsRef<Path>>(path: P) -> bool {
    /*
        判断文件是否存在
        参数：文件路径
        返回值：文件是否存在
        注：如果文件不存在，返回 false
        注：如果文件存在，返回 true
    */
    let dir = path.as_ref().parent().unwrap_or(Path::new("."));
    let file_name = path.as_ref().file_name().unwrap_or_default();

    fs::read_dir(dir)
        .expect("REASON")
        .flatten()
        .any(|entry| entry.file_name() == file_name)
}
