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
static SIGHUP_FLAG: AtomicBool = AtomicBool::new(true);
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
const RUNFILE: &str = "/var/run/utdnsmasq.pid";
const CHUSER: &str = "nobody"; // 默认用户名
const CHGRP: &str = "dip"; // 默认组名
const IFPACKET: &str = "/usr/include/netpacket/packet.h";
const IFBPF: &str = "/usr/include/linux/bpf.h";
const OPT_DEBUG: u32 = 64;
const LEASEFILE: &str = "/var/lib/misc/dnsmasq.leases";
const VERSION: &str = "0.0.3";
const OPT_NO_POLL: u32 = 32;
const OPT_LOG: u32 = 4;
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

    // 阻塞信号集中的所有信号，相当于 sigprocmask(SIG_BLOCK, &sigact.sa_mask, &sigmask)
    signal::sigprocmask(SigmaskHow::SIG_BLOCK, Some(&sigset), None).expect("无法阻塞信号");

    // 解析命令行参数
    parse_args();

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
        complain("********* FAILED to start up", "");
        // return 1;
        die("", "");
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
                    iname.addr.in_.sin_addr.s_addr.to_string();
                } else {
                    // ipv6转换
                    // iname.addr.in6.sin6_addr.s6_addr.to_string();
                }
            }
            die("********* no interface with address", "");
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
            die("********* no DHCP support available on this OS.", "");
        }
    }

    if (options & OPT_DEBUG) == 0 {
        let username_str: &str = username.as_str(); // 获取用户名字符串  将string类型转换为&str类型
        let groupname_str: &str = groupname.as_str();

        let runfile = match runfile {
            Some(t) => t,
            None => String::from("/var/run/utdnsmasq.pid"),
        };

        let daemonize = Daemonize::new()
            .pid_file(runfile)
            .working_directory("/")
            .umask(0o022)
            .user(username_str)
            .group(groupname_str)
            .chown_pid_file(false)
            .privileged_action(|| {
                nix::unistd::setgroups(&[]).unwrap(); // 清除附加组
            });

        match daemonize.start() {
            Ok(_) => println!("success, daemonize"),
            Err(e) => println!("Error, {}", e),
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

    if getuid().is_root() || geteuid().is_root() {
        syslog!(LOG_WARNING, "failed to drop root privs for user",);
    }
    let mut servers = check_servers(serv_addrs, &interfaces, &mut sfds);
    let mut last_server = servers.clone();
    while !SIGTERM_FLAG.load(Ordering::Relaxed) {
        // 创建 Poll 实例
        let mut poll = Poll::new().expect("无法创建 Poll 实例");

        // 创建一个容量为 128 的 Events 集合，类似于 fd_set
        let mut events = Events::with_capacity(128);
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

                // 注册文件描述符到 poll，相当于 FD_SET
                poll.registry()
                    .register(
                        &mut SourceFd(&raw_fd),
                        Token(raw_fd as usize),
                        Interest::READABLE,
                    )
                    .expect("无法注册 fd");

                // 更新最大文件描述符
                if raw_fd > maxfd {
                    maxfd = raw_fd;
                }

                // 移动到下一个节点
                serverfdp = server.next.as_deref();
            }

            let mut iface = interfaces.as_deref_mut();
            while let Some(interface) = iface {
                let raw_fd = interface.fd;

                // 如果文件描述符有效，将其注册到 poll
                if interface.valid {
                    poll.registry()
                        .register(
                            &mut SourceFd(&raw_fd),
                            Token(raw_fd as usize),
                            Interest::READABLE,
                        )
                        .expect("无法注册文件描述符");

                    // 更新最大文件描述符
                    if raw_fd > maxfd {
                        maxfd = raw_fd;
                    }
                }

                // 移动到下一个节点
                iface = interface.next.as_deref_mut();
            }

            // 遍历链表，将每个文件描述符注册到 Poll 中
            let mut dhcp_tmp = dhcp.as_deref_mut();
            while let Some(dhcp_entry) = dhcp_tmp {
                let raw_fd = dhcp_entry.fd;

                // 将文件描述符注册到 Poll 中，相当于 FD_SET
                poll.registry()
                    .register(
                        &mut SourceFd(&raw_fd),
                        Token(raw_fd as usize),
                        Interest::READABLE,
                    )
                    .expect("无法注册文件描述符");

                // 更新最大文件描述符
                if raw_fd > maxfd {
                    maxfd = raw_fd;
                }

                // 移动到下一个节点
                dhcp_tmp = dhcp_entry.next.as_deref_mut();
            }

            // 条件编译：如果支持 `pselect`
            #[cfg(feature = "pselect")]
            {
                // 使用 `pselect` 等效实现
                // 设置信号掩码以阻塞信号
                signal::sigprocmask(SigmaskHow::SIG_SETMASK, Some(&sigset), None)
                    .expect("无法设置信号掩码");

                // 调用 `poll.poll` 来等待事件，相当于 `pselect`
                if poll
                    .poll(&mut events, Some(Duration::from_secs(5)))
                    .is_err()
                {
                    events = Events::with_capacity(128); // 如果出错，清空 events
                }

                // 恢复原始信号掩码
                signal::sigprocmask(SigmaskHow::SIG_SETMASK, None, Some(&mut sigset))
                    .expect("无法恢复信号掩码");
            }

            // 如果不支持 `pselect`，则使用 `select` 的等效实现
            #[cfg(not(feature = "pselect"))]
            {
                // 保存当前的信号掩码
                let mut save_mask = SigSet::empty();
                signal::sigprocmask(SigmaskHow::SIG_SETMASK, Some(&sigset), Some(&mut save_mask))
                    .expect("无法设置信号掩码");

                // 使用 `poll.poll` 等效 `select` 实现
                if poll
                    .poll(&mut events, Some(Duration::from_secs(5)))
                    .is_err()
                {
                    events = Events::with_capacity(128); // 如果出错，清空 events
                }

                // 恢复保存的信号掩码
                signal::sigprocmask(SigmaskHow::SIG_SETMASK, Some(&save_mask), None)
                    .expect("无法恢复信号掩码");
            }
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
            poll.registry()
                .register(
                    &mut SourceFd(&server.fd),
                    Token(server.fd as usize),
                    Interest::READABLE,
                )
                .expect("无法注册文件描述符");
            serverfdp = server.next.as_deref_mut();
        }

        // 等待事件并处理
        poll.poll(&mut events, None).expect("poll 失败");
        for event in events.iter() {
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

        let mut dhcp_tmp = dhcp.as_deref_mut();
        while let Some(dtp) = dhcp_tmp {
            poll.registry()
                .register(
                    &mut SourceFd(&dtp.fd),
                    Token(dtp.fd as usize),
                    Interest::READABLE,
                )
                .expect("无法注册文件描述符");
            dhcp_tmp = dtp.next.as_deref_mut();
        }

        poll.poll(&mut events, None).expect("poll 失败");
        for event in events.iter() {
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

        let mut iface_opt = interfaces.as_mut();
        // 遍历接口链表，处理接收到的数据包
        unsafe {
            while let Some(iface) = iface_opt {
                let mut udpaddr = MySockAddr {
                    sa: SockAddr {
                        sa_family: iface.addr.sa.sa_family,
                        sa_data: [0; 14],
                    },
                };
                // 将 UDP 套接字转换为 mio 兼容的类型并注册到 Poll 中
                let mut udp_socket = MioUdpSocket::from_raw_fd(iface.fd);
                // 使用标准的 Registry 注册 UDP 套接字
                let _ = poll
                    .registry()
                    .register(&mut udp_socket, Token(0), Interest::READABLE);
                // 轮询事件，等待数据包的到来
                let _ = poll.poll(&mut events, None);
                // 遍历所有事件
                for event in events.iter() {
                    if event.token() == Token(0) {
                        // 接收到数据包，读取数据
                        let mut packet = [0u8; 512];
                        let (n, src_addr) = match udp_socket.recv_from(&mut packet) {
                            Ok((n, addr)) => (n, addr),
                            Err(_) => {
                                continue;
                            }
                        };
                        // 初始化 udpaddr 结构体，用于存储源地址
                        // 根据接收到的地址类型（IPv4 或 IPv6），设置 udpaddr
                        match src_addr {
                            SocketAddr::V4(addr) => {
                                udpaddr = MySockAddr {
                                    in_: SockAddrIn {
                                        sin_family: AF_INET as SaFamilyT,
                                        sin_port: addr.port(),
                                        sin_addr: InAddr {
                                            s_addr: u32::from(*addr.ip()),
                                        },
                                        sin_zero: [0; 8],
                                    },
                                };
                                // 记录查询日志，IPv4
                                log_query(
                                    &mut caches,
                                    F_QUERY | F_IPV4 | F_FORWARD,
                                    &dnamebuff,
                                    Some(&udpaddr.in_.sin_addr.s_addr.octets()),
                                );
                            }
                            SocketAddr::V6(addr) => {
                                udpaddr = MySockAddr {
                                    in6: SockAddrIn6 {
                                        sin6_family: AF_INET6 as SaFamilyT,
                                        sin6_port: addr.port(),
                                        sin6_flowinfo: 0,
                                        sin6_addr: In6Addr {
                                            s6_addr: addr.ip().octets(),
                                        },
                                        sin6_scope_id: addr.scope_id(),
                                    },
                                };
                                // 记录查询日志，IPv6
                                log_query(
                                    &mut caches,
                                    F_QUERY | F_IPV6 | F_FORWARD,
                                    &dnamebuff,
                                    Some(&udpaddr.in_.sin_addr.s_addr.octets()),
                                );
                            }
                        }

                        // 尝试解析数据包的头部
                        let mut header = Header::from_bytes(&packet[..n]);
                        if let Some(ref mut header) = header {
                            if !header.qr == 0 {
                                // 如果是查询请求，提取请求并处理
                                if extract_request(&Some(*header), n as u32, &mut dnamebuff) {
                                    let m = answer_request(
                                        &mut Some(*header),
                                        &mut packet[..],
                                        n as u32,
                                        &mut mxname,
                                        &mut mxtarget,
                                        options,
                                        now,
                                        local_ttl,
                                        &mut dnamebuff,
                                        &mut caches,
                                    );

                                    if m >= 1 {
                                        // 从缓存回答，发送回复
                                        let _ = udp_socket.send_to(&packet[..m as usize], src_addr);
                                    } else {
                                        // 无法从缓存中回答，将请求转发给真实的 DNS 服务器
                                        last_server = forward_query(
                                            iface.fd,
                                            &udpaddr,
                                            &mut Some(*header),
                                            n,
                                            options,
                                            &mut dnamebuff,
                                            &mut servers,
                                            last_server,
                                            now,
                                            local_ttl,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }

                // 处理下一个接口
                iface_opt = iface.next.as_mut();
            }
        }
    }
    syslog!(LOG_INFO, "exiting on receipt of SIGTERM",);
    exit(0);
}

fn daemonize() -> Result<(), nix::Error> {
    // 第一次 fork
    match unsafe { fork()? } {
        ForkResult::Parent { child } => {
            // 父进程退出
            println!("Parent process exiting, child PID: {}", child);
            process::exit(0);
        }
        ForkResult::Child => {
            // 子进程继续执行
            println!("First child process created, PID: {}", process::id());

            // 创建新的会话
            setsid()?;

            // 关闭标准输入、输出和错误
            let _ = nix::unistd::dup2(nix::libc::STDERR_FILENO, nix::libc::STDOUT_FILENO);
            let _ = nix::unistd::dup2(nix::libc::STDERR_FILENO, nix::libc::STDIN_FILENO);

            // 第二次 fork
            match unsafe { fork()? } {
                ForkResult::Parent { .. } => {
                    // 第一次子进程退出
                    println!(
                        "First child process exiting, second child PID: {}",
                        process::id()
                    );
                    process::exit(0);
                }
                ForkResult::Child => {
                    // 第二次子进程继续执行
                    println!("Second child process created, PID: {}", process::id());
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
