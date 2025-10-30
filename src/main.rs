/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

pub mod cache;
pub mod dhcp;
pub mod forward;
pub mod lease;
pub mod logs;
pub mod network;
pub mod option;
pub mod rfc1035;
pub mod util;
use cache::*;
use daemonize::Daemonize;
use dhcp::*;
use forward::*;
use lease::*;
use logs::*;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use network::*;
use nix::sys::signal::{self, SaFlags, SigAction, SigHandler, SigSet, SigmaskHow, Signal};
use nix::sys::stat::{umask, Mode};
use nix::unistd::{chdir, close, geteuid, getuid, setgid, setuid, Gid, Uid};
use option::*;
use rfc1035::*;
use std::fs::File;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{env, fs, process};
use users::{get_group_by_name, get_user_by_name};

// 全局标志变量，使用 AtomicBool 来保证线程安全
static SIGHUP_FLAG: AtomicBool = AtomicBool::new(true);
static SIGUSR1_FLAG: AtomicBool = AtomicBool::new(false);
static SIGUSR2_FLAG: AtomicBool = AtomicBool::new(false);
static SIGTERM_FLAG: AtomicBool = AtomicBool::new(false);

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
const VERSION: &str = "2.0";
const OPT_NO_POLL: u32 = 32;
const OPT_LOG: u32 = 4;

// 存储接口名称和地址
#[derive(Clone)]
pub struct Irec {
    pub addr: MySockAddr,
    pub fd: i32,
    pub valid: bool,
    pub next: Option<Box<Irec>>,
}

fn start(argc: usize, args: Vec<String>) -> usize {
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
    let mut now: SystemTime = SystemTime::now();
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
    let mut dhcp_sname: Option<&mut String> = None;
    let mut dhcp_file: Option<&mut String> = Default::default();
    let serv_addrs: Option<Box<Server>> = None;
    let mut dnamebuff = vec![0u8; MAXDNAME];
    let mut packet = vec![0u8; PACKETSZ + MAXDNAME + RRFIXEDSZ];
    let dhcp_next_server = Ipv4Addr::new(0, 0, 0, 0);
    let leasefd: i32 = 0;
    let serverfdp: Option<Box<ServerFd>> = None;
    let mut sfds: Option<Box<ServerFd>> = None;

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

    let options = read_opts(
        argc,
        args,
        &mut dnamebuff,
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
        &serv_addrs,
        &mut cachesize,
        Some(&mut port),
        Some(&mut query_port),
        Some(&mut local_ttl),
        &mut addn_hosts,
        &dhcp,
        &mut dhcp_conf,
        &mut dhcp_opts,
        &mut dhcp_file,
        &mut dhcp_sname,
        dhcp_next_server,
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
        if_names.clone(),
        if_addrs.clone(),
        if_except.clone(),
        &mut dhcp,
        port,
    );
    if int_err_string.is_err() {
        complain("********* FAILED to start up", "");
        return 1;
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
    if dhcp.is_none() {
        let packet_path = IFPACKET;
        let bpf_path = IFBPF;
        if file_exists(packet_path) && file_exists(bpf_path) {
            let mut current = &dhcp;
            while let Some(ctx) = current {
                if ctx.iface.is_empty() {
                    // 如果 iface 为空字符串，执行后续代码块
                    // die("********* No suitable interface for DHCP service at address", inet_ntoa(dhcp_tmp->start));
                    let mut leasefd = lease_init(
                        lease_file.as_ref().map(|s| s.as_str()),
                        domain_suffix.clone(),
                        dnamebuff,
                        packet,
                        SystemTime::now(),
                        &mut dhcp_conf,
                    );
                    let _ = lease_update_dns(&mut caches, 1);
                    return 1;
                }

                // 移动到下一个节点
                current = &ctx.next;
            }
        } else {
            die("********* no DHCP support available on this OS.", "");
        }
    }

    if (options & OPT_DEBUG) == 0 {
        let pidfile: Option<File> = match File::create("pidfile.txt") {
            Ok(file) => Some(file),
            Err(_) => None,
        };
        // 进程守护化
        daemonize();
        // 将进程的当前工作目录切换到根目录是守护进程通常的操作，避免锁定文件系统
        let _ = chdir("/");
        // 确保创建的文件权限符合系统和应用的安全要求
        umask(Mode::from_bits_truncate(0o022));
        if let Some(runfile) = runfile {
            // 打开文件用于写入 pid
            if let Ok(mut pidfile) = File::create(runfile) {
                // 获取当前进程 ID 并写入文件
                let pid = process::id();
                if writeln!(pidfile, "{}", pid).is_err() {
                    eprintln!("Failed to write pid to file");
                }
            } else {
                eprintln!("Failed to open runfile for writing");
            }
        }

        // 设置文件权限掩码为 0
        umask(Mode::from_bits_truncate(0));

        // 根据特定条件关闭未被占用的文件描述符
        // 通过安全的数据结构管理和迭代器遍历来实现对文件描述符的查找和关闭，确保只关闭那些未被占用的文件描述符，同时避免了可能的内存不安全问题。
        for i in 0..64 {
            let mut iface_tmp = &interfaces;
            while let Some(ref iface) = iface_tmp {
                if iface.fd == i {
                    break;
                }
                iface_tmp = &iface.next;
            }

            if iface_tmp.is_none() {
                let mut dhcp_tmp = &mut dhcp;
                let mut found_in_dhcp = false; // 标记是否找到匹配的 DHCP 条目

                while let Some(ref mut dhcp_entry) = dhcp_tmp {
                    if dhcp_entry.fd == i && dhcp_entry.rawfd == i {
                        found_in_dhcp = true;
                        break;
                    }
                    dhcp_tmp = &mut dhcp_entry.next;
                }

                if !found_in_dhcp {
                    if !(dhcp.is_none() && i == leasefd) {
                        let _ = close(i);
                    }
                }
            }
        }
        let username_str: &str = username.as_str(); // 获取用户名字符串  将string类型转换为&str类型
        let groupname_str: &str = groupname.as_str();
        if Some(username_str).is_some() {
            // 获取用户信息
            if let Some(user) = get_user_by_name(username_str) {
                // 设置组ID
                if Some(groupname_str).is_some() {
                    if let Some(group) = get_group_by_name(groupname_str) {
                        let gid = Gid::from_raw(group.gid());
                        // 设置组ID
                        if let Err(_e) = setgid(gid) {
                            die("Failed to set group ID: {}", &gid.to_string());
                        }
                    } else {
                        die("Group not found: {}", groupname_str);
                    }
                } else {
                    // 如果没有提供组名，则使用用户的主组
                    let primary_gid = Gid::from_raw(user.primary_group_id());
                    if let Err(_e) = setgid(primary_gid) {
                        die("Failed to set group ID: {}", &primary_gid.to_string());
                    }
                }

                // 最后，设置用户ID
                if let Err(_e) = setuid(Uid::from_raw(user.uid())) {
                    die("Failed to set user ID: {}", &user.uid().to_string());
                }
            } else {
                die("User not found: {}", username_str);
            }
        } else {
            die("Username cannot be None", "");
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
        let dnamebuff = config.start.to_string();

        // 租约时间格式化
        let packet = if config.lease_time == 0 {
            String::from("infinite")
        } else {
            format!("{}s", config.lease_time)
        };

        // 移动到下一个配置
        dhcp_tmp = &config.next;
    }

    if getuid().is_root() || geteuid().is_root() {
        complain("failed to drop root privs for user", "");
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
                domain_suffix.clone(),
                addn_hosts.as_ref().map(|x| x.to_string()),
            );
            let _ = lease_update_dns(&mut caches, 1);
        }
        if resolv.is_some() && (options & OPT_NO_POLL) != 0 {
            servers = check_servers(
                reload_servers(resolv.clone(), servers.clone(), query_port),
                &interfaces,
                &mut sfds,
            );
            let mut laster_server = servers.clone();
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
                    if_names.clone(),
                    if_addrs.clone(),
                    if_except.clone(),
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

        now = SystemTime::now();
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
                                reload_servers(Some(latest), servers, query_port),
                                &interfaces,
                                &mut sfds,
                            );
                            let last_server = servers.clone();
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
                        bogus_addr.clone(),
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
                        dhcp_opts.clone(),
                        dhcp_conf.clone(),
                        now,
                        &mut dnamebuff,
                        domain_suffix.clone(),
                        &mut dhcp_file,
                        &mut dhcp_sname,
                        dhcp_next_server,
                    );
                }
                dhcp_tmp = dtp.next.as_deref_mut();
            }
        }
    }

    0
}

fn daemonize() {
    // 创建守护进程
    let daemonize = Daemonize::new()
        .pid_file(RUNFILE.to_string()) // 设置 PID 文件的路径
        .chown_pid_file(true) // 设置是否将 PID 文件的所有权更改为当前用户
        .umask(0o027) // 设置 umask
        .working_directory("/") // 设置工作目录
        .stdout(File::open("/dev/null").unwrap()) // 将标准输出重定向到 /dev/null
        .stderr(File::open("/dev/null").unwrap()); // 将标准错误重定向到 /dev/null

    match daemonize.start() {
        Ok(_) => {}
        Err(_e) => {
            die("Error starting daemon: {}", "");
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

fn main() {
    // 创建一个 Vec<String> 类型的向量 args
    let mut args: Vec<String> = Vec::new();

    // 初始化日志
    log_init();

    // 遍历 std::env::args() 获取所有命令行参数
    for arg in env::args() {
        // 获取原始指针，并存储到 args 向量中
        args.push(arg);
    }

    // 参数数量（减一：去掉程序名）
    let argc = args.len() - 1;

    //日志功能示例
    syslog!(LOG_INFO, "argc: {}", argc);

    // 调用 start 函数，传入参数数量和参数指针数组
    let exit_code = start(argc, args);

    exit(exit_code.try_into().unwrap());
}
