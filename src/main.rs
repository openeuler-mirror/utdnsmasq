/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use daemonize::Daemonize;
use lazy_static::lazy_static;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use nix::sys::signal::{self, SigSet, SigmaskHow};
use nix::unistd::{geteuid, getuid, setgid, setuid, Gid, Uid};
use nix::NixPath;
use signal_hook::consts::signal::{SIGHUP, SIGTERM, SIGUSR1, SIGUSR2};
use signal_hook::flag;
use std::fs;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use users::{get_group_by_name, get_user_by_name};
use utdnsmasq::cache::{cache_reload, dump_cache, log_query, Cache};
use utdnsmasq::cli::parse_args;
use utdnsmasq::config::{Config, LEASEFILE, VERSION};
use utdnsmasq::dhcp::{dhcp_packet, DhcpPacketArgs};
use utdnsmasq::dnsmasq::{
    Header, MySockAddr, ResolvC, ServerFd, CHGRP, CHUSER, F_FORWARD, F_IPV4, F_IPV6, F_QUERY,
    MAXDNAME, OPT_DEBUG, OPT_LOCALMX, OPT_LOG, OPT_NO_POLL, PACKETSZ, RRFIXEDSZ,
};
use utdnsmasq::forward::{forward_init, forward_query, reply_query, ForwardQueryArgs};
use utdnsmasq::lease::{lease_init, lease_update_dns};
use utdnsmasq::logs::{
    complain, die, log_init, LOG_CRIT, LOG_DEBUG, LOG_ERR, LOG_INFO, LOG_WARNING,
};
use utdnsmasq::network::{check_servers, enumerate_interfaces, reload_servers};
use utdnsmasq::rfc1035::{answer_request, extract_request};
use utdnsmasq::syslog;

lazy_static! {
    // 全局标志变量，使用 AtomicBool 来保证线程安全
    static ref SIGHUP_FLAG: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    static ref SIGUSR1_FLAG: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    static ref SIGUSR2_FLAG: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    static ref SIGTERM_FLAG: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
}

fn main() {
    let mut first_loop: bool = true;
    // 时间戳相关变量
    let mut resolv_changed: SystemTime = UNIX_EPOCH;
    let mut now: SystemTime;
    let mut last: SystemTime = UNIX_EPOCH;
    let mut sfds: Vec<ServerFd> = Vec::new();

    SIGHUP_FLAG.store(true, Ordering::SeqCst);

    // 初始化日志
    log_init();

    // 注册信号处理：收到信号时设置对应的 AtomicBool 标志
    flag::register(SIGUSR1, Arc::clone(&SIGUSR1_FLAG)).expect("无法注册 SIGUSR1");
    flag::register(SIGUSR2, Arc::clone(&SIGUSR2_FLAG)).expect("无法注册 SIGUSR2");
    flag::register(SIGHUP, Arc::clone(&SIGHUP_FLAG)).expect("无法注册 SIGHUP");
    flag::register(SIGTERM, Arc::clone(&SIGTERM_FLAG)).expect("无法注册 SIGTERM");

    // 解析命令行参数，加载配置
    let args: utdnsmasq::cli::Args = parse_args();
    let mut config = match Config::load(&args) {
        Ok(cfg) => cfg,
        Err(e) => {
            syslog!(LOG_ERR, "{}", e);
            exit(1);
        }
    };

    if config.lease_file.is_empty() {
        config.lease_file = PathBuf::from(LEASEFILE);
    } else if config.dhcp.is_empty() {
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

    // 初始化网络接口和配置
    if let Err(e) = enumerate_interfaces(&mut config) {
        println!("Failed to enumerate network interfaces");
        die(&e.to_string(), "");
    }

    // 检查未知接口配置
    for if_tmp in &config.if_names {
        if !if_tmp.name.is_empty() && !if_tmp.found {
            die("unknown interface ", &if_tmp.name);
        }
    }

    // 检查未找到地址的接口配置
    for if_tmp in &config.if_addrs {
        if !if_tmp.found {
            let address = if_tmp.addr.ip();
            die("no interface with address", &address.to_string());
        }
    }

    // 初始化转发设置
    forward_init(true);

    // 初始化缓存
    let cache_size = config.get_cache_size();
    let mut caches: Cache = Cache::cache_init(cache_size, config.options & OPT_LOG);

    // 如果配置dncp服务，初始化DHCP相关设置
    if !config.dhcp.is_empty() {
        for dhcp_tmp in config.dhcp.iter_mut() {
            if dhcp_tmp.iface.is_empty() {
                die(
                    "No suitable interface for DHCP service at address ",
                    &dhcp_tmp.start.to_string(),
                ); // 地址处没有适合DHCP服务的接口
            }
        }

        let _leasefd = lease_init(&mut config, SystemTime::now());
        lease_update_dns(&config.lease_file, &mut caches, true);
    }

    // 非调试模式
    if (config.options & OPT_DEBUG) == 0 {
        let username: &str = &config.username; // 获取用户名字符串  将string类型转换为&str类型
        let groupname: &str = &config.groupname;

        let runfile = &config.runfile;

        // 创建后台服务
        let daemonize = Daemonize::new()
            .working_directory("/") // 改变工作目录
            .umask(0o022) // 设置文件权限
            .pid_file(runfile) // 进程号写入pidfile
            .user(username) // 改变用户和组id
            .group(groupname)
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
        let username: &str = &config.username; // 获取用户名字符串  将string类型转换为&str类型
        let groupname: &str = &config.groupname;
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

    let cachesize = config.cache_size;
    if cachesize != 0 {
        syslog!(
            LOG_INFO,
            "started, version {}, cachesize {}",
            VERSION,
            cachesize
        );
    } else {
        syslog!(LOG_INFO, "started, version {} cache disabled", VERSION);
    }

    // Use references to avoid moving values
    let mxtarget = &config.mxtarget;
    let mxname = &config.mxname;
    if (config.options & OPT_LOCALMX) != 0 {
        syslog!(
            LOG_INFO,
            "serving MX record for local hosts target {:?}",
            mxtarget
        );
    } else if !mxname.is_empty() {
        syslog!(
            LOG_INFO,
            "serving MX record for mailhost {:?} target {:?}",
            mxname,
            mxtarget
        )
    }

    for dhcp_tmp in &config.dhcp {
        let dnamebuff = dhcp_tmp.start.to_string();
        let end = dhcp_tmp.end.to_string();
        let iface = &dhcp_tmp.iface;
        // 租约时间格式化
        let packet = if dhcp_tmp.lease_time == 0 {
            String::from("infinite")
        } else {
            format!("{}s", dhcp_tmp.lease_time)
        };

        syslog!(
            LOG_INFO,
            "DHCP on {}, IP range {} -- {}, lease time {}",
            iface,
            dnamebuff,
            end,
            packet
        );
    }

    // 权限降级检查
    if getuid().is_root() || geteuid().is_root() {
        syslog!(LOG_WARNING, "failed to drop root privs");
    }

    // 检查服务器地址并初始化服务器连接
    let mut temp_serv_addrs = config.serv_addrs.clone();
    let mut servers = check_servers(&mut temp_serv_addrs, &config, &mut sfds);
    let mut last_server = servers.clone();

    /* rust实现文件io复用  poll 特征，不需要 在while中反复重新注册监听端口，只需要在接口改变的时候重新扫描即可
    在没有接收到 SIGHUP_FLAG SIGUSR2_FLAG信号时， 监听的端口是不会发生变化的 */
    // 创建 Poll 实例
    let mut poll = Poll::new().expect("无法创建 Poll 实例");
    // 创建一个容量为 128 的 Events 集合，类似于 fd_set
    let mut events = Events::with_capacity(1024);
    let mut update_listen: bool = true;

    while !SIGTERM_FLAG.load(Ordering::Relaxed) {
        // 重新加载配置文件、更新dns租约信息
        if SIGHUP_FLAG.load(Ordering::Relaxed) {
            cache_reload(&mut config, &mut caches);
            lease_update_dns(&config.lease_file, &mut caches, true);
            let resolvs: &Vec<utdnsmasq::dnsmasq::ResolvC> = &config.resolv;
            if !resolvs.is_empty() && config.options & OPT_NO_POLL != 0 {
                for resolv in resolvs {
                    let mut re_serve =
                        reload_servers(resolv.name.clone(), &mut servers, config.query_port);
                    servers = check_servers(&mut re_serve, &config, &mut sfds);
                    last_server = servers.clone();
                }
            }
            SIGHUP_FLAG.store(false, Ordering::SeqCst);
            update_listen = true;
            // 清空之前注册
            poll = Poll::new().expect("无法创建 Poll 实例");
        }

        // 日志缓存
        if SIGUSR1_FLAG.load(Ordering::SeqCst) {
            dump_cache(config.options & (OPT_DEBUG | OPT_LOG), &mut caches);
            SIGUSR1_FLAG.store(false, Ordering::SeqCst);
        }

        // 重新扫描接口
        if SIGUSR2_FLAG.load(Ordering::SeqCst) {
            if getuid().as_raw() != 0 && config.port <= 1024 {
                syslog!(LOG_ERR, "cannot re-scan interfaces unless --user=root",);
            } else {
                syslog!(LOG_INFO, "rescanning network interfaces");
                if let Err(e) = enumerate_interfaces(&mut config) {
                    syslog!(LOG_ERR, "Error: {:?}", e);
                }
            }
            SIGUSR2_FLAG.store(false, Ordering::SeqCst);
            update_listen = true;
            // 清空之前注册
            poll = Poll::new().expect("无法创建 Poll 实例");
        }

        /*
           第一次循环   first_loop = true，update_listen = true 条件不成立，不执行
           第二次循环   first_loop = false，update_listen = true  条件成立， 执行
           第三次及以后 first_loop = false，update_listen = false 条件不成立， 不执行
           当接收到信号的时候  first_loop = false，update_listen = true  条件成立， 执行
        */
        // if !first_loop && update_listen {
        if !first_loop {
            if update_listen {
                // 事件不能重复注册
                update_listen = false;
                // 注册上游服务器sfds
                for sfd in &sfds {
                    // 获取socket的原始文件描述符并包装为SourceFd
                    let raw_fd = sfd.socket.as_raw_fd();
                    let mut source_fd = SourceFd(&raw_fd);

                    match poll.registry().register(
                        &mut source_fd,
                        Token(raw_fd as usize),
                        Interest::READABLE,
                    ) {
                        Ok(_) => {
                            if config.options & OPT_DEBUG != 0 {
                                syslog!(LOG_DEBUG, "sfds fd {} 注册成功", raw_fd);
                            }
                        }
                        Err(e) => {
                            // 记录到系统日志而不是标准输出
                            syslog!(
                                LOG_WARNING,
                                "Failed to register server fd={}, error: {}",
                                raw_fd,
                                e
                            );
                        }
                    }
                }

                // 注册interface接口
                for iface in &config.interfaces {
                    // 获取socket的原始文件描述符并包装为SourceFd
                    let raw_fd = iface.socket.as_raw_fd();
                    let mut source_fd = SourceFd(&raw_fd);
                    // 注册文件描述符到 poll，相当于 FD_SET
                    match poll.registry().register(
                        &mut source_fd,
                        Token(raw_fd as usize),
                        Interest::READABLE,
                    ) {
                        Ok(_) => {
                            if config.options & OPT_DEBUG != 0 {
                                syslog!(LOG_DEBUG, "iface fd {} 注册成功 ", raw_fd);
                            }
                        }
                        Err(e) => {
                            // 记录到系统日志而不是标准输出
                            let fd_value = raw_fd;
                            syslog!(
                                LOG_WARNING,
                                "Failed to register iface fd={}, error: {}",
                                fd_value,
                                e
                            );
                        }
                    }
                }

                // 注册dhcp
                for cur_dhcp in &config.dhcp {
                    let raw_fd = cur_dhcp.fd_socket.as_ref().unwrap().as_raw_fd();
                    let mut source_fd = SourceFd(&raw_fd);
                    // 将文件描述符注册到 Poll 中，相当于 FD_SET
                    match poll.registry().register(
                        &mut source_fd,
                        Token(raw_fd as usize),
                        Interest::READABLE,
                    ) {
                        Ok(_) => {
                            if config.options & OPT_DEBUG != 0 {
                                syslog!(LOG_DEBUG, "dhcp  fd {} 注册成功 ", raw_fd);
                            }
                        }
                        Err(_) => {
                            // 记录到系统日志而不是标准输出
                            syslog!(LOG_WARNING, "Failed to register DHCP fd={}", raw_fd);
                        }
                    }
                }
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

            // 每次循环都要重新执行下面语句，不然不能触发新事件
            if poll.poll(&mut events, None).is_err() {
                events.clear(); // 如果出错，清空 events
            }

            // 恢复信号阻塞
            signal::sigprocmask(SigmaskHow::SIG_SETMASK, Some(&old_mask), None)
                .expect("无法恢复信号掩码");
        }

        first_loop = false;
        now = SystemTime::now();

        if last == UNIX_EPOCH || now.duration_since(last).expect("time err").as_secs() > 1 {
            last = now;
            if config.options & OPT_NO_POLL == 0 {
                // 用于记录最近修改的文件信息
                let mut latest: Option<ResolvC> = None;
                let mut last_change = UNIX_EPOCH;

                for res in config.resolv.iter_mut() {
                    let path = Path::new(&res.name);
                    // 获取文件元数据
                    match fs::metadata(path) {
                        Ok(metadata) => {
                            // 获取文件的最后修改时间
                            let modified_time = metadata.modified().unwrap_or(UNIX_EPOCH);
                            // 更新 `logged` 状态
                            res.logged = false;
                            if modified_time > last_change {
                                last_change = modified_time;
                                latest = Some(res.clone());
                            }
                        }
                        Err(e) => {
                            let name = res.name.clone();
                            if !res.logged {
                                syslog!(LOG_WARNING, "failed to access {}: {}", name, e);
                            }
                            res.logged = true;
                        }
                    }
                }

                if let Some(latest) = latest {
                    if last_change > resolv_changed {
                        resolv_changed = last_change;
                        let mut re_serve =
                            reload_servers(latest.name, &mut servers, config.query_port);
                        servers = check_servers(&mut re_serve, &config, &mut sfds);
                        last_server = servers.clone();
                    }
                }
            }
        }

        // 有事件触发
        for event in events.iter() {
            // 上游服务器
            for serv in &sfds {
                let raw_fd = serv.socket.as_raw_fd();

                if event.token() == Token(raw_fd as usize) && event.is_readable() {
                    last_server = reply_query(
                        &mut caches,
                        &mut config,
                        serv.socket.try_clone().unwrap(),
                        now,
                        last_server,
                    )
                }
            }

            // dhcp
            // Use references instead of moving values to avoid ownership issues
            let c_lease_file = &config.lease_file;
            let dhcp_configs = &config.dhcp_configs;
            let domain_suffix = &config.domain_suffix;
            let dhcp_file = &config.dhcp_file;
            let dhcp_sname = &config.dhcp_sname;
            let dhcp_next_server = config.dhcp_next_server;
            let dhcp_options = &config.dhcp_options;
            for dhcp_tmp in &mut config.dhcp {
                let raw_fd = dhcp_tmp.fd_socket.as_ref().unwrap().as_raw_fd();

                if event.token() == Token(raw_fd as usize) && event.is_readable() {
                    dhcp_packet(
                        dhcp_tmp,
                        DhcpPacketArgs {
                            c_lease_file,
                            dhcp_configs,
                            domain_suffix,
                            dhcp_file,
                            dhcp_sname,
                            dhcp_next_server,
                            dhcp_options,
                            cache: &mut caches,
                            now,
                        },
                    );
                }
            }
            // 接口访问
            for iface in &config.interfaces {
                let raw_fd = iface.socket.as_raw_fd();

                if event.token() == Token(raw_fd as usize) && event.is_readable() {
                    let udpaddr: MySockAddr;
                    let recv_len: usize;
                    let mut recv_packet = [0u8; PACKETSZ + MAXDNAME + RRFIXEDSZ];

                    // 接收数据
                    (recv_len, udpaddr) = match iface.socket.try_clone() {
                        Ok(cloned_socket) => {
                            let udp_socket: UdpSocket = cloned_socket.into();
                            let (n, src_addr) = match udp_socket.recv_from(&mut recv_packet) {
                                Ok((n, addr)) => (n, addr),
                                Err(_) => {
                                    // 提示数据解析失败，并提供时间
                                    continue;
                                }
                            };
                            (n, src_addr)
                        }
                        Err(e) => {
                            syslog!(LOG_WARNING, "Failed to clone socket: {}", e);
                            continue;
                        }
                    };
                    let packet = &mut recv_packet[..recv_len];
                    // 解析出来头信息
                    match Header::parse(packet) {
                        Ok(header) => {
                            if !header.qr {
                                // 提取请求类型
                                let (_, dnamebuff) = extract_request(packet);
                                if !dnamebuff.is_empty() {
                                    if udpaddr.is_ipv4() {
                                        log_query(
                                            &mut caches,
                                            F_QUERY | F_IPV4 | F_FORWARD,
                                            &dnamebuff,
                                            Some(udpaddr.ip()),
                                        );
                                    } else {
                                        log_query(
                                            &mut caches,
                                            F_QUERY | F_IPV6 | F_FORWARD,
                                            &dnamebuff,
                                            Some(udpaddr.ip()),
                                        );
                                    }
                                }

                                // 在缓存中查找
                                let buffer = answer_request(
                                    packet,
                                    &config.mxname,
                                    &config.mxtarget,
                                    config.options,
                                    &mut caches,
                                    now,
                                    config.local_ttl,
                                );
                                if !buffer.is_empty() {
                                    if let Ok(udp_socket) = iface.socket.try_clone() {
                                        let udp_socket: std::net::UdpSocket = udp_socket.into();
                                        let _ = udp_socket.send_to(&buffer, udpaddr);
                                    }
                                } else if let Ok(cloned_socket) = iface.socket.try_clone() {
                                    last_server = forward_query(ForwardQueryArgs {
                                        cache: &mut caches,
                                        udpfd: cloned_socket,
                                        udpaddr,
                                        packet,
                                        options: config.options,
                                        servers: servers.clone(),
                                        last_server: &last_server,
                                        now,
                                        local_ttl: config.local_ttl,
                                    });
                                } else {
                                    syslog!(
                                        LOG_WARNING,
                                        "Failed to clone socket for forward_query"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            syslog!(LOG_WARNING, "接受dns访问头解析失败, {}", e);
                            continue;
                        }
                    };
                }
            }
        }
    }

    syslog!(LOG_INFO, "exiting on receipt of SIGTERM");
}
