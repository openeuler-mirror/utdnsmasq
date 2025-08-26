/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

extern crate libc;
pub mod cache;
pub mod dhcp;
pub mod forward_init;
pub mod lease;
pub mod log;
pub mod network;
pub mod option;
pub mod util;
use cache::*;
use forward_init::*;
use lease::*;
use libc::{getegid, getgrnam, getpwnam, getuid, gid_t, group, passwd, setgid, setgroups, setuid};
use log::*;
use network::*;
use nix::sys::stat::{umask, Mode};
use nix::unistd::{chdir, close, fork, setsid, ForkResult};
use option::*;
use signal_hook::consts::signal::*;
use signal_hook::iterator::Signals;
use std::ffi::CString;
use std::fs::File;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;
use std::{env, fs, process, thread};

// 全局标志变量，使用 AtomicBool 来保证线程安全
static SIGHUP_FLAG: AtomicBool = AtomicBool::new(true);
static SIGUSR1_FLAG: AtomicBool = AtomicBool::new(false);
static SIGUSR2_FLAG: AtomicBool = AtomicBool::new(false);
static SIGTERM_FLAG: AtomicBool = AtomicBool::new(false);

fn sig_handler(mut signals: Signals) {
    // 处理信号，将信号标志设置为 true
    for sig in signals.forever() {
        match sig {
            SIGTERM => SIGTERM_FLAG.store(true, Ordering::SeqCst),
            SIGHUP => SIGHUP_FLAG.store(true, Ordering::SeqCst),
            SIGUSR1 => SIGUSR1_FLAG.store(true, Ordering::SeqCst),
            SIGUSR2 => SIGUSR2_FLAG.store(true, Ordering::SeqCst),
            _ => {}
        }
    }
}

// 定义常量
const MAXDNAME: usize = 256; // 域名最大长度
const PACKETSZ: usize = 512; // 典型的 DNS 数据包大小
const RRFIXEDSZ: usize = 10; // 资源记录的固定大小
const CACHESIZ: usize = 1024; // 缓存大小默认值
const NAMESERVER_PORT: u16 = 53; // Default DNS server port
const RUNFILE: Option<&str> = Some("/var/run/utdnsmasq.pid");
const CHUSER: &str = "nobody"; // 默认用户名
const CHGRP: &str = "dip"; // 默认组名
const IFPACKET: &str = "/usr/include/netpacket/packet.h";
const IFBPF: &str = "/usr/include/linux/bpf.h";
const OPT_DEBUG: u32 = 64;
const LEASEFILE: Option<&str> = Some("/var/lib/misc/dnsmasq.leases");

#[derive(Debug)]
struct Passwd {
    pw_name: String,
    pw_passwd: String,
    pw_uid: u32,
    pw_gid: u32,
    pw_gecos: String,
    pw_dir: String,
    pw_shell: String,
}

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
    let file_logger = Logger::new(Some("/var/log/utdnsmasq.log".to_string()));
    let mut cachesize: usize = CACHESIZ; // 缓存大小，默认值为 CACHESIZ
    let mut port: u16 = NAMESERVER_PORT; // 名称服务器端口，默认为 NAMESERVER_PORT
    let mut query_port: i32 = 0; // 查询端口，初始值为0
    let first_loop: bool = true;
    let mut local_ttl: u64 = 0; // 本地缓存 TTL，初始值为 0
    let runfile: Option<&str> = RUNFILE; // 进程 PID 文件路径，默认为 RUNFILE

    let mut interfaces: Option<Box<Irec>> = None;
    // 时间戳相关变量
    let resolv_changed: u64 = 0;
    let now: u64 = 0;
    let last: u64 = 0;
    // 邮件交换相关变量
    let mut resolv = Resolv::default();
    let mut dhcp: Option<Box<DhcpContext>> = None;
    let mut dhcp_conf: Option<Box<DhcpConfig>> = None;
    let dhcp_opts: Option<Box<DhcpOpt>> = None;
    let mxname: Option<&mut String> = None;
    let mxtarget: Option<&mut String> = None;
    let mut lease_file: Option<&str> = None; // 租约文件路径
    let addn_hosts: Option<&mut String> = None; // 额外主机文件路径
    let domain_suffix: Option<String> = None; // 域名后缀
    let mut username: &str = CHUSER; // 用户名，默认值为 CHUSER
    let mut groupname: &str = CHGRP; // 组名，默认值为 CHGRP
    let if_names: Option<Box<Iname>> = None; // 用于存储接口名称
    let if_addrs: Option<Box<Iname>> = None; // 用于存储接口地址
    let if_except: Option<Box<Iname>> = None; // 用于存储例外情况
    let bogus_addr: Option<&mut BogusAddr> = None;
    let dhcp_sname: Option<&mut String> = None;
    let dhcp_file: Option<&mut String> = Default::default();
    let serv_addrs: Option<&mut Vec<Server>> = None;
    let mut dnamebuff = vec![0u8; MAXDNAME];
    let packet = vec![0u8; PACKETSZ + MAXDNAME + RRFIXEDSZ];
    let dhcp_next_server = Ipv4Addr::new(0, 0, 0, 0);
    let leasefd: i32 = 0;

    let signals = Signals::new(&[SIGUSR1, SIGUSR2, SIGHUP, SIGTERM]).unwrap();
    let signals_handle = thread::spawn(move || {
        sig_handler(signals);
    });

    let options = read_opts(
        argc,
        args,
        &mut dnamebuff,
        Some(&mut resolv),
        mxname,
        mxtarget,
        &mut lease_file,
        &mut username,
        &mut groupname,
        &domain_suffix,
        runfile,
        &if_names,
        &if_addrs,
        &if_except,
        bogus_addr,
        serv_addrs,
        Some(&mut cachesize),
        Some(&mut port),
        Some(&mut query_port),
        Some(&mut local_ttl),
        addn_hosts,
        &dhcp,
        &mut dhcp_conf,
        dhcp_opts,
        dhcp_file,
        dhcp_sname,
        dhcp_next_server,
    );
    if lease_file.is_none() {
        lease_file = LEASEFILE;
    } else if dhcp.is_none() {
        file_logger.error("********* dhcp-lease option set, but not dhcp-range.");
        file_logger.error("********* Are you trying to use the obsolete ISC dhcpd integration?");
        file_logger.error("********* Please configure the dnsmasq integrated DHCP server by using");
        file_logger.error("********* the \"dhcp-range\" option, and remove any other DHCP server.");
    }
    let int_err_string = enumerate_interfaces(
        &mut interfaces,
        if_names.clone(),
        if_addrs.clone(),
        if_except,
        &mut dhcp,
        port,
    );
    if int_err_string.is_err() {
        file_logger.error("********* FAILED to start up");
        return 1;
    }

    let mut if_tmp = &if_names;
    while let Some(ref iname) = if_tmp {
        if iname.name.is_none() && !iname.found {
            file_logger.error(&format!("********* unknown interface"));
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
            file_logger.error(&format!("********* no interface with address"));
        }
        if_tmp = &iname.next;
    }

    forward_init(true);
    Cache::new(cachesize, options & 4);

    // 检查DHCP配置并验证必要的文件是否存在
    if dhcp.is_none() {
        let packet_path = IFPACKET;
        let bpf_path = IFBPF;
        if file_exists(packet_path) && file_exists(bpf_path) {
            let mut current = &dhcp;
            while let Some(ctx) = current {
                if ctx.iface.is_empty() {
                    // 如果 iface 为空字符串，执行后续代码块
                    file_logger
                        .error("********* No suitable interface for DHCP service at address");
                    let mut leasefd = lease_init(
                        lease_file,
                        domain_suffix.clone(),
                        dnamebuff,
                        packet,
                        SystemTime::now(),
                        &mut dhcp_conf,
                    );
                    // lease_update_dns(1);
                    return 1;
                }

                // 移动到下一个节点
                current = &ctx.next;
            }
        } else {
            file_logger.error("********* no DHCP support available on this OS.");
        }
    }

    if (options & OPT_DEBUG) == 0 {
        let pidfile: Option<File> = match File::create("pidfile.txt") {
            Ok(file) => Some(file),
            Err(_) => None,
        };
        let i: i32 = 0;
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

        unsafe {
            let c_username = CString::new(username).expect("CString::new failed");
            let ent_pw: *mut passwd = getpwnam(c_username.as_ptr());

            if !ent_pw.is_null() {
                // 移除所有附加组
                let dummy: [gid_t; 0] = [];
                setgroups(0, dummy.as_ptr());

                // 获取组信息
                let c_groupname = CString::new(groupname).expect("CString::new failed");
                let gp: *mut group = getgrnam(c_groupname.as_ptr());

                if !gp.is_null() {
                    // 设置组 ID
                    setgid((*gp).gr_gid);
                }

                // 丢弃 root 权限并设置用户 ID
                setuid((*ent_pw).pw_uid);
            }
        }
    }

    /*  后面要补上
        openlog("dnsmasq",
    DNSMASQ_LOG_OPT(options & OPT_DEBUG),
    DNSMASQ_LOG_FAC(options & OPT_DEBUG));

    if (cachesize)
    syslog(LOG_INFO, "started, version %s cachesize %d", VERSION, cachesize);
    else
    syslog(LOG_INFO, "started, version %s cache disabled", VERSION);

    if (options & OPT_LOCALMX)
    syslog(LOG_INFO, "serving MX record for local hosts target %s", mxtarget);
    else if (mxname)
    syslog(LOG_INFO, "serving MX record for mailhost %s target %s",
        mxname, mxtarget);
    */

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

        // 记录 DHCP 信息 syslog
        println!(
            "DHCP on {}, IP range {} -- {}, lease time {}",
            config.iface, dnamebuff, config.end, packet
        );

        // 移动到下一个配置
        dhcp_tmp = &config.next;
    }

    if unsafe { getuid() == 0 || getegid() == 0 } {
        // syslog("failed to drop root privs for user");
    }

    // 退出前加入信号处理线程
    // signals_handle.join().unwrap();
    0
}

fn daemonize() {
    // 第一次 fork
    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => {
            // 父进程退出
            exit(0);
        }
        Ok(ForkResult::Child) => {
            // 子进程继续
        }
        Err(err) => {
            eprintln!("Fork failed: {}", err);
            exit(1);
        }
    }

    // 创建新会话
    if let Err(err) = setsid() {
        eprintln!("setsid failed: {}", err);
        exit(1);
    }

    // 第二次 fork
    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => {
            // 父进程退出
            exit(0);
        }
        Ok(ForkResult::Child) => {
            // 最终的子进程继续
        }
        Err(err) => {
            eprintln!("Second fork failed: {}", err);
            exit(1);
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

    // 遍历 std::env::args() 获取所有命令行参数
    for arg in env::args() {
        // 获取原始指针，并存储到 args 向量中
        args.push(arg);
    }

    // 参数数量（减一：去掉程序名）
    let argc = args.len() - 1;

    // 调用 start 函数，传入参数数量和参数指针数组
    let exit_code = start(argc, args);

    exit(exit_code.try_into().unwrap());
}
