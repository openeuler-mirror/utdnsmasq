/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

pub mod log;
pub mod option;
use if_addrs::{IfAddr, Ifv4Addr, Ifv6Addr};
use log::*;
use option::*;
use signal_hook::consts::signal::*;
use signal_hook::iterator::Signals;
use std::collections::HashMap;
use std::env;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

// 全局标志变量，使用 AtomicBool 来保证线程安全
static SIGHUP_FLAG: AtomicBool = AtomicBool::new(true);
static SIGUSR1_FLAG: AtomicBool = AtomicBool::new(false);
static SIGUSR2_FLAG: AtomicBool = AtomicBool::new(false);
static SIGTERM_FLAG: AtomicBool = AtomicBool::new(false);

fn sig_handler(mut signals: Signals) {
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
const RUNFILE: &str = "/var/run/dnsmasq.pid";
const CHUSER: &str = "utdnsmasq"; // 默认用户名
const CHGRP: &str = "utdnsmasq"; // 默认组名

#[derive(Debug)]
struct Interface {
    name: String,
    addr: Option<IpAddr>,
}

#[derive(Debug)]
struct Interfaces {
    if_names: Vec<String>,
    if_addrs: HashMap<String, Option<IpAddr>>,
}

impl Interfaces {
    fn new() -> Self {
        Interfaces {
            if_names: Vec::new(),
            if_addrs: HashMap::new(),
        }
    }
}

fn enumerate_interfaces(
    interfaces: &mut Interfaces,
    dhcp: bool, // 控制参数
    port: u16,  // 配置端口
) -> Result<(), String> {
    // 使用 if_addrs 库来枚举网络接口
    match if_addrs::get_if_addrs() {
        Ok(ifaces) => {
            for iface in ifaces {
                let name = iface.name.clone();
                let addr = match iface.addr {
                    IfAddr::V4(Ifv4Addr { ip, .. }) => Some(IpAddr::V4(ip)),
                    IfAddr::V6(Ifv6Addr { ip, .. }) => Some(IpAddr::V6(ip)),
                };

                // 存储接口名称和地址
                interfaces.if_names.push(name.clone());
                interfaces.if_addrs.insert(name, addr);
            }
        }
        Err(e) => {
            return Err(format!("Failed to enumerate network interfaces: {}", e));
        }
    }

    if dhcp {
        println!("DHCP is enabled, configuring port: {}", port);
    }

    Ok(())
}

fn start(argc: usize, args: Vec<String>) -> usize {
    let file_logger = Logger::new(Some("/var/log/utdnsmasq.log".to_string()));
    let mut cachesize: usize = CACHESIZ; // 缓存大小，默认值为 CACHESIZ
    let mut port: u16 = NAMESERVER_PORT; // 名称服务器端口，默认为 NAMESERVER_PORT
    let mut query_port: i32 = 0; // 查询端口，初始值为0
    let first_loop: bool = true;
    let mut local_ttl: u64 = 0; // 本地缓存 TTL，初始值为 0
    let runfile: &str = RUNFILE; // 进程 PID 文件路径，默认为 RUNFILE
                                 // 时间戳相关变量
    let resolv_changed: u64 = 0;
    let now: u64 = 0;
    let last: u64 = 0;
    // 邮件交换相关变量
    let mut resolv = Resolv::default();
    let mut dhcp: Option<&mut DhcpContext> = None;
    let mut dhcp_conf: Option<&mut Vec<DhcpConfig>> = None;
    let mut dhcp_opts: Option<&mut Vec<DhcpOpt>> = None;
    let mxname: Option<&mut String> = None;
    let mxtarget: Option<&mut String> = None;
    let mut lease_file: Option<&mut String> = None; // 租约文件路径
    let mut addn_hosts: Option<&mut String> = None; // 额外主机文件路径
    let domain_suffix: Option<String> = None; // 域名后缀
    let mut username: &str = CHUSER; // 用户名，默认值为 CHUSER
    let mut groupname: &str = CHGRP; // 组名，默认值为 CHGRP
    let mut if_names: Option<&mut Vec<Iname>> = None; // 用于存储接口名称
    let mut if_addrs: Option<&mut Vec<Iname>> = None; // 用于存储接口地址
    let if_except: Option<&mut Vec<Iname>> = None; // 用于存储例外情况
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
        &lease_file,
        &mut username,
        &mut groupname,
        domain_suffix,
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
        dhcp_conf,
        dhcp_opts,
        dhcp_file,
        dhcp_sname,
        dhcp_next_server,
    );
    if lease_file.is_none() {
        let mut lease_files = String::from("/var/lib/misc/dnsmasq.leases");
        lease_file = Some(&mut lease_files);
    } else if dhcp.is_none() {
        file_logger.error("********* dhcp-lease option set, but not dhcp-range.");
        file_logger.error("********* Are you trying to use the obsolete ISC dhcpd integration?");
        file_logger.error("********* Please configure the dnsmasq integrated DHCP server by using");
        file_logger.error("********* the \"dhcp-range\" option, and remove any other DHCP server.");
    }
    let mut interfaces = Interfaces::new();
    let int_err_string = enumerate_interfaces(&mut interfaces, dhcp.is_some(), port);
    if int_err_string.is_err() {
        file_logger.error("********* FAILED to start up");
        return 1;
    }

    for if_names in interfaces.if_names {
        if if_names.is_empty() {
            file_logger.error("********* Unknown interface name found");
            return 1;
        }
    }

    // 退出前加入信号处理线程
    // signals_handle.join().unwrap();
    0
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
