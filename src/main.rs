/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use signal_hook::consts::signal::*;
use std::ffi::CString;
use std::net::{SocketAddr};
use std::os::raw::{c_char, c_int};
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;
use std::{env, ptr};

#[derive(Debug)]
struct Iname {
    name: Option<String>,
    addr: SocketAddr,
    found: bool,
    next: Option<Box<Iname>>,
}

// 全局标志变量，使用 AtomicBool 来保证线程安全
static SIGTERM_RECEIVED: AtomicBool = AtomicBool::new(false);
static SIGHUP_RECEIVED: AtomicBool = AtomicBool::new(false);
static SIGUSR1_RECEIVED: AtomicBool = AtomicBool::new(false);
static SIGUSR2_RECEIVED: AtomicBool = AtomicBool::new(false);

// 信号处理函数
fn sig_handler(sig: i32) {
    match sig {
        SIGTERM => {
            SIGTERM_RECEIVED.store(true, Ordering::SeqCst);
        }
        SIGHUP => {
            SIGHUP_RECEIVED.store(true, Ordering::SeqCst);
        }
        SIGUSR1 => {
            SIGUSR1_RECEIVED.store(true, Ordering::SeqCst);
        }
        SIGUSR2 => {
            SIGUSR2_RECEIVED.store(true, Ordering::SeqCst);
        }
        _ => {}
    }
}

// 定义常量
const CACHESIZ: usize = 1024; // 缓存大小默认值
const NAMESERVER_PORT: u16 = 53; // 名称服务器端口默认值
const RUNFILE: &str = "/var/run/dnsmasq.pid"; // PID 文件默认路径
const CHUSER: &str = "dnsmasq"; // 默认用户名
const CHGRP: &str = "dnsmasq"; // 默认组名

fn start(_argc: usize, _argv: *mut *mut c_char) -> usize {
    let _int_err_string: String = String::new(); // 错误信息字符串
    let _cachesize: usize = CACHESIZ; // 缓存大小，默认值为 CACHESIZ
    let _port: u16 = NAMESERVER_PORT; // 名称服务器端口，默认为 NAMESERVER_PORT
    let _query_port: u16 = 0; // 查询端口，初始值为0
    let _first_loop: bool = true; // 标记是否首次运行，1 表示是
    let _local_ttl: u32 = 0; // 本地缓存 TTL，初始值为 0
    let _options: u32 = 0; // 选项标志位
    let _runfile: String = RUNFILE.to_string(); // 进程 PID 文件路径，默认为 RUNFILE
                                               // 时间戳相关变量
    let _resolv_changed: SystemTime = SystemTime::now();
    let _now: SystemTime = SystemTime::now();
    let _last: SystemTime = SystemTime::now();
    // 网络接口相关信息
    let _iface: String = String::new();
    let _interfaces: String = String::new();
    // 邮件交换相关变量
    let _mxname: String = String::new();
    let _mxtarget: String = String::new();
    let _lease_file: String = String::new(); // 租约文件路径
    let _addn_hosts: String = String::new(); // 额外主机文件路径
    let _domain_suffix: String = String::new(); // 域名后缀
    let _username: String = CHUSER.to_string(); // 用户名，默认值为 CHUSER
    let _groupname: String = CHGRP.to_string(); // 组名，默认值为 CHGRP
    let _if_names: *mut Iname = std::ptr::null_mut(); // 用于存储接口名称
    let _if_addrs: *mut Iname = std::ptr::null_mut(); // 用于存储接口地址
    let _if_except: *mut Iname = std::ptr::null_mut(); // 用于存储例外情况
    let _if_tmp: *mut Iname = std::ptr::null_mut(); // 作为临时变量使用
    sig_handler(0);
    0
}

fn main() {
    // 创建一个 Vec<*mut libc::c_char> 类型的向量 args
    let mut args: Vec<*mut c_char> = Vec::new();

    // 遍历 std::env::args() 获取所有命令行参数
    for arg in env::args() {
        // 将每个参数转换为 CString，并获取其原始指针
        let cstring = CString::new(arg).expect("Failed to convert to CString");
        // 获取原始指针，并存储到 args 向量中
        args.push(cstring.into_raw());
    }

    // 在 args 向量末尾添加一个空指针 null_mut()，用于表示参数列表的结束
    args.push(ptr::null_mut());

    // 参数数量（减一：去掉程序名）
    let argc = (args.len() as c_int) - 1;

    // 调用 start 函数，传入参数数量和参数指针数组
    let exit_code = start(argc.try_into().unwrap(), args.as_mut_ptr()) as i32;

    exit(exit_code);
}
