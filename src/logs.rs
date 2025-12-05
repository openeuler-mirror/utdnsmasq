/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

 use colored::*;
use std::borrow::Cow;
use tklog::{LOG, MODE};

pub const LOG_EMERG: i8 = 0;
pub const LOG_ALERT: i8 = 1;
pub const LOG_CRIT: i8 = 2;
pub const LOG_ERR: i8 = 3;
pub const LOG_WARNING: i8 = 4;
pub const LOG_NOTICE: i8 = 5;
pub const LOG_INFO: i8 = 6;
pub const LOG_DEBUG: i8 = 7;

// 日志记录到当前目录下的utdnsmasq.log文件
const LOG_FILE: &str = "utdnsmasq.log";

pub fn log_init() {
    let levelstr = "{level}".green(); //日志级别标识设置为绿色
    let timestr = "{time}".yellow(); // 时间属性标识设置为黄色
    let filestr = "{file}".red(); //文件属性标识设置为红色
    let messagestr = ":{message}".blue(); // 信息属性标识修改为蓝色
    let s = format!("{} {} {} {}\n", levelstr, timestr, filestr, messagestr);
    //设置日志格式
    LOG.set_formatter(s.as_str()).uselog();
    // 日志写入到文件
    LOG.set_cutmode_by_time(LOG_FILE, MODE::MONTH, 0, false);
    // 设置日志级别为debug
    LOG.set_level(tklog::LEVEL::Debug);
    //开启同步写入日志
    LOG.set_printmode(tklog::PRINTMODE::PUNCTUAL);
}

#[macro_export]
macro_rules! syslog {
    ($priority:expr, $fmt:expr, $($args:tt),*) => {{
        match $priority {
            LOG_EMERG | LOG_ALERT |LOG_CRIT => {
                log::error!($fmt, $($args),*);
            }
            LOG_ERR => {
                log::error!($fmt, $($args),*);
            }
            LOG_WARNING => {
                log::warn!($fmt, $($args),*);
            }
            LOG_NOTICE | LOG_INFO => {
                log::info!($fmt, $($args),*);
            }
            LOG_DEBUG => {
                log::debug!($fmt, $($args),*);
            }
            _ => {
                log::debug!($fmt, $($args),*);
            }
        }
    }};
}

pub fn complain(message: &str, arg1: &str) {
    let errmess = std::io::Error::last_os_error().to_string();

    let arg1: Cow<str> = if arg1.is_empty() {
        Cow::Owned(errmess.clone())
    } else {
        Cow::Borrowed(arg1)
    };

    // 把错误信息输出到标准错误
    eprintln!("dnsmasq: {message}, {arg1}, {errmess}");

    // 把错误信息输出到系统日志
    syslog!(LOG_CRIT, "{} {}, {}", message, arg1, errmess);
}

// 第二个参数为NULL时，调用die函数。
pub fn die(message: &str, arg1: &str) {
    complain(message, arg1);
    syslog!(LOG_CRIT, "FAILED to start up",);
    panic!("{}", message);
}

// 处理需要通过{} 传递参数的情况，两个参数
// 第二个参数有值时，调用die宏
#[macro_export]
macro_rules! die {
    ($message:expr, $arg1:expr) => {{
        let errmess = std::io::Error::last_os_error().to_string();
        if !errmess.is_empty() {
            eprintln!("dnsmasq: error: {}", errmess);
        }
        eprintln!($message, $arg1);
        syslog!(LOG_CRIT, $message, $arg1);
        syslog!(LOG_CRIT, "FAILED to start up",);
        panic!($message, $arg1);
    }};
}


 
