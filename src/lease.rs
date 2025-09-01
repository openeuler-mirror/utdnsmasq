/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use crate::*;
use cache::*;
use dhcp::find_config;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Seek, Write};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::time::{SystemTime, UNIX_EPOCH};

const ETHER_ADDR_LEN: usize = 6;
static mut DNS_DIRTY: Option<u32> = None;
static mut FILE_DIRTY: Option<u32> = None;
static mut LEASES: Option<Box<DhcpLease>> = None;
static LEASE_FILE_PATH: &str = "/var/lib/misc/dnsmasq.leases";

#[derive(Debug)]
struct DhcpLease {
    clid_len: usize,
    clid: Vec<u8>,
    hostname: Option<String>,
    fqdn: Option<String>,
    expires: u64, // 使用u64表示UNIX时间戳
    hwaddr: [u8; ETHER_ADDR_LEN],
    addr: AllAddr,
    next: Option<Box<DhcpLease>>,
}

pub fn lease_init(
    filename: Option<&str>,
    domain: Option<String>,
    _buff: Vec<u8>,
    _buff2: Vec<u8>,
    now: SystemTime,
    dhcp_configs: &mut Option<Box<DhcpConfig>>,
) -> i32 {
    let mut leases: Option<Box<DhcpLease>> = None;
    let now_unix = now.duration_since(UNIX_EPOCH).unwrap().as_secs();

    // 打开文件
    let lease_file = match filename {
        Some(f) => File::open(f).expect("Cannot open or create leases file"),
        None => return -1,
    };

    let reader = io::BufReader::new(&lease_file);

    // 逐行读取租约文件
    for line in reader.lines() {
        let line = line.unwrap();
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 13 {
            continue; // 忽略格式不正确的行
        }

        // 解析租约信息
        let ei: u64 = parts[0].parse().unwrap();
        let e0 = u32::from_str_radix(parts[1], 16).unwrap();
        let e1 = u32::from_str_radix(parts[2], 16).unwrap();
        let e2 = u32::from_str_radix(parts[3], 16).unwrap();
        let e3 = u32::from_str_radix(parts[4], 16).unwrap();
        let e4 = u32::from_str_radix(parts[5], 16).unwrap();
        let e5 = u32::from_str_radix(parts[6], 16).unwrap();
        let buff = parts[11].as_bytes().to_vec();
        let buff2 = parts[12].as_bytes().to_vec();

        // 检查租约是否过期
        if ei != 0 && now_unix > ei {
            continue; // 跳过过期的租约
        }

        // 创建新的租约
        let mut lease: Box<DhcpLease> = Box::new(DhcpLease {
            clid_len: buff2.len(),
            clid: buff2,
            hwaddr: [e0 as u8, e1 as u8, e2 as u8, e3 as u8, e4 as u8, e5 as u8],
            hostname: None,
            fqdn: None,
            addr: AllAddr::Addr4(Ipv4Addr::new(0, 0, 0, 0)),
            expires: ei,
            next: None,
        });

        // 设置主机名
        if buff != b"*" {
            lease_set_hostname(
                Some(std::str::from_utf8(&buff).unwrap()),
                domain.clone(),
                &mut lease,
            );
        }

        unsafe { DNS_DIRTY = Some(1) };
        unsafe { FILE_DIRTY = Some(0) };
        // 将租约添加到链表中
        lease.next = leases;
        leases = Some(Box::new(*lease));
    }

    // 处理配置文件和租约之间的关系
    let mut lease_ptr = leases.as_mut();
    while let Some(lease) = lease_ptr {
        // 查找与当前租约匹配的 DHCP 配置
        if let Some(config) = find_config(
            dhcp_configs,
            None,
            lease.clid.clone(),
            lease.clid_len,
            &lease.hwaddr,
            None,
        ) {
            if let Some(ref hostname) = config.hostname {
                lease_set_hostname(Some(hostname), domain.clone(), lease);
            }
        }
        lease_ptr = lease.next.as_mut();
    }

    // 返回文件描述符
    lease_file.as_raw_fd()
}

fn lease_set_hostname(name: Option<&str>, suffix: Option<String>, leases: &mut Box<DhcpLease>) {
    let mut new_name: Option<String> = None;
    let mut new_fqdn: Option<String> = None;

    // 如果没有提供名称且没有主机名，返回
    if name.is_none() && leases.hostname.is_none() {
        return;
    }

    // 如果提供了名称，处理可能的冲突
    if let Some(name) = name {
        let mut lease_current: Option<&mut Box<DhcpLease>> = Some(leases);

        // 遍历租约链表以查找冲突
        //把ref mut 去掉
        while let Some(current_lease) = lease_current {
            // 检查当前租约的主机名是否与新名称冲突
            if let Some(ref hostname) = current_lease.hostname {
                if hostname == name {
                    new_name = Some(hostname.clone()); // 保存旧主机名
                    current_lease.hostname = None; // 移除旧主机名
                    current_lease.fqdn = None; // 移除旧的FQDN
                }
            }

            // 移动到下一个租约
            lease_current = current_lease.next.as_mut(); // 获取下一个租约的可变引用
        }

        // 如果没有找到旧主机名，则分配新的内存
        if new_name.is_none() {
            new_name = Some(name.to_string());
        }

        // 如果提供了后缀并且没有旧的FQDN，则生成新的FQDN
        if let Some(suffix) = suffix {
            if new_fqdn.is_none() {
                new_fqdn = Some(format!("{}.{}", name, suffix));
            }
        }
    }

    // 更新当前租约的主机名和FQDN
    leases.hostname = new_name;
    leases.fqdn = new_fqdn;

    unsafe { FILE_DIRTY = Some(1) };
    unsafe { DNS_DIRTY = Some(1) };
}

// 更新 DHCP 租约文件和 DNS 缓存：
pub fn lease_update_dns(caches: &mut Cache, force_dns: i32) -> io::Result<()> {
    unsafe {
        // 检查是否需要更新文件
        if FILE_DIRTY.is_some() {
            // 打开或创建文件
            let mut lease_file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(LEASE_FILE_PATH)?;

            // 重置文件指针并清空文件内容
            lease_file.rewind()?;
            lease_file.set_len(0)?;

            // 遍历 DHCP 租约链表并写入信息到文件
            let mut lease_opt = LEASES.as_deref();
            while let Some(lease) = lease_opt {
                // 写入租约基本信息
                write!(
                    lease_file,
                    "{} {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} {:?} {} ",
                    lease.expires,
                    lease.hwaddr[0],
                    lease.hwaddr[1],
                    lease.hwaddr[2],
                    lease.hwaddr[3],
                    lease.hwaddr[4],
                    lease.hwaddr[5],
                    lease.addr,
                    lease.hostname.as_deref().unwrap_or("*")
                )?;

                // 写入客户端 ID（`clid`）
                if lease.clid_len > 0 {
                    for i in 0..lease.clid_len - 1 {
                        write!(lease_file, "{:02x}:", lease.clid[i])?;
                    }
                    writeln!(lease_file, "{:02x}", lease.clid[lease.clid_len - 1])?;
                } else {
                    writeln!(lease_file, "*")?;
                }

                // 继续遍历链表
                lease_opt = lease.next.as_deref();
            }

            lease_file.flush()?; // 刷新文件内容到磁盘
            lease_file.sync_all()?; // 同步文件内容
            FILE_DIRTY = Some(0); // 重置文件脏标志
        }

        // 检查是否需要更新 DNS 缓存
        if DNS_DIRTY.is_some() || force_dns != 0 {
            cache_unhash_dhcp(caches);

            let mut lease_opt = LEASES.as_deref();
            while let Some(lease) = lease_opt {
                if let Some(ref fqdn) = lease.fqdn {
                    // 如果有 FQDN，添加到缓存
                    cache_add_dhcp_entry(fqdn, lease.addr.clone(), lease.expires, 4, caches);
                    cache_add_dhcp_entry(
                        lease.hostname.as_deref().unwrap_or("*"),
                        lease.addr.clone(),
                        lease.expires,
                        0,
                        caches,
                    );
                } else if let Some(ref hostname) = lease.hostname {
                    // 只添加 hostname
                    cache_add_dhcp_entry(hostname, lease.addr.clone(), lease.expires, 4, caches);
                }

                // 继续遍历链表
                lease_opt = lease.next.as_deref();
            }

            DNS_DIRTY = Some(0); // 重置 DNS 脏标志
        }
    }

    Ok(())
}
