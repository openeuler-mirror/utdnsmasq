/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use crate::*;
use std::cell::RefCell;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::Ipv4Addr;
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const ETHER_ADDR_LEN: usize = 6;

#[derive(Debug)]
struct DhcpLease {
    clid_len: usize,                      // client identifier 的长度
    clid: Option<Vec<u8>>,                // client identifier，使用 Vec<u8> 来存储字节数组
    hostname: Option<String>,             // 客户端提供的主机名，使用 Option<String> 来处理可选字段
    fqdn: Option<String>,                 // 完全限定域名，使用 Option<String>
    expires: SystemTime,                  // 租约到期时间，使用 SystemTime 来存储时间
    hwaddr: [u8; ETHER_ADDR_LEN],         // MAC 地址，使用固定大小的数组存储
    addr: Ipv4Addr,                       // IPv4 地址，使用标准库中的 Ipv4Addr 类型
    next: Option<Rc<RefCell<DhcpLease>>>, // 指向下一个租约，使用 Rc 和 RefCell 来实现可变的共享所有权
}

fn lease_set_hostname(lease: &mut DhcpLease, hostname: &str, domain: &str) {
    // 如果域名存在，将其添加到主机名中
    let fqdn = if !domain.is_empty() {
        format!("{}.{}", hostname, domain)
    } else {
        hostname.to_string()
    };
    lease.hostname = Some(fqdn);
}

fn find_config<'a>(
    dhcp_configs: &'a [DhcpConfig],
    _hwaddr: &[u8; ETHER_ADDR_LEN],
) -> Option<&'a DhcpConfig> {
    // 在 dhcp_configs 中查找与硬件地址匹配的配置
    // 这里可以根据需求加入匹配 hwaddr 的逻辑
    dhcp_configs.iter().find(|config| config.hostname.is_some())
}

pub fn lease_init<P: AsRef<Path>>(
    filename: P,
    domain: &str,
    buff: &mut String,
    buff2: &mut String,
    now: SystemTime,
    dhcp_configs: &[DhcpConfig],
) -> std::io::Result<File> {
    // 打开租约文件，若文件不存在则创建它
    let mut lease_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .append(true)
        .open(&filename)?;

    // 使用 BufReader 逐行读取文件
    lease_file.seek(SeekFrom::Start(0))?; // 确保从文件开头读取
    let reader = BufReader::new(&lease_file);

    let mut has_old = false;
    let mut leases: Option<Rc<RefCell<DhcpLease>>> = None;

    for line in reader.lines() {
        let line = line?;
        let mut parts = line.split_whitespace();

        // 解析 ei（过期时间）
        let ei = parts.next().unwrap_or("0").parse::<u64>().unwrap_or(0);
        let expires = UNIX_EPOCH + Duration::from_secs(ei);

        // 跳过已过期的租约
        if ei != 0
            && now.duration_since(expires).unwrap_or(Duration::new(0, 0)) > Duration::new(0, 0)
        {
            has_old = true;
            continue;
        }

        // 解析 MAC 地址
        let hwaddr = [
            u8::from_str_radix(parts.next().unwrap_or("00"), 16).unwrap_or(0),
            u8::from_str_radix(parts.next().unwrap_or("00"), 16).unwrap_or(0),
            u8::from_str_radix(parts.next().unwrap_or("00"), 16).unwrap_or(0),
            u8::from_str_radix(parts.next().unwrap_or("00"), 16).unwrap_or(0),
            u8::from_str_radix(parts.next().unwrap_or("00"), 16).unwrap_or(0),
            u8::from_str_radix(parts.next().unwrap_or("00"), 16).unwrap_or(0),
        ];

        // 解析 IP 地址
        let addr = Ipv4Addr::new(
            parts.next().unwrap_or("0").parse::<u8>().unwrap_or(0),
            parts.next().unwrap_or("0").parse::<u8>().unwrap_or(0),
            parts.next().unwrap_or("0").parse::<u8>().unwrap_or(0),
            parts.next().unwrap_or("0").parse::<u8>().unwrap_or(0),
        );

        // 解析主机名
        *buff = match parts.next().unwrap_or("*") {
            "*" => String::new(),
            name => name.to_string(),
        };

        // 解析客户端标识符
        *buff2 = parts.next().unwrap_or("*").to_string();
        let client_id: Option<_> = if buff2 == "*" {
            None
        } else {
            let hex_pairs = buff2.as_bytes().chunks(2); // 每两位一组解析为hex
            Some(
                hex_pairs
                    .map(|chunk| {
                        let hex_str = std::str::from_utf8(chunk).unwrap(); // 将切片转为字符串
                        u8::from_str_radix(hex_str, 16).unwrap_or(0) // 解析为u8
                    })
                    .collect::<Vec<_>>(),
            )
        };

        // 计算 clid_len，使用 match 处理 Option
        let clid_len = match &client_id {
            Some(clid) => clid.len(), // 如果 client_id 存在，返回其长度
            None => 0,                // 如果 client_id 是 None，返回 0
        };

        // 创建租约结构
        let lease = Rc::new(RefCell::new(DhcpLease {
            clid_len,
            clid: client_id,
            hostname: Some(buff.clone()),
            fqdn: None,
            expires,
            hwaddr,
            addr,
            next: None,
        }));

        // 将 lease 链接到 leases 链表
        if let Some(ref mut lease_head) = leases {
            lease.borrow_mut().next = Some(lease_head.clone());
        }
        leases = Some(lease.clone());
    }

    // 遍历租约并根据配置更新主机名
    let mut lease_head = leases.clone();
    while let Some(lease_rc) = lease_head {
        let lease = lease_rc.borrow();
        if let Some(config) = find_config(dhcp_configs, &lease.hwaddr) {
            if let Some(hostname) = &config.hostname {
                lease_set_hostname(&mut lease_rc.borrow_mut(), hostname, domain);
            }
        }
        lease_head = lease.next.clone();
    }

    // 返回文件句柄
    Ok(lease_file)
}
