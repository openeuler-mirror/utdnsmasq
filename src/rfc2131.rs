/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

//! RFC 2131 - Dynamic Host Configuration Protocol
//! Constants and types for DHCP protocol implementation

use crate::dhcp::{address_allocate, address_available, find_config};
use crate::dnsmasq::ETHER_ADDR_LEN;
use crate::dnsmasq::{DhcpConfig, DhcpContext, DhcpLease, DhcpOpt, DhcpPacket};
use crate::lease::{
    lease_find_by_addr, lease_find_by_client, lease_prune, lease_set_expires, lease_set_hostname,
    lease_set_hwaddr, LEASES,
};
use crate::logs::{LOG_INFO, LOG_WARNING};
use crate::rfc1035::INADDRSZ;
use crate::syslog;
use crate::util::{canonicalise, difftime};
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// DHCP message types
pub const BOOTREQUEST: u8 = 1; // 客户端请求
pub const BOOTREPLY: u8 = 2; // 服务端回应

/// DHCP magic cookie value (RFC 2131)
pub const DHCP_COOKIE: u32 = 0x63825363;

pub const OPTION_PAD: u8 = 0;
pub const OPTION_NETMASK: u8 = 1;
pub const OPTION_ROUTER: u8 = 3;
pub const OPTION_DNSSERVER: u8 = 6;
pub const OPTION_HOSTNAME: u8 = 12; // 客户端可以在此选项中告知服务器它的主机名
pub const OPTION_DOMAINNAME: u8 = 15;
pub const OPTION_BROADCAST: u8 = 28;
pub const OPTION_CLIENT_ID: u8 = 61; //  DHCP 协议中的客户端标识符选项
pub const OPTION_REQUESTED_IP: u8 = 50;
pub const OPTION_LEASE_TIME: u8 = 51;
pub const OPTION_OVERLOAD: u8 = 52;
pub const OPTION_MESSAGE_TYPE: u8 = 53;
pub const OPTION_SERVER_IDENTIFIER: u8 = 54;
pub const OPTION_REQUESTED_OPTIONS: u8 = 55; // 客户端通过这个选项告诉服务器，除了IP地址之外，它还希望获取哪些配置参数。
pub const OPTION_MAXMESSAGE: u8 = 57;
pub const OPTION_END: u8 = 255;

pub const DHCPDISCOVER: u8 = 1;
pub const DHCPOFFER: u8 = 2;
pub const DHCPREQUEST: u8 = 3;
pub const DHCPDECLINE: u8 = 4;
pub const DHCPACK: u8 = 5;
pub const DHCPNAK: u8 = 6;
pub const DHCPRELEASE: u8 = 7;
pub const DHCPINFORM: u8 = 8;

const ARPHRD_ETHER: u8 = 1; /* Ethernet 10/100Mbps.  */
/*
主要功能是处理DHCP协议中的不同消息类型，包括LEASE_TIME、DHCPRELEASE、DHCPDISCOVER、DHCPREQUEST和DHCPINFORM。
根据消息类型，函数执行不同的操作，如更新租约时间、记录日志、查找或分配IP地址、发送ACK或NAK消息等。
函数还涉及到查找配置信息、处理选项、记录日志和更新消息字段等辅助功能。

返回值：
如果返回一个正整数，表示成功处理并构建了DHCP响应消息，返回值即为新消息的有效字节数。
如果返回0，通常表示处理过程中遇到问题或者消息类型不被识别。
如果返回一个负数，通常意味着需要进行广播处理，负号前的绝对值表示响应消息的有效字节数。
 */
pub struct DncpReplyArgs<'a> {
    pub context: Option<&'a mut DhcpContext>,
    pub mess: &'a mut DhcpPacket,
    pub dhcp_configs: &'a [DhcpConfig],
    pub domain_suffix: &'a Option<String>,
    pub dhcp_file: &'a Path,
    pub dhcp_sname: &'a Option<String>,
    pub dhcp_next_server: Ipv4Addr,
    pub dhcp_options: &'a [DhcpOpt],
    pub sz: usize,
    pub now: SystemTime,
}

pub fn dncp_reply(args: DncpReplyArgs<'_>) -> i32 {
    let DncpReplyArgs {
        mut context,
        mess,
        dhcp_configs,
        domain_suffix,
        dhcp_file,
        dhcp_sname,
        dhcp_next_server,
        dhcp_options,
        sz,
        now,
    } = args;
    let mut req_options = Vec::new();
    let mut hostname = String::new();
    if mess.op != BOOTREQUEST
        || mess.htype != ARPHRD_ETHER
        || mess.hlen != ETHER_ADDR_LEN as u8
        || mess.cookie != DHCP_COOKIE
    {
        return 0;
    }

    mess.op = BOOTREPLY;

    // 客户端标识符 (Client Identifier) 检查 - copy data to avoid borrow conflicts
    let (clid_data, clid_len) = if let Some(opt) = option_find(mess, sz, OPTION_CLIENT_ID) {
        let data = option_ptr(opt);
        (data.to_vec(), option_len(opt))
    } else {
        (mess.chaddr[..ETHER_ADDR_LEN].to_vec(), 0) // 使用硬件地址
    };

    let mut lease = lease_find_by_client(&clid_data, clid_len);

    if let Some(opt) = option_find(mess, sz, OPTION_REQUESTED_OPTIONS) {
        let len = option_len(opt);
        req_options = Vec::with_capacity(len + 1);
        req_options.extend_from_slice(&option_ptr(opt)[..len]);
        req_options.push(OPTION_END);
    }

    let mess_chaddr: [u8; 6] = mess.chaddr[0..6].try_into().unwrap_or([0; 6]);
    if let Some(dhcp_config) = find_config(
        dhcp_configs,
        context.as_deref(),
        &clid_data,
        clid_len,
        mess_chaddr,
        None,
    ) {
        if let Some(name) = dhcp_config.hostname {
            hostname = name;
        }
    } else if let Some(opt) = option_find(mess, sz, OPTION_HOSTNAME) {
        let len = option_len(opt);
        let hostname_bytes = option_ptr(opt);
        hostname = String::from_utf8_lossy(&hostname_bytes[..len]).to_string();
        if canonicalise(&hostname) {
            hostname = String::new();
        }
    }

    if !hostname.is_empty() {
        let names: Vec<&str> = hostname.split('.').collect();
        if names.len() > 1 {
            if domain_suffix.is_none()
                || (domain_suffix.is_some() && names[1] != domain_suffix.as_ref().unwrap())
            {
                syslog!(
                    LOG_WARNING,
                    "Ignoring DHCP host name {} because it has an illegal domain part",
                    hostname
                );
            } else {
                hostname = names[0].to_string();
            }
        }
    }

    let (dhcp_config, def_time) = match find_config(
        dhcp_configs,
        context.as_deref(),
        &clid_data,
        clid_len,
        mess_chaddr,
        Some(hostname.clone()),
    ) {
        Some(dncp_config) => {
            let lease_time = dncp_config.lease_time;
            (Some(dncp_config), lease_time)
        }
        None => {
            let lease_time = context.as_ref().unwrap().lease_time;
            (None, lease_time)
        }
    };

    let expires_time;
    let renewal_time;
    if let Some(opt) = option_find(mess, sz, OPTION_LEASE_TIME) {
        // 客户端带有租约时间
        let req_time = option_uint(opt);

        if def_time == 0xffffffff || (req_time != 0xffffffff && req_time < def_time) {
            expires_time = req_time;
            renewal_time = req_time;
        } else {
            expires_time = def_time;
            renewal_time = def_time;
        }
    } else {
        renewal_time = def_time;
        if let Some(ref lease) = lease {
            expires_time = difftime(lease.expires, now) as u32;
        } else {
            expires_time = def_time;
        }
    }

    // 最核心、最必要的一个选项 定义了 DHCP 报文本身的类型，决定了该报文在 DHCP 工作流程（D-O-R-A）中所扮演的角色
    if let Some(opt) = option_find(mess, sz, OPTION_MESSAGE_TYPE) {
        match opt[2] {
            // 客户端主动释放IP地址
            DHCPRELEASE => {
                if let Some(ref lease) = lease {
                    log_packet(
                        "RELEASE",
                        &lease.addr,
                        &mess.chaddr,
                        context.as_ref().unwrap().iface.clone(),
                    );
                    lease_prune(Some(lease), now);
                }
            }

            // D 过程， 客户端广播消息，寻找可用服务器。
            DHCPDISCOVER => {
                // 向服务器请求一个特定的 IP 地址。
                let mut yiaddr_copy = mess.yiaddr;
                let has_requested_ip;
                let requested_ip_was_none;

                // Extract the option information before any borrows
                if let Some(opt) = option_find(mess, sz, OPTION_REQUESTED_IP) {
                    yiaddr_copy = option_addr(opt);
                    has_requested_ip = true;
                    requested_ip_was_none = false;
                } else {
                    has_requested_ip = false;
                    requested_ip_was_none = true;
                };

                // Log the packet before assigning to mess.yiaddr to avoid borrow conflicts
                let log_addr = if has_requested_ip {
                    yiaddr_copy
                } else {
                    Ipv4Addr::UNSPECIFIED
                };
                log_packet(
                    "DISCOVER",
                    &log_addr,
                    &mess.chaddr,
                    context.as_ref().unwrap().iface.clone(),
                );

                mess.yiaddr = yiaddr_copy;

                if let Some(lease) = lease {
                    mess.yiaddr = lease.addr;
                } else if let Some(d_config) = dhcp_config {
                    if d_config.addr != Ipv4Addr::UNSPECIFIED
                        && lease_find_by_addr(d_config.addr).is_none()
                    {
                        mess.yiaddr = d_config.addr;
                    } else if (requested_ip_was_none
                        || !address_available(context.as_ref().unwrap(), mess.yiaddr))
                        && address_allocate(
                            context.as_mut().unwrap(),
                            dhcp_configs,
                            &mut mess.yiaddr,
                        )
                        .is_none()
                    {
                        syslog!(LOG_WARNING, "address pool exhausted");
                        return 0;
                    }
                } else if (requested_ip_was_none
                    || !address_available(context.as_ref().unwrap(), mess.yiaddr))
                    && address_allocate(context.as_mut().unwrap(), dhcp_configs, &mut mess.yiaddr)
                        .is_none()
                {
                    syslog!(LOG_WARNING, "address pool exhausted");
                    return 0;
                }

                // 填充回复数据
                bootp_option_put(mess, Some(dhcp_file.to_path_buf()), dhcp_sname.clone());
                let mut p = &mut mess.options[..];
                mess.siaddr = dhcp_next_server;
                p = option_put(p, OPTION_MESSAGE_TYPE, 1, DHCPOFFER as u32);
                p = option_put(
                    p,
                    OPTION_SERVER_IDENTIFIER,
                    INADDRSZ as usize,
                    u32::from_be_bytes(context.as_ref().unwrap().serv_addr.octets()),
                );
                p = option_put(p, OPTION_LEASE_TIME, 4, expires_time);
                p = do_req_options(
                    context.as_ref().unwrap(),
                    p,
                    &req_options,
                    dhcp_options,
                    domain_suffix.as_deref(),
                    None,
                );
                p = option_put(p, OPTION_END, 0, 0); // 结尾

                log_packet(
                    "OFFER",
                    &mess.yiaddr,
                    &mess.chaddr,
                    context.as_ref().unwrap().iface.clone(),
                );
                // 返回偏移量
                return (p.as_ptr() as usize - mess as *const _ as usize)
                    .try_into()
                    .unwrap();
            }

            // O阶段 客户端选择一台服务器的Offer并广播请求。
            DHCPREQUEST => {
                if mess.ciaddr != Ipv4Addr::UNSPECIFIED {
                    log_packet(
                        "REQUEST",
                        &mess.ciaddr,
                        &mess.chaddr,
                        context.as_ref().unwrap().iface.clone(),
                    );

                    if lease.is_none() || mess.ciaddr != lease.unwrap().addr {
                        log_packet(
                            "NAK",
                            &mess.ciaddr,
                            &mess.chaddr,
                            context.as_ref().unwrap().iface.clone(),
                        );

                        mess.siaddr = Ipv4Addr::UNSPECIFIED;
                        mess.yiaddr = Ipv4Addr::UNSPECIFIED;
                        mess.ciaddr = Ipv4Addr::UNSPECIFIED;

                        bootp_option_put(mess, None, None);
                        let mut p = &mut mess.options[..];
                        p = option_put(p, OPTION_MESSAGE_TYPE, 1, DHCPNAK as u32);
                        p = option_put(p, OPTION_END, 0, 0);
                        return -(p.as_ptr() as i32 - mess as *const _ as i32);
                    }
                    mess.yiaddr = mess.ciaddr;
                } else {
                    let opt = option_find(mess, sz, OPTION_SERVER_IDENTIFIER);
                    if opt.is_some()
                        && context.as_ref().unwrap().serv_addr != option_addr(opt.unwrap())
                    {
                        return 0;
                    }

                    let requested_ip_opt = option_find(mess, sz, OPTION_REQUESTED_IP);
                    if requested_ip_opt.is_none() {
                        return 0;
                    }

                    let requested_addr = option_addr(requested_ip_opt.unwrap());
                    mess.yiaddr = requested_addr;
                    log_packet(
                        "REQUEST",
                        &mess.yiaddr,
                        &mess.chaddr,
                        context.as_ref().unwrap().iface.clone(),
                    );

                    if lease.is_some() && lease.as_ref().unwrap().addr != mess.yiaddr {
                        lease_prune(lease.as_ref(), now);
                        lease = None;
                    }

                    if lease.is_none()
                        && !address_available(context.as_ref().unwrap(), mess.yiaddr)
                        && (dhcp_config.is_none()
                            || dhcp_config.as_ref().unwrap().addr == Ipv4Addr::UNSPECIFIED
                            || dhcp_config.as_ref().unwrap().addr != mess.yiaddr)
                    {
                        log_packet(
                            "NAK",
                            &mess.yiaddr,
                            &mess.chaddr,
                            context.as_ref().unwrap().iface.clone(),
                        );

                        mess.siaddr = Ipv4Addr::UNSPECIFIED;
                        mess.yiaddr = Ipv4Addr::UNSPECIFIED;
                        mess.ciaddr = Ipv4Addr::UNSPECIFIED;

                        bootp_option_put(mess, None, None);
                        let mut p = &mut mess.options[..];
                        p = option_put(p, OPTION_MESSAGE_TYPE, 1, DHCPNAK as u32);
                        p = option_put(p, OPTION_END, 0, 0);
                        return -(p.as_ptr() as i32 - mess as *const _ as i32);
                    }

                    // 没有租约文件，新建并添加到租约链表
                    if lease.is_none() {
                        let mut leases = LEASES.lock().unwrap();
                        let addr = mess.yiaddr;
                        let mut lease_temp = DhcpLease {
                            clid_len,
                            clid: clid_data.clone(),
                            hwaddr: [0; 6],
                            hostname: None,
                            fqdn: None,
                            expires: SystemTime::now(),
                            addr,
                            // next: None,
                        };

                        lease_set_hwaddr(&mut lease_temp, &mess.chaddr);
                        let hostname_clone = hostname.clone();
                        lease_set_hostname(
                            &mut lease_temp,
                            &hostname_clone,
                            domain_suffix,
                            &mut leases,
                        );
                        let expires_time = if renewal_time == 0xffffffff {
                            UNIX_EPOCH
                        } else {
                            SystemTime::now() + std::time::Duration::from_secs(renewal_time as u64)
                        };
                        lease_set_expires(&mut lease_temp, expires_time);

                        leases.push(lease_temp);
                    } else {
                        let mut leases = LEASES.lock().unwrap();
                        // 有对应租约，直接修改
                        lease_set_hwaddr(lease.as_mut().unwrap(), &mess.chaddr);
                        let hostname_clone = hostname.clone();
                        lease_set_hostname(
                            lease.as_mut().unwrap(),
                            &hostname_clone,
                            domain_suffix,
                            &mut leases,
                        );
                        let expires_time = if renewal_time == 0xffffffff {
                            UNIX_EPOCH
                        } else {
                            SystemTime::now() + std::time::Duration::from_secs(renewal_time as u64)
                        };
                        lease_set_expires(lease.as_mut().unwrap(), expires_time);
                    }

                    // 填充回复数据
                    bootp_option_put(mess, Some(dhcp_file.to_path_buf()), dhcp_sname.clone());
                    let mut p = &mut mess.options[..];
                    mess.siaddr = dhcp_next_server;
                    p = option_put(p, OPTION_MESSAGE_TYPE, 1, DHCPACK as u32);
                    p = option_put(
                        p,
                        OPTION_SERVER_IDENTIFIER,
                        INADDRSZ as usize,
                        u32::from_be_bytes(context.as_ref().unwrap().serv_addr.octets()),
                    );
                    p = option_put(p, OPTION_LEASE_TIME, 4, renewal_time);
                    p = do_req_options(
                        context.as_ref().unwrap(),
                        p,
                        &req_options,
                        dhcp_options,
                        domain_suffix.as_deref(),
                        None,
                    );
                    p = option_put(p, OPTION_END, 0, 0); // 结尾

                    log_packet(
                        "ACK",
                        &mess.yiaddr,
                        &mess.chaddr,
                        context.as_ref().unwrap().iface.clone(),
                    );
                    // 返回偏移量
                    return (p.as_ptr() as usize - mess as *const _ as usize)
                        .try_into()
                        .unwrap();
                }
            }

            // 客户端已有IP，仅请求其他配置参数（如DNS、域名）。
            DHCPINFORM => {
                log_packet(
                    "INFORM",
                    &mess.yiaddr,
                    &mess.chaddr,
                    context.as_ref().unwrap().iface.clone(),
                );
                let mut p = &mut mess.options[..];
                p = option_put(p, OPTION_MESSAGE_TYPE, 1, DHCPACK as u32);
                p = option_put(
                    p,
                    OPTION_SERVER_IDENTIFIER,
                    INADDRSZ as usize,
                    u32::from_be_bytes(context.as_ref().unwrap().serv_addr.octets()),
                );
                p = do_req_options(
                    context.as_ref().unwrap(),
                    p,
                    &req_options,
                    dhcp_options,
                    domain_suffix.as_deref(),
                    None,
                );
                p = option_put(p, OPTION_END, 0, 0); // 结尾

                log_packet(
                    "ACK",
                    &mess.yiaddr,
                    &mess.chaddr,
                    context.as_ref().unwrap().iface.clone(),
                );

                // 返回偏移量
                return (p.as_ptr() as usize - mess as *const _ as usize)
                    .try_into()
                    .unwrap();
            }

            _ => {
                return 0;
            }
        }
    } else {
        return 0;
    }

    0
}

// 在给定的缓冲区 buffer 中写入一个选项，并返回一个新的缓冲区切片，表示写入后的剩余部分
fn option_put(buffer: &mut [u8], option_code: u8, len: usize, value: u32) -> &mut [u8] {
    if len + 2 < buffer.len() {
        // 检查是否有足够的空间来存放选项
        let p = &mut buffer[..];

        // 写入选项代码
        p[0] = option_code;

        // 写入选项长度
        p[1] = len as u8;

        // 写入选项值
        for i in 0..len {
            p[2 + i] = (value >> (8 * (len - (i + 1)))) as u8;
        }

        // 返回新偏移量的缓冲区
        &mut buffer[(len + 2)..]
    } else {
        buffer // 如果空间不足，返回原始缓冲区
    }
}

fn option_find2(opts: &[DhcpOpt], opt: u8) -> Option<&DhcpOpt> {
    opts.iter().find(|&temp| temp.opt == opt)
}

// 处理 DHCP 协议中的各种请求，并生成相应的响应
fn do_req_options<'a>(
    context: &DhcpContext,
    buffer: &'a mut [u8],
    req_options: &[u8],
    config_opts: &[DhcpOpt],
    domainname: Option<&str>,
    hostname: Option<&str>,
) -> &'a mut [u8] {
    if req_options.is_empty() {
        return buffer;
    }

    let mut p = buffer;

    // 添加 OPTION_NETMASK
    if in_list(req_options, OPTION_NETMASK)     // 子网掩码
        && option_find2(config_opts, OPTION_NETMASK).is_none()
    {
        p = option_put(
            p,
            OPTION_NETMASK,
            INADDRSZ as usize,
            u32::from_be_bytes(context.netmask.octets()),
        );
    }

    // 添加 OPTION_BROADCAST
    if in_list(req_options, OPTION_BROADCAST)
        && option_find2(config_opts, OPTION_BROADCAST).is_none()
    {
        let broadcast = context.broadcast.octets();
        let u32_val = u32::from_be_bytes(broadcast);
        p = option_put(p, OPTION_BROADCAST, INADDRSZ as usize, u32_val);
    }

    // 添加 OPTION_ROUTER
    if in_list(req_options, OPTION_ROUTER) && option_find2(config_opts, OPTION_ROUTER).is_none() {
        let router = context.serv_addr.octets();
        let u32_val = u32::from_be_bytes(router);
        p = option_put(p, OPTION_ROUTER, INADDRSZ as usize, u32_val);
    }

    // 添加 OPTION_DNSSERVER
    if in_list(req_options, OPTION_DNSSERVER)
        && option_find2(config_opts, OPTION_DNSSERVER).is_none()
    {
        let dns_server = context.serv_addr.octets();
        let u32_val = u32::from_be_bytes(dns_server);
        p = option_put(p, OPTION_DNSSERVER, INADDRSZ as usize, u32_val);
    }

    // 添加 OPTION_DOMAINNAME
    if in_list(req_options, OPTION_DOMAINNAME)
        && option_find2(config_opts, OPTION_DOMAINNAME).is_none()
        && domainname.is_some()
        && p.len() >= domainname.unwrap().len() + 2
    {
        let domainname = domainname.unwrap();
        p[0] = OPTION_DOMAINNAME;
        p[1] = domainname.len() as u8;
        p[2..2 + domainname.len()].copy_from_slice(domainname.as_bytes());
        p = &mut p[2 + domainname.len()..];
    }

    // 添加 OPTION_HOSTNAME
    if in_list(req_options, OPTION_HOSTNAME)
        && hostname.is_some()
        && p.len() >= hostname.unwrap().len() + 2
    {
        let hostname = hostname.unwrap();
        p[0] = OPTION_HOSTNAME;
        p[1] = hostname.len() as u8;
        p[2..2 + hostname.len()].copy_from_slice(hostname.as_bytes());
        p = &mut p[2 + hostname.len()..];
    }

    // 遍历请求的选项列表，添加额外的选项
    for &req_option in req_options.iter() {
        if req_option == OPTION_END {
            break;
        }

        if let Some(opt) = option_find2(config_opts, req_option) {
            if req_option != OPTION_HOSTNAME && p.len() >= (opt.len + 2).into() {
                p[0] = opt.opt;
                p[1] = opt.len;
                p[2..2 + opt.len as usize].copy_from_slice(&opt.val);
                p = &mut p[2 + opt.len as usize..];
            }
        }
    }

    p
}

// 检查一个字节 opt 是否存在于字节数组 list 中
pub fn in_list(list: &[u8], opt: u8) -> bool {
    for &item in list {
        if item == OPTION_END {
            break;
        }
        if item == opt {
            return true;
        }
    }
    false
}

// 将 dhcp_sname 和 dhcp_file 中的内容分别设置到 DhcpPacket 结构体的 sname 和 file 字段中，并确保这些字段的长度不会超过其数组长度
fn bootp_option_put(
    packet: &mut DhcpPacket,
    dhcp_file: Option<std::path::PathBuf>,
    dhcp_sname: Option<String>,
) {
    // 清空 `sname` 和 `file` 字段
    packet.sname.fill(0);
    packet.file.fill(0);

    // 设置 `sname`，确保长度不会超过 `sname` 数组长度
    if let Some(sname) = dhcp_sname {
        if !sname.is_empty() {
            let sname_len = std::cmp::min(packet.sname.len() - 1, sname.len());
            packet.sname[..sname_len].copy_from_slice(&sname.as_bytes()[..sname_len]);
        }
    }

    // 设置 `file`，确保长度不会超过 `file` 数组长度
    if let Some(file_str) = dhcp_file {
        let file_cow = file_str.to_string_lossy();
        let file_bytes = file_cow.as_bytes();
        let file_len = std::cmp::min(packet.file.len() - 1, file_bytes.len());
        packet.file[..file_len].copy_from_slice(&file_bytes[..file_len]);
    }
}

fn option_ptr(opt: &[u8]) -> &[u8] {
    &opt[2..]
}

fn option_len(opt: &[u8]) -> usize {
    opt[1] as usize
}

fn option_uint(opt: &[u8]) -> u32 {
    // 确保字节长度足够
    assert!(opt.len() >= std::mem::size_of::<u32>());

    // 将前四个字节转换为 u32，处理未对齐数据和字节顺序
    u32::from_be_bytes([opt[0], opt[1], opt[2], opt[3]])
}

fn option_addr(opt: &[u8]) -> Ipv4Addr {
    // 确保字节长度足够
    let opt = option_ptr(opt);
    assert!(opt.len() >= std::mem::size_of::<u32>());

    // 将前四个字节转换为 IPv4 地址
    Ipv4Addr::new(opt[0], opt[1], opt[2], opt[3])
}
// 在 DHCP 数据包中查找指定的选项
pub fn option_find(packet: &DhcpPacket, sz: usize, option: u8) -> Option<&[u8]> {
    // 内部辅助函数，用于查找指定的 DHCP 选项
    fn find<'a>(data: &'a [u8], end: usize, option: u8, overload: &mut u8) -> Option<&'a [u8]> {
        let mut i = 0;
        while i < data.len() {
            if data[i] == OPTION_END {
                break; // 找到选项结束标志
            } else if data[i] == OPTION_PAD {
                i += 1; // 跳过填充字节
                continue;
            } else if data[i] == OPTION_OVERLOAD {
                // 检查是否越界
                if i + 2 >= data.len() || i + 2 >= end {
                    return None; // 数据包格式错误
                }
                *overload = data[i + 2]; // 记录 overload 值
                i += 3; // 跳过 overload 选项及其值
            } else {
                // 检查是否越界
                if i + 1 >= data.len() || i + 1 >= end {
                    return None; // 数据包格式错误
                }
                let opt_len = data[i + 1] as usize; // 获取选项长度
                                                    // 再次检查是否越界
                if i + 2 + opt_len > data.len() || i + 2 + opt_len > end {
                    return None; // 数据包格式错误
                }
                if data[i] == option {
                    return Some(&data[i..i + 2 + opt_len]); // 找到目标选项
                }
                i += 2 + opt_len; // 跳过当前选项及其值
            }
        }
        None // 未找到目标选项
    }

    let mut overload: u8 = 0;
    let size_limit = sz.min(packet.options.len()); // 限制搜索范围为 options 的长度

    // 在 options 字段中查找目标选项
    if let Some(result) = find(&packet.options, size_limit, option, &mut overload) {
        return Some(result);
    }

    // 如果 overload 指定了 file 字段，继续查找
    if (overload & 1) != 0 {
        if let Some(result) = find(&packet.file, packet.file.len(), option, &mut overload) {
            return Some(result);
        }
    }

    // 如果 overload 指定了 sname 字段，继续查找
    if (overload & 2) != 0 {
        if let Some(result) = find(&packet.sname, packet.sname.len(), option, &mut overload) {
            return Some(result);
        }
    }

    None // 未找到目标选项
}

fn log_packet(type_: &str, addr: &Ipv4Addr, hwaddr: &[u8], interface: String) {
    let addr_str = if addr.is_unspecified() {
        "".to_string()
    } else {
        format!(" {}", addr)
    };

    // Extract hardware address bytes to avoid macro parsing issues
    let hw0 = hwaddr[0];
    let hw1 = hwaddr[1];
    let hw2 = hwaddr[2];
    let hw3 = hwaddr[3];
    let hw4 = hwaddr[4];
    let hw5 = hwaddr[5];

    syslog!(
        LOG_INFO,
        "DHCP{}({}){} hwaddr={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        type_,
        interface,
        addr_str,
        hw0,
        hw1,
        hw2,
        hw3,
        hw4,
        hw5
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnsmasq::{DhcpContext, DhcpOpt};

    /// 测试 option_put 函数的基本功能
    #[test]
    fn test_option_put_basic() {
        // 创建一个足够大的缓冲区
        let mut buffer_array = [0u8; 20];
        let buffer_slice = &mut buffer_array[..];

        // 测试写入一个简单的选项
        option_put(buffer_slice, OPTION_NETMASK, 4, 0xFF);

        // 验证选项代码 - 使用原始缓冲区的切片来访问数据
        assert_eq!(buffer_array[0], OPTION_NETMASK);
        // 验证选项长度
        assert_eq!(buffer_array[1], 4);
        // 验证选项值（4字节的 0xFF）
        assert_eq!(buffer_array[2], 0x00);
        assert_eq!(buffer_array[3], 0x00);
        assert_eq!(buffer_array[4], 0x00);
        assert_eq!(buffer_array[5], 0xFF);
    }

    /// 测试 option_put 函数处理不同长度的选项
    #[test]
    fn test_option_put_different_lengths() {
        // 测试写入1字节选项
        let mut buffer1 = [0u8; 10];
        let remaining1_len =
            option_put(&mut buffer1, OPTION_MESSAGE_TYPE, 1, DHCPDISCOVER as u32).len();

        assert_eq!(buffer1[0], OPTION_MESSAGE_TYPE);
        assert_eq!(buffer1[1], 1);
        assert_eq!(buffer1[2], DHCPDISCOVER);
        assert_eq!(remaining1_len, 10 - 3);

        // 测试写入2字节选项
        let mut buffer2 = [0u8; 10];
        let remaining2_len = option_put(&mut buffer2, OPTION_MAXMESSAGE, 2, 0x1234).len();

        assert_eq!(buffer2[0], OPTION_MAXMESSAGE);
        assert_eq!(buffer2[1], 2);
        assert_eq!(buffer2[2], 0x12); // 高位字节
        assert_eq!(buffer2[3], 0x34); // 低位字节
        assert_eq!(remaining2_len, 10 - 4);
    }

    /// 测试 option_put 函数处理缓冲区不足的情况
    #[test]
    fn test_option_put_insufficient_buffer() {
        // 创建一个太小的缓冲区
        let mut buffer = [0u8; 3]; // 只能容纳选项代码和长度，无法容纳值

        // 尝试写入4字节的选项
        let remaining = option_put(&mut buffer, OPTION_NETMASK, 4, 0xFF);

        // 应该返回原始缓冲区，因为空间不足
        assert_eq!(remaining.len(), buffer.len());
        // 缓冲区应该没有被修改
        assert_eq!(buffer, [0, 0, 0]);
    }

    /// 测试 option_put 函数连续写入多个选项
    #[test]
    fn test_option_put_multiple_options() {
        let mut buffer = [0u8; 30];

        // 写入第一个选项
        let _remaining_len =
            option_put(&mut buffer, OPTION_MESSAGE_TYPE, 1, DHCPDISCOVER as u32).len();

        // 验证第一个选项
        assert_eq!(buffer[0], OPTION_MESSAGE_TYPE);
        assert_eq!(buffer[1], 1);
        assert_eq!(buffer[2], DHCPDISCOVER);

        // 在剩余空间中写入第二个选项
        let remaining_len2 = option_put(&mut buffer[3..], OPTION_NETMASK, 4, 0xFFFFFF00).len();

        // 验证第二个选项的位置
        assert_eq!(buffer[3], OPTION_NETMASK);
        assert_eq!(buffer[4], 4);
        assert_eq!(buffer[5], 0xFF);
        assert_eq!(buffer[6], 0xFF);
        assert_eq!(buffer[7], 0xFF);
        assert_eq!(buffer[8], 0x00);

        // 验证剩余空间
        assert_eq!(remaining_len2, 30 - 9);
    }

    /// 测试 do_req_options 函数的基本功能
    #[test]
    fn test_do_req_options_basic() {
        // 创建测试用的 DhcpContext
        let context = DhcpContext {
            serv_addr: Ipv4Addr::new(192, 168, 1, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::new(192, 168, 1, 255),
            ..Default::default()
        };

        // 创建测试用的配置选项
        // let config_opts = vec![
        //     DhcpOpt { opt: OPTION_NETMASK, len: 0, val: Vec::new(), next: None },
        //     DhcpOpt { opt: OPTION_ROUTER, len: 0, val: Vec::new(), next: None },
        //     DhcpOpt { opt: OPTION_DNSSERVER, len: 0, val: Vec::new(), next: None },
        //     DhcpOpt { opt: OPTION_BROADCAST, len: 0, val: Vec::new(), next: None },
        //     DhcpOpt { opt: OPTION_DOMAINNAME, len: 0, val: Vec::new(), next: None },
        // ];
        let config_opts = Vec::new();

        // 创建请求的选项列表
        let req_options = [OPTION_NETMASK, OPTION_ROUTER, OPTION_END];

        // 创建足够大的缓冲区
        let mut buffer = [0u8; 100];

        // 调用 do_req_options 函数
        let result = do_req_options(
            &context,
            &mut buffer,
            &req_options,
            &config_opts,
            Some("example.com"),
            Some("testhost"),
        );

        // 验证返回的缓冲区切片长度正确
        assert!(
            result.len() < buffer.len(),
            "返回的缓冲区应该比原始缓冲区小"
        );

        // 验证缓冲区中写入了正确的选项
        // OPTION_NETMASK 应该被写入
        assert_eq!(buffer[0], OPTION_NETMASK);
        assert_eq!(buffer[1], 4); // IPv4地址长度
    }

    /// 测试 do_req_options 函数处理空请求选项的情况
    #[test]
    fn test_do_req_options_empty_request() {
        let context = DhcpContext::default();
        let config_opts = Vec::new();
        let req_options: [u8; 0] = [];
        let mut buffer = [0u8; 100];
        let original_buffer_len = buffer.len();
        let original_buffer_ptr = buffer.as_mut_ptr();

        // 调用函数，请求选项为空
        let result = do_req_options(
            &context,
            &mut buffer,
            &req_options,
            &config_opts,
            None,
            None,
        );

        // 当请求选项为空时，应该返回原始缓冲区
        assert_eq!(result.len(), original_buffer_len);
        assert_eq!(result.as_ptr(), original_buffer_ptr);
    }

    /// 测试 do_req_options 函数处理不存在的请求选项
    #[test]
    fn test_do_req_options_nonexistent_options() {
        let context = DhcpContext::default();
        let config_opts = Vec::new(); // 空的配置选项
        let req_options = [99, 100, OPTION_END]; // 不存在的选项代码
        let mut buffer = [0u8; 100];
        let original_buffer_len = buffer.len();
        let original_buffer_ptr = buffer.as_mut_ptr();

        // 调用函数
        let result = do_req_options(
            &context,
            &mut buffer,
            &req_options,
            &config_opts,
            None,
            None,
        );

        // 当请求的选项在配置中不存在时，应该返回原始缓冲区
        assert_eq!(result.len(), original_buffer_len);
        assert_eq!(result.as_ptr(), original_buffer_ptr);

        // 缓冲区应该保持原样（全为0）
        assert!(buffer.iter().all(|&b| b == 0));
    }

    /// 测试 do_req_options 函数处理域名和主机名选项
    #[test]
    fn test_do_req_options_domain_and_hostname() {
        let context = DhcpContext::default();

        // 创建包含域名和主机名选项的配置
        // let config_opts = vec![
        //     DhcpOpt { opt: OPTION_DOMAINNAME, len: 14, val: "testdomain.com".as_bytes().to_vec(), next: None },
        // ];
        let config_opts = Vec::new();

        let req_options = [OPTION_DOMAINNAME, OPTION_HOSTNAME, OPTION_END];
        let mut buffer = [0u8; 100];

        let _result = do_req_options(
            &context,
            &mut buffer,
            &req_options,
            &config_opts,
            Some("testdomain.com"),
            Some("testhost"),
        );

        // 验证域名选项被正确写入
        assert_eq!(buffer[0], OPTION_DOMAINNAME);
        assert_eq!(buffer[1], "testdomain.com".len() as u8);

        // 验证主机名选项被正确写入
        let domainname_len = "testdomain.com".len();
        let hostname_start = 2 + domainname_len;
        assert_eq!(buffer[hostname_start], OPTION_HOSTNAME);
        assert_eq!(buffer[hostname_start + 1], "testhost".len() as u8);
    }

    /// 测试 do_req_options 函数处理缓冲区不足的情况
    #[test]
    fn test_do_req_options_insufficient_buffer() {
        let context = DhcpContext {
            serv_addr: Ipv4Addr::new(192, 168, 1, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            ..Default::default()
        };

        let config_opts = vec![
            DhcpOpt {
                opt: OPTION_NETMASK,
                len: 4,
                val: Ipv4Addr::new(255, 0, 0, 0).octets().to_vec(),
                // next: None,
            },
            DhcpOpt {
                opt: OPTION_ROUTER,
                len: 4,
                val: Ipv4Addr::new(255, 0, 0, 1).octets().to_vec(),
                // next: None,
            },
        ];

        let req_options = [OPTION_NETMASK, OPTION_ROUTER, OPTION_END];

        // 创建太小的缓冲区（只能容纳一个选项）
        let mut buffer = [0u8; 10];
        let original_buffer_ptr = buffer.as_mut_ptr();

        let buffer_len = buffer.len();
        let result = do_req_options(
            &context,
            &mut buffer,
            &req_options,
            &config_opts,
            None,
            None,
        );

        // 当缓冲区不足时，函数应该正确处理并返回剩余缓冲区
        assert!(result.len() <= buffer_len);
        assert_eq!(result.as_ptr(), original_buffer_ptr.wrapping_add(6)); // 第一个选项占用了6字节
    }

    /// 测试 do_req_options 函数处理各种IP地址选项
    #[test]
    fn test_do_req_options_ip_address_options() {
        let context = DhcpContext {
            serv_addr: Ipv4Addr::new(10, 0, 0, 1),
            netmask: Ipv4Addr::new(255, 0, 0, 0),
            broadcast: Ipv4Addr::new(10, 255, 255, 255),
            ..Default::default()
        };

        let config_opts = vec![
            DhcpOpt {
                opt: OPTION_NETMASK,
                len: 4,
                val: Ipv4Addr::new(255, 0, 0, 0).octets().to_vec(),
                // next: None,
            },
            DhcpOpt {
                opt: OPTION_BROADCAST,
                len: 4,
                val: Ipv4Addr::new(255, 0, 0, 1).octets().to_vec(),
                // next: None,
            },
            DhcpOpt {
                opt: OPTION_ROUTER,
                len: 4,
                val: Ipv4Addr::new(255, 0, 0, 2).octets().to_vec(),
                // next: None,
            },
            DhcpOpt {
                opt: OPTION_DNSSERVER,
                len: 4,
                val: Ipv4Addr::new(255, 0, 0, 3).octets().to_vec(),
                // next: None,
            },
        ];
        // let config_opts = Vec::new();

        let req_options = [
            OPTION_NETMASK,
            OPTION_BROADCAST,
            OPTION_ROUTER,
            OPTION_DNSSERVER,
            OPTION_END,
        ];

        let mut buffer = [0u8; 50];
        let original_buffer_len = buffer.len();

        let result = do_req_options(
            &context,
            &mut buffer,
            &req_options,
            &config_opts,
            None,
            None,
        );

        // 验证返回的缓冲区长度正确
        let expected_used_bytes = 4 * 6; // 4个选项，每个占用6字节
        assert_eq!(result.len(), original_buffer_len - expected_used_bytes);

        // 验证每个选项都被正确写入
        let mut pos = 0;

        // OPTION_NETMASK
        assert_eq!(buffer[pos], OPTION_NETMASK);
        assert_eq!(buffer[pos + 1], 4);
        pos += 6;

        // OPTION_BROADCAST
        assert_eq!(buffer[pos], OPTION_BROADCAST);
        assert_eq!(buffer[pos + 1], 4);
        pos += 6;

        // OPTION_ROUTER
        assert_eq!(buffer[pos], OPTION_ROUTER);
        assert_eq!(buffer[pos + 1], 4);
        pos += 6;

        // OPTION_DNSSERVER
        assert_eq!(buffer[pos], OPTION_DNSSERVER);
        assert_eq!(buffer[pos + 1], 4);
    }

    /// 测试 do_req_options 函数处理边界情况
    #[test]
    fn test_do_req_options_edge_cases() {
        let context = DhcpContext::default();
        let config_opts = Vec::new();

        // 测试只有 OPTION_END 的情况
        let req_options_end_only = [OPTION_END];
        let mut buffer1 = [0u8; 10];
        let original_buffer1_len = buffer1.len();
        let original_buffer1_ptr = buffer1.as_mut_ptr();

        let result1 = do_req_options(
            &context,
            &mut buffer1,
            &req_options_end_only,
            &config_opts,
            None,
            None,
        );

        // 当只有 OPTION_END 时，应该立即返回原始缓冲区
        assert_eq!(result1.len(), original_buffer1_len);
        assert_eq!(result1.as_ptr(), original_buffer1_ptr);

        // 测试包含 OPTION_PAD 的情况
        let req_options_with_pad = [OPTION_PAD, OPTION_NETMASK, OPTION_END];
        let config_opts_with_netmask = vec![DhcpOpt {
            opt: OPTION_NETMASK,
            len: 0,
            val: Vec::new(),
            // next: None,
        }];
        let mut buffer2 = [0u8; 20];

        let _result2 = do_req_options(
            &context,
            &mut buffer2,
            &req_options_with_pad,
            &config_opts_with_netmask,
            None,
            None,
        );

        // OPTION_PAD 应该被忽略，OPTION_NETMASK 应该被处理
        assert_eq!(buffer2[0], OPTION_NETMASK);
    }

    /// 测试 do_req_options 函数处理自定义选项
    #[test]
    fn test_do_req_options_custom_options() {
        let context = DhcpContext::default();

        // 创建包含自定义选项的配置
        let config_opts = vec![
            DhcpOpt {
                opt: 100,
                len: 5,
                val: "value".as_bytes().to_vec(),
                // next: None,
            },
            DhcpOpt {
                opt: 101,
                len: 3,
                val: "val".as_bytes().to_vec(),
                // next: None,
            },
        ];

        let req_options = [100, 101, OPTION_END];
        let mut buffer = [0u8; 50];

        let _result = do_req_options(
            &context,
            &mut buffer,
            &req_options,
            &config_opts,
            None,
            None,
        );

        // 验证自定义选项被正确写入
        assert_eq!(buffer[0], 100);
        assert_eq!(buffer[1], 5);
        assert_eq!(&buffer[2..7], b"value");

        // 第二个自定义选项
        assert_eq!(buffer[7], 101);
        assert_eq!(buffer[8], 3);
        assert_eq!(&buffer[9..12], b"val");
    }

    /// 测试 do_req_options 函数返回值的一致性
    #[test]
    fn test_do_req_options_return_value_consistency() {
        let context = DhcpContext {
            serv_addr: Ipv4Addr::new(192, 168, 1, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            ..Default::default()
        };

        let config_opts = Vec::new();

        let req_options = [OPTION_NETMASK, OPTION_END];
        let mut buffer = [0u8; 100];

        // 多次调用，验证返回值的一致性
        for _ in 0..5 {
            let result = do_req_options(
                &context,
                &mut buffer,
                &req_options,
                &config_opts,
                None,
                None,
            );

            // 每次调用应该返回相同的缓冲区位置和长度
            assert_eq!(result.len(), 94); // 100 - 6 (一个选项占6字节)
            assert_eq!(result.as_ptr(), buffer.as_mut_ptr().wrapping_add(6));

            // 重置缓冲区
            buffer.fill(0);
        }
    }
}
