/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use crate::lease::*;
use crate::util::*;
use crate::*;

const OPTION_END: u8 = 255;
const OPTION_PAD: u8 = 0;
const OPTION_OVERLOAD: u8 = 52;
const OPTION_NETMASK: u8 = 1;
const OPTION_BROADCAST: u8 = 28;
const OPTION_ROUTER: u8 = 3;
const OPTION_DNSSERVER: u8 = 6;
const OPTION_DOMAINNAME: u8 = 15;
const OPTION_HOSTNAME: u8 = 12;
const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;
const DHCP_COOKIE: u32 = 0x63825363;
const OPTION_MESSAGE_TYPE: u8 = 53;
const DHCPDISCOVER: u8 = 1;
const DHCPOFFER: u8 = 2;
const DHCPREQUEST: u8 = 3;
const DHCPACK: u8 = 5;
const ARPHRD_ETHER: u8 = 1;
const OPTION_CLIENT_ID: u8 = 61;
const OPTION_REQUESTED_OPTIONS: u8 = 55;
const OPTION_LEASE_TIME: u8 = 51;
const OPTION_REQUESTED_IP: u8 = 50;
const OPTION_SERVER_IDENTIFIER: u8 = 54;
const INADDRSZ: usize = 4;
const DHCPNAK: u8 = 6;
const DHCPINFORM: u8 = 8;

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

// 处理 DHCP 协议中的各种请求，并生成相应的响应
pub fn dhcp_reply(
    context: &DhcpContext,
    packet: &mut DhcpPacket,
    sz: usize,
    now: SystemTime,
    namebuff: &mut [u8],
    dhcp_opts: &DhcpOpt,
    mut dhcp_configs: &mut Option<Box<DhcpConfig>>,
    domain_suffix: &str,
    dhcp_file: &mut Option<String>,
    dhcp_sname: &mut Option<String>,
    dhcp_next_server: InAddr,
) -> i32 {
    let mut hostname: Option<String> = None;
    let req_options: Option<String> = None;
    let mut p: &mut [u8] = &mut packet.options.clone();
    // 验证基本条件
    if packet.op != BOOTREQUEST
        || packet.htype != ARPHRD_ETHER
        || packet.hlen as usize != ETHER_ADDR_LEN
        || packet.cookie != DHCP_COOKIE.to_be()
    {
        return 0;
    }

    packet.op = BOOTREPLY;

    // 客户端标识符 (Client Identifier) 检查
    let (clid, clid_len) = if let Some(opt) = option_find(packet, sz, OPTION_CLIENT_ID) {
        (option_ptr(opt), option_len(opt) as usize)
    } else {
        (&packet.chaddr[..ETHER_ADDR_LEN], 0) // 使用硬件地址
    };

    // 查找客户端租约
    let mut lease = lease_find_by_client(clid, clid_len);

    if let Some(opt) = option_find(&packet, sz, OPTION_REQUESTED_OPTIONS) {
        let len = option_len(&opt);
        let mut req_options = Vec::with_capacity(len + 1);
        req_options.extend_from_slice(&option_ptr(&opt)[..len]);
        req_options.push(OPTION_END);
    }

    let config = find_config(
        &mut dhcp_configs,
        Some(context),
        (&clid).to_vec(),
        clid_len,
        &packet.chaddr,
        None,
    );
    if let Some(ref h_name) = config {
        if h_name.hostname.is_some() && config.is_some() {
            hostname = h_name.hostname.clone();
        }
    }

    // 如果配置中没有主机名，则在消息中查找 OPTION_HOSTNAME 选项
    if let Some(opt) = option_find(&packet, sz, OPTION_HOSTNAME) {
        let len = option_len(&opt);

        // 使用 namebuff 的后半部分存储主机名
        let hostname_slice = &mut namebuff[500..500 + len];
        hostname_slice.copy_from_slice(&option_ptr(&opt)[..len]);

        // 将字节切片转换为字符串，确保它是有效的 UTF-8
        if let Ok(hostname_str) = std::str::from_utf8(&hostname_slice[..len]) {
            // 确保字符串被标准化
            if canonicalise(hostname_str).is_some() {
                hostname = None;
            }
        }
    }

    if let Some(ref mut host) = hostname {
        if let Some(dot_idx) = host.find('.') {
            let domain_part = &host[dot_idx + 1..];
            if domain_suffix.is_empty() || !hostname_isequal(domain_part, domain_suffix) {
                syslog!(
                    LOG_WARNING,
                    "Ignoring DHCP host name {} because it has an illegal domain part",
                    host
                );
                hostname = None;
            } else {
                host.truncate(dot_idx);
            }
        }
    }

    let config = find_config(
        &mut dhcp_configs,
        Some(context),
        clid.to_vec(),
        clid_len,
        &packet.chaddr,
        hostname.as_deref(),
    );

    let def_time = config.clone().map_or(context.lease_time, |c| c.lease_time);
    let (renewal_time, expires_time) = if let Some(opt) = option_find(packet, sz, OPTION_LEASE_TIME)
    {
        let req_time = option_uint(opt);
        if def_time == 0xffffffff || (req_time != 0xffffffff && req_time < def_time) {
            (req_time, req_time)
        } else {
            (def_time, def_time)
        }
    } else {
        let renewal_time = def_time;
        let expires_time = if let Some(lease) = &lease {
            let now = SystemTime::now();
            let expires_time = UNIX_EPOCH + Duration::from_secs(lease.expires);
            expires_time
                .duration_since(now)
                .unwrap_or(Duration::ZERO)
                .as_secs() as u32
        } else {
            def_time
        };
        (renewal_time, expires_time)
    };

    if let Some(opt) = option_find(packet, sz, OPTION_MESSAGE_TYPE) {
        match opt[2] {
            DHCPRELEASE => {
                if let Some(lease) = &lease {
                    lease_prune(Some(lease.clone()), now);
                }
                return 0;
            }
            DHCPDISCOVER => {
                if let Some(opt) = option_find(packet, sz, OPTION_REQUESTED_IP) {
                    packet.yiaddr = option_addr(opt);
                }
                if let Some(lease) = lease {
                    packet.yiaddr = lease.addr;
                } else if let Some(config) = config {
                    if config.addr.s_addr != 0 && lease_find_by_addr(config.addr) {
                        packet.yiaddr = config.addr;
                    } else if packet.yiaddr.s_addr == 0
                        || !address_available(context, packet.yiaddr)
                    {
                        if !address_allocate(context, &mut dhcp_configs, &mut packet.yiaddr) {
                            return 0;
                        }
                    }
                }

                bootp_option_put(packet, dhcp_file, dhcp_sname);
                packet.siaddr = dhcp_next_server;
                packet.siaddr = dhcp_next_server;
                let end = &packet.options[308..];
                // 添加 OPTION_MESSAGE_TYPE 选项
                let mut p = option_put(p, end, OPTION_MESSAGE_TYPE, 1, DHCPOFFER);
                // 添加 OPTION_SERVER_IDENTIFIER 选项
                let u32_val = u32::from_be_bytes(context.serv_addr.s_addr.octets());
                p = option_put(
                    p,
                    end,
                    OPTION_SERVER_IDENTIFIER,
                    INADDRSZ,
                    u32_val.try_into().unwrap(),
                );
                // 添加 OPTION_LEASE_TIME 选项
                p = option_put(
                    p,
                    end,
                    OPTION_LEASE_TIME,
                    INADDRSZ,
                    expires_time.try_into().unwrap(),
                );
                // 添加请求选项
                p = do_req_options(
                    context,
                    p,
                    end,
                    req_options,
                    dhcp_opts,
                    Some(domain_suffix),
                    None,
                );
                // 添加 OPTION_END 选项
                p = option_put(p, end, OPTION_END, 0, 0);

                // 返回偏移量
                return (p.as_ptr() as usize - packet as *const _ as usize)
                    .try_into()
                    .unwrap();
            }
            DHCPREQUEST => {
                if packet.ciaddr != InAddr::new(0) {
                    // RENEWING or REBINDING
                    // 必须存在此地址的租约
                    if lease.is_none() {
                        packet.siaddr = InAddr::new(0);
                        packet.yiaddr = InAddr::new(0);
                        packet.ciaddr = InAddr::new(0);
                        bootp_option_put(&mut packet.clone(), &mut None, &mut None);
                        let end = &packet.options[308..];
                        p = option_put(p, end, OPTION_MESSAGE_TYPE, 1, DHCPNAK);
                        p = option_put(p, end, OPTION_END, 0, 0);

                        return -(p.as_ptr() as i32 - packet as *const _ as i32);
                        // 返回负值以强制广播
                    }

                    packet.yiaddr = packet.ciaddr;
                } else {
                    // SELECTING 或 INIT_REBOOT
                    if let Some(opt) = option_find(packet, sz, OPTION_SERVER_IDENTIFIER) {
                        if context.serv_addr != option_addr(opt) {
                            return 0;
                        }
                    }
                    if let Some(_opt) = option_find(packet, sz, OPTION_REQUESTED_IP) {
                    } else {
                        return 0;
                    }

                    // 如果有租约并且地址与请求的地址不匹配，则删除该租约
                    if let Some(leases) = &lease {
                        if leases.addr != packet.yiaddr {
                            lease_prune(Some(leases.clone()), now);
                            lease = None;
                        }
                    }

                    // 接受动态范围内的地址，或已分配给特定主机的静态地址，或主机已经拥有的地址
                    if lease.is_none()
                        && !address_available(context, packet.yiaddr)
                        && (config.is_none()
                            || config.as_ref().unwrap().addr == InAddr::new(0)
                            || config.as_ref().unwrap().addr != packet.yiaddr)
                    {
                        packet.siaddr = InAddr::new(0);
                        packet.yiaddr = InAddr::new(0);
                        packet.ciaddr = InAddr::new(0);
                        let end = &packet.options[308..];
                        bootp_option_put(&mut packet.clone(), &mut None, &mut None);
                        p = option_put(p, end, OPTION_MESSAGE_TYPE, 1, DHCPNAK);
                        p = option_put(p, end, OPTION_END, 0, 0);

                        return -(p.as_ptr() as i32 - packet as *const _ as i32);
                        // 返回负值以强制广播
                    }

                    if lease.is_none() {
                        let mut yiaddr = packet.yiaddr;
                        if !address_allocate(context, &mut dhcp_configs, &mut yiaddr) {
                            return 0;
                        }
                        lease = lease_allocate(Some(clid), clid_len, packet.yiaddr);
                        if lease.is_none() {
                            return 0;
                        }
                    }

                    // 设置租约硬件地址
                    lease_set_hwaddr(&mut lease, &packet.chaddr);

                    // 设置租约主机名和域名后缀
                    if let Some(ref mut lease) = lease {
                        lease_set_hostname(
                            hostname.as_deref(),
                            Some(domain_suffix.to_string()),
                            lease,
                        );
                    }
                    // 设置租约过期时间
                    let expiration_time = if renewal_time == 0xffffffff {
                        0 // 永不过期，用 0 表示
                    } else {
                        let now = SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .expect("Time went backwards");
                        (now + Duration::from_secs(renewal_time.into())).as_secs()
                    };

                    lease_set_expires(&mut lease, expiration_time);

                    // 设置 BOOTP 选项
                    bootp_option_put(packet, dhcp_file, dhcp_sname);

                    // 设置下一跳服务器的地址
                    packet.siaddr = dhcp_next_server;

                    // 添加 OPTION_MESSAGE_TYPE 选项
                    let end = &packet.options[308..];
                    let p = option_put(p, end, OPTION_MESSAGE_TYPE, 1, DHCPACK);

                    // 添加 OPTION_SERVER_IDENTIFIER 选项
                    let server_identifier = context.serv_addr.s_addr.octets();
                    let u32_val = u32::from_be_bytes(server_identifier);
                    let p = option_put(
                        p,
                        end,
                        OPTION_SERVER_IDENTIFIER,
                        4,
                        u32_val.try_into().unwrap(),
                    );

                    // 添加 OPTION_LEASE_TIME 选项
                    let lease_time = renewal_time.to_be_bytes();
                    let u32_val = u32::from_be_bytes(lease_time);
                    let p = option_put(p, end, OPTION_LEASE_TIME, 4, u32_val.try_into().unwrap());

                    // 处理请求的选项
                    let p = do_req_options(
                        context,
                        p,
                        end,
                        req_options.clone(),
                        dhcp_opts,
                        Some(domain_suffix),
                        hostname.as_deref(),
                    );

                    // 添加 OPTION_END 选项
                    let p = option_put(p, end, OPTION_END, 0, 0);

                    // 记录 ACK 包信息

                    // 返回偏移量
                    return p.as_ptr() as i32 - packet as *const _ as i32;
                }
            }
            DHCPINFORM => {
                let end = &packet.options[308..];
                // 添加 OPTION_MESSAGE_TYPE 选项
                let p = option_put(p, end, OPTION_MESSAGE_TYPE, 1, DHCPACK);

                // 添加 OPTION_SERVER_IDENTIFIER 选项
                let server_identifier = context.serv_addr.s_addr.octets();
                let u32_val = u32::from_be_bytes(server_identifier);
                let p = option_put(
                    p,
                    end,
                    OPTION_SERVER_IDENTIFIER,
                    4,
                    u32_val.try_into().unwrap(),
                );

                // 添加请求的选项
                let p = do_req_options(
                    context,
                    p,
                    end,
                    req_options,
                    dhcp_opts,
                    Some(domain_suffix),
                    hostname.as_deref(),
                );

                // 添加 OPTION_END 选项
                let p = option_put(p, end, OPTION_END, 0, 0);

                // 返回偏移量
                return p.as_ptr() as i32 - packet as *const _ as i32;
            }
        }
    }

    0
}

// 处理 DHCP 协议中的各种请求，并生成相应的响应
fn do_req_options<'a>(
    context: &DhcpContext,
    mut p: &'a mut [u8],
    end: &'a [u8],
    req_options: Option<String>,
    config_opts: &DhcpOpt,
    domainname: Option<&str>,
    hostname: Option<&str>,
) -> &'a mut [u8] {
    if req_options.is_none() {
        return p;
    }

    let req_options = req_options.unwrap();
    let req_options_bytes = req_options.as_bytes();

    // 添加 OPTION_NETMASK
    if in_list(req_options_bytes, OPTION_NETMASK)
        && !option_find_dhcp(config_opts, OPTION_NETMASK).is_none()
    {
        let netmask = context.broadcast.s_addr.octets();
        let u32_val = u32::from_be_bytes(netmask);
        p = option_put(
            p,
            end,
            OPTION_NETMASK,
            INADDRSZ,
            u32_val.try_into().unwrap(),
        );
    }

    // 添加 OPTION_BROADCAST
    if in_list(req_options_bytes, OPTION_BROADCAST)
        && !option_find_dhcp(config_opts, OPTION_BROADCAST).is_none()
    {
        let broadcast = context.broadcast.s_addr.octets();
        let u32_val = u32::from_be_bytes(broadcast);
        p = option_put(
            p,
            end,
            OPTION_BROADCAST,
            INADDRSZ,
            u32_val.try_into().unwrap(),
        );
    }

    // 添加 OPTION_ROUTER
    if in_list(req_options_bytes, OPTION_ROUTER)
        && !option_find_dhcp(config_opts, OPTION_ROUTER).is_none()
    {
        let router = context.serv_addr.s_addr.octets();
        let u32_val = u32::from_be_bytes(router);
        p = option_put(p, end, OPTION_ROUTER, INADDRSZ, u32_val.try_into().unwrap());
    }

    // 添加 OPTION_DNSSERVER
    if in_list(req_options_bytes, OPTION_DNSSERVER)
        && !option_find_dhcp(config_opts, OPTION_DNSSERVER).is_none()
    {
        let dns_server = context.serv_addr.s_addr.octets();
        let u32_val = u32::from_be_bytes(dns_server);
        p = option_put(
            p,
            end,
            OPTION_DNSSERVER,
            INADDRSZ,
            u32_val.try_into().unwrap(),
        );
    }

    // 添加 OPTION_DOMAINNAME
    if in_list(req_options_bytes, OPTION_DOMAINNAME)
        && !option_find_dhcp(config_opts, OPTION_DOMAINNAME).is_none()
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
    if in_list(req_options_bytes, OPTION_HOSTNAME)
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
    for &req_option in req_options_bytes.iter() {
        if req_option == OPTION_END {
            break;
        }

        if let Some(opt) = option_find_dhcp(config_opts, req_option) {
            if req_option != OPTION_HOSTNAME && p.len() >= (opt.len + 2).into() {
                p[0] = opt.opt;
                p[1] = opt.len as u8;
                p[2..2 + opt.len as usize].copy_from_slice(&opt.val);
                p = &mut p[2 + opt.len as usize..];
            }
        }
    }

    p
}

// DHCP 选项链表中查找指定的选项
pub fn option_find_dhcp(dhcp_opts: &DhcpOpt, option: u8) -> Option<&DhcpOpt> {
    let mut current = Some(dhcp_opts);

    while let Some(opt) = current {
        if opt.opt == option {
            return Some(opt);
        }
        current = opt.next.as_deref(); // 获取链表的下一个节点
    }

    None
}

// 在给定的缓冲区 buffer 中写入一个选项，并返回一个新的缓冲区切片，表示写入后的剩余部分
fn option_put<'a>(
    buffer: &'a mut [u8],
    end: &'a [u8],
    option_code: u8,
    length: usize,
    value: u8,
) -> &'a mut [u8] {
    if buffer.len() + length + 2 < end.len() {
        // 检查是否有足够的空间来存放选项
        let p = &mut buffer[..];

        // 写入选项代码
        p[0] = option_code;

        // 写入选项长度
        p[1] = length as u8;

        // 写入选项值
        for i in 0..length {
            p[2 + i] = (value >> (8 * (length - (i + 1)))) as u8;
        }

        // 返回新偏移量的缓冲区
        &mut buffer[(length + 2)..]
    } else {
        buffer // 如果空间不足，返回原始缓冲区
    }
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
    dhcp_file: &mut Option<String>,
    dhcp_sname: &mut Option<String>,
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
    if let Some(file) = dhcp_file {
        if !file.is_empty() {
            let file_len = std::cmp::min(packet.file.len() - 1, file.len());
            packet.file[..file_len].copy_from_slice(&file.as_bytes()[..file_len]);
        }
    }
}

fn option_addr(opt: &[u8]) -> InAddr {
    InAddr::new(0)
}

pub fn option_ptr(opt: &[u8]) -> &[u8] {
    &opt[2..]
}

pub fn option_len(opt: &[u8]) -> usize {
    opt[1] as usize
}

fn option_uint(opt: &[u8]) -> u32 {
    // 确保字节长度足够
    assert!(opt.len() >= std::mem::size_of::<u32>());

    // 将前四个字节转换为 u32，处理未对齐数据和字节顺序
    let ret = u32::from_be_bytes([opt[0], opt[1], opt[2], opt[3]]);

    ret
}
