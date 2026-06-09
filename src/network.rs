/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use libc::IFF_LOOPBACK;
use nix::unistd::close;
use pnet_datalink::{interfaces, NetworkInterface};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;

use crate::config::{Config, DHCP_SERVER_PORT, NAMESERVER_PORT};
use crate::dnsmasq::{
    Irec, MySockAddr, Server, ServerFd, SERV_FOR_NODOTS, SERV_FROM_RESOLV, SERV_HAS_DOMAIN,
    SERV_LITERAL_ADDRESS, SERV_NO_ADDR,
};
use crate::forward::{forward_init, reap_forward};
use crate::logs::{LOG_INFO, LOG_WARNING};
use crate::syslog;
use crate::util::ipv4_and_mask;
use crate::{DnsmasqError::NetworkError, Result};

// 添加接口函数
pub fn add_iface(
    config: &mut Config,
    flags: u32,
    name: String,
    addr: MySockAddr, // 接口地址
) -> Option<String> {
    let mut find_iname: bool = false;
    let mut find_iaddr: bool = false;

    /*检查白名单 */
    if !config.if_names.is_empty() {
        for iname in config.if_names.iter_mut() {
            if !iname.name.is_empty() && iname.name == name {
                iname.found = true;
                find_iname = true;
                break;
            }
        }

        // 不在白名单上，也不在环回
        if flags & IFF_LOOPBACK as u32 == 0 && !find_iname {
            return None;
        }
    }

    // 检查地址
    if !config.if_addrs.is_empty() {
        for iaddr in config.if_addrs.iter_mut() {
            if iaddr.addr == addr {
                // 判断两个sockaddr是否相等
                iaddr.found = true;
                find_iaddr = true;
            }
        }
        if !find_iaddr {
            return None;
        }
    }

    // 检查黑名单
    if !config.if_except.is_empty() {
        for iexcept in config.if_except.iter_mut() {
            if !iexcept.name.is_empty() && iexcept.name == name {
                return None;
            }
        }
    }

    // 检查接口IP是否已经添加，可能有多个接口有相同的地址，我们可能会重新扫描
    let mut iface = Irec::default();
    let mut find_iface: bool = false;
    for c_iface in config.interfaces.clone() {
        if c_iface.addr == addr {
            iface = c_iface;
            find_iface = true;
            break;
        }
    }
    if find_iface {
        iface.valid = true;
        return None;
    }

    // 绑定ip端口
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };

    let socket: Socket = match Socket::new(domain, Type::DGRAM, Some(Protocol::from(0))) {
        Ok(value) => value,
        Err(_) => {
            return Some("failed to create socket".to_string());
        }
    };
    // 设置 SO_REUSEADDR
    match socket.set_reuse_address(true) {
        Ok(_) => {}
        Err(_) => {
            return Some("failed to set SO_REUSEADDR".to_string());
        }
    }
    // 绑定地址
    match socket.bind(&SockAddr::from(addr)) {
        Ok(_) => {}
        Err(_) => {
            return Some("failed to bind socket".to_string());
        }
    }

    // 保存socket文件描述符到iface中，防止socket被自动关闭
    // iface.fd = socket.as_raw_fd();
    iface.socket = socket;
    iface.addr = addr;
    iface.valid = true;
    config.interfaces.insert(0, iface);

    // 使用std::mem::forget防止socket被自动关闭
    // std::mem::forget(socket);

    None
}

pub fn enumerate_interfaces(config: &mut Config) -> Result<()> {
    let mut err: Option<String> = None;
    // let _socket = UdpSocket::bind("0.0.0.0:0")?;
    let mut rawfd = -1;

    for iface in config.interfaces.iter_mut() {
        iface.valid = false;
    }

    let all_interfaces: Vec<NetworkInterface> = interfaces(); // 获取网络接口信息
    for ifr in all_interfaces {
        // let mut addr: MySockAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

        // ip
        if !ifr.ips.is_empty() {
            for ip_network in &ifr.ips {
                let addr = match ip_network.ip() {
                    IpAddr::V4(ipv4) => SocketAddr::new(IpAddr::V4(ipv4), config.port),
                    IpAddr::V6(ipv6) => {
                        // 获取网络接口索引
                        let scope_id = ifr.index;

                        // 创建带 scope_id 的 IPv6 地址
                        let ipv6_with_scope = std::net::Ipv6Addr::from(ipv6.octets());
                        SocketAddr::V6(std::net::SocketAddrV6::new(
                            ipv6_with_scope,
                            config.port,
                            0, // flowinfo
                            scope_id,
                        ))
                    }
                };

                //ifr 中就已经包含了网络接口标志信息，因此这里不用单独获取
                // 添加网络接口 每个接口都添加 所以要放在遍历接口的里面，不能放在外面
                err = add_iface(config, ifr.flags, ifr.name.clone(), addr);
                // 产生错误跳出循环，跳出for遍历循环
                if err.is_some() {
                    break; // 跳出for循环，调到end处
                }

                // dhcp只在第一次调用时是非空的:在这里设置与接口相关的dhcp内容。
                // DHCP仅支持IPv4协议。因为这里的错误最终是致命的，我们可以直接返回，而不必关闭描述符。
                if !config.dhcp.is_empty()
                    && addr.is_ipv4()
                    && !ifr.is_loopback()
                    && !ifr.is_point_to_point()
                {
                    let mut netmask: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
                    let mut broadcast: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);

                    for ip_network in &ifr.ips {
                        // 获取子网掩码
                        if let IpAddr::V4(ipv4_mask) = ip_network.mask() {
                            netmask = ipv4_mask;
                        } else {
                            continue;
                        }

                        // 获广播地址
                        if let IpAddr::V4(ipv4_broadcast) = ip_network.broadcast() {
                            broadcast = ipv4_broadcast;
                        } else {
                            continue;
                        }
                    }

                    // 遍历DHCP上下文，寻找匹配的接口地址范围
                    for context in config.dhcp.iter_mut() {
                        if context.iface.is_empty()
                            && ipv4_and_mask(addr.ip(), netmask)
                                == ipv4_and_mask(context.start, netmask)
                            && ipv4_and_mask(addr.ip(), netmask)
                                == ipv4_and_mask(context.end, netmask)
                        {
                            // let mut saddr:Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);

                            match Socket::new(
                                Domain::PACKET,               // PF_PACKET     底层数据包
                                Type::DGRAM,                  // 原始套接字
                                Some(Protocol::from(0x0800)), // ETH_P_ALL = 3
                            ) {
                                Ok(packet_socket) => {
                                    let ipv4_addr = match addr {
                                        SocketAddr::V4(v4) => *v4.ip(),
                                        _ => unreachable!(), // 因为已经检查过是 IPv4
                                    };
                                    rawfd = packet_socket.as_raw_fd();
                                    context.ifindex = ifr.index; // 获取接口索引
                                    context.rawfd = Some(packet_socket);
                                    context.serv_addr = ipv4_addr;
                                    context.netmask = netmask;
                                    context.broadcast = broadcast;
                                    context.iface = ifr.name.clone();

                                    // 创建 socket (PF_INET, SOCK_DGRAM, IPPROTO_UDP)
                                    let ipv4_socket = Socket::new(
                                        Domain::IPV4,
                                        Type::DGRAM,
                                        Some(Protocol::UDP),
                                    )?;

                                    // 设置 SO_REUSEADDR
                                    ipv4_socket.set_reuse_address(true)?;

                                    // 设置 SO_BROADCAST
                                    ipv4_socket.set_broadcast(true)?;

                                    // 绑定到特定网络设备（如果提供了接口名）
                                    ipv4_socket.bind_device(Some(ifr.name.as_bytes()))?;

                                    // 创建地址结构 (INADDR_ANY, DHCP_SERVER_PORT)
                                    let addr =
                                        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DHCP_SERVER_PORT);
                                    let sock_addr = SockAddr::from(addr);

                                    // 绑定 socket
                                    ipv4_socket
                                        .bind(&sock_addr)
                                        .expect("failed to bind DHCP server socket");
                                    context.fd_socket = Some(ipv4_socket); // 文件描述符赋值
                                }
                                Err(e) => {
                                    if rawfd == -1 {
                                        let string =
                                            format!("Cannot create DHCP packet socket: {}", e);
                                        return Err(NetworkError(string));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            continue;
        }
        // 这个地方是上面添加接口产生错误，跳出外层for循环
        if err.is_some() {
            break; // 跳出for循环，调到end处
        }
    }

    if let Some(e) = err {
        // 有错误返回报错
        return Err(NetworkError(e));
    }

    // 删除扫描中没有找到的接口
    config.interfaces.retain(|item| {
        // 使用 retain 过滤，但保存不需要关闭的项
        if item.valid {
            true
        } else {
            close(item.socket.as_raw_fd()).unwrap_or_else(|e| {
                eprintln!("Failed to close socket: {}", e);
            });
            reap_forward(&item.socket);
            false
        }
    });

    Ok(())
}

fn allocate_sfd(addr: &MySockAddr, sfds: &mut Vec<ServerFd>) -> Option<ServerFd> {
    // 检查是否已经存在相同的 ServerFd
    for sfd in sfds.iter() {
        if sfd.source_addr == *addr {
            // 返回一个克隆的副本
            return Some(sfd.clone());
        }
    }

    // 绑定ip端口
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };

    let socket: Socket = match Socket::new(domain, Type::DGRAM, Some(Protocol::from(0))) {
        Ok(value) => value,
        Err(_) => {
            return None;
        }
    };
    // 绑定地址
    match socket.bind(&SockAddr::from(*addr)) {
        Ok(_) => {}
        Err(_) => {
            return None;
        }
    }

    let sfd = ServerFd {
        source_addr: *addr,
        socket,
    };

    // 将新的 ServerFd 添加到链表头部
    sfds.insert(0, sfd.clone());

    Some(sfd)
}

pub fn check_servers(
    new: &mut Option<Box<Server>>,
    config: &Config,
    sfds: &mut Vec<ServerFd>,
) -> Option<Box<Server>> {
    let mut ret: Option<Box<Server>> = None;
    let mut addrbuff: String = String::new();
    let mut port: u16 = 0;
    forward_init(false);

    // 使用take获取所有权，原new变为None，并且不用主动释放new链表中的某一项，离开作用于后会自动释放
    let mut current = new.take();
    while let Some(mut tmp) = current {
        current = tmp.next.clone();

        if tmp.flags & (SERV_LITERAL_ADDRESS | SERV_NO_ADDR) == 0 {
            addrbuff = tmp.addr.ip().to_string();
            port = tmp.addr.port();

            // 检查是否是本地接口
            let mut iface_found = false;
            for iface in &config.interfaces {
                if tmp.addr == iface.addr {
                    iface_found = true;
                    break;
                }
            }

            if iface_found {
                syslog!(
                    LOG_WARNING,
                    "Ignoring nameserver {} - local interface",
                    addrbuff
                );
                continue;
            }

            if tmp.sfd.is_none() {
                if let Some(sfd) = allocate_sfd(&tmp.source_addr, sfds) {
                    tmp.sfd = Some(sfd);
                } else {
                    syslog!(
                        LOG_WARNING,
                        "Ignoring nameserver {} - cannot make/bind socket",
                        addrbuff
                    );
                    continue;
                }
            }
        }

        // 保存标志位信息，因为tmp将在下一步被移动
        let flags = tmp.flags;
        let domain = tmp.domain.clone();
        // 如果服务器具有特定标志，则记录相关信息  根据具体情况填写日志
        if flags & (SERV_HAS_DOMAIN | SERV_FOR_NODOTS) != 0 {
            let (s1, s2) = if flags & SERV_HAS_DOMAIN != 0 {
                let s1 = String::from("domain");
                let s2 = domain;
                (s1, s2)
            } else {
                let s1 = String::from("unqualified");
                let s2 = String::from("domains");
                (s1, s2)
            };

            if flags & SERV_NO_ADDR != 0 {
                syslog!(LOG_INFO, "using local addresses only for {} {}", s1, s2);
            } else if flags & SERV_LITERAL_ADDRESS == 0 {
                syslog!(
                    LOG_INFO,
                    "using nameserver {}#{} for {} {} ",
                    addrbuff,
                    port,
                    s1,
                    s2
                );
            }
        } else {
            syslog!(LOG_INFO, "using nameserver {}#{}", addrbuff, port);
        }

        // 将当前服务器添加到结果列表的头部，实现反序
        // 这样输入 A→B→C 会变成输出 C→B→A
        tmp.next = ret;
        ret = Some(tmp);
    }

    ret
}

// 配置文件和命令行指定的服务器保留，/etc/resolv.conf的删掉，重新读取
pub fn reload_servers(
    fname: String,
    servs: &mut Option<Box<Server>>,
    query_port: u16,
) -> Option<Box<Server>> {
    let mut new_servers: Option<Box<Server>> = None;

    // 只保留配置配置文件或命令行的设置的服务器
    let mut current = servs.take();
    while let Some(mut cur_serv) = current {
        let next = cur_serv.next.take();

        if cur_serv.flags & SERV_FROM_RESOLV == 0 {
            cur_serv.next = new_servers;
            new_servers = Some(cur_serv);
        }

        current = next;
    }

    // 打开文件并逐行读取
    let file = match File::open(&fname) {
        Ok(f) => {
            syslog!(LOG_INFO, "reading {}", fname);
            f
        }
        Err(e) => {
            syslog!(LOG_INFO, "Failed to open file {}: {}", fname, e);
            return new_servers;
        }
    };

    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.expect("failed to read line");
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let mut serv: Server = Server::default();

        // 检查 "nameserver" 关键字
        if tokens.is_empty() || tokens[0] != "nameserver" || tokens.len() < 2 {
            continue;
        }

        // 获取 IP 地址字符串
        let ip_str = tokens[1]; // tokens[1]为ip地址

        // 解析 IP 地址并生成 MySockAddr
        let ip_addr: IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => {
                continue;
            }
        };

        let (source_addr, addr) = match ip_addr {
            IpAddr::V4(ip) => {
                let source_addr =
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), query_port);
                let addr = SocketAddr::new(IpAddr::V4(ip), NAMESERVER_PORT);
                (source_addr, addr)
            }

            IpAddr::V6(ip) => {
                // 使用 SocketAddrV6 设置 flowinfo 和 scope_id
                let source_addr_v6 =
                    SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), query_port, 0, 0);
                let addr_v6 = SocketAddrV6::new(ip, NAMESERVER_PORT, 0, 0);
                let source_addr = SocketAddr::V6(source_addr_v6);
                let addr = SocketAddr::V6(addr_v6);
                (source_addr, addr)
            }
        };

        serv.next = new_servers;
        serv.addr = addr;
        serv.source_addr = source_addr;
        serv.domain = String::new();
        serv.sfd = None;
        serv.flags = SERV_FROM_RESOLV;
        new_servers = Some(Box::new(serv));
    }

    new_servers
}
