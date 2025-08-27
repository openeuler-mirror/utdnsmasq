/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use crate::*;
use forward_init::*;
use get_if_addrs::{get_if_addrs, IfAddr, Interface};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::os::unix::io::AsRawFd; // 用于获取文件描述符
use util::*;

// 添加接口函数
pub fn add_iface(
    list: &mut Option<Box<Irec>>, // 接口链表
    flags: u32,                   // 接口标志
    name: &str,                   // 接口名称
    addr: &MySockAddr,            // 接口地址
    names: Option<Box<Iname>>,    // 名称白名单
    addrs: Option<Box<Iname>>,    // 地址白名单
    except: Option<Box<Iname>>,   // 名称黑名单
) -> Option<String> {
    let mut tmp: Option<Box<Iname>> = None;

    // 检查名称白名单
    if let Some(mut names_list) = names {
        while let Some(mut current_name) = names_list.next.take() {
            if current_name
                .name
                .as_ref()
                .map_or(false, |n| n.as_str() == name)
            {
                current_name.found = true; // 直接修改为true
                tmp = Some(current_name);
                break;
            }
            names_list = current_name;
        }
        if (flags & 0x8 == 0) && tmp.is_none() {
            // 0x8代表IFF_LOOPBACK，假设为常量值
            return None;
        }
    }

    // 检查地址白名单
    if let Some(mut addr_list) = addrs {
        while let Some(mut current_addr) = addr_list.next.take() {
            unsafe {
                if current_addr.addr.sa == addr.sa {
                    current_addr.found = true; // 直接修改为true
                    tmp = Some(current_addr);
                    break;
                }
            }
            addr_list = current_addr;
        }
        if tmp.is_none() {
            return None;
        }
    }

    // 检查黑名单
    if let Some(mut except_list) = except {
        while let Some(current_except) = except_list.next.take() {
            if current_except
                .name
                .as_ref()
                .map_or(false, |n| n.as_str() == name)
            {
                return None;
            }
            except_list = current_except;
        }
    }

    // 检查是否已经存在相同地址的接口
    let mut current_iface = list.as_mut(); // 使用as_mut获取可变引用而不是clone
    while let Some(current) = current_iface {
        unsafe {
            if current.addr.sa == addr.sa {
                current.valid = true; // 直接修改为true
                return None;
            }
        }
        current_iface = current.next.as_mut(); // 继续遍历链表
    }

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        // 这里需要将自定义的SockAddr转换为合法的地址格式
        Ok(sock) => sock,
        Err(_) => return Some("创建套接字失败".to_string()),
    };

    // 获取文件描述符
    let fd = socket.as_raw_fd();
    // 分配新的接口并添加到链表中
    let new_iface = Box::new(Irec {
        addr: *addr,
        fd,                // 使用文件描述符
        valid: true,       // 设置为true表示有效
        next: list.take(), // 将原来的链表连接到新节点
    });

    *list = Some(new_iface);

    None
}

// 将 `Ipv4Addr` 转换为 `InAddr`
fn create_in_addr(ip: Ipv4Addr) -> InAddr {
    InAddr {
        s_addr: u32::from(ip).to_be(), // 转换为网络字节序
    }
}

// 将 `Ipv6Addr` 转换为 `In6Addr`
fn create_in6_addr(ip: Ipv6Addr) -> In6Addr {
    In6Addr {
        s6_addr: ip.octets(), // 直接使用 `octets` 方法获取16字节数组
    }
}

// 获取 IPv6 作用域 ID
fn get_scope_id(ipv6_addr: Ipv6Addr, port: u16) -> u32 {
    let socket_addr_v6 = SocketAddrV6::new(ipv6_addr, port, 0, 0);
    socket_addr_v6.scope_id() // 获取作用域 ID
}

pub fn enumerate_interfaces(
    interfacep: &mut Option<Box<Irec>>,
    names: Option<Box<Iname>>,
    addrs: Option<Box<Iname>>,
    except: Option<Box<Iname>>,
    dhcp: &mut Option<Box<DhcpContext>>,
    port: u16,
) -> Result<(), String> {
    let _socket = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) {
        Ok(sock) => sock,
        Err(e) => {
            // 如果创建套接字失败，返回错误消息
            return Err(format!("无法创建套接字以枚举接口: {}", e));
        }
    };

    // 将所有接口标记为无效
    let mut iface = interfacep.as_mut();
    while let Some(current_iface) = iface {
        current_iface.valid = false;
        iface = current_iface.next.as_mut();
    }

    // 获取真实的网络接口
    let interfaces = get_network_interfaces();
    for iface in interfaces {
        let flags: u32 = 0;
        // 处理接口的 IP 地址
        match iface.addr {
            IfAddr::V4(ifaddr) => {
                let my_sock_addr = MySockAddr {
                    in_: SockAddrIn {
                        sin_family: 2,                       // AF_INET
                        sin_addr: create_in_addr(ifaddr.ip), // 模拟的地址数据
                        sin_port: port.to_be(),
                        sin_zero: [0; 8],
                    },
                };
                // 处理 DHCP 配置（如果传递了 DHCP 上下文）
                if let Some(dhcp_ctx) = dhcp.as_mut() {
                    if iface.name != "lo" && !(flags & (0x8 | 0x10) != 0) {
                        let netmask = Ipv4Addr::new(255, 255, 255, 0); // 模拟的子网掩码
                        let broadcast = Ipv4Addr::new(192, 168, 1, 255); // 模拟的广播地址

                        // 检查是否符合 DHCP 配置
                        if dhcp_ctx.start <= ifaddr.ip && dhcp_ctx.end >= ifaddr.ip {
                            dhcp_ctx.iface = iface.name.clone();
                            dhcp_ctx.netmask = netmask;
                            dhcp_ctx.broadcast = broadcast;

                            // 模拟 DHCP 套接字创建
                            let dhcp_socket =
                                Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
                                    .map_err(|e| {
                                        format!("Failed to create DHCP socket: {:?}", e)
                                    })?;

                            dhcp_ctx.fd = dhcp_socket.as_raw_fd();
                        }
                    }
                }

                // 调用 add_iface 函数
                add_iface(
                    interfacep,
                    0, // 模拟的 flags
                    &iface.name,
                    &my_sock_addr,
                    names.clone(),
                    addrs.clone(),
                    except.clone(),
                );
            }
            IfAddr::V6(ifaddr) => {
                let scope_id = get_scope_id(ifaddr.ip, port);
                let my_sock_addr = MySockAddr {
                    in6: SockAddrIn6 {
                        sin6_family: 10,                       // AF_INET6
                        sin6_port: port.to_be(),               // 网络字节序端口
                        sin6_flowinfo: 0,                      // 模拟的流信息
                        sin6_addr: create_in6_addr(ifaddr.ip), // 使用正确的 `In6Addr`
                        sin6_scope_id: scope_id,               // 作用域ID
                    },
                };

                // 调用 add_iface 函数
                add_iface(
                    interfacep,
                    0, // 模拟的 flags
                    &iface.name,
                    &my_sock_addr,
                    names.clone(),
                    addrs.clone(),
                    except.clone(),
                );
            }
        }
    }

    Ok(())
}

// 获取网络接口的真实函数
fn get_network_interfaces() -> Vec<Interface> {
    // 获取系统中的所有网络接口
    match get_if_addrs() {
        Ok(interfaces) => interfaces,
        Err(e) => {
            println!("获取接口时发生错误: {}", e);
            Vec::new()
        }
    }
}

pub fn check_servers(
    mut new: Option<Box<Server>>,
    interfaces: &Option<Box<Irec>>,
    sfds: &mut VecDeque<ServerFd>,
) -> Option<Box<Server>> {
    let mut ret: Option<Box<Server>> = None;

    // 进行 DHCP 服务器检查
    forward_init(false);

    while let Some(ref mut server) = new {
        let addr_str = match unsafe { server.addr.sa.sa_family } {
            2 => {
                // IPv4
                let addr = unsafe { server.addr.in_ };
                format!("{}:{}", addr.sin_addr.s_addr, addr.sin_port)
            }
            10 => {
                // IPv6
                let addr = unsafe { server.addr.in6 };
                format!(
                    "{}:{}",
                    addr.sin6_addr
                        .s6_addr
                        .iter()
                        .map(|b| format!("{:x}", b))
                        .collect::<Vec<_>>()
                        .join(":"),
                    addr.sin6_port
                )
            }
            _ => continue,
        };

        let port = match unsafe { server.addr.sa.sa_family } {
            2 => unsafe { server.addr.in_.sin_port },
            10 => unsafe { server.addr.in6.sin6_port },
            _ => continue,
        };

        // 检查是否是本地接口
        let mut iface_found = false;
        if let Some(iface) = interfaces {
            let mut iface_tmp = Some(iface);
            while let Some(current_iface) = iface_tmp {
                if sockaddr_isequal(&server.addr, &current_iface.addr) {
                    iface_found = true;
                    break;
                }
                iface_tmp = current_iface.next.as_ref();
            }
        }

        if iface_found {
            // warn!("Ignoring nameserver {} - local interface", addr_str);
            new = server.next.take();
            continue;
        }

        // 分配 socket 文件描述符
        if server.sfd.is_none() {
            if let Some(sfd) = allocate_sfd(&server.source_addr, sfds) {
                server.sfd = Some(sfd);
            } else {
                // warn!("Ignoring nameserver {} - cannot make/bind socket", addr_str);
                new = server.next.take();
                continue;
            }
        }

        // 将服务器添加到返回链表
        let next = server.next.take();
        server.next = ret.take();
        ret = Some(server.clone());
        new = next;

        // info("Using nameserver {}#{}", addr_str, port);
    }

    ret
}

pub fn allocate_sfd(source_addr: &MySockAddr, sfds: &mut VecDeque<ServerFd>) -> Option<ServerFd> {
    // 首先检查是否已有合适的文件描述符
    for sfd in sfds.iter() {
        if sockaddr_isequal(&sfd.source_addr, source_addr) {
            return Some(sfd.clone());
        }
    }

    // 创建一个新的 ServerFd
    let mut sfd = ServerFd {
        fd: -1, // 默认值
        source_addr: *source_addr,
        next: None,
    };

    // 创建 UDP 套接字
    let socket_addr: SocketAddr = unsafe {
        match source_addr.sa.sa_family {
            2 => {
                let addr = source_addr.in_;
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(addr.sin_addr.s_addr)),
                    addr.sin_port,
                )
            }
            10 => {
                let addr = source_addr.in6;
                SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(addr.sin6_addr.s6_addr)),
                    addr.sin6_port,
                )
            }
            _ => return None,
        }
    };

    // 尝试绑定套接字
    match UdpSocket::bind(socket_addr) {
        Ok(sock) => {
            sfd.fd = sock.as_raw_fd(); // 获取文件描述符
                                       // 将新的 ServerFd 添加到 sfds 中
            sfds.push_back(sfd.clone());
            Some(sfd)
        }
        Err(err) => {
            // warn!("Failed to create socket: {}", err);
            None
        }
    }
}
