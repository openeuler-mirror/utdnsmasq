/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use crate::*;
use get_if_addrs::{get_if_addrs, IfAddr, Interface};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::UdpSocket;
use std::os::unix::io::AsRawFd; // 用于获取文件描述符

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

pub fn enumerate_interfaces(
    interfacep: &mut Option<Box<Irec>>,
    names: Option<Box<Iname>>,
    addrs: Option<Box<Iname>>,
    except: Option<Box<Iname>>,
    dhcp: &mut Option<Box<DhcpContext>>,
    port: u16,
) -> Result<(), String> {
    let socket = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) {
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
                    sa: SockAddr {
                        sa_family: 2,     // AF_INET
                        sa_data: [0; 14], // 模拟的地址数据
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
                let my_sock_addr = MySockAddr {
                    sa: SockAddr {
                        sa_family: 10,    // AF_INET6
                        sa_data: [0; 14], // 模拟的地址数据
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
