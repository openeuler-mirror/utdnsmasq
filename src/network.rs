/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use crate::*;
use forward::*;
use util::*;
// use get_if_addrs::{get_if_addrs, IfAddr, Interface};
use nix::errno::Errno;
// use socket2::{Domain, Protocol, Socket, Type};
use nix::libc::ioctl;
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::unix::io::AsRawFd; // 用于获取文件描述符

pub const IFHWADDRLEN: usize = 6;
pub const IFNAMSIZ: usize = 16;
const SERV_FROM_RESOLV: u32 = 1; //1 表示从解析器（resolv）获取服务器，0 表示从命令行获取。
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;
const IFF_LOOPBACK: i16 = 0x8;
const IFF_POINTOPOINT: i16 = 0x10;

#[repr(C)]
#[derive(Copy, Clone)]
pub union IfcIfcu {
    pub ifcu_buf: *mut u8,    // 缓冲区地址
    pub ifcu_req: *mut IfReq, // 指向 ifreq 数组的指针
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct IfConf {
    pub ifc_len: i32,      // 缓冲区大小
    pub ifc_ifcu: IfcIfcu, // 联合体
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union IfReqName {
    pub ifrn_name: [u8; IFNAMSIZ], // 接口名称，使用 `u8` 表示字符数组
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union IfReqUnion {
    pub ifru_addr: SockAddr,          // 地址
    pub ifru_dstaddr: SockAddr,       // 目的地址
    pub ifru_broadaddr: SockAddr,     // 广播地址
    pub ifru_netmask: SockAddr,       // 网络掩码
    pub ifru_hwaddr: SockAddr,        // 硬件地址
    pub ifru_flags: i16,              // 标志，使用 `i16` 表示 `short int`
    pub ifru_ivalue: i32,             // 整型值
    pub ifru_mtu: i32,                // 最大传输单元
    pub ifru_map: IfMap,              // 映射
    pub ifru_slave: [u8; IFNAMSIZ],   // 从设备名称，使用 `u8` 表示字符数组
    pub ifru_newname: [u8; IFNAMSIZ], // 新设备名称
    pub ifru_data: *mut u8,           // 数据指针
}

#[repr(C)]
#[derive(Clone)]
pub struct IfReq {
    pub ifr_ifrn: IfReqName,  // 接口名称或其他字段
    pub ifr_ifru: IfReqUnion, // 各种用途的联合体
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct IfMap {
    pub mem_start: u64, // 映射内存起始地址
    pub mem_end: u64,   // 映射内存结束地址
    pub base_addr: u16, // 基址
    pub irq: u8,        // 中断号
    pub dma: u8,        // DMA 通道
    pub port: u8,       // I/O 端口
}

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
    if names.is_some() {
        tmp = names;
        while let Some(mut current_name) = tmp.take() {
            // 使用 take 方法
            match current_name.name {
                Some(cur_name) => {
                    if cur_name == name {
                        current_name.found = true;
                        break;
                    }
                }
                _ => {}
            }
            tmp = current_name.next.take();
        }

        if flags & 0x8 == 0 && tmp.is_some() {
            return None;
        }
    }
    println!(" aaaaaaaaaaaaaaaaaaaa ");

    if addrs.is_some() {
        tmp = addrs;
        while let Some(mut current_addr) = tmp.take() {
            // 使用 take 方法
            unsafe {
                println!(
                    " aaaaaaaaaaaaaaaaaaaa&current_addr.addr{:?} ",
                    &current_addr.addr.in_.sin_addr.s_addr
                );
            }
            unsafe {
                println!(" aaaaaaaaaaaaaaaaaaaaaddr{:?} ", addr.in_.sin_addr.s_addr);
            }
            if sockaddr_isequal(&current_addr.addr, addr) {
                current_addr.found = true;
                println!(" current_addr.found is true");
                break;
            }
            tmp = current_addr.next.take();
        }

        if tmp.is_none() {
            return None;
        }
    }

    // 检查黑名单
    if except.is_some() {
        tmp = except;
        while let Some(mut current) = tmp.take() {
            // 使用 take 方法
            if let Some(cur_name) = current.name {
                if cur_name == name {
                    return None;
                }
            }
            tmp = current.next.take();
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
    let mut len = 100 * std::mem::size_of::<IfReq>();
    let fd = match socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    ) {
        Ok(fd) => fd,
        Err(e) => return Err(format!("Failed to create socket: {}", e)),
    };

    let mut buf: Vec<u8> = vec![0; len];
    let mut ifc = IfConf {
        ifc_len: len as i32,
        ifc_ifcu: IfcIfcu {
            ifcu_buf: buf.as_mut_ptr(),
        },
    };

    let mut lastlen = 0;
    let mut current_iface = interfacep.as_mut();

    while let Some(iface) = current_iface {
        iface.valid = false;
        current_iface = iface.next.as_mut();
    }

    // 获取接口信息
    loop {
        buf = vec![0; len]; // 重新分配缓冲区
        if buf.len() < len {
            close(fd).unwrap_or_else(|e| eprintln!("Failed to close socket: {}", e));
            return Err("Cannot allocate buffer".to_string());
        }
        ifc.ifc_ifcu.ifcu_buf = buf.as_mut_ptr(); // 更新缓冲区指针
        let res = unsafe { ioctl(fd, libc::SIOCGIFCONF, &mut ifc) };
        if res < 0 {
            let errno = Errno::last();
            if errno != Errno::EINVAL || lastlen != 0 {
                close(fd).unwrap_or_else(|e| eprintln!("Failed to close socket: {}", e));
                return Err(format!("ioctl error: {}", errno));
            }
        } else if ifc.ifc_len == lastlen {
            break;
        }
        lastlen = ifc.ifc_len;
        len += 10 * std::mem::size_of::<IfReq>();
    }

    // 遍历获取的接口信息
    let mut ptr = buf.as_ptr();
    let end_ptr = unsafe { buf.as_ptr().add(ifc.ifc_len as usize) };
    while ptr < end_ptr {
        // 将当前指针转换为 IfReq
        let ifr = unsafe { &*(ptr as *const IfReq) };

        // 获取接口地址
        let addr: MySockAddr;

        // 根据 HAVE_SOCKADDR_SA_LEN 的定义计算下一个指针位置
        #[cfg(feature = "HAVE_SOCKADDR_SA_LEN")]
        {
            let sa_len = unsafe { ifr.ifr_ifru.ifru_addr.sa_data.len() };
            ptr = ptr.wrapping_add(sa_len + IFNAMSIZ);
        }
        #[cfg(not(feature = "HAVE_SOCKADDR_SA_LEN"))]
        {
            ptr = ptr.wrapping_add(std::mem::size_of::<IfReq>());
        }

        unsafe {
            // println!("xxxxxxxxxxxxxxxxxxxxx ifr.ifr_ifru.ifru_addr.sa_family={:?}  ", ifr.ifr_ifru.ifru_addr.sa_family);
            if ifr.ifr_ifru.ifru_addr.sa_family == AF_INET {
                addr = MySockAddr {
                    in_: SockAddrIn {
                        sin_family: AF_INET,
                        sin_port: port.to_be(), // htons() 等价的操作
                        sin_addr: InAddr::from_ipv4_addr(Ipv4Addr::new(
                            ifr.ifr_ifru.ifru_addr.sa_data[2],
                            ifr.ifr_ifru.ifru_addr.sa_data[3],
                            ifr.ifr_ifru.ifru_addr.sa_data[4],
                            ifr.ifr_ifru.ifru_addr.sa_data[5],
                        )),
                        sin_zero: [0; 8],
                    },
                };
            } else if ifr.ifr_ifru.ifru_addr.sa_family == AF_INET6 {
                addr = MySockAddr {
                    in6: SockAddrIn6 {
                        sin6_family: AF_INET6,
                        sin6_port: port.to_be(),     // htons() 等价的操作
                        sin6_flowinfo: 0u32.to_be(), // htonl(0) 等价的操作
                        sin6_addr: In6Addr::from_ipv6_addr(Ipv6Addr::new(
                            ((ifr.ifr_ifru.ifru_addr.sa_data[0] as u16) << 8)
                                | (ifr.ifr_ifru.ifru_addr.sa_data[1] as u16),
                            ((ifr.ifr_ifru.ifru_addr.sa_data[2] as u16) << 8)
                                | (ifr.ifr_ifru.ifru_addr.sa_data[3] as u16),
                            ((ifr.ifr_ifru.ifru_addr.sa_data[4] as u16) << 8)
                                | (ifr.ifr_ifru.ifru_addr.sa_data[5] as u16),
                            ((ifr.ifr_ifru.ifru_addr.sa_data[6] as u16) << 8)
                                | (ifr.ifr_ifru.ifru_addr.sa_data[7] as u16),
                            ((ifr.ifr_ifru.ifru_addr.sa_data[8] as u16) << 8)
                                | (ifr.ifr_ifru.ifru_addr.sa_data[9] as u16),
                            ((ifr.ifr_ifru.ifru_addr.sa_data[10] as u16) << 8)
                                | (ifr.ifr_ifru.ifru_addr.sa_data[11] as u16),
                            ((ifr.ifr_ifru.ifru_addr.sa_data[12] as u16) << 8)
                                | (ifr.ifr_ifru.ifru_addr.sa_data[13] as u16),
                            0,
                        )),
                        sin6_scope_id: 0,
                    },
                };
            } else {
                continue;
            }

            let res = ioctl(fd, libc::SIOCGIFFLAGS, ifr);
            if res < 0 {
                let errno = Errno::last();
                if errno != Errno::EINVAL || lastlen != 0 {
                    close(fd).unwrap_or_else(|e| {
                        eprintln!("ioctl error getting interface flags: {:?}", e)
                    });
                    return Err(format!("ioctl error: {}", errno));
                }
            }
            // 将字节数组转为切片，查找空字节的位置
            let name_bytes = &ifr.ifr_ifrn.ifrn_name;
            let end = name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(name_bytes.len());

            // 截取到第一个空字节为止的有效部分
            let name_str = match std::str::from_utf8(&name_bytes[..end]) {
                Ok(name) => name,
                Err(_) => {
                    return Err("Invalid UTF-8 sequence in interface name".to_string());
                }
            };

            let err = add_iface(
                interfacep,
                ifr.ifr_ifru.ifru_flags.try_into().unwrap(),
                name_str,
                &addr,
                names.clone(),
                addrs.clone(),
                except.clone(),
            );
            if err.is_some() {
                close(fd)
                    .unwrap_or_else(|e| eprintln!("ioctl error getting interface flags: {:?}", e));
                return Err(format!("ioctl error: {:?}", err));
            }

            if dhcp.is_some()
                && addr.sa.sa_family == AF_INET
                && ((ifr.ifr_ifru.ifru_flags & IFF_LOOPBACK != 0)
                    || (ifr.ifr_ifru.ifru_flags & IFF_POINTOPOINT != 0))
            {}
            break;
        }
    }

    Ok(())
}

/*
//将 `Ipv4Addr` 转换为 `InAddr`
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
                        sin_family: AF_INET,                 // AF_INET
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
                        sin6_family: AF_INET6,                 // AF_INET6
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
*/

pub fn check_servers(
    mut new: Option<Box<Server>>,
    interfaces: &Option<Box<Irec>>,
    sfds: &mut Option<Box<ServerFd>>,
) -> Option<Box<Server>> {
    let mut ret: Option<Box<Server>> = None;

    // 进行 DHCP 服务器检查
    forward_init(false);

    while let Some(ref mut server) = new {
        let addr_str = match unsafe { server.addr.sa.sa_family } {
            AF_INET => {
                // IPv4
                let addr = unsafe { server.addr.in_ };
                format!("{}:{}", addr.sin_addr.s_addr, addr.sin_port)
            }
            AF_INET6 => {
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
            AF_INET => unsafe { server.addr.in_.sin_port },
            AF_INET6 => unsafe { server.addr.in6.sin6_port },
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
            syslog!(
                LOG_WARNING,
                "Ignoring nameserver {} - local interface",
                addr_str
            );
            new = server.next.take();
            continue;
        }

        // 分配 socket 文件描述符
        if server.sfd.is_none() {
            if let Some(sfd) = allocate_sfd(&server.source_addr, sfds) {
                server.sfd = Some(sfd);
            } else {
                syslog!(
                    LOG_WARNING,
                    "Ignoring nameserver {} - cannot make/bind socket",
                    addr_str
                );
                new = server.next.take();
                continue;
            }
        }

        // 将服务器添加到返回链表
        let next = server.next.take();
        server.next = ret.take();
        ret = Some(server.clone());
        new = next;

        syslog!(LOG_INFO, "Using nameserver {}#{}", addr_str, port);
    }

    ret
}

pub fn allocate_sfd(
    source_addr: &MySockAddr,
    sfds: &mut Option<Box<ServerFd>>,
) -> Option<ServerFd> {
    // 首先检查是否已有合适的文件描述符
    for sfd in sfds.iter() {
        if sockaddr_isequal(&sfd.source_addr, source_addr) {
            return Some(*sfd.clone());
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
            AF_INET => {
                let addr = source_addr.in_;
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(addr.sin_addr.s_addr)),
                    addr.sin_port,
                )
            }
            AF_INET6 => {
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
            Some(sfd)
        }
        Err(err) => {
            syslog!(LOG_WARNING, "Failed to create socket: {}", err);
            None
        }
    }
}

// 从配置文件中重新加载 DNS 服务器列表，并更新现有的服务器链表
pub fn reload_servers(
    fname: Option<Box<ResolvC>>,
    mut serv: Option<Box<Server>>,
    query_port: i32,
) -> Option<Box<Server>> {
    let mut old_servers = Vec::new();
    let mut new_servers: Option<Box<Server>> = None;

    // 将旧服务器放入可重用列表中
    while let Some(mut server) = serv.take() {
        serv = server.next.take(); // 获取下一个节点
        if server.flags & SERV_FROM_RESOLV != 0 {
            old_servers.push(server); // 将匹配的放入旧服务器队列
        } else {
            server.next = new_servers.take();
            new_servers = Some(server); // 保留非匹配服务器
        }
    }

    // 如果没有提供 fname 或其中没有文件名，则返回现有的服务器列表
    let file_path = match fname.and_then(|resolv| resolv.name) {
        Some(path) => path,
        None => {
            syslog!(LOG_INFO, "No file path specified in ResolvC struct",);
            return new_servers;
        }
    };

    // 打开文件并逐行读取
    let file = match File::open(&file_path) {
        Ok(f) => f,
        Err(e) => {
            syslog!(LOG_INFO, "Failed to open file {}: {}", file_path, e);
            return new_servers;
        }
    };

    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.expect("failed to read line");
        let mut tokens = line.split_whitespace();

        // 检查 "nameserver" 关键字
        if tokens.next() != Some("nameserver") {
            continue;
        }

        // 获取 IP 地址字符串
        let token = match tokens.next() {
            Some(tok) => tok,
            None => continue,
        };

        // 解析 IP 地址并生成 MySockAddr
        let (addr, source_addr) = if let Ok(ipv4_addr) = token.parse::<Ipv4Addr>() {
            (
                MySockAddr {
                    in_: SockAddrIn {
                        sin_family: AF_INET,
                        sin_port: NAMESERVER_PORT,
                        sin_addr: option::InAddr {
                            s_addr: u32::from(ipv4_addr).to_be(),
                        },
                        sin_zero: [0; 8],
                    },
                },
                MySockAddr {
                    in_: SockAddrIn {
                        sin_family: AF_INET,
                        sin_port: query_port as u16,
                        sin_addr: option::InAddr { s_addr: 0 },
                        sin_zero: [0; 8],
                    },
                },
            )
        } else if let Ok(ipv6_addr) = token.parse::<Ipv6Addr>() {
            (
                MySockAddr {
                    in6: SockAddrIn6 {
                        sin6_family: AF_INET6,
                        sin6_port: NAMESERVER_PORT,
                        sin6_flowinfo: 0,
                        sin6_addr: option::In6Addr {
                            s6_addr: ipv6_addr.octets(),
                        },
                        sin6_scope_id: 0,
                    },
                },
                MySockAddr {
                    in6: SockAddrIn6 {
                        sin6_family: AF_INET6,
                        sin6_port: query_port as u16,
                        sin6_flowinfo: 0,
                        sin6_addr: option::In6Addr { s6_addr: [0; 16] },
                        sin6_scope_id: 0,
                    },
                },
            )
        } else {
            continue;
        };

        // 重用旧服务器或创建新服务器
        let mut server = if let Some(mut old_server) = old_servers.pop() {
            old_server.addr = addr;
            old_server.source_addr = source_addr;
            old_server
        } else {
            Box::new(Server {
                addr,
                source_addr,
                sfd: None,
                domain: None,
                flags: SERV_FROM_RESOLV,
                next: None,
            })
        };

        // 插入新服务器链表的头部
        server.next = new_servers.take();
        new_servers = Some(Box::new(*server));
    }

    new_servers
}
