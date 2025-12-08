/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#![allow(unexpected_cfgs)]

use crate::*;
use forward::*;
use libc::INADDR_ANY;
use nix::errno::Errno;
use nix::libc::ioctl;
use nix::sys::socket::sockopt::{Broadcast, ReuseAddr};
use nix::sys::socket::{setsockopt, socket, AddressFamily, SockFlag, SockProtocol, SockType};
use util::*;

use std::ffi::CString;
use std::io::{BufRead, BufReader, Error};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::unix::io::AsRawFd; // 用于获取文件描述符

pub const IFHWADDRLEN: usize = 6;
pub const IFNAMSIZ: usize = 16;
const SERV_FROM_RESOLV: u32 = 1; //1 表示从解析器（resolv）获取服务器，0 表示从命令行获取。
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;
const IFF_LOOPBACK: i16 = 0x8;
const IFF_POINTOPOINT: i16 = 0x10;
const DHCP_SERVER_PORT: u16 = 67;

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
    list: &mut Option<Box<Irec>>,    // 接口链表
    flags: u32,                      // 接口标志
    name: &str,                      // 接口名称
    addr: &MySockAddr,               // 接口地址
    names: &mut Option<Box<Iname>>,  // 名称白名单
    addrs: &mut Option<Box<Iname>>,  // 地址白名单
    except: &mut Option<Box<Iname>>, // 名称黑名单
) -> Option<String> {
    // 检查名称白名单
    if let Some(ref mut head) = names {
        let mut current = head;

        loop {
            if let Some(cur_name) = &current.name {
                if cur_name == name {
                    current.found = true;
                    break;
                }
            }

            if let Some(ref mut next) = current.next {
                current = next;
            } else {
                break;
            }
        }
    }

    if flags & 0x8 == 0 && names.as_ref().map_or(true, |n| !n.found) {
        return None;
    }

    if let Some(ref mut head) = addrs {
        let mut current = head;

        loop {
            if sockaddr_isequal(&current.addr, addr) {
                current.found = true;
                break;
            }

            if let Some(ref mut next) = current.next {
                current = next;
            } else {
                break;
            }
        }
    }

    if addrs.as_ref().map_or(true, |n| !n.found) {
        return None;
    }

    // 检查黑名单
    if let Some(ref mut head) = except {
        let mut current = head;

        loop {
            if let Some(ref cur_name) = current.name {
                if cur_name == name {
                    return None;
                }
            }

            if let Some(ref mut next) = current.next {
                current = next;
            } else {
                break;
            }
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

    let bind_addr: String = unsafe {
        match addr.sa.sa_family {
            AF_INET => {
                // 处理 IPv4 地址
                let ip: String = addr.in_.sin_addr.to_ipv4_addr().to_string();
                let port: String = addr.in_.sin_port.to_string();
                format!("{}:{}", ip, port)
            }
            AF_INET6 => {
                // 处理 IPv6 地址
                let ip = addr.in6.sin6_addr.to_ipv6_addr().to_string();
                let port = addr.in6.sin6_port.to_string();
                format!("{}:{}", ip, port)
            }
            _ => {
                return Some("不支持的地址类型".to_string());
            }
        }
    };

    let socket = match UdpSocket::bind(bind_addr) {
        // 这里需要将自定义的SockAddr转换为合法的地址格式
        Ok(sock) => sock,
        Err(_) => return Some("创建套接字失败".to_string()),
    };

    // 获取文件描述符
    let fd = socket.as_raw_fd();
    // 设置允许多个套接字绑定到同一个地址和端口
    unsafe {
        let optval: i32 = 1; // 启用 SO_REUSEPORT
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            &optval as *const _ as *const _,
            std::mem::size_of::<i32>() as u32,
        );
    }

    // 分配新的接口并添加到链表中
    let new_iface = Box::new(Irec {
        addr: *addr,
        fd,                 // 使用文件描述符
        valid: true,        // 设置为true表示有效
        next: list.clone(), // 将原来的链表连接到新节点
    });

    *list = Some(new_iface);
    None
}

pub fn enumerate_interfaces(
    interfacep: &mut Option<Box<Irec>>,
    names: &mut Option<Box<Iname>>,
    addrs: &mut Option<Box<Iname>>,
    except: &mut Option<Box<Iname>>,
    dhcp: &mut Option<Box<DhcpContext>>,
    port: u16,
) -> Result<(), String> {
    let rawfd = -1;
    let mut len = 100 * std::mem::size_of::<IfReq>();
    let opt = true;
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
            close(fd.as_raw_fd()).unwrap_or_else(|e| eprintln!("Failed to close socket: {}", e));
            return Err("Cannot allocate buffer".to_string());
        }
        ifc.ifc_ifcu.ifcu_buf = buf.as_mut_ptr(); // 更新缓冲区指针
        let res = unsafe { ioctl(fd.as_raw_fd(), libc::SIOCGIFCONF, &mut ifc) };
        if res < 0 {
            let errno = Errno::last();
            if errno != Errno::EINVAL || lastlen != 0 {
                close(fd.as_raw_fd())
                    .unwrap_or_else(|e| eprintln!("Failed to close socket: {}", e));
                return Err(format!("ioctl error: {}", errno));
            }
        } else {
            if ifc.ifc_len == lastlen {
                break;
            }
            lastlen = ifc.ifc_len;
        }
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

            let res = ioctl(fd.as_raw_fd(), libc::SIOCGIFFLAGS, ifr);
            if res < 0 {
                let errno = Errno::last();
                if errno != Errno::EINVAL || lastlen != 0 {
                    close(fd.as_raw_fd()).unwrap_or_else(|e| {
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
                names,
                addrs,
                except,
            );
            if err.is_some() {
                close(fd.as_raw_fd())
                    .unwrap_or_else(|e| eprintln!("ioctl error getting interface flags: {:?}", e));
                return Err(format!("ioctl error: {:?}", err));
            }

            if dhcp.is_some()
                && addr.sa.sa_family == AF_INET
                && ((ifr.ifr_ifru.ifru_flags & IFF_LOOPBACK != 0)
                    || (ifr.ifr_ifru.ifru_flags & IFF_POINTOPOINT != 0))
            {
                let res = ioctl(fd.as_raw_fd(), libc::SIOCGIFNETMASK, ifr);
                if res < 0 {
                    let errno = Errno::last();
                    if errno != Errno::EINVAL || lastlen != 0 {
                        close(fd.as_raw_fd())
                            .unwrap_or_else(|e| eprintln!("Failed to close socket: {}", e));
                        return Err(format!(
                            "ioctl error getting interface netmask: {:?}",
                            errno
                        ));
                    }
                }

                let sockaddr_in_ptr = &ifr.ifr_ifru.ifru_addr as *const _ as *const SockAddrIn;
                let netmask = (*sockaddr_in_ptr).sin_addr;

                let res = ioctl(fd.as_raw_fd(), libc::SIOCGIFBRDADDR, ifr);
                if res < 0 {
                    let errno = Errno::last();
                    if errno != Errno::EINVAL || lastlen != 0 {
                        close(fd.as_raw_fd())
                            .unwrap_or_else(|e| eprintln!("Failed to close socket: {}", e));
                        return Err(format!(
                            "ioctl error getting interface broadcast address: {:?}",
                            errno
                        ));
                    }
                }

                let sockaddr_in_ptr = &ifr.ifr_ifru.ifru_addr as *const _ as *const SockAddrIn;
                let broadcast = (*sockaddr_in_ptr).sin_addr;

                let mut context = dhcp.as_mut();
                while let Some(ref mut ctx) = context {
                    if ctx.iface.is_empty()
                        && (addr.in_.sin_addr.s_addr & netmask.s_addr)
                            == (ctx.start.s_addr & netmask.s_addr)
                        && (addr.in_.sin_addr.s_addr & netmask.s_addr)
                            == (ctx.end.s_addr & netmask.s_addr)
                    {
                        let mut saddr: Option<Box<SockAddrIn>> = None;
                        ctx.rawfd = rawfd;
                        ctx.serv_addr = addr.in_.sin_addr;
                        ctx.netmask = netmask;
                        ctx.broadcast = broadcast;
                        ctx.iface =
                            CString::from_raw(ifr.ifr_ifrn.ifrn_name.as_ptr() as *mut libc::c_char)
                                .into_string()
                                .unwrap_or_else(|_| "".to_string());

                        if let Some(ref mut s) = saddr {
                            s.sin_family = AF_INET;
                            s.sin_port = DHCP_SERVER_PORT.to_be();
                            s.sin_addr.s_addr = INADDR_ANY;
                        }

                        let sock_fd = socket(
                            AddressFamily::Inet,     // 对应 PF_INET
                            SockType::Datagram,      // 对应 SOCK_DGRAM
                            SockFlag::empty(),       // 无额外标志
                            Some(SockProtocol::Udp), // 对应 IPPROTO_UDP
                        )
                        .map_err(|e| format!("cannot create DHCP server socket: {}", e))?;
                        ctx.fd = sock_fd.as_raw_fd();
                        setsockopt(&sock_fd, ReuseAddr, &opt)
                            .map_err(|e| format!("failed to set SO_REUSEADDR: {}", e))?;

                        // 设置 SO_BROADCAST
                        setsockopt(&sock_fd, Broadcast, &opt)
                            .map_err(|e| format!("failed to set SO_BROADCAST: {}", e))?;
                        let raw_fd = sock_fd.as_raw_fd();
                        let mut saddr_ref_c: libc::sockaddr_in = std::mem::zeroed(); // 初始化 全为0
                        if let Some(s) = saddr {
                            saddr_ref_c.sin_family = s.sin_family;
                            saddr_ref_c.sin_port = s.sin_port;
                            saddr_ref_c.sin_addr.s_addr = s.sin_addr.s_addr;
                        }

                        let saddr_size =
                            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
                        let res = libc::bind(
                            raw_fd,
                            &saddr_ref_c as *const _ as *const libc::sockaddr,
                            saddr_size,
                        );
                        if res < 0 {
                            return Err(format!(
                                "failed to bind DHCP server socket: {}",
                                Error::last_os_error()
                            ));
                        }
                    }
                }
            }
        }
    }
    let mut prev = None;
    let mut binding = interfacep.clone();
    let mut iface = binding.as_deref_mut();
    while let Some(iface_ref) = iface {
        if iface_ref.valid {
            prev = Some(iface_ref.clone());
            iface = iface_ref.next.as_deref_mut();
        } else {
            unsafe {
                libc::close(iface_ref.fd);
                reap_forward(iface_ref.fd);
            }

            if let Some(ref mut prev_ref) = prev {
                prev_ref.next = iface_ref.next.clone();
            } else {
                *interfacep = iface_ref.next.clone();
            }

            iface = iface_ref.next.as_deref_mut();
        }
    }
    Ok(())
}

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
            new = server.next.clone();
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
                new = server.next.clone();
                continue;
            }
        }

        // 将服务器添加到返回链表
        let next = server.next.clone();
        server.next = ret.clone();
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
    fname: &mut Option<Box<ResolvC>>,
    serv: &mut Option<Box<Server>>,
    query_port: &mut i32,
) -> Option<Box<Server>> {
    let mut old_servers: Option<Box<Server>> = None;
    let mut new_servers: Option<Box<Server>> = None;

    // 将旧服务器放入可重用列表中
    while let Some(mut current) = serv.take() {
        let next = current.next.take(); // 获取下一个节点并断开当前节点的链接
        *serv = next; // 更新 serv 到下一个节点

        if current.flags & SERV_FROM_RESOLV != 0 {
            // 将匹配的服务器放入 old_servers 链表
            current.next = old_servers.take(); // 将当前节点的 next 设置为 old_servers
            old_servers = Some(current); // 更新 old_servers 为当前节点
        } else {
            // 保留非匹配的服务器，放入 new_servers 链表
            current.next = new_servers.take(); // 将当前节点的 next 设置为 new_servers
            new_servers = Some(current); // 更新 new_servers 为当前节点
        }
    }

    // 如果没有提供 fname 或其中没有文件名，则返回现有的服务器列表
    let file_path = match <Option<Box<option::ResolvC>> as Clone>::clone(fname)
        .and_then(|resolv| resolv.name)
    {
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
                        sin_port: *query_port as u16,
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
                        sin6_port: *query_port as u16,
                        sin6_flowinfo: 0,
                        sin6_addr: option::In6Addr { s6_addr: [0; 16] },
                        sin6_scope_id: 0,
                    },
                },
            )
        } else {
            continue;
        };

        if let Some(first_old) = old_servers.take() {
            *serv = Some(first_old);
            if let Some(ref mut serv_inner) = serv.as_mut() {
                old_servers = serv_inner.next.take();
            }
        }

        new_servers = serv.take();

        if let Some(ref mut serv_inner) = new_servers {
            serv_inner.next = None;
            serv_inner.addr = addr;
            serv_inner.source_addr = source_addr;
            serv_inner.domain = None;
            serv_inner.sfd = None;
            serv_inner.flags = SERV_FROM_RESOLV;
        }
    }

    new_servers
}
