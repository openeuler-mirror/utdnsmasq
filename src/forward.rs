/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#![allow(
    clippy::collapsible_if,
    static_mut_refs,
    unused_mut,
    unused_unsafe,
    unused_variables,
    unused_assignments,
    clippy::too_many_arguments,
    clippy::missing_safety_doc,
    clippy::map_identity
)]

use crate::rfc1035::*;
use crate::util::*;
use crate::*;
use std::{
    net::{SocketAddr, UdpSocket},
    os::fd::FromRawFd,
    time::SystemTime,
};

#[derive(Clone)]
pub struct FRec {
    source: MySockAddr,
    sentto: Option<Box<Server>>,
    orig_id: u16,
    new_id: u16,
    fd: i32,
    time: std::time::SystemTime,
    next: Option<Box<FRec>>,
}

static mut FREC_LIST: Option<Box<FRec>> = None;
const OPT_NO_NEG: u32 = 2048;
const FTABSIZ: usize = 150;
const LOGRATE: Duration = Duration::from_secs(120);
const TIMEOUT: Duration = Duration::from_secs(40);
static mut WARN_TIME: Option<SystemTime> = None;
const F_NOERR: u32 = 32768;

pub fn forward_init(first: bool) {
    unsafe {
        // 初始化链表头部
        if first {
            FREC_LIST = None; // 首次调用，清空链表
        }

        // 遍历链表并重置每个节点的 new_id 字段
        let mut current = &mut FREC_LIST;
        while let Some(ref mut node) = *current {
            node.new_id = 0;
            current = &mut node.next;
        }
    }
}

const NOERROR: u8 = 0;
// 处理DNS查询的响应包，根据响应包中的信息，更新本地缓存，并根据需要发送响应包
pub fn reply_query(
    fd: i32,
    options: u32,
    packet: &mut Vec<u8>,
    now: SystemTime,
    dnamebuff: &mut Vec<u8>,
    mut last_server: Option<Box<Server>>,
    bogus_nxdomain: &mut Option<Box<BogusAddr>>,
    caches: &mut Cache,
) -> Option<Box<Server>> {
    let socket = unsafe { UdpSocket::from_raw_fd(fd) };
    let mut buf = vec![0u8; PACKETSZ];
    let (n, src_addr) = match socket.recv_from(&mut buf) {
        Ok((n, addr)) => (n, addr),
        Err(_) => return last_server, // 如果读取失败，则返回上次的服务器
    };

    if n < std::mem::size_of::<Header>() {
        return last_server; // 如果包太小，返回上次的服务器
    }

    // 将数据转换为 Header 结构
    let header = match Header::from_bytes(&buf[..12]) {
        Some(h) => h,
        None => return last_server, // 如果无法解析数据包头，返回上次的服务器
    };
    let header_option = Some(header);

    if header.qr == 1 {
        if let Some(forward) = unsafe { lookup_frec(header.id) } {
            if header.rcode == NOERROR || header.rcode == NXDOMAIN {
                if let Some(server) = &forward.sentto {
                    if server.domain.is_none() {
                        last_server = Some(forward.sentto.clone()?);
                    }
                }

                if header.opcode == QUERY {
                    if !(bogus_nxdomain.is_some()
                        && header.rcode == NOERROR
                        && check_for_bogus_wildcard(
                            &header_option,
                            n,
                            dnamebuff,
                            bogus_nxdomain,
                            now,
                            caches,
                        ))
                    {
                        if header.rcode == NOERROR && header.ancount != 0 {
                            extract_addresses(caches, &header_option, n, dnamebuff, now);
                        } else if (options & OPT_NO_NEG) == 0 {
                            extract_neg_addrs(caches, &header_option, n, dnamebuff, now);
                        }
                    }
                }
            }

            // 恢复原始请求 ID
            let orig_id = forward.orig_id;
            let mut header_mut = header;
            header_mut.id = orig_id;

            // 删除 TC 标志位
            header_mut.tc = 0;

            // 重新写入数据包
            let header_bytes = header_mut.to_bytes();
            packet.splice(0..12, header_bytes);

            // 发送数据包
            let _ = socket.send_to(&packet[..n], src_addr);

            // 使用可变引用修改 new_id
            forward.new_id = 0; // 取消新 ID
        }
    }

    last_server
}

pub unsafe fn lookup_frec(id: u16) -> Option<&'static mut FRec> {
    let mut current = FREC_LIST.as_mut();

    while let Some(frec) = current {
        if frec.new_id == id {
            return Some(frec);
        }
        current = frec.next.as_mut().map(|f| f);
    }

    None
}

pub unsafe fn forward_query(
    udp_socket: i32,
    udp_addr: &MySockAddr,
    header: &mut Option<Header>,
    plen: usize,
    options: u32,
    mut dnamebuff: &mut Vec<u8>,
    servers: &mut Option<Box<option::Server>>,
    last_server: Option<Box<option::Server>>,
    now: SystemTime,
    local_ttl: u64,
) -> Option<Box<Server>> {
    let mut forward: Option<Box<FRec>> = None;
    let mut domain: Option<String> = None;
    let mut flags: u32 = 0;
    let mut type_ = 0;

    // 提取请求中的信息
    let gotname = extract_request(header, plen.try_into().unwrap(), dnamebuff);

    let header = match header {
        Some(ref mut hdr) => hdr, // 如果存在，解引用
        None => {
            // 如果 header 为空，直接返回 None
            return None;
        }
    };
    let header_bytes = header_to_bytes(*header);
    // 递归未启用或没有可用服务器
    if header.rd == 0 || servers.is_none() {
        forward = None;
    }
    // 检查是否有已有的转发记录
    if let Some(existing_forward) = lookup_frec_by_sender(header.id, udp_addr) {
        forward = Some(existing_forward);
        if let Some(ref mut fwd) = forward {
            fwd.sentto = fwd
                .sentto
                .as_mut()
                .and_then(|s| s.next.clone())
                .or(servers.clone());
            header.id = fwd.new_id;
        }
    } else {
        // 如果没有转发记录，查找匹配的服务器
        if gotname {
            let namelen = dnamebuff.len();
            let mut matchlen = 0;
            let current_server = servers.as_deref();
            while let Some(serv) = current_server {
                // 检查是否为 NODOTS 匹配
                if (serv.flags & SERV_FOR_NODOTS) != 0
                    && (serv.flags & SERV_HAS_DOMAIN) == 0
                    && !dnamebuff.contains(&b'.')
                {
                    if (serv.flags & SERV_LITERAL_ADDRESS) != 0 {
                        let sflag = if serv.addr.sa.sa_family == 2 {
                            F_IPV4
                        } else {
                            F_IPV6
                        };
                        if sflag != 0 {
                            type_ = SERV_FOR_NODOTS;
                            flags = sflag;
                        }
                    } else {
                        flags = 0;
                    }
                } else if (serv.flags & SERV_HAS_DOMAIN) != 0 {
                    if let Some(serv_domain) = &serv.domain {
                        let domainlen = serv_domain.len();
                        if namelen >= domainlen
                            && dnamebuff[namelen - domainlen..]
                                .eq_ignore_ascii_case(serv_domain.as_bytes())
                            && domainlen > matchlen
                        {
                            if (serv.flags & SERV_LITERAL_ADDRESS) != 0 {
                                let sflag = if serv.addr.sa.sa_family == AF_INET {
                                    F_IPV4
                                } else {
                                    F_IPV6
                                };
                                if sflag != 0 {
                                    domain = Some(serv_domain.clone());
                                    flags = sflag;
                                    matchlen = domainlen;
                                }
                            } else {
                                domain = Some(serv_domain.clone());
                                matchlen = domainlen;
                            }
                        }
                    }
                }
            }
        }
        if gotname && (options & OPT_NODOTS_LOCAL != 0) && !dnamebuff.contains(&b'.') {
            flags = F_NXDOMAIN; // 设置 NXDOMAIN 标志
        }

        if let Some(new_frec) = get_new_frec(now) {
            if let Some(ref fwd) = forward {
                // 比较两者的指针地址，或者根据业务逻辑比较具体字段
                if std::ptr::eq(&**fwd, &*new_frec) {
                    flags = F_NEG;
                }
            }
            forward = Some(new_frec);
        }

        // 如果成功获取转发记录，设置转发参数
        if let Some(ref mut fwd) = forward {
            // 检查是否使用严格顺序或特定服务器顺序
            if options & OPT_ORDER != 0 || fwd.sentto.is_some() {
                fwd.sentto = servers.clone();
            } else {
                fwd.sentto = last_server.clone();
            }

            fwd.source = *udp_addr;
            fwd.new_id = get_id(); // 生成新 ID
            fwd.orig_id = header.id;
            header.id = fwd.new_id; // 更新 header 的 ID
        }
    }

    if flags == 0 {
        if let Some(ref mut forward) = forward.as_mut() {
            let first_sentto = forward.sentto.clone();
            loop {
                if let Some(sentto) = forward.sentto.as_ref() {
                    if type_ == (sentto.flags & SERV_TYPE)
                        && (type_ != SERV_HAS_DOMAIN
                            || (domain.is_some()
                                && sentto.domain.is_some()
                                && hostname_isequal(
                                    &domain.clone().unwrap(),
                                    sentto.domain.as_ref().unwrap(),
                                )))
                    {
                        if sentto.flags & SERV_NO_ADDR != 0 {
                            flags = F_NOERR;
                        } else if sentto.flags & SERV_LITERAL_ADDRESS == 0 {
                            if let Some(sfd) = &sentto.sfd {
                                // 使用 send_query 函数来发送数据
                                if send_query(
                                    sfd.fd,
                                    header_bytes,
                                    extract_socket_addr(&sentto.addr),
                                )
                                .is_ok()
                                {
                                    return if domain.is_some() {
                                        last_server
                                    } else {
                                        sentto.next.clone()
                                    };
                                }
                            }
                        }
                    }
                }
                if let Some(sentto) = &forward.sentto {
                    // 尝试将 `forward.sentto` 设置为 `sentto.next`
                    forward.sentto = sentto.next.clone();

                    // 如果 `sentto.next` 为 `None`，设置为 `servers`
                    if forward.sentto.is_none() {
                        forward.sentto = servers.clone();
                    }
                }

                // 检查是否回到了第一个节点
                if let Some(ref current_sentto) = forward.sentto {
                    if let Some(first_sentto) = first_sentto.as_deref() {
                        if std::ptr::eq(current_sentto.as_ref(), first_sentto) {
                            break;
                        }
                    }
                }
            }
            header.id = forward.orig_id.to_be();
            forward.new_id = 0;
        }
    }
    // let plen = setup_reply(header, plen, addrp, flags, local_ttl);
    let _ = send_query(udp_socket, header_bytes, extract_socket_addr(udp_addr));

    last_server
}

fn header_to_bytes(header: Header) -> &'static [u8] {
    unsafe {
        std::slice::from_raw_parts(
            &header as *const Header as *const u8,
            std::mem::size_of::<Header>(),
        )
    }
}

// 发送udp协议查询请求
pub fn send_query(fd: i32, header: &[u8], addr: SocketAddr) -> Result<(), std::io::Error> {
    // 将 i32 文件描述符转换为临时 UdpSocket
    let socket = unsafe { UdpSocket::from_raw_fd(fd) };

    // 发送数据
    let result = socket.send_to(header, addr);

    // 避免文件描述符被 Drop 关闭，重新使用文件描述符而不销毁它
    std::mem::forget(socket);

    result.map(|_| ())
}

// 提取ip地址和端口
pub fn extract_socket_addr(addr: &MySockAddr) -> SocketAddr {
    unsafe {
        if addr.sa.sa_family == AF_INET {
            // IPv4 地址
            let addr_in = unsafe { addr.in_ };
            let addr_u32 = NetworkEndian::read_u32(&addr_in.sin_addr.s_addr.to_be_bytes());
            let ip = Ipv4Addr::from(addr_u32);
            let port = u16::from_be(addr_in.sin_port);
            SocketAddr::new(std::net::IpAddr::V4(ip), port)
        } else if addr.sa.sa_family == AF_INET6 {
            let ipv6 = addr.in6;
            let ip = std::net::Ipv6Addr::from(ipv6.sin6_addr.s6_addr);
            let port = u16::from_be(ipv6.sin6_port);
            SocketAddr::new(std::net::IpAddr::V6(ip), port)
        } else {
            panic!("Unsupported address family");
        }
    }
}

pub fn get_id() -> u16 {
    let mut ret: u16 = 0;

    while ret == 0 {
        ret = rand16();

        // 如果 ID 已经存在于链表中，重新生成
        if ret != 0 && unsafe { lookup_frec(ret).is_some() } {
            ret = 0;
        }
    }

    ret
}

// 从缓存中获取一个可用的 FRec 结构体
pub fn get_new_frec(now: SystemTime) -> Option<Box<FRec>> {
    unsafe {
        let mut f = FREC_LIST.as_mut();
        let mut oldest: Option<Box<FRec>> = None;
        let mut oldtime = now;
        let mut count = 0;

        // 遍历链表
        while let Some(frec) = f {
            if frec.new_id == 0 {
                frec.time = now;
                return Some(frec.clone());
            }

            if frec.time <= oldtime {
                oldtime = frec.time;
                oldest = Some(frec.clone());
            }

            count += 1;

            // 获取下一节点
            f = frec.next.as_mut();
        }

        // 如果没有空闲记录，复用最旧记录
        if let Some(mut oldest_frec) = oldest {
            if now.duration_since(oldest_frec.time).unwrap_or_default() > TIMEOUT {
                oldest_frec.time = now;
                return Some(oldest_frec);
            }
        }

        // 如果记录数超出限制，记录日志并返回 None
        if count > FTABSIZ {
            if WARN_TIME.is_none()
                || now.duration_since(WARN_TIME.unwrap()).unwrap_or_default() > LOGRATE
            {
                WARN_TIME = Some(now);
            }
            return None;
        }

        // 如果没有找到合适的记录，则分配新的记录
        let new_frec = Box::new(FRec {
            source: MySockAddr::default(),
            sentto: None,
            orig_id: 0,
            new_id: 0,
            fd: -1,
            time: now,
            next: FREC_LIST.clone(),
        });

        // 更新链表头
        FREC_LIST = Some(new_frec.clone());

        // 返回新分配的记录
        Some(new_frec)
    }
}

pub fn lookup_frec_by_sender(id: u16, addr: &MySockAddr) -> Option<Box<FRec>> {
    // 遍历链表寻找匹配的 FRec
    let mut current = unsafe { FREC_LIST.as_ref() };
    while let Some(frec) = current {
        if frec.new_id != 0 && frec.orig_id == id && sockaddr_isequal(&frec.source, addr) {
            return Some(frec.clone());
        }
        current = frec.next.as_ref();
    }

    // 如果没有匹配，返回默认值
    None
}

pub fn reap_forward(fd: i32) {
    let mut current = unsafe { FREC_LIST.as_mut() };

    while let Some(f) = current {
        if f.fd == fd {
            f.new_id = 0; // 重置 new_id 字段
        }
        current = f.next.as_mut(); // 移动到下一个节点
    }
}
