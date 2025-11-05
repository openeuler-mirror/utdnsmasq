/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use crate::rfc1035::*;
use crate::util::*;
use crate::*;
use std::{net::UdpSocket, os::fd::FromRawFd, time::SystemTime};

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
    bogus_nxdomain: Option<Box<BogusAddr>>,
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
                            n as usize,
                            dnamebuff,
                            bogus_nxdomain,
                            now,
                            caches,
                        ))
                    {
                        if header.rcode == NOERROR && header.ancount != 0 {
                            extract_addresses(caches, &header_option, n as usize, dnamebuff, now);
                        } else if (options & OPT_NO_NEG) == 0 {
                            extract_neg_addrs(caches, &header_option, n as usize, dnamebuff, now);
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
    mut dnamebuff: Vec<u8>,
    servers: Option<Box<option::Server>>,
    last_server: Option<Box<option::Server>>,
    now: SystemTime,
    local_ttl: u64,
) -> Option<Box<Server>> {
    let mut forward: Option<Box<FRec>> = None;
    let mut domain: Option<String> = None;
    let mut flags: u32 = 0;
    let mut type_ = 0;
    let addrp: Option<&[u8]> = None;

    // 提取请求中的信息
    let gotname = extract_request(header, plen.try_into().unwrap(), &mut dnamebuff);

    let header = match header {
        Some(ref mut hdr) => hdr, // 如果存在，解引用
        None => {
            // 如果 header 为空，直接返回 None
            return None;
        }
    };

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
            let mut current_server = servers.as_deref();
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

        // if forward == get_new_frec(now) {
        //     flags = F_NEG;
        // }

        // 如果成功获取转发记录，设置转发参数
        if let Some(ref mut fwd) = forward {
            // 检查是否使用严格顺序或特定服务器顺序
            if options & OPT_ORDER != 0 || fwd.sentto.is_some() {
                fwd.sentto = servers;
            } else {
                fwd.sentto = last_server;
            }

            fwd.source = udp_addr.clone();
            // fwd.new_id = get_id(); // 生成新 ID
            fwd.fd = udp_socket;
            fwd.orig_id = header.id;
            header.id = fwd.new_id; // 更新 header 的 ID
        }
    }

    None
}

// pub fn get_new_frec(now: SystemTime) -> Option<Box<FRec>> {
//     unsafe {
//         let mut f = FREC_LIST.as_mut();
//         let mut oldest: Option<Box<FRec>> = None;
//         let mut oldtime = now;
//         let mut count = 0;

//         // 遍历链表
//         while let Some(ref mut frec) = f {
//             if frec.new_id == 0 {
//                 frec.time = now;
//                 return f.cloned();
//             }

//             if frec.time <= oldtime {
//                 oldtime = frec.time;
//                 // oldest = frec;
//             }

//             count += 1;
//             f = frec.next.as_mut();
//         }

//         // 如果没有空闲记录，复用最旧记录
//         if let Some(mut oldest_frec) = oldest {
//             if now.duration_since(oldest_frec.time).unwrap_or_default() > TIMEOUT {
//                 oldest_frec.time = now;
//                 return oldest;
//             }
//         }

//         // 如果记录数超出限制，记录日志并返回 None
//         if count > FTABSIZ {
//             if WARN_TIME.is_none()
//                 || now.duration_since(WARN_TIME.unwrap()).unwrap_or_default() > LOGRATE
//             {
//                 WARN_TIME = Some(now);
//             }
//             return None;
//         }

//         None
//     }
// }
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
