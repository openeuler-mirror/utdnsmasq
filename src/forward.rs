/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use lazy_static::lazy_static;
use socket2::Socket;
use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cache::{log_query, Cache};
use crate::config::{Config, FTABSIZ, LOGRATE, TIMEOUT};
use crate::dnsmasq::{
    AllAddr, Frec, Header, MySockAddr, Server, F_CONFIG, F_FORWARD, F_IPV4, F_IPV6, F_NEG, F_NOERR,
    F_NXDOMAIN, F_SERVER, NOERROR, NXDOMAIN, OPT_NODOTS_LOCAL, OPT_NO_NEG, OPT_ORDER, QUERY,
    SERV_FOR_NODOTS, SERV_HAS_DOMAIN, SERV_LITERAL_ADDRESS, SERV_NO_ADDR, SERV_TYPE,
};
use crate::logs::LOG_WARNING;
use crate::rfc1035::{
    check_for_bogus_wildcard, extract_addresses, extract_neg_addrs, extract_request, setup_reply,
};
use crate::syslog;
use crate::util::{difftime, hostname_isequal, rand16, socket_is_eq};

lazy_static! {
    static ref FREC_LIST: Mutex<Vec<Arc<Mutex<Frec>>>> = Mutex::new(Vec::new());
    static ref FREC_LIST_ID: Mutex<Vec<u16>> = Mutex::new(Vec::new());
}
static WARN_TIME: Mutex<SystemTime> = Mutex::new(UNIX_EPOCH);

// 初始化FREC_LIST
pub fn forward_init(first: bool) {
    // 清空整个id存储列表
    if let Ok(mut list) = FREC_LIST_ID.lock() {
        list.clear();
    }
    if first {
        // 清空整个列表
        if let Ok(mut list) = FREC_LIST.lock() {
            list.clear();
        }
    } else {
        // 将所有项目的 new_id 设为 0
        if let Ok(mut list) = FREC_LIST.lock() {
            for frec in list.iter_mut() {
                if let Ok(mut frec_guard) = frec.lock() {
                    frec_guard.new_id = 0;
                }
            }
        }
    }
}

// 在id存储表中删除id
fn delete_frec_list_id(id: u16) {
    if let Ok(mut list) = FREC_LIST_ID.lock() {
        list.retain(|&x| x != id);
    }
}

/*
 * Delete all forward records received from socket fd
 * 删除从套接字fd收到的所有转发记录
 */
pub fn reap_forward(socket: &Socket) {
    // 假设 frec_list 是全局的 Mutex<Vec<Frec>>
    if let Ok(mut list) = FREC_LIST.lock() {
        for frec in list.iter_mut() {
            if let Ok(mut frec_guard) = frec.lock() {
                if socket_is_eq(&frec_guard.socket, socket) {
                    // 在id存储表中删除id
                    delete_frec_list_id(frec_guard.new_id);
                    frec_guard.new_id = 0;
                }
            }
        }
    }
}

pub struct ForwardQueryArgs<'a> {
    pub cache: &'a mut Cache,
    pub udpfd: Socket,
    pub udpaddr: MySockAddr,
    pub packet: &'a mut [u8],
    pub options: u32,
    pub servers: Option<Box<Server>>,
    pub last_server: &'a Option<Box<Server>>,
    pub now: SystemTime,
    pub local_ttl: u32,
}

pub fn forward_query(args: ForwardQueryArgs<'_>) -> Option<Box<Server>> {
    let ForwardQueryArgs {
        cache,
        udpfd,
        udpaddr,
        packet,
        options,
        servers,
        last_server,
        now,
        local_ttl,
    } = args;
    let mut forward: Option<Arc<Mutex<Frec>>>;
    let mut domain: String = String::new();
    let mut typ: u32 = 0;
    let mut flags: u16 = 0;
    let mut addrp: Option<AllAddr> = None;
    let (gotname, dnamebuff) = extract_request(packet);

    // 解析头数据
    let mut header = Header::parse(packet).unwrap();

    forward = lookup_frec_by_sender(header.id, udpaddr); // 不转发
    if !header.rd || servers.is_none() {
        forward = None;
    } else if let Some(ref forward) = forward {
        if let Ok(mut frec) = forward.lock() {
            if let Some(sentto) = &frec.sent_to {
                domain = sentto.domain.clone();
                typ = sentto.flags & SERV_TYPE;
            } else {
                println!("forward_query sentto faild");
            }
            if let Some(current_server) = frec.sent_to.clone() {
                frec.sent_to = current_server.next;
                if frec.sent_to.is_none() {
                    frec.sent_to = servers.clone();
                }
            }
        }
    } else {
        if gotname != 0 {
            let namelen: usize = dnamebuff.len();
            let mut matchlen: usize = 0;
            let mut current = servers.clone();
            while let Some(serv) = current {
                if serv.flags & SERV_FOR_NODOTS != 0
                    && typ != SERV_HAS_DOMAIN
                    && dnamebuff.contains('.')
                {
                    if serv.flags & SERV_LITERAL_ADDRESS != 0 {
                        let sflag = if serv.addr.is_ipv4() { F_IPV4 } else { F_IPV6 };

                        if sflag & gotname != 0 {
                            typ = SERV_FOR_NODOTS;
                            flags = sflag;
                            addrp = Some(serv.addr.ip());
                        }
                    } else {
                        flags = 0;
                    }
                } else if serv.flags & SERV_HAS_DOMAIN != 0 {
                    let domainlen = serv.domain.len();
                    if namelen >= domainlen
                        && hostname_isequal(&dnamebuff[namelen - domainlen..], &serv.domain)
                        && domainlen > matchlen
                    {
                        if serv.flags & SERV_LITERAL_ADDRESS != 0 {
                            let sflag = if serv.addr.is_ipv4() { F_IPV4 } else { F_IPV6 };

                            if sflag & gotname != 0 {
                                typ = SERV_HAS_DOMAIN;
                                flags = sflag;
                                domain = serv.domain.clone();
                                matchlen = domainlen;
                                addrp = Some(serv.addr.ip());
                            }
                        } else {
                            flags = 0;
                            domain = serv.domain.clone();
                            matchlen = domainlen;
                        }
                    }
                }

                current = serv.next;
            }
        }

        if flags != 0 && addrp.is_some() {
            log_query(cache, F_CONFIG | F_FORWARD | flags, &dnamebuff, addrp);
        } else if gotname != 0 && options & OPT_NODOTS_LOCAL != 0 && !dnamebuff.contains('.') {
            flags = F_NXDOMAIN;
        } else {
            forward = get_new_frec(now);
            if forward.is_none() {
                flags = F_NEG;
            }
        }

        // 记录向上游转发的转发信息
        if let Some(ref forward) = forward {
            if let Ok(mut cur_forward) = forward.lock() {
                if typ != 0 || options & OPT_ORDER != 0 {
                    cur_forward.sent_to = servers.clone(); // 严格顺序模式或特定服务器
                } else {
                    cur_forward.sent_to = last_server.clone(); // 使用上次成功的服务器
                }

                cur_forward.source = udpaddr;
                let id = get_id();
                let mut frec_list_id = FREC_LIST_ID.lock().unwrap();
                cur_forward.new_id = id;
                frec_list_id.push(id);
                cur_forward.socket = udpfd.try_clone().expect("Failed to clone udpfd");
                cur_forward.orig_id = header.id;
                header.id = cur_forward.new_id;
            }
        }
    }

    if flags == 0 && forward.is_some() {
        if let Some(ref forward_arc) = forward {
            if let Ok(mut forward_guard) = forward_arc.lock() {
                let firstsentto = forward_guard.sent_to.clone();

                loop {
                    let logflags;
                    if let Some(sentto) = &forward_guard.sent_to {
                        if sentto.addr.is_ipv4() {
                            logflags = F_SERVER | F_IPV4 | F_FORWARD;
                            addrp = Some(sentto.addr.ip());
                        } else {
                            logflags = F_SERVER | F_IPV6 | F_FORWARD;
                            addrp = Some(sentto.addr.ip());
                        }

                        if typ == (sentto.flags & SERV_TYPE) && typ != SERV_HAS_DOMAIN
                            || hostname_isequal(&domain, &sentto.domain)
                        {
                            if sentto.flags & SERV_NO_ADDR != 0 {
                                flags = F_NOERR;
                            } else if sentto.flags & SERV_LITERAL_ADDRESS == 0 {
                                // 数据发送到客户端，使用客户端的socket链接
                                if let Some(sfd) = &sentto.sfd {
                                    if let Ok(forward_addr) = sfd.socket.try_clone() {
                                        let forward_addr: UdpSocket = forward_addr.into();
                                        let header_bytes = header.to_bytes();
                                        packet[..12].copy_from_slice(&header_bytes);
                                        let _ = forward_addr.send_to(packet, sentto.addr);
                                    }
                                    let name = if gotname != 0 {
                                        dnamebuff.clone()
                                    } else {
                                        "query".to_string()
                                    };
                                    log_query(cache, logflags, &name, addrp);
                                    if !domain.is_empty() {
                                        return last_server.clone();
                                    } else if sentto.next.is_some() {
                                        return sentto.next.clone();
                                    } else {
                                        return servers;
                                    }
                                }
                            }
                        }

                        if let Some(current_server) = forward_guard.sent_to.clone() {
                            forward_guard.sent_to = current_server.next;
                            if forward_guard.sent_to.is_none() {
                                forward_guard.sent_to = servers.clone();
                            }

                            // Compare using pointer equality or check if both are None/Some
                            match (&forward_guard.sent_to, &firstsentto) {
                                (Some(a), Some(b)) if std::ptr::eq(a.as_ref(), b.as_ref()) => break,
                                (None, None) => break,
                                _ => (),
                            }
                        }
                    }
                }

                header.id = forward_guard.orig_id;
                delete_frec_list_id(forward_guard.new_id); // 删除列表中的id
                forward_guard.new_id = 0;
            }
        }
    }

    let send_packet = setup_reply(packet, addrp, flags, local_ttl);
    // let send_packet = &packet[..qlen];
    // 数据发送到客户端，使用客户端的socket链接
    if let Ok(forward_addr) = udpfd.try_clone() {
        let forward_addr: UdpSocket = forward_addr.into();
        let _ = forward_addr.send_to(&send_packet, udpaddr);
    }

    if flags & (F_NOERR | F_NXDOMAIN) != 0 {
        log_query(
            cache,
            F_CONFIG | F_FORWARD | F_NEG | gotname | (flags & F_NXDOMAIN),
            &dnamebuff,
            None,
        );
    }
    last_server.clone()
}

pub fn reply_query(
    caches: &mut Cache,
    config: &mut Config,
    socket: Socket, // 上游服务器的socket链接
    now: SystemTime,
    mut last_server: Option<Box<Server>>,
) -> Option<Box<Server>> {
    let mut packet: [u8; 1024] = [0; 1024];

    // 从上游服务器接收数据
    let udpsocket: UdpSocket = socket.into(); // 转换为udpsocket，用于方便接受数据
    let (n, _) = match udpsocket.recv_from(&mut packet) {
        Ok((n, addr)) => (n, addr),
        Err(_) => {
            return last_server;
        }
    };

    let mut header = match Header::parse(&packet[..12]) {
        Ok(header) => header,
        Err(_) => return last_server,
    };

    if header.qr {
        if let Some(forward_arc) = lookup_frec(header.id) {
            if header.rcode == NOERROR || header.rcode == NXDOMAIN {
                let forward = forward_arc.lock().unwrap();
                if let Some(sentto) = &forward.sent_to {
                    if sentto.domain.is_empty() {
                        last_server = Some(sentto.clone());
                    }
                }

                if header.opcode == QUERY
                    && !(!config.bogus_addr.is_empty()
                        && header.rcode == NOERROR
                        && check_for_bogus_wildcard(caches, &mut packet, &config.bogus_addr, now)
                            != 0)
                {
                    header = Header::parse(&packet[..12]).unwrap(); // check_for_bogus_wildcard函数改变了header的数值，所以需要重新解析一下

                    if header.rcode == NOERROR && header.ancount != 0 {
                        extract_addresses(caches, &packet, now);
                    } else if config.options & OPT_NO_NEG == 0 {
                        extract_neg_addrs(caches, &packet, now);
                    }
                }
                header = Header::parse(&packet[..12]).unwrap(); // 获取header被修改后的信息。在重新修改header
                header.id = forward.orig_id;
                header.tc = false;

                // 重新写入数据包
                let header_bytes = header.to_bytes();
                packet[..12].copy_from_slice(header_bytes.as_slice());

                // 数据发送到客户端，使用客户端的socket链接
                if let Ok(forward_addr) = forward.socket.try_clone() {
                    let forward_addr: UdpSocket = forward_addr.into();
                    let _ = forward_addr.send_to(&packet[..n], forward.source);
                }
            }
        }
    }

    last_server
}

// 管理和分配转发记录
fn get_new_frec(now: SystemTime) -> Option<Arc<Mutex<Frec>>> {
    let mut frec_list = FREC_LIST.lock().unwrap();
    let mut oldtime = now;
    let mut oldest: Option<&Arc<Mutex<Frec>>> = None;
    let mut count: u32 = 0;
    let mut warntime = WARN_TIME.lock().unwrap();

    for f in frec_list.iter() {
        if let Ok(frec) = f.lock() {
            if frec.new_id == 0 {
                // 需要重新获取可变引用以修改时间
                if let Ok(mut frec_mut) = f.lock() {
                    frec_mut.time = now;
                }
                return Some(Arc::clone(f));
            }

            if difftime(frec.time, oldtime) <= 0 {
                oldtime = frec.time;
                oldest = Some(f);
            }
            count += 1;
        }
    }

    if let Some(old_arc) = oldest {
        if difftime(now, oldtime) > TIMEOUT as i64 {
            // 需要获取可变引用以修改时间
            if let Ok(mut old_frec) = old_arc.lock() {
                old_frec.time = now;
            }
            return Some(Arc::clone(old_arc));
        }
    }

    // // 超过最大记录数
    if count > FTABSIZ {
        // 限制日志记录速率，这样syslog日志也不会被DOSed
        if *warntime == UNIX_EPOCH || difftime(now, *warntime) > LOGRATE {
            *warntime = now;
            syslog!(
                LOG_WARNING,
                "forwarding table overflow: check for server loops."
            );
        }
        return None;
    }

    // 新建一个存储项
    let new: Frec = Frec {
        time: now,
        ..Default::default()
    };

    let new_arc = Arc::new(Mutex::new(new));
    frec_list.push(Arc::clone(&new_arc));
    Some(new_arc)
}

// 在frec_list中查询 id是否已经被占用
fn lookup_frec(id: u16) -> Option<Arc<Mutex<Frec>>> {
    if let Ok(frec_list) = FREC_LIST.lock() {
        for frec in frec_list.iter() {
            if let Ok(f) = frec.lock() {
                if f.new_id == id {
                    return Some(Arc::clone(frec));
                }
            }
        }
    }

    None
}

// 根据发送者 查找frec
fn lookup_frec_by_sender(id: u16, addr: MySockAddr) -> Option<Arc<Mutex<Frec>>> {
    if let Ok(frec_list) = FREC_LIST.lock() {
        for frec in frec_list.iter() {
            if let Ok(f) = frec.lock() {
                if f.new_id != 0 && f.orig_id == id && f.source == addr {
                    return Some(Arc::clone(frec));
                }
            }
        }
    }
    None
}

// 返回1到65535之间唯一的随机id
fn get_id() -> u16 {
    let frec_list_id = FREC_LIST_ID.lock().unwrap();
    let mut ret: u16 = 0;

    while ret == 0 {
        ret = rand16();

        if ret != 0 && frec_list_id.contains(&ret) {
            ret = 0;
        }
    }

    ret
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::SystemTime;

    #[test]
    fn test_lookup_frec_empty_list() {
        // 测试空列表的情况
        forward_init(true); // 清空列表
        let result = lookup_frec(123);
        assert!(result.is_none(), "Should return None for empty list");
    }

    #[test]
    fn test_lookup_frec_not_found() {
        // 测试查找不存在的ID
        forward_init(true); // 清空列表

        // 添加一些测试记录
        let frec1 = Frec {
            time: SystemTime::now(),
            new_id: 100,
            orig_id: 50,
            source: MySockAddr::from(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 53)),
            socket: Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap(),
            sent_to: None,
            // next: None,
        };

        let frec2 = Frec {
            time: SystemTime::now(),
            new_id: 200,
            orig_id: 150,
            source: MySockAddr::from(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 53)),
            socket: Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap(),
            sent_to: None,
            // next: None,
        };

        // 手动添加到列表
        if let Ok(mut list) = FREC_LIST.lock() {
            list.push(Arc::new(Mutex::new(frec1)));
            list.push(Arc::new(Mutex::new(frec2)));
        }

        // 查找不存在的ID
        let result = lookup_frec(300);
        assert!(result.is_none(), "Should return None for non-existent ID");

        // 查找存在的ID
        let result = lookup_frec(100);
        assert!(result.is_some(), "Should find record with ID 100");

        let result = lookup_frec(200);
        assert!(result.is_some(), "Should find record with ID 200");
    }

    #[test]
    fn test_lookup_frec_multiple_records() {
        // 测试多个记录的情况
        forward_init(true); // 清空列表

        // 添加多个记录
        for i in 1..=5 {
            let frec = Frec {
                time: SystemTime::now(),
                new_id: i * 100,
                orig_id: i * 50,
                source: MySockAddr::from(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    53,
                )),
                socket: Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap(),
                sent_to: None,
                // next: None,
            };

            if let Ok(mut list) = FREC_LIST.lock() {
                list.push(Arc::new(Mutex::new(frec)));
            }
        }

        // 测试查找每个记录
        for i in 1..=5 {
            let result = lookup_frec(i * 100);
            assert!(result.is_some(), "Should find record with ID {}", i * 100);
        }

        // 测试查找不存在的记录
        let result = lookup_frec(999);
        assert!(
            result.is_none(),
            "Should return None for non-existent ID 999"
        );
    }

    #[test]
    fn test_lookup_frec_zero_id() {
        // 测试ID为0的情况（通常表示未分配）
        forward_init(true); // 清空列表

        // 添加一个new_id为0的记录
        let frec = Frec {
            time: SystemTime::now(),
            new_id: 0, // 未分配的ID
            orig_id: 100,
            source: MySockAddr::from(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 53)),
            socket: Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap(),
            sent_to: None,
            // next: None,
        };

        if let Ok(mut list) = FREC_LIST.lock() {
            list.push(Arc::new(Mutex::new(frec)));
        }

        // 查找ID为0的记录 - 应该能找到，因为lookup_frec会匹配new_id == 0
        let result = lookup_frec(0);
        assert!(
            result.is_some(),
            "Should find record with ID 0 (unassigned records are still in the list)"
        );
    }

    #[test]
    fn test_get_id_avoids_duplicates() {
        // 测试避免重复ID的功能
        forward_init(true); // 清空列表

        // 预填充一些ID到列表中
        {
            let mut frec_list_id = FREC_LIST_ID.lock().unwrap();
            frec_list_id.clear();
            frec_list_id.push(100);
            frec_list_id.push(200);
            frec_list_id.push(300);
        }

        // 生成多个ID，确保不会生成已存在的ID
        for _ in 0..50 {
            let id = get_id();

            // 验证ID不是已存在的ID
            assert_ne!(id, 100, "Should not generate ID 100");
            assert_ne!(id, 200, "Should not generate ID 200");
            assert_ne!(id, 300, "Should not generate ID 300");
        }
    }

    #[test]
    fn test_get_id_never_zero() {
        // 测试生成的ID永远不会是0
        forward_init(true); // 清空列表
        {
            let mut frec_list_id = FREC_LIST_ID.lock().unwrap();
            frec_list_id.clear();
        }

        // 生成多个ID，确保没有0
        for _ in 0..100 {
            let id = get_id();
            assert_ne!(id, 0, "Generated ID should never be 0");
        }
    }

    #[test]
    fn test_get_id_with_full_list() {
        // 测试当列表几乎满时的情况
        forward_init(true); // 清空列表

        // 预填充几乎所有的ID
        {
            let mut frec_list_id = FREC_LIST_ID.lock().unwrap();
            frec_list_id.clear();

            // 添加除少数ID外的所有ID
            for i in 1..=65534 {
                if i != 5000 && i != 10000 && i != 15000 {
                    frec_list_id.push(i);
                }
            }
        }

        // 生成多个ID，应该能成功生成可用的ID
        for _ in 0..3 {
            let id = get_id();

            // 验证ID是预留给用的ID之一
            assert!(
                id == 5000 || id == 10000 || id == 15000 || id == 65535,
                "Generated ID should be one of the available IDs, got {}",
                id
            );

            // 将生成的ID添加到列表中，模拟实际使用
            {
                let mut frec_list_id = FREC_LIST_ID.lock().unwrap();
                frec_list_id.push(id);
            }
        }
    }
}
