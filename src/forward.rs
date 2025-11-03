/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use crate::*;
use std::{net::UdpSocket, os::fd::FromRawFd, time::SystemTime};

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
