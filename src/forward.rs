/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use crate::*;
use byteorder::{ByteOrder, NetworkEndian};
use std::{collections::HashMap, net::UdpSocket, os::fd::FromRawFd, time::SystemTime};

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

// 处理DNS查询的响应包，根据响应包中的信息，更新本地缓存，并根据需要发送响应包
pub fn reply_query(
    fd: i32,
    options: u32,
    packet: &mut Vec<u8>,
    now: SystemTime,
    dnamebuff: &mut Vec<u8>,
    mut last_server: Option<Box<option::Server>>,
    bogus_nxdomain: Option<Box<option::BogusAddr>>,
    caches: &mut Cache,
) -> Option<Box<Server>> {
    let forward_records: &mut HashMap<u16, FRec> = todo!();
    // 使用原始文件描述符创建 UdpSocket
    let socket = unsafe { UdpSocket::from_raw_fd(fd) };
    let mut buf = [0; 512];

    // 接收数据包
    let (n, src_addr) = match socket.recv_from(&mut buf) {
        Ok((n, addr)) => (n, addr),
        Err(_) => return last_server,
    };

    packet.clear();
    packet.extend_from_slice(&buf[..n]);

    if n < 12 {
        return last_server;
    }

    let header = &packet[..12];
    let qr = header[2] & 0b1000_0000 != 0;

    if qr {
        let id = NetworkEndian::read_u16(&header[0..2]);
        if let Some(forward) = forward_records.get_mut(&id) {
            let rcode = header[3] & 0b0000_1111;
            if rcode == 0 || rcode == 3 {
                if forward.sentto.as_ref().unwrap().domain.is_none() {
                    last_server = forward.sentto.clone();
                }
                let opcode = (header[2] & 0b0111_1000) >> 3;
                if opcode == 0 {
                    if !(bogus_nxdomain.is_some()
                        && rcode == 0
                        && check_for_bogus_wildcard(
                            header,
                            n,
                            dnamebuff,
                            bogus_nxdomain,
                            now,
                            caches,
                        ))
                    {
                        let ancount = NetworkEndian::read_u16(&header[6..8]);
                        if rcode == 0 && ancount != 0 {
                            extract_addresses(caches, header, n, dnamebuff, now);
                        } else if options & OPT_NO_NEG == 0 {
                            extract_neg_addrs(caches, header, n, dnamebuff, now);
                        }
                    }
                }
            }
            let orig_id = forward.orig_id;
            NetworkEndian::write_u16(&mut packet[0..2], orig_id);
            packet[2] &= 0b1111_0111; // 清除 TC 标志位

            // 发送数据包
            if let Err(_) = socket.send_to(&packet[..n], src_addr) {
                syslog!(LOG_ERR, "sendto failed",);
            }
            forward.new_id = 0;
        }
    }

    last_server
}
