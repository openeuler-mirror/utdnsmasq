/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use crate::util::*;
use crate::*;
use byteorder::{ByteOrder, NetworkEndian};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

pub type InAddrT = u32;

const F_IPV4: u32 = 128;
const F_FORWARD: u32 = 8;
const F_NEG: u32 = 32;
const F_NXDOMAIN: u32 = 4096;
const F_CONFIG: u32 = 2;
pub const C_IN: u16 = 1;
const F_REVERSE: u32 = 4;
const F_IPV6: u32 = 256;
const NS_INT16SZ: usize = 2;
const NS_INT32SZ: usize = 4;
const MAXARPANAME: usize = 75;
const T_PTR: u16 = 12; // PTR 记录
pub const T_A: u16 = 1; // A 记录
pub const T_AAAA: u16 = 28; // AAAA 记录
const T_SOA: u16 = 6; // SOA 记录
pub const NXDOMAIN: u8 = 3; // NXDOMAIN 响应码
const T_ANY: u16 = 255;
const NOERROR: u8 = 0;
const IN6ADDRSZ: u16 = 16;
pub const QUERY: u8 = 0;
pub const C_CHAOS: u16 = 3;
pub const T_TXT: u16 = 16;
const OPT_FILTER: u32 = 2;
const T_SRV: u16 = 33;
const T_MX: u16 = 15;
const T_MAILB: u16 = 253;
const SERVFAIL: u8 = 2;
const REFUSED: u8 = 5;

// 检查DNS响应数据包中是否存在虚假的IP地址
pub fn check_for_bogus_wildcard(
    header: &Option<Header>,
    qlen: usize,
    name: &mut [u8],
    baddr: Option<Box<BogusAddr>>,
    now: SystemTime,
    caches: &mut Cache,
) -> bool {
    // 将 Option<Header> 转换为字节数组
    let header_bytes = match header {
        Some(h) => h.to_bytes(),
        None => return false, // 无效的数据包
    };

    // 跳过问题部分
    let mut p = match skip_questions(&header, qlen) {
        Some(p) => p,
        None => return false, // 无效的数据包
    };

    // 获取回答部分数量
    let ancount = NetworkEndian::read_u16(&header_bytes[6..8]) as usize;

    // 遍历回答部分
    for _ in 0..ancount {
        if !extract_name(&header_bytes, qlen, &mut p, name, true) {
            return false; // 无效的数据包
        }

        if p.len() < 10 {
            return false; // 数据包太短
        }

        // 读取回答部分的 qtype, qclass, ttl, rdlen
        let qtype = NetworkEndian::read_u16(&p[0..2]);
        let qclass = NetworkEndian::read_u16(&p[2..4]);
        let ttl = NetworkEndian::read_u32(&p[4..8]);
        let rdlen = NetworkEndian::read_u16(&p[8..10]) as usize;
        p = &p[10..];

        // 判断是否为 C_IN 和 T_A 类型的回答
        if qclass == 1 && qtype == 1 {
            let mut baddrp = baddr.as_ref();

            while let Some(baddr_ref) = baddrp {
                // 对比回答部分的 IP 地址
                if rdlen >= 4 && baddr_ref.addr.s_addr == NetworkEndian::read_u32(&p[0..4]) {
                    // 找到虚假地址，修改包头为 NXDOMAIN
                    let mut header_mut = header_bytes.clone();
                    header_mut[2] &= 0b0111_1111; // 清除 AA 位
                    header_mut[3] |= 0b1000_0000; // 设置 RA 位
                    NetworkEndian::write_u16(&mut header_mut[8..10], 0);
                    NetworkEndian::write_u16(&mut header_mut[10..12], 0);
                    NetworkEndian::write_u16(&mut header_mut[6..8], 0);
                    header_mut[3] = (header_mut[3] & 0b1111_0000) | 3;

                    cache_start_insert(caches);
                    cache_insert(
                        caches,
                        name,
                        None,
                        now,
                        ttl,
                        F_IPV4 | F_FORWARD | F_NEG | F_NXDOMAIN | F_CONFIG,
                    );
                    cache_end_insert(caches);

                    return true;
                }
                baddrp = baddr_ref.next.as_ref();
            }
        }

        if p.len() < rdlen {
            return false; // 数据包太短
        }

        p = &p[rdlen..];
    }

    false
}

// 从 DNS 数据包中跳过所有问题部分，并返回指向答案部分的切片。
pub fn skip_questions(header: &Option<Header>, plen: usize) -> Option<&[u8]> {
    // 确保 header 存在
    let header = header.as_ref()?;

    // 假设 Header 的大小为 12 字节
    let header_size = 12;

    // 获取 qdcount (问题部分的数量)
    let qdcount = header.qdcount;

    // 使用 Header 之后的数据开始解析
    // 注意：这里假设输入的数据是在 header 之后紧跟着的 DNS 消息内容
    // 直接对内存进行操作，避免创建新的字节数组，header 是外部引用
    // 假设 Header 本身是一个实际包数据的一部分，计算从 Header 结束后的位置开始的数据。
    let ansp = unsafe {
        let ptr = header as *const Header as *const u8;
        let data_ptr = ptr.add(header_size);
        std::slice::from_raw_parts(data_ptr, plen.saturating_sub(header_size))
    };

    let mut ansp = &ansp[..];

    // 遍历所有的问题部分
    for _ in 0..qdcount {
        loop {
            if ansp.is_empty() || ansp.len() > plen {
                return None; // 数据包无效
            }

            let label_type = ansp[0] & 0xc0;

            if label_type == 0xc0 {
                // 指针压缩
                if ansp.len() < 2 {
                    return None; // 数据包无效
                }
                ansp = &ansp[2..];
                break;
            } else if label_type == 0x80 {
                return None; // 保留标签，无效的数据包
            } else if label_type == 0x40 {
                // 扩展标签类型
                if ansp.len() < 2 {
                    return None; // 数据包无效
                }
                if (ansp[0] & 0x3f) != 1 {
                    return None; // 只支持位串类型为 1
                }
                let count = ansp[1];
                ansp = &ansp[2..];
                if count == 0 {
                    if ansp.len() < 32 {
                        return None; // 数据包无效
                    }
                    ansp = &ansp[32..];
                } else {
                    let bytes_to_skip = ((count - 1) >> 3) + 1;
                    if ansp.len() < bytes_to_skip as usize {
                        return None; // 数据包无效
                    }
                    ansp = &ansp[bytes_to_skip as usize..];
                }
            } else {
                // 标签类型为 0，底部六位是长度
                let len = (ansp[0] & 0x3f) as usize;
                ansp = &ansp[1..];
                if len == 0 {
                    break; // 零长度标签表示结束
                }
                if ansp.len() < len {
                    return None; // 数据包无效
                }
                ansp = &ansp[len..];
            }
        }
        if ansp.len() < 4 {
            return None; // 数据包无效
        }
        ansp = &ansp[4..]; // 跳过 class 和 type
    }

    if ansp.len() > plen {
        return None; // 数据包无效
    }

    Some(ansp)
}

// 用于从 DNS 报文的字节数组中提取域名，并将其存储到 name 数组中
fn extract_name<'a>(
    header: &'a [u8],
    plen: usize,
    pp: &mut &'a [u8],
    name: &mut [u8],
    is_extract: bool,
) -> bool {
    let mut cp = 0;
    let mut p = *pp;
    let mut p1 = None;
    let mut hops = 0;

    while let Some(&l) = p.get(0) {
        p = &p[1..];
        let label_type = l & 0xc0;

        if label_type == 0xc0 {
            if p.len() < 1 || p.as_ptr() as usize - header.as_ptr() as usize + 1 >= plen {
                return false;
            }
            let offset = (((l & 0x3f) as usize) << 8) | p[0] as usize;
            p = &p[1..];
            if offset >= plen {
                return false;
            }
            if p1.is_none() {
                p1 = Some(p);
            }
            p = &header[offset..];
            hops += 1;
            if hops > 255 {
                return false;
            }
        } else if label_type == 0x80 {
            return false;
        } else if label_type == 0x40 {
            if (l & 0x3f) != 1 {
                return false;
            }
            if !is_extract {
                return false;
            }
            if p.len() < 1 {
                return false;
            }
            let count = if p[0] == 0 { 256 } else { p[0] as usize };
            p = &p[1..];
            let digs = ((count - 1) >> 2) + 1;
            if cp + digs + 9 >= name.len() || p.len() < ((count - 1) >> 3) + 1 {
                return false;
            }
            name[cp] = b'\\';
            name[cp + 1] = b'[';
            name[cp + 2] = b'x';
            cp += 3;
            for j in 0..digs {
                let dig = if j % 2 == 0 {
                    p[j / 2] >> 4
                } else {
                    p[j / 2] & 0x0f
                };
                name[cp] = if dig < 10 {
                    dig + b'0'
                } else {
                    dig + b'A' - 10
                };
                cp += 1;
            }
            write!(&mut name[cp..], "/{count}]").unwrap();
            cp += 9;
            name[cp] = b'.';
            cp += 1;
            p = &p[((count - 1) >> 3) + 1..];
        } else {
            let len = (l & 0x3f) as usize;
            if cp + len + 1 >= name.len() || p.len() < len {
                return false;
            }
            name[cp..cp + len].copy_from_slice(&p[..len]);
            cp += len;
            p = &p[len..];
            name[cp] = b'.';
            cp += 1;
        }

        if p.as_ptr() as usize - header.as_ptr() as usize >= plen {
            return false;
        }
    }

    if cp > 0 {
        name[cp - 1] = 0; // 终止字符串，去掉最后一个句点
    }

    if let Some(p1) = p1 {
        *pp = p1;
    } else {
        *pp = p;
    }

    true
}

// 从 DNS 响应包中提取地址记录并缓存
pub fn extract_addresses(
    caches: &mut Cache,
    header: &Option<Header>,
    qlen: usize,
    name: &mut [u8],
    now: SystemTime,
) {
    let header_bytes = match header {
        Some(h) => h.to_bytes(),
        None => return,
    };

    let mut p = match skip_questions(&header, qlen) {
        Some(ptr) => ptr,
        None => return,
    };

    cache_start_insert(caches);
    let psave = p;

    // 根据DNS响应头中的答案数量，遍历每个答案记录
    for _ in 0..get_short(&mut &header_bytes[6..8]) {
        let origname = p;

        if !extract_name(&header_bytes, qlen, &mut p, name, true) {
            return;
        }

        let qtype = get_short(&mut p);
        let qclass = get_short(&mut p);
        let ttl = get_long(&mut p);
        let rdlen = get_short(&mut p);

        let endrr = p.get(rdlen as usize..).unwrap_or(&[]);
        if endrr.len() > qlen {
            return;
        }

        if qclass != C_IN {
            p = endrr;
            continue;
        }

        match qtype {
            T_A => {
                let ipv4_bytes = &p[..4];
                cache_insert(caches, name, Some(ipv4_bytes), now, ttl, F_IPV4 | F_FORWARD);
            }
            T_AAAA => {
                let ipv6_bytes = &p[..16];
                cache_insert(caches, name, Some(ipv6_bytes), now, ttl, F_IPV6 | F_FORWARD);
            }
            T_PTR => {
                let mut addr = vec![0; 16];
                let name_encoding = in_arpa_name_2_addr(name, &mut addr);
                if name_encoding != 0 {
                    if !extract_name(&header_bytes, qlen, &mut p, name, true) {
                        return;
                    }
                    cache_insert(
                        caches,
                        name,
                        Some(&addr),
                        now,
                        ttl,
                        name_encoding | F_REVERSE,
                    );
                }
            }
            T_CNAME => {
                let mut targp = p;
                p = psave;
                for _ in 0..get_short(&mut &header_bytes[6..8]) {
                    let mut tmp = targp;
                    if !extract_name(&header_bytes, qlen, &mut tmp, name, true) {
                        return;
                    }
                    let res = extract_name(&header_bytes, qlen, &mut p, name, false);
                    if !res {
                        return;
                    }

                    let qtype = get_short(&mut p);
                    let qclass = get_short(&mut p);
                    let cttl = get_long(&mut p);
                    let rdlen = get_short(&mut p);

                    let endrr1 = p.get(rdlen as usize..).unwrap_or(&[]);
                    if endrr1.len() > qlen {
                        return;
                    }

                    if qclass != C_IN {
                        p = endrr1;
                        continue;
                    }

                    let cttl = if ttl < cttl { ttl } else { cttl };

                    let mut tmp = origname;
                    if !extract_name(&header_bytes, qlen, &mut tmp, name, true) {
                        return;
                    }

                    match qtype {
                        T_A => {
                            let ipv4_bytes = &p[..4];
                            cache_insert(
                                caches,
                                name,
                                Some(ipv4_bytes),
                                now,
                                cttl,
                                F_IPV4 | F_FORWARD,
                            );
                        }
                        T_AAAA => {
                            let ipv6_bytes = &p[..16];
                            cache_insert(
                                caches,
                                name,
                                Some(ipv6_bytes),
                                now,
                                cttl,
                                F_IPV6 | F_FORWARD,
                            );
                        }
                        T_PTR => {
                            let mut addr = vec![0; 16];
                            let name_encoding = in_arpa_name_2_addr(name, &mut addr);
                            if name_encoding != 0 {
                                if !extract_name(&header_bytes, qlen, &mut p, name, true) {
                                    return; // bad packet
                                }
                                cache_insert(
                                    caches,
                                    name,
                                    Some(&addr),
                                    now,
                                    cttl,
                                    name_encoding | F_REVERSE,
                                );
                            }
                        }
                        _ => {}
                    }
                    p = endrr1;
                }
            }
            _ => {}
        }

        p = endrr;
    }

    cache_end_insert(caches);
}

// 从一个字节切片中读取一个16位无符号整数，并更新切片的起始位置
pub fn get_short(cp: &mut &[u8]) -> u16 {
    if cp.len() < NS_INT16SZ {
        panic!("Not enough data to read 16 bits value");
    }

    let value = ((cp[0] as u16) << 8) | (cp[1] as u16);
    *cp = &cp[NS_INT16SZ..]; // 更新指针位置，相当于 C 代码中的 (cp) += NS_INT16SZ;

    value
}

// 从一个字节切片中读取一个32位整数，并更新切片的起始位置
pub fn get_long(cp: &mut &[u8]) -> u32 {
    if cp.len() < NS_INT32SZ {
        panic!("Not enough data to read 32 bits value");
    }

    let value =
        ((cp[0] as u32) << 24) | ((cp[1] as u32) << 16) | ((cp[2] as u32) << 8) | (cp[3] as u32);
    *cp = &cp[NS_INT32SZ..]; // 更新指针位置，相当于 C 代码中的 (cp) += NS_INT32SZ;

    value
}

// 将一个 ARPA 域名转换为 IP 地址，并将结果存储在 addrr 中
pub fn in_arpa_name_2_addr(name: &[u8], addrr: &mut Vec<u8>) -> u32 {
    if name.len() > MAXARPANAME {
        return 0;
    }

    let name_str = match std::str::from_utf8(name) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    let mut labels: Vec<&str> = name_str.split('.').collect();
    if labels.len() < 3 {
        return 0;
    }

    let lastchunk = labels.pop().unwrap();
    let penchunk = labels.pop().unwrap();

    // 处理 IPv4 地址
    if hostname_isequal(lastchunk, "arpa") && hostname_isequal(penchunk, "in-addr") {
        addrr.clear();
        addrr.resize(4, 0);
        for (i, label) in labels.iter().enumerate() {
            if !label.chars().all(|c| c.is_digit(10)) {
                return 0;
            }
            let octet: u8 = match label.parse() {
                Ok(v) => v,
                Err(_) => return 0,
            };
            addrr[3 - i] = octet;
        }
        return F_IPV4;
    // 处理 IPv6 地址
    } else if hostname_isequal(penchunk, "ip6")
        && (hostname_isequal(lastchunk, "int") || hostname_isequal(lastchunk, "arpa"))
    {
        addrr.clear();
        addrr.resize(16, 0);
        if name_str.starts_with("\\[x") {
            let hex_part = &name_str[3..name_str.len() - 1];
            let mut j = 0;
            for (i, ch) in hex_part.chars().enumerate() {
                if !ch.is_digit(16) {
                    return 0;
                }
                let value = ch.to_digit(16).unwrap() as u8;
                if i % 2 == 0 {
                    addrr[j] = value << 4;
                } else {
                    addrr[j] |= value;
                    j += 1;
                }
            }
            if j == 16 {
                return F_IPV6;
            }
        } else {
            let mut idx = 15;
            for label in labels.iter().rev() {
                if label.len() != 1 || !label.chars().all(|c| c.is_digit(16)) {
                    return 0;
                }
                let value = match u8::from_str_radix(label, 16) {
                    Ok(v) => v,
                    Err(_) => return 0,
                };
                if idx % 2 == 1 {
                    addrr[idx / 2] |= value;
                } else {
                    addrr[idx / 2] = value << 4;
                }
                if idx > 0 {
                    idx -= 1;
                }
            }
            return F_IPV6;
        }
    }

    0
}

pub fn extract_neg_addrs(
    caches: &mut Cache,
    header: &Option<Header>,
    plen: usize,
    dnamebuff: &mut Vec<u8>,
    now: SystemTime,
) {
    let header_bytes = match header {
        Some(h) => h.to_bytes(),
        None => return, // 无效的数据包
    };

    let mut found_soa = false;
    let mut minttl: u32 = 0;
    let mut flags = F_NEG;

    // 确保数据包头部长度足够
    if header_bytes.len() < 12 {
        return; // 数据包无效
    }

    // 提取响应码
    let rcode = header_bytes[3] & 0x0F;
    if rcode == NXDOMAIN {
        flags |= F_NXDOMAIN;
    }

    // 确保无回答记录
    let ancount = u16::from_be_bytes([header_bytes[6], header_bytes[7]]);
    if ancount != 0 {
        return; // 存在回答记录，不生成负缓存
    }

    // 跳过问题部分
    let mut p = match skip_questions(&header, plen) {
        Some(ptr) => ptr,
        None => return, // 数据包无效
    };

    // 遍历 NS 部分以查找 SOA 记录
    let nscount = u16::from_be_bytes([header_bytes[8], header_bytes[9]]);
    for _ in 0..nscount {
        if !extract_name(&header_bytes, plen, &mut p, dnamebuff, true) {
            return; // 提取失败
        }

        if p.len() < 10 {
            return; // 包太短
        }

        let qtype = get_short(&mut p);
        let qclass = get_short(&mut p);
        let ttl = get_long(&mut p);
        let rdlen = get_short(&mut p) as usize;

        if qclass == C_IN && qtype == T_SOA {
            // 提取 SOA 记录的 MNAME 和 RNAME
            if !extract_name(&header_bytes, plen, &mut p, dnamebuff, true)
                || !extract_name(&header_bytes, plen, &mut p, dnamebuff, true)
            {
                return; // 提取失败
            }

            if p.len() < 20 {
                return; // 数据包无效
            }

            let min_ttl = get_long(&mut p);
            if !found_soa || ttl.min(min_ttl) < minttl {
                minttl = ttl.min(min_ttl);
            }

            found_soa = true;
        } else {
            p = &p[rdlen..]; // 跳过其他记录
        }

        if p.len() > plen {
            return; // 数据包无效
        }
    }

    if !found_soa {
        return; // 未找到 SOA 记录
    }

    cache_start_insert(caches);

    // 遍历问题部分并生成负缓存
    let mut p = &header_bytes[12..]; // 重置指针到问题部分
    let qdcount = u16::from_be_bytes([header_bytes[4], header_bytes[5]]);
    for _ in 0..qdcount {
        dnamebuff.clear(); // 清空缓冲区

        if !extract_name(&header_bytes, plen, &mut p, dnamebuff, true) {
            return; // 提取失败
        }

        if p.len() < 4 {
            return; // 包无效
        }

        let qtype = get_short(&mut p);
        let qclass = get_short(&mut p);

        if qclass == C_IN {
            if qtype == T_PTR {
                let mut addr = Vec::new();
                if in_arpa_name_2_addr(dnamebuff, &mut addr) != 0 {
                    cache_insert(
                        caches,
                        dnamebuff,
                        Some(&addr),
                        now,
                        minttl,
                        F_REVERSE | flags,
                    );
                }
            } else if qtype == T_A {
                cache_insert(
                    caches,
                    dnamebuff,
                    None,
                    now,
                    minttl,
                    F_IPV4 | F_FORWARD | flags,
                );
            } else if qtype == T_AAAA {
                cache_insert(
                    caches,
                    dnamebuff,
                    None,
                    now,
                    minttl,
                    F_IPV6 | F_FORWARD | flags,
                );
            }
        }
    }

    cache_end_insert(caches);
}

pub fn answer_request(
    header: &mut Option<Header>,
    limit: &mut [u8],
    qlen: u32,
    mxname: Option<String>,
    mxtarget: Option<String>,
    options: u32,
    now: SystemTime,
    local_ttl: u64,
    mut name: Vec<u8>,
    caches: &mut Cache,
) -> i32 {
    let mut addr: Vec<u8> = vec![0; 16];
    let mut qtype = 0;
    let mut qclass = 0;
    let mut crecp: Option<Box<Crec>> = None;
    let qdcount = if let Some(h) = header {
        u16::from_be(h.qdcount) as i32
    } else {
        return 0;
    };

    let all_addr = if addr.len() == 4 {
        AllAddr::Addr4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]))
    } else if addr.len() == 16 {
        let segments: [u8; 16] = addr
            .clone()
            .try_into()
            .expect("Invalid IPv6 address length");
        AllAddr::Addr6(Ipv6Addr::new(
            ((segments[0] as u16) << 8) | segments[1] as u16,
            ((segments[2] as u16) << 8) | segments[3] as u16,
            ((segments[4] as u16) << 8) | segments[5] as u16,
            ((segments[6] as u16) << 8) | segments[7] as u16,
            ((segments[8] as u16) << 8) | segments[9] as u16,
            ((segments[10] as u16) << 8) | segments[11] as u16,
            ((segments[12] as u16) << 8) | segments[13] as u16,
            ((segments[14] as u16) << 8) | segments[15] as u16,
        ))
    } else {
        return 0; // 无效的地址长度
    };
    let mut anscount = 0;
    let mut nxdomain = 0;
    let mut auth = 1;

    if qdcount == 0 || header.as_ref().unwrap().opcode != QUERY {
        return 0;
    }

    // 使用 skip_questions 来获得不可变的切片
    let mut ansp = if let Some(ans) = skip_questions(header, qlen as usize) {
        ans
    } else {
        return 0;
    };
    let mut ansp_vec = ansp.to_vec();
    // 将不可变切片复制到一个可变缓冲区中
    let mut ansp_copy = Vec::from(ansp);

    let header_bytes = match header {
        Some(h) => h.to_bytes(),
        None => return 0, // 无效的数据包
    };

    let mut p = &mut &limit[1..];
    let name_binding = name.clone();
    let name_str = std::str::from_utf8(&name_binding).expect("Invalid UTF-8 sequence in name");

    for _ in 0..qdcount {
        // 保存指向名称的指针以便复制到答案中
        let nameoffset = p.as_ptr() as usize - limit.as_ptr() as usize;

        if !extract_name(&header_bytes, qlen as usize, p, &mut name, true) {
            return 0; // 错误的包
        }

        let is_arpa = in_arpa_name_2_addr(&name, &mut addr);
        qtype = get_short(&mut p);
        qclass = get_short(&mut p);

        let mut ans = 0;

        if qclass == C_CHAOS {
            if qtype == T_TXT {
                if hostname_isequal(name_str, "version.bind") {
                    name = format!("dnsmasq-{}", VERSION).as_bytes().to_vec();
                } else if hostname_isequal(name_str, "authors.bind") {
                    name = b"Simon Kelley".to_vec();
                } else {
                    name = vec![0];
                }

                let len = name.len();
                put_short((nameoffset as u16) | 0xc000, &mut ansp_copy);
                put_short(T_TXT, &mut ansp_copy);
                put_short(C_CHAOS, &mut ansp_copy);
                put_long(0, &mut ansp_copy); // TTL
                put_short((len + 1) as u16, &mut ansp_copy);
                ansp_copy[0] = len as u8;
                ansp_copy[1..=len].copy_from_slice(&name);
                ansp_copy = ansp_copy[len + 1..].to_vec(); // 更新 ansp_copy 指针

                ans = 1;
                anscount += 1;

                if limit.len() < ansp_copy.len() {
                    return 0;
                }
            }
        } else if qclass != C_IN {
            return 0;
        } else {
            if (options & OPT_FILTER) != 0 && ((qtype == T_SOA) || (qtype == T_SRV)) {
                ans = 1;
            }
            if qtype == T_PTR || qtype == T_ANY {
                while let Some(mut crec) = crecp.take() {
                    // 确定 TTL 的值
                    let ttl = if crec.flags & (F_IMMORTAL | F_DHCP) != 0 {
                        local_ttl
                    } else {
                        match crec.ttd.duration_since(now) {
                            Ok(duration) => duration.as_secs() as u64,
                            Err(_) => return 0, // 如果时间已过，则返回错误
                        }
                    };

                    // 如果是 T_ANY 类型且数据不是来自 /etc/hosts 或 DHCP 租约，则返回 0
                    if qtype == T_ANY && (crec.flags & (F_HOSTS | F_DHCP)) == 0 {
                        return 0;
                    }

                    ans = 1; // 标识已经回答了这个查询

                    // 如果是负面缓存记录
                    if crec.flags & F_NEG != 0 {
                        log_query(caches, crec.flags & !F_FORWARD, &name, Some(&addr)); // 记录查询日志
                        auth = 0; // 设置为非授权
                        if crec.flags & F_NXDOMAIN != 0 {
                            nxdomain = 1; // 设置 NXDOMAIN 错误
                        }
                    } else {
                        if (crec.flags & (F_HOSTS | F_DHCP)) == 0 {
                            auth = 0; // 设置为非授权
                        }

                        // 获取缓存名称并添加文本记录到回答部分
                        let cache_name = cache_get_name(Some(Box::into_raw(crec.clone())));

                        let new_ansp = add_text_record(
                            nameoffset.try_into().unwrap(),
                            &mut ansp_vec,
                            ttl.try_into().unwrap(),
                            0,
                            T_PTR,
                            &cache_name,
                        );
                        ansp = new_ansp; // 更新回答缓冲区
                        log_query(
                            caches,
                            crec.flags & !F_FORWARD,
                            &cache_name.as_bytes(),
                            Some(&addr),
                        ); // 记录日志
                        anscount += 1; // 增加回答记录计数

                        // 检查最后一个回答是否超出了数据包大小限制
                        if ansp.len() > limit.len() {
                            return 0;
                        }
                    }

                    // 获取下一个缓存记录
                    let next_crecp = cache_find_by_addr(
                        caches,
                        Some(Box::into_raw(crec)),
                        &all_addr,
                        now,
                        is_arpa,
                    );
                    if let Some(ref mut crecp_inner) = crecp {
                        *crecp_inner = next_crecp
                            .map(|ptr| unsafe { Box::from_raw(ptr) })
                            .expect("REASON");
                    }
                    if ans == 0
                        && is_arpa == F_IPV4
                        && (options & OPT_BOGUSPRIV != 0)
                        && private_net(&all_addr)
                    {
                        let addr_str = std::str::from_utf8(&addr).expect("Invalid UTF-8 sequence");
                        ansp = add_text_record(
                            nameoffset.try_into().unwrap(),
                            &mut ansp_vec,
                            local_ttl.try_into().unwrap(),
                            0,
                            T_PTR,
                            &addr_str,
                        );
                        log_query(caches, F_CONFIG | F_REVERSE | F_IPV4, &addr, Some(&addr));
                        ans = 1;
                        anscount += 1;

                        if limit.len() < ansp_copy.len() {
                            return 0;
                        }
                    }
                }
            }
            if qtype == T_A || qtype == T_ANY {
                if (options & OPT_FILTER) != 0 && qtype == T_ANY && name_str.contains('_') {
                    ans = 1;
                } else {
                    crecp = None;
                    while let Some(crec) = crecp.take() {
                        let ttl = if crec.flags & (F_IMMORTAL | F_DHCP) != 0 {
                            local_ttl
                        } else {
                            match crec.ttd.duration_since(now) {
                                Ok(duration) => duration.as_secs() as u64,
                                Err(_) => return 0,
                            }
                        };

                        if qtype == T_ANY && (crec.flags & (F_HOSTS | F_DHCP)) == 0 {
                            return 0;
                        }

                        ans = 1;
                        if crec.flags & F_NEG != 0 {
                            log_query(caches, crec.flags, &name, None);
                            auth = 0;
                            if crec.flags & F_NXDOMAIN != 0 {
                                nxdomain = 1;
                            }
                        } else {
                            if (crec.flags & (F_HOSTS | F_DHCP)) == 0 {
                                auth = 0;
                            }
                            log_query(caches, crec.flags & !F_REVERSE, &name, Some(&addr));

                            put_short((nameoffset as u16) | 0xc000, &mut ansp_copy);
                            put_short(T_A, &mut ansp_copy);
                            put_short(C_IN, &mut ansp_copy);
                            put_long(ttl as u32, &mut ansp_copy);

                            if let AllAddr::Addr4(ipv4) = crec.addr {
                                let ipv4_bytes = ipv4.octets();
                                ansp_copy.extend_from_slice(&ipv4_bytes);
                                anscount += 1;
                            }

                            if limit.len() < ansp_copy.len() {
                                return 0;
                            }
                        }
                    }
                }
            }
            if addr.len() > 4 {
                if qtype == T_AAAA || qtype == T_ANY {
                    if (options & OPT_FILTER) != 0 && qtype == T_ANY && name_str.contains('_') {
                        ans = 1;
                    } else {
                        crecp = None;
                        while let Some(crec) = cache_find_by_name(
                            caches,
                            crecp.clone().map(|c| Box::into_raw(c)),
                            &name_str,
                            now,
                            F_IPV6,
                        ) {
                            let ttl = if (unsafe { &*crec }).flags & (F_IMMORTAL | F_DHCP) != 0 {
                                local_ttl
                            } else {
                                match (unsafe { &*crec }).ttd.duration_since(now) {
                                    Ok(duration) => duration.as_secs() as u64,
                                    Err(_) => return 0,
                                }
                            };

                            if qtype == T_ANY
                                && ((unsafe { &*crec }).flags & (F_HOSTS | F_DHCP)) == 0
                            {
                                return 0;
                            }

                            ans = 1;

                            if (unsafe { &*crec }).flags & F_NEG != 0 {
                                log_query(caches, (unsafe { &*crec }).flags, &name, None);
                                auth = 0;
                                if (unsafe { &*crec }).flags & F_NXDOMAIN != 0 {
                                    nxdomain = 1;
                                }
                            } else {
                                if ((unsafe { &*crec }).flags & (F_HOSTS | F_DHCP)) == 0 {
                                    auth = 0;
                                }
                                log_query(
                                    caches,
                                    (unsafe { &*crec }).flags & !F_REVERSE,
                                    &name,
                                    Some(&addr),
                                );

                                put_short((nameoffset as u16) | 0xc000, &mut ansp_copy);
                                put_short(T_AAAA, &mut ansp_copy);
                                put_short(C_IN, &mut ansp_copy);
                                put_long(ttl as u32, &mut ansp_copy);

                                put_short(IN6ADDRSZ, &mut ansp_copy);
                                if let AllAddr::Addr6(ipv6) = (unsafe { &*crec }).addr {
                                    let ipv6_bytes = ipv6.octets();
                                    ansp_copy.extend_from_slice(&ipv6_bytes);
                                    anscount += 1;
                                }

                                if limit.len() < ansp_copy.len() {
                                    return 0;
                                }
                            }
                        }
                    }
                }
            }
            if qtype == T_MX || qtype == T_ANY {
                if let Some(ref mxname) = mxname {
                    if hostname_isequal(&name_str, mxname) {
                        ansp_copy = add_text_record(
                            nameoffset.try_into().unwrap(),
                            &mut ansp_copy,
                            local_ttl as u32,
                            1,
                            T_MX,
                            mxtarget.as_deref().unwrap_or(""),
                        )
                        .to_vec();
                        anscount += 1;
                        ans = 1;
                    }
                } else if (options & (OPT_SELFMX | OPT_LOCALMX)) != 0
                    && cache_find_by_name(caches, None, &name_str, now, F_HOSTS | F_DHCP).is_some()
                {
                    let target = if (options & OPT_SELFMX) != 0 {
                        &name_str
                    } else {
                        mxtarget.as_deref().unwrap_or("")
                    };
                    ansp_copy = add_text_record(
                        nameoffset.try_into().unwrap(),
                        &mut ansp_copy,
                        local_ttl as u32,
                        1,
                        T_MX,
                        target,
                    )
                    .to_vec();
                    anscount += 1;
                    ans = 1;
                }
                if limit.len() < ansp_copy.len() {
                    return 0;
                }
            }

            if qtype == T_MAILB {
                ans = 1;
                nxdomain = 1;
            }

            if ans == 0 {
                return 0;
            }
        }
    }

    if let Some(ref mut header) = header {
        header.qr = 1; // Response
        header.aa = auth as u8; // Authoritative - only hosts and DHCP derived names
        header.ra = 1; // Recursion available
        header.tc = 0; // No truncation

        if anscount == 0 && nxdomain != 0 {
            header.rcode = NXDOMAIN;
        } else {
            header.rcode = NOERROR; // No error
        }

        header.ancount = anscount as u16;
        header.nscount = 0;
        header.arcount = 0;
    }

    // 计算返回值，相当于 `return ansp - (unsigned char *)header;` 在C中指针的偏移
    let return_value =
        (ansp_copy.len() as isize) - (header_bytes.as_ptr() as isize - limit.as_ptr() as isize);
    return_value as i32
}

// 判断地址是否为私有网络地址
pub fn private_net(addr: &AllAddr) -> bool {
    // 如果地址是 IPv4 类型，进行私有网络检查
    if let AllAddr::Addr4(ipv4_addr) = addr {
        let octets = ipv4_addr.octets();

        // 对应 C 代码中的 inet_netof 检查
        // 10.x.x.x (0x0A == 10)
        if octets[0] == 10 {
            return true;
        }

        // 172.16.x.x - 172.31.x.x (0xAC == 172, 范围 0xAC10 - 0xAC1F)
        if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
            return true;
        }

        // 192.168.x.x (0xC0 == 192, 0xA8 == 168)
        if octets[0] == 192 && octets[1] == 168 {
            return true;
        }
    }

    // 如果不是 IPv4 地址，返回 false
    false
}

pub fn add_text_record<'a>(
    nameoffset: u16,
    p: &'a mut Vec<u8>,
    ttl: u32,
    pref: u16,
    record_type: u16,
    name: &'a str,
) -> &'a mut Vec<u8> {
    // 保存初始位置
    let sav_len = p.len();

    // 添加压缩后的名称偏移
    put_short(nameoffset | 0xc000, p);

    // 添加记录类型
    put_short(record_type, p);

    // 添加类 (C_IN)
    put_short(C_IN, p);

    // 添加 TTL (大端序)
    put_long(ttl, p);

    // 占位符添加 RDLENGTH，稍后更新
    let rdlength_index = p.len();
    put_short(0, p); // 占位符，稍后会更新

    // 如果 pref 不是 0，则添加它
    if pref != 0 {
        put_short(pref, p);
    }

    // 处理名称部分
    let mut label_len_pos = None; // 用于保存每个标签长度的位置
    let mut label_len = 0; // 当前标签的长度

    for c in name.chars() {
        if c == '.' {
            if let Some(pos) = label_len_pos {
                p[pos] = label_len as u8; // 更新标签长度
            }
            // 新的标签开始
            label_len_pos = Some(p.len());
            p.push(0); // 先占位，表示标签长度
            label_len = 0;
        } else {
            p.push(c as u8);
            label_len += 1;
        }
    }

    // 处理最后一个标签
    if let Some(pos) = label_len_pos {
        p[pos] = label_len as u8; // 更新最后一个标签长度
    }

    // 添加终止符
    p.push(0);

    // 计算 RDLENGTH 的值并更新
    let rdlength = (p.len() - sav_len - 10) as u16; // RDLENGTH 不包括 10 个字节（TYPE、CLASS、TTL、RDLENGTH 本身）
    let rdlength_bytes = rdlength.to_be_bytes();
    p[rdlength_index..rdlength_index + 2].copy_from_slice(&rdlength_bytes);

    // 返回最终的向量
    p
}

pub fn put_long(l: u32, cp: &mut Vec<u8>) {
    const NS_INT32SZ: usize = 4;

    // 确保 `cp` 有足够的长度以写入 32 位数据
    if cp.len() < NS_INT32SZ {
        panic!("Not enough space in buffer to write 32-bit value");
    }

    // 将 32 位整数按大端序写入到 `cp` 中
    cp[0] = (l >> 24) as u8; // 写入高 8 位
    cp[1] = (l >> 16) as u8; // 写入次高 8 位
    cp[2] = (l >> 8) as u8; // 写入次低 8 位
    cp[3] = (l & 0xff) as u8; // 写入低 8 位

    // 更新 `cp` 的位置，相当于 C 中的 `(cp) += NS_INT32SZ`
    cp.drain(..NS_INT32SZ);
}

pub fn put_short(s: u16, cp: &mut Vec<u8>) {
    const NS_INT16SZ: usize = 2;

    // 确保向 `cp` 写入的数据有足够的空间
    if cp.len() < NS_INT16SZ {
        panic!("Not enough space in buffer to write 16-bit value");
    }

    // 将 16 位值拆分为两个字节，按大端序写入到 `cp` 中
    cp[0] = (s >> 8) as u8;
    cp[1] = (s & 0xff) as u8;

    // 更新 `cp`，移除已经写入的部分
    cp.drain(..NS_INT16SZ);
}

pub fn extract_request(header: &Option<Header>, qlen: u32, name: &mut Vec<u8>) -> bool {
    let header = match header {
        Some(h) => h,
        None => return false, // 如果 header 不存在，返回 false
    };

    let header_size = std::mem::size_of::<Header>();
    let mut p = &header.to_bytes()[header_size..];
    let qdcount = NetworkEndian::read_u16(&header.to_bytes()[4..6]);

    if qdcount != 1 || header.opcode != QUERY {
        return false; // 必须恰好有一个查询
    }

    let binding = header.to_bytes();
    if !extract_name(&binding, qlen.try_into().unwrap(), &mut p, name, true) {
        return false; // 数据包无效
    }

    let qtype = NetworkEndian::read_u16(&p[0..2]);
    p = &p[2..];
    let qclass = NetworkEndian::read_u16(&p[0..2]);
    p = &p[2..];

    if qclass == C_IN {
        if qtype == T_A || qtype == T_AAAA || qtype == T_ANY {
            return true;
        }
    }

    false
}

// pub fn setup_reply(
//     header: &mut Header,
//     qlen: usize,
//     addrp: Option<&[u8]>,
//     flags: u32,
//     ttl: u64,
// ) -> usize {
//     // 调用 skip_questions 辅助函数
//     let binding = Some(*header);
//     let mut p = if let Some(offset) = skip_questions(&binding, qlen) {
//         offset
//     } else {
//         return 0;
//     };

//     let mut p_vec = p.to_vec();
//     // 将不可变切片复制到一个可变缓冲区中
//     let mut p_copy = Vec::from(p);

//     // 初始化回复头部信息
//     header.qr = 1; // 设置为响应
//     header.aa = 0; // 非权威回答
//     header.ra = 1; // 支持递归
//     header.tc = 0; // 无截断
//     header.nscount = 0;
//     header.arcount = 0;
//     header.ancount = 0; // 初始没有答案，除非后续改变

//     // 根据 flags 设置不同的返回码和响应内容
//     match flags {
//         F_NEG => {
//             header.rcode = SERVFAIL; // 内存获取失败
//         }
//         F_NOERR => {
//             header.rcode = NOERROR; // 空域名
//         }
//         F_NXDOMAIN => {
//             header.rcode = NXDOMAIN; // 域名不存在
//         }
//         F_IPV4 if p.len() > 0 => {
//             if let Some(addr) = addrp {
//                 if addr.len() == INADDRSZ {
//                     header.rcode = NOERROR;
//                     header.ancount = 1;
//                     header.aa = 1;

//                     // 写入资源记录
//                     put_short(0xc000 | (std::mem::size_of::<Header>()) as u16, &mut p_copy);
//                     put_short(T_A, &mut p_copy);
//                     put_short(C_IN, &mut p_copy);
//                     put_long(ttl as u32, &mut p_copy); // TTL 只保留低 32 位
//                     put_short(INADDRSZ as u16, &mut p_copy);
//                     p_copy.extend_from_slice(addr);
//                 }
//             }
//         }
//         F_IPV6 if p.len() > 0 => {
//             if let Some(addr) = addrp {
//                 if addr.len() == IN6ADDRSZ.into() {
//                     header.rcode = NOERROR;
//                     header.ancount = 1;
//                     header.aa = 1;

//                     // // 写入资源记录
//                     put_short(0xc000 | (std::mem::size_of::<Header>()) as u16, &mut p_copy);
//                     put_short(T_AAAA, &mut p_copy);
//                     put_short(C_IN, &mut p_copy);
//                     put_long(ttl as u32, &mut p_copy); // TTL 只保留低 32 位
//                     put_short(IN6ADDRSZ as u16, &mut p_copy);
//                     p_copy.extend_from_slice(addr);
//                 }
//             }
//         }
//         _ => {
//             header.rcode = REFUSED; // 拒绝请求
//         }
//     }

//     p_copy.len()
// }
