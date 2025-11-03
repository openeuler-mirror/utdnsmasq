/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use crate::util::*;
use crate::*;
use byteorder::{ByteOrder, NetworkEndian};
use std::time::SystemTime;

pub type InAddrT = u32;

const F_IPV4: u32 = 128;
const F_FORWARD: u32 = 8;
const F_NEG: u32 = 32;
const F_NXDOMAIN: u32 = 4096;
const F_CONFIG: u32 = 2;
const C_IN: u16 = 1;
const F_REVERSE: u32 = 4;
const F_IPV6: u32 = 256;
const NS_INT16SZ: usize = 2;
const NS_INT32SZ: usize = 4;
const MAXARPANAME: usize = 75;
const T_PTR: u16 = 12; // PTR 记录
const T_A: u16 = 1; // A 记录
const T_AAAA: u16 = 28; // AAAA 记录
const T_SOA: u16 = 6; // SOA 记录
pub const NXDOMAIN: u8 = 3; // NXDOMAIN 响应码
const T_ANY: u16 = 255;

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
fn skip_questions(header: &Option<Header>, plen: usize) -> Option<&[u8]> {
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

pub const QUERY: u8 = 0;
pub fn answer_request(
    header: &Option<Header>,
    limit: &mut [u8],
    qlen: u32,
    mxname: Option<String>,
    mxtarget: Option<String>,
    options: u32,
    now: SystemTime,
    local_ttl: u64,
    name: Vec<u8>,
) -> i32 {
    let mut qdcount = if let Some(h) = header {
        u16::from_be(h.qdcount) as i32
    } else {
        return 0;
    };

    let mut anscount = 0;
    let mut nxdomain = 0;
    let mut auth = 1;

    if qdcount == 0 || header.as_ref().unwrap().opcode != QUERY {
        return 0;
    }

    let ansp = if let Some(ans) = skip_questions(header, qlen.try_into().unwrap()) {
        ans
    } else {
        return 0; // bad packet
    };

    return 1;
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
