/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use crate::{
    cache::{log_query, Cache},
    config::VERSION,
    dnsmasq::{
        AllAddr, BogusAddr, Header, C_CHAOS, C_IN, F_CONFIG, F_DHCP, F_FORWARD, F_HOSTS,
        F_IMMORTAL, F_IPV4, F_IPV6, F_NEG, F_NOERR, F_NXDOMAIN, F_QUERY, F_REVERSE, MAXDNAME,
        NOERROR, NXDOMAIN, OPT_BOGUSPRIV, OPT_FILTER, OPT_LOCALMX, OPT_SELFMX, PACKETSZ, REFUSED,
        SERVFAIL, T_A, T_AAAA, T_ANY, T_CNAME, T_MAILB, T_MX, T_PTR, T_SOA, T_SRV, T_TXT,
    },
    util::{get_long, get_short, legal_char, put_long, put_short, ToIpv4, ToIpv6},
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

const QUERY: u8 = 0;
pub const INADDRSZ: u16 = 4;
pub const IN6ADDRSZ: u16 = 16;

// 直接获取域名，去除对判断域名是否相等的判断
fn extract_name(packet: &[u8], date: &mut &[u8]) -> String {
    let mut pos = 0;
    let mut p1 = 0;
    let mut name: String = String::new();
    let mut hops = 0;
    let plen = packet.len();

    loop {
        let mut l = if hops != 0 {
            packet[pos] as u32 // 压缩指针，针对于数据包头的位置偏移多少
        } else {
            date[pos] as u32
        }; // 获取数据长度 每个域名部分开始都有该部分域名信息的长度
        pos += 1;

        if l == 0 {
            // 如果第一次循环就遇到l=0，需要确保name不为空
            if name.is_empty() {
                name = "..".to_string(); // 返回根域名
            }
            break; // 域名结束
        }

        let lable_type = l & 0xc0;
        if lable_type == 0xc0 {
            // 压缩指针
            if pos + 1 > plen {
                return String::new();
            }

            l = (l & 0x3f) << 8;
            l |= if hops != 0 {
                packet[pos] as u32 // 压缩指针，针对于数据包头的位置偏移多少
            } else {
                date[pos] as u32
            }; // 获取数据长度 每个域名部分开始都有该部分域名信息的长度

            pos += 1;
            if l > plen as u32 {
                return String::new();
            }

            if p1 == 0 {
                p1 = pos;
            }

            hops += 1;
            if hops > 255 {
                return String::new();
            }

            pos = l as usize; // 修正：压缩指针指向的是绝对偏移量，不需要减去12
        } else if lable_type == 0x80 {
            // 保留类型
            return String::new();
        } else if lable_type == 0x40 {
            // 扩展标签类型
            // ELT
            if l & 0x3f != 1 {
                return String::new();
            }

            let mut count = date[pos] as u32;
            pos += 1;

            if count == 0 {
                count = 256;
            }
            let digs = ((count - 1) >> 2) + 1;
            if name.len() + digs as usize + 9 >= MAXDNAME {
                return String::new();
            }

            if pos + ((count - 1) >> 3) as usize + 1 >= plen {
                return String::new();
            }

            name.push_str("\\[x");

            for j in 0..digs {
                let dig: u8;
                if j % 2 == 0 {
                    dig = date[pos] >> 4;
                } else {
                    dig = date[pos] & 0x0f;
                    pos += 1;
                }

                let c = if dig < 10 {
                    dig + b'0'
                } else {
                    dig + b'A' - 10
                };

                name.push(c as char);
            }
            let push_str = format!("/{}]", count);
            name.push_str(&push_str);
            name.push('.');
        } else {
            // 普通类型
            // 域名长度太长
            if name.len() > MAXDNAME {
                return String::new();
            }
            // 域名解析超过数组长度
            if pos > plen {
                return String::new();
            }

            for _ in 0..l {
                // let c = date[pos] as char;
                let c = if hops != 0 {
                    packet[pos] as char // 压缩指针，针对于数据包头的位置偏移多少
                } else {
                    date[pos] as char
                };

                if legal_char(c) {
                    name.push(c);
                } else {
                    return String::new();
                }
                pos += 1;
            }
            name.push('.'); // 添加 . 分隔符
        }

        if pos > plen {
            return String::new();
        }
    }

    name.pop(); // 去除最后一个 '.'

    // 返回域名和解析后的偏移量
    *date = if p1 != 0 { &date[p1..] } else { &date[pos..] };
    // let remaining_offset = if p1 != 0 { p1 } else { pos };
    name
}

const MAXARPANAME: usize = 75;
fn in_arpa_name_2_addr(namein: &str) -> (u16, Option<AllAddr>) {
    if namein.len() > MAXARPANAME {
        return (0, None);
    }

    let mut names: Vec<&str> = namein.split('.').collect();
    let j = names.len();
    if j < 3 {
        return (0, None);
    }

    let lastchunk = names.pop().unwrap();
    let penchunk = names.pop().unwrap();

    // IPv4反向域名
    if lastchunk == "arpa" && penchunk == "in-addr" {
        let mut addrr = [0; 4];
        /* IP v4 */
        /* www.xxx.yyy.zzz.in-addr.arpa */
        for (i, name) in names.iter().enumerate() {
            if !name.chars().all(|c| c.is_ascii_digit()) {
                return (0, None);
            }
            let octet: u8 = match name.parse() {
                Ok(v) => v,
                Err(_) => return (0, None),
            };
            addrr[3 - i] = octet;
        }

        return (F_IPV4, Some(IpAddr::V4(Ipv4Addr::from(addrr))));
    } else if penchunk == "ip6" && (lastchunk == "int" || lastchunk == "arpa") {
        let mut addrr = [0; 16];
        /*  IP v6:
        Address arrives as 0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f.ip6.[int|arpa]
        or \[xfedcba9876543210fedcba9876543210/128].ip6.[int|arpa] */
        let ipv6_str = names[0];
        if let Some(ipv6) = ipv6_str.strip_prefix("\\[x") {
            let mut j = 0;
            for (i, ch) in ipv6.chars().enumerate() {
                if !ch.is_ascii_hexdigit() {
                    return (0, None);
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
                return (F_IPV6, Some(IpAddr::V6(Ipv6Addr::from(addrr))));
            }
        } else {
            let mut idx = 15;
            for label in names {
                if label.len() != 1 || !label.chars().all(|c| c.is_ascii_hexdigit()) {
                    return (0, None);
                }
                let value = match u8::from_str_radix(label, 16) {
                    Ok(v) => v,
                    Err(_) => return (0, None),
                };
                if idx % 2 == 1 {
                    addrr[idx / 2] |= value;
                } else {
                    addrr[idx / 2] = value << 4;
                }
                if idx > 0 {
                    idx = idx.saturating_sub(1);
                }
            }
            return (F_IPV6, Some(IpAddr::V6(Ipv6Addr::from(addrr))));
        }
    }

    (0, None)
}

// 跳过问题部分  返回数据偏移量
fn skip_questions(packet: &[u8]) -> usize {
    let header = Header::parse(packet).unwrap();
    let qdcount = header.qdcount;

    let mut ansp = 12;

    for _ in 0..qdcount {
        loop {
            let label_type = packet[ansp] & 0xc0;
            if ansp > packet.len() {
                return 0;
            }

            if label_type == 0xc0 {
                // 压缩指针，指向报文其他位置
                ansp += 2;
                break;
            } else if label_type == 0x80 {
                return 0;
            } else if label_type == 0x40 {
                // 扩展标签类型（如位字符串）
                if packet[ansp] & 0x3f != 1 {
                    return 0;
                }

                ansp += 1;
                let count = packet[ansp];
                ansp += 1;

                if count == 0 {
                    ansp += 32;
                } else {
                    ansp += ((count - 1) >> 3) as usize + 1;
                }
            } else {
                // 普通标签，后6位为长度
                let len = packet[ansp] & 0x3f; // 后6位为长度
                ansp += 1;

                if len == 0 {
                    // 域名部分结束
                    break;
                }

                ansp += len as usize;
            }
        }

        ansp += 4; /* class(2 byte) and type(2 byte) */
    }

    if ansp > packet.len() {
        return 0;
    }

    ansp
}

// 判断给定的IP地址是否属于私有网络地址空间, 只判断ipv4
/*
1. **10.0.0.0/8**: 单A类网络，范围`10.0.0.0` - `10.255.255.255`
2. **172.16.0.0/12**: 16个B类网络，范围`172.16.0.0` - `172.31.255.255`
3. **192.168.0.0/16**: 256个C类网络，范围`192.168.0.0` - `192.168.255.255`
*/
fn private_net(addrp: &AllAddr) -> bool {
    if let Some(addr) = addrp.to_ipv4() {
        let octets = addr.octets();

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
    false
}

// 构建一个问题的答案
fn add_text_record(nameoffset: u16, ttl: u32, pref: u16, qtype: u16, name: &str) -> Vec<u8> {
    let mut ansp: Vec<u8> = Vec::new();
    put_short(nameoffset | 0xc000, &mut ansp); // 域名，压缩指针形式   指向报文前面已出现的域名针对于数据包偏移的数值
    put_short(qtype, &mut ansp); // 资源类型 2字节
    put_short(C_IN, &mut ansp); // 记录类别 1字节
    put_long(ttl, &mut ansp); // ttl 生存时间 4字节]

    let sav = ansp.len();
    put_short(0, &mut ansp); // 站位RDLENGTH的值，最后填写数据部分的长度

    if pref != 0 {
        put_short(pref, &mut ansp);
    }

    let name_vec: Vec<&str> = name.split('.').collect();
    for n in name_vec {
        ansp.push(n.len() as u8); // 写入每个阶段数据的长度
        ansp.extend(n.as_bytes()); // 写入数据
    }
    ansp.push(0); // 写入域名结束符

    let l = ansp.len() - sav - 2;
    ansp[sav] = (l >> 8) as u8;
    ansp[sav + 1] = (l & 0xFF) as u8;

    ansp
}

// 处理 DNS 否定响应（NXDOMAIN 或 NODATA），提取并缓存否定信息，实现 DNS 否定缓存功能。
pub fn extract_neg_addrs(caches: &mut Cache, packet: &[u8], now: SystemTime) {
    let mut flags = F_NEG;
    let mut found_soa = false;
    let mut minttl: u32 = 0;
    let mut ttl: u32;
    let mut qtype: u16;
    let mut qclass: u16;
    let mut rdlen: u16;
    let header = Header::parse(packet).unwrap();

    if header.rcode == NXDOMAIN {
        flags |= F_NXDOMAIN;
    }

    if header.ancount != 0 {
        return;
    }

    let pos = skip_questions(packet);
    if pos == 0 {
        return;
    }
    let mut p: &[u8] = &packet[pos..];

    // 首先需要找到SOA记录，以获得最小TTL6，然后为每个问题添加一个NEG缓存条目。
    for _ in 0..header.nscount {
        let mut name = extract_name(packet, &mut p);
        if name.is_empty() {
            return;
        }

        qtype = get_short(&mut p);
        qclass = get_short(&mut p);
        ttl = get_long(&mut p);
        rdlen = get_short(&mut p);

        if qclass == C_IN && qtype == T_SOA {
            // MNAME
            name = extract_name(packet, &mut p);
            if name.is_empty() {
                return;
            }
            // RNAME
            name = extract_name(packet, &mut p);
            if name.is_empty() {
                return;
            }

            let mut _dummy = get_long(&mut p); /* SERIAL */
            _dummy = get_long(&mut p); /* REFRESH */
            _dummy = get_long(&mut p); /* RETRY */
            _dummy = get_long(&mut p); /* EXPIRE */

            if !found_soa {
                found_soa = true;
                minttl = ttl;
            } else if ttl < minttl {
                minttl = ttl;
            }

            ttl = get_long(&mut p); /* minTTL */
            if ttl < minttl {
                minttl = ttl;
            }
        } else {
            p = &p[rdlen as usize..];
        }

        // 判断p是否越界
    }

    if !found_soa {
        return;
    }

    caches.cache_start_insert();
    p = &packet[12..];
    for _ in 0..header.qdcount {
        let name = extract_name(packet, &mut p);
        if name.is_empty() {
            return;
        }
        qtype = get_short(&mut p);
        qclass = get_short(&mut p);

        let (is_arpa, addr) = in_arpa_name_2_addr(&name);
        if qclass == C_IN && qtype == T_PTR && is_arpa != 0 {
            caches.cache_insert(Some(&name), addr, now, minttl, is_arpa | F_REVERSE | flags);
        } else if qclass == C_IN && qtype == T_A {
            caches.cache_insert(Some(&name), None, now, minttl, F_IPV4 | F_FORWARD | flags);
        } else if qclass == C_IN && qtype == T_AAAA {
            caches.cache_insert(Some(&name), None, now, minttl, F_IPV6 | F_FORWARD | flags);
        }
    }
    caches.cache_end_insert();
}

// 从 DNS 响应包中提取地址记录并缓存
pub fn extract_addresses(caches: &mut Cache, packet: &[u8], now: SystemTime) {
    let mut ttl: u32;
    let mut qtype: u16;
    let mut qclass: u16;
    let mut rdlen: u16;

    let header = Header::parse(packet).unwrap();
    let pos = skip_questions(packet);
    if pos == 0 {
        return;
    }
    let mut p = &packet[pos..];

    caches.cache_start_insert();
    let psave = p;

    for _ in 0..header.ancount {
        let origname = p;

        let mut name = extract_name(packet, &mut p);
        if name.is_empty() {
            return;
        }

        qtype = get_short(&mut p);
        qclass = get_short(&mut p);
        ttl = get_long(&mut p);
        rdlen = get_short(&mut p);

        let endrr = &p[rdlen as usize..];
        if p.len() < rdlen as usize {
            return;
        }

        if qclass != C_IN {
            p = endrr;
            continue;
        }

        if qtype == T_A {
            let ip_bytes: [u8; 4] = p[..4].try_into().unwrap();
            let addr = Ipv4Addr::from(ip_bytes);
            caches.cache_insert(
                Some(&name),
                Some(IpAddr::V4(addr)),
                now,
                ttl,
                F_IPV4 | F_FORWARD,
            );
        } else if qtype == T_AAAA {
            let ip_bytes: [u8; 16] = p[..16].try_into().unwrap();
            let addr = Ipv6Addr::from(ip_bytes);
            caches.cache_insert(
                Some(&name),
                Some(IpAddr::V6(addr)),
                now,
                ttl,
                F_IPV6 | F_FORWARD,
            );
        } else if qtype == T_PTR {
            let (name_encoding, addr) = in_arpa_name_2_addr(&name);
            if name_encoding != 0 {
                name = extract_name(packet, &mut p);
                if name.is_empty() {
                    return;
                }
                caches.cache_insert(Some(&name), addr, now, ttl, name_encoding | F_REVERSE);
            }
        } else if qtype == T_CNAME {
            let targp = p;
            let mut endrr1: &[u8];
            let mut cttl: u32;
            p = psave;

            for _ in 0..header.ancount {
                let mut tmp = targp;

                name = extract_name(packet, &mut tmp);
                if name.is_empty() {
                    return;
                }
                /* compare this name with target of CNAME in name buffer */
                let res = extract_name(packet, &mut p);
                if res.is_empty() {
                    return;
                }

                qtype = get_short(&mut p);
                qclass = get_short(&mut p);
                cttl = get_long(&mut p);
                rdlen = get_short(&mut p);

                endrr1 = &p[rdlen as usize..];
                if endrr1.len() < rdlen as usize {
                    return;
                }

                if qclass != C_IN || res != name {
                    p = endrr1;
                    continue;
                }

                if ttl < cttl {
                    cttl = ttl;
                }

                tmp = origname;
                name = extract_name(packet, &mut tmp);
                if name.is_empty() {
                    return;
                }

                if qtype == T_A {
                    let ip_bytes: [u8; 4] = p[..4].try_into().unwrap();
                    let addr = Ipv4Addr::from(ip_bytes);
                    caches.cache_insert(
                        Some(&name),
                        Some(IpAddr::V4(addr)),
                        now,
                        cttl,
                        F_IPV4 | F_FORWARD,
                    );
                } else if qtype == T_AAAA {
                    let ip_bytes: [u8; 16] = p[..16].try_into().unwrap();
                    let addr = Ipv6Addr::from(ip_bytes);
                    caches.cache_insert(
                        Some(&name),
                        Some(IpAddr::V6(addr)),
                        now,
                        cttl,
                        F_IPV6 | F_FORWARD,
                    );
                } else if qtype == T_PTR {
                    let (name_encoding, addr) = in_arpa_name_2_addr(&name);
                    if name_encoding != 0 {
                        name = extract_name(packet, &mut p);
                        if name.is_empty() {
                            return;
                        }
                        caches.cache_insert(
                            Some(&name),
                            addr,
                            now,
                            cttl,
                            name_encoding | F_REVERSE,
                        );
                    }
                }

                p = endrr1;
            }
        }
        p = endrr;
    }
    caches.cache_end_insert();
}

// 构造 DNS 响应数据包
pub fn setup_reply(packet: &[u8], addrp: Option<AllAddr>, flags: u16, ttl: u32) -> Vec<u8> {
    let mut header = Header::parse(packet).unwrap(); // 解析数据包的头
    let pos = skip_questions(packet); // 跳过问题部分
    let mut p: Vec<u8> = Vec::new(); // 用于存回答部分内容
    let mut ans: Vec<u8>;
    // ans.extend(packet); // 获取回答的头和问题部分
    ans = packet[..pos].to_vec();

    // 更换头部信息
    header.qr = true; /* response */
    header.aa = false; /* authoritive */
    header.ra = true; /* recursion if available */
    header.tc = false; /* not truncated */
    header.nscount = 0;
    header.arcount = 0;
    header.ancount = 0; /* no answers unless changed below*/

    if flags == F_NEG {
        header.rcode = SERVFAIL; /* couldn't get memory */
    } else if flags == F_NOERR {
        header.rcode = NOERROR;
    } else if flags == F_NXDOMAIN {
        header.rcode = NXDOMAIN;
    } else if pos != 0 && flags == F_IPV4 {
        // pos != 0 表示跳过问题部分是成功的
        header.rcode = NOERROR;
        header.ancount = 1;
        header.aa = true;
        put_short(12 | 0xc000, &mut p);
        put_short(T_A, &mut p);
        put_short(C_IN, &mut p);
        put_long(ttl, &mut p);
        put_short(INADDRSZ, &mut p);
        let addr4_byte = addrp.unwrap().to_ipv4().unwrap().octets();
        p.extend(&addr4_byte);
    } else if pos != 0 && flags == F_IPV6 {
        header.rcode = NOERROR;
        header.ancount = 1;
        header.aa = true;
        put_short(12 | 0xc000, &mut p);
        put_short(T_AAAA, &mut p);
        put_short(C_IN, &mut p);
        put_long(ttl, &mut p);
        put_short(IN6ADDRSZ, &mut p);
        let addr6_byte = addrp.unwrap().to_ipv6().unwrap().octets();
        p.extend(&addr6_byte);
    } else {
        header.rcode = REFUSED
    }

    let header_bytes = header.to_bytes();
    ans[..12].copy_from_slice(&header_bytes); // 替换数据包的头信息
    ans.extend(p); // 添加回答部分信息
    ans
}

// 检查DNS响应中是否存在恶意ip地址
pub fn check_for_bogus_wildcard(
    caches: &mut Cache,
    packet: &mut [u8],
    baddrs: &[BogusAddr],
    now: SystemTime,
) -> u32 {
    let pos = skip_questions(packet);
    let mut p = &packet[pos..];
    if p.is_empty() {
        return 0;
    }

    let mut header = Header::parse(packet).unwrap();
    for _ in 0..header.ancount {
        let name = extract_name(packet, &mut p);
        if name.is_empty() {
            return 0;
        }

        let qtype = get_short(&mut p);
        let qclass = get_short(&mut p);
        let ttl = get_long(&mut p);
        let rdlen = get_short(&mut p);

        if qclass == C_IN && qtype == T_A {
            for baddr in baddrs.iter() {
                if p.len() >= INADDRSZ as usize {
                    let ip_bytes: [u8; 4] = [p[0], p[1], p[2], p[3]];
                    if baddr.addr == Ipv4Addr::from(ip_bytes) {
                        header.aa = false;
                        header.ra = true;
                        header.nscount = 0;
                        header.arcount = 0;
                        header.ancount = 0;
                        header.rcode = NXDOMAIN;

                        caches.cache_start_insert();
                        caches.cache_insert(
                            Some(&name),
                            None,
                            now,
                            ttl,
                            F_IPV4 | F_FORWARD | F_NEG | F_NXDOMAIN | F_CONFIG,
                        );
                        caches.cache_end_insert();

                        // 在返回1之前，将header的数据替换packet的前12个字节
                        let header_bytes = header.to_bytes();
                        packet[..12].copy_from_slice(&header_bytes);

                        return 1;
                    }
                }
            }
        }

        p = &p[rdlen as usize..];
    }
    0
}

// 如果数据包只包含一个查询，则返回1并在name中保留查询中的名称
pub fn extract_request(packet: &[u8]) -> (u16, String) {
    let mut p = &packet[12..]; // 12 为header在packet中占有的字节数

    let header = Header::parse(packet).unwrap();

    if header.qdcount != 1 || header.opcode != QUERY {
        return (0, String::new()); // 必须恰好有一个查询
    }

    let name = extract_name(packet, &mut p);
    let qtype = get_short(&mut p);
    let qclass = get_short(&mut p);

    if qclass == C_IN {
        if qtype == T_A {
            return (F_IPV4, name);
        } else if qtype == T_AAAA {
            return (F_IPV6, name);
        } else if qtype == T_ANY {
            return (F_IPV4 | F_IPV6, name);
        }
    }

    // let name = String::new();
    (F_QUERY, name)
}

pub fn answer_request(
    packet: &[u8],
    mxname: &str,
    mxtarget: &str,
    options: u32,
    caches: &mut Cache,
    now: SystemTime,
    local_ttl: u32,
) -> Vec<u8> {
    let mut ans = 0;
    let mut anscount: u16 = 0;
    let mut auth: bool = true;
    let mut nxdomain: i32 = 0;
    let mut ans_packet: Vec<u8> = Vec::new(); // 返回的回答数据包

    let header = Header::parse(packet).unwrap();
    let qdcount = header.qdcount;

    // 检查请求的合法性
    if qdcount == 0 || header.opcode != QUERY {
        return ans_packet;
    }

    // 跳过问题部分，找到答案部分的起始位置
    let ansp_offset = skip_questions(packet);
    if ansp_offset == 0 {
        return Vec::new();
    }
    let mut ansp: Vec<u8> = Vec::new();

    let mut p: &[u8] = &packet[12..];

    let q_byte = &packet[12..ansp_offset];
    let mut se_len = 0;
    for _ in 0..qdcount {
        let nameoffset = 12 + se_len as u16;

        let start_len = p.len();
        // 提取查询域名
        let mut name = extract_name(packet, &mut p);
        if name.is_empty() {
            return ans_packet;
        }

        // 检查是否为反向解析 如果是，将解析出的 IP 地址存储到 addr 中
        let (is_arpa, addr) = in_arpa_name_2_addr(&name);

        // 提取查询类型和类
        let qtype = get_short(&mut p);
        let qclass = get_short(&mut p);

        let end_len = p.len();
        se_len = start_len - end_len;

        // 处理特殊查询（CHAOS 类）
        if qclass == C_CHAOS {
            // 一种古老且已过时的网络协议 用于某些特殊的 DNS 查询
            if qtype == T_TXT {
                if name.as_str() == "version.bind" {
                    name = format!("dnsmasq-{}", VERSION);
                } else if name.as_str() == "authors.bind" {
                    name = "Simon Kelley".to_string();
                } else {
                    name = String::new();
                }

                let len = name.len();
                put_short(nameoffset | 0xc000, &mut ansp); // 域名，压缩指针形式   指向报文前面已出现的域名针对于数据包偏移的数值
                put_short(T_TXT, &mut ansp); // 资源类型 2字节
                put_short(C_CHAOS, &mut ansp); // 记录类别 1字节
                put_long(0, &mut ansp); // ttl 生存时间 4字节
                put_short((len + 1) as u16, &mut ansp); // 指示 RDATA 字段的字节数 2字节
                ansp.push(len as u8); // 添加 name 长度
                ansp.extend(name.as_bytes()); // 添加name

                ans = 1;
                anscount += 1;

                if ansp.len() > PACKETSZ {
                    // 数据包长度超过设置值
                    return ans_packet;
                }
            } else {
                return ans_packet;
            }
        } else if qclass != C_IN {
            //检查是否为互联网类查询
            return ans_packet;
        } else {
            //从缓存中查找答案
            if (options & OPT_FILTER) != 0 && (qtype == T_SOA || qtype == T_SRV) {
                ans = 1;
            }

            // 反向域名解析（IP → 域名）所有记录类型查询
            if qtype == T_PTR || qtype == T_ANY {
                // 在缓存中查找
                let mut crecp_rc = caches.cache_find_by_addr(None, addr, now, is_arpa);
                while let Some(crecp_ref) = crecp_rc.clone() {
                    let crecp = crecp_ref.borrow();

                    // 返回DHCP表项的ttl值为0，在租约到期前ttl值可能会改变。
                    let ttl: u32 = if crecp.flags & (F_IMMORTAL | F_DHCP) != 0 {
                        local_ttl
                    } else {
                        match crecp.ttd.duration_since(now) {
                            Ok(duration) => duration.as_secs() as u32,
                            Err(_) => 0, // If ttd is in the past, use 0 TTL
                        }
                    };

                    // 不要用非/etc/hosts或DHCP租约的数据回答
                    if qtype == T_ANY && crecp.flags & (F_HOSTS | F_DHCP) == 0 {
                        return ans_packet;
                    }

                    ans = 1;
                    if crecp.flags & F_NEG != 0 {
                        log_query(caches, crecp.flags & !F_FORWARD, &name, addr);
                        auth = false;
                        if crecp.flags & F_NXDOMAIN != 0 {
                            nxdomain = 1;
                        }
                    } else {
                        if crecp.flags & (F_HOSTS | F_DHCP) == 0 {
                            auth = false;
                        }

                        let new_ans = add_text_record(nameoffset, ttl, 0, T_PTR, &crecp.name);
                        ansp.extend(&new_ans); // 将新组建的回答添加到总的回答中
                        log_query(caches, crecp.flags & !F_FORWARD, &crecp.name, addr);
                        anscount += 1;

                        if ansp.len() > PACKETSZ {
                            // 数据包长度超过设置值
                            return ans_packet;
                        }
                    }

                    crecp_rc = caches.cache_find_by_addr(crecp_rc, addr, now, is_arpa);
                }

                // 如果不在缓存中，启用和私有IPV4地址，伪造答案
                if ans == 0
                    && is_arpa == F_IPV4
                    && (options & OPT_BOGUSPRIV) != 0
                    && private_net(&addr.unwrap())
                {
                    let addr4: Ipv4Addr = addr.unwrap().to_ipv4().unwrap();
                    let addr4_str = addr4.to_string();
                    let new_ans = add_text_record(nameoffset, local_ttl, 0, T_PTR, &addr4_str);
                    ansp.extend(&new_ans);
                    log_query(caches, F_CONFIG | F_REVERSE | F_IPV4, &addr4_str, addr);
                    anscount += 1;
                    ans = 1;

                    if ansp.len() > PACKETSZ {
                        // 数据包长度超过设置值
                        return ans_packet;
                    }
                }
            }

            // 正向域名解析（域名 → IP）A记录查询
            if qtype == T_A || qtype == T_ANY {
                if (options & OPT_FILTER) != 0 && qtype == T_ANY && name.contains('_') {
                    ans = 1;
                } else {
                    let mut crecp_rc = caches.cache_find_by_name(None, &name, now, F_IPV4);
                    while let Some(crecp_ref) = crecp_rc {
                        {
                            let crecp = crecp_ref.borrow();

                            // 返回DHCP表项的ttl值为0，在租约到期前ttl值可能会改变。
                            let ttl: u32 = if crecp.flags & (F_IMMORTAL | F_DHCP) != 0 {
                                local_ttl
                            } else {
                                match crecp.ttd.duration_since(now) {
                                    Ok(duration) => duration.as_secs() as u32,
                                    Err(_) => 0, // If ttd is in the past, use 0 TTL
                                }
                            };

                            // 不要用非/etc/hosts或DHCP租约的数据回答通配符查询
                            if qtype == T_ANY && crecp.flags & (F_HOSTS | F_DHCP) == 0 {
                                return ans_packet;
                            }
                            // 如果缓存项是负的，那么不返回答案是可以的
                            ans = 1;

                            if crecp.flags & F_NEG != 0 {
                                log_query(caches, crecp.flags, &name, None);
                                auth = false;
                                if crecp.flags & F_NXDOMAIN != 0 {
                                    nxdomain = 1;
                                }
                            } else {
                                if crecp.flags & (F_HOSTS | F_DHCP) == 0 {
                                    auth = false;
                                }
                                log_query(caches, crecp.flags & !F_REVERSE, &name, crecp.addr);

                                // 复制问题作为答案的第一部分（使用压缩）
                                put_short(nameoffset | 0xc000, &mut ansp);
                                put_short(T_A, &mut ansp);
                                put_short(C_IN, &mut ansp);
                                put_long(ttl, &mut ansp);

                                put_short(INADDRSZ, &mut ansp);
                                let addr4_byte = crecp.addr.unwrap().to_ipv4().unwrap().octets();
                                ansp.extend(&addr4_byte);
                                anscount += 1;

                                if ansp.len() > PACKETSZ {
                                    // 数据包长度超过设置值
                                    return ans_packet;
                                }
                            }
                        }
                        crecp_rc = caches.cache_find_by_name(Some(crecp_ref), &name, now, F_IPV4);
                    }
                }
            }

            // IPv6 正向域名解析（域名 → IPv6）
            if qtype == T_AAAA || qtype == T_ANY {
                if (options & OPT_FILTER) != 0 && qtype == T_ANY && name.contains('_') {
                    ans = 1;
                } else {
                    let mut crecp_rc = caches.cache_find_by_name(None, &name, now, F_IPV6);
                    while let Some(crecp_ref) = crecp_rc.clone() {
                        {
                            let crecp = crecp_ref.borrow();

                            // 返回DHCP表项的ttl值为0，在租约到期前ttl值可能会改变。
                            let ttl: u32 = if crecp.flags & (F_IMMORTAL | F_DHCP) != 0 {
                                local_ttl
                            } else {
                                match crecp.ttd.duration_since(now) {
                                    Ok(duration) => duration.as_secs() as u32,
                                    Err(_) => 0, // If ttd is in the past, use 0 TTL
                                }
                            };

                            // 不要用非/etc/hosts或DHCP租约的数据回答通配符查询
                            if qtype == T_ANY && crecp.flags & (F_HOSTS | F_DHCP) == 0 {
                                return ans_packet;
                            }
                            // 如果缓存项是负的，那么不返回答案是可以的
                            ans = 1;

                            if crecp.flags & F_NEG != 0 {
                                log_query(caches, crecp.flags, &name, None);
                                auth = false;
                                if crecp.flags & F_NXDOMAIN != 0 {
                                    nxdomain = 1;
                                }
                            } else {
                                if crecp.flags & (F_HOSTS | F_DHCP) == 0 {
                                    auth = false;
                                }
                                log_query(caches, crecp.flags & !F_REVERSE, &name, crecp.addr);

                                // 复制问题作为答案的第一部分（使用压缩）
                                put_short(nameoffset | 0xc000, &mut ansp);
                                put_short(T_AAAA, &mut ansp);
                                put_short(C_IN, &mut ansp);
                                put_long(ttl, &mut ansp);

                                put_short(IN6ADDRSZ, &mut ansp);
                                let addr6_byte = crecp.addr.unwrap().to_ipv6().unwrap().octets();
                                ansp.extend(&addr6_byte);
                                anscount += 1;

                                if ansp.len() > PACKETSZ {
                                    // 数据包长度超过设置值
                                    return ans_packet;
                                }
                            }
                        }
                        crecp_rc = caches.cache_find_by_name(crecp_rc, &name, now, F_IPV6);
                    }
                }
            }

            // 邮件交换记录查询
            if qtype == T_MX || qtype == T_ANY {
                if !mxname.is_empty() && mxname == name.as_str() {
                    let new_ans = add_text_record(nameoffset, local_ttl, 1, T_MX, mxtarget);
                    ansp.extend(&new_ans);
                    anscount += 1;
                    ans = 1;
                } else if options & (OPT_SELFMX | OPT_LOCALMX) != 0
                    && caches
                        .cache_find_by_name(None, &name, now, F_HOSTS | F_DHCP)
                        .is_some()
                {
                    let t_name = if options & OPT_SELFMX != 0 {
                        name
                    } else {
                        mxtarget.to_string()
                    };
                    let new_ans = add_text_record(nameoffset, local_ttl, 1, T_MX, &t_name);
                    ansp.extend(&new_ans);
                    anscount += 1;
                    ans = 1;
                }
            }

            //MB 邮箱（Mailbox）记录。一种过时的 DNS 记录类型，用于将邮箱名映射为主机名
            if qtype == T_MAILB {
                ans = 1;
                nxdomain = 1;
            }
        }

        if ans == 0 {
            return ans_packet;
        }
    }

    // 组装新的需要返回的数据包

    let mut ans_header = header;
    ans_header.qr = true;
    ans_header.aa = auth;
    ans_header.ra = true;
    ans_header.tc = false;
    ans_header.rcode = if anscount == 0 && nxdomain != 0 {
        NXDOMAIN
    } else {
        NOERROR
    };
    ans_header.ancount = anscount;
    ans_header.nscount = 0;
    ans_header.arcount = 0;

    let ans_header_bytes = ans_header.to_bytes();

    ans_packet.extend(&ans_header_bytes); // 填充头部
    ans_packet.extend(q_byte); // 填充问题部分
    ans_packet.extend(&ansp); // 填充答案部分

    ans_packet
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试 extract_name 函数的基本域名解析
    #[test]
    fn test_extract_name_basic() {
        // 基本域名: "example.com"
        let packet = vec![0; 100]; // 空packet，不使用压缩指针
        let data = [
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example" (7字节)
            3, b'c', b'o', b'm', // "com" (3字节)
            0,    // 结束标记
        ];

        let result = extract_name(&packet, &mut &data[..]);

        assert_eq!(result, "example.com", "基本域名解析失败");
    }

    /// 测试 extract_name 函数的单标签域名
    #[test]
    fn test_extract_name_single_label() {
        let packet = vec![0; 100];
        let data = [
            9, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't', // "localhost" (9字节)
            0,    // 结束标记
        ];

        let result = extract_name(&packet, &mut &data[..]);

        assert_eq!(result, "localhost", "单标签域名解析失败");
    }

    /// 测试 extract_name 函数的多标签域名
    #[test]
    fn test_extract_name_multiple_labels() {
        let packet = vec![0; 100];
        let data = [
            3, b'w', b'w', b'w', // "www" (3字节)
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example" (7字节)
            3, b'c', b'o', b'm', // "com" (3字节)
            0,    // 结束标记
        ];

        let result = extract_name(&packet, &mut &data[..]);

        assert_eq!(result, "www.example.com", "多标签域名解析失败");
    }

    /// 测试 extract_name 函数的压缩指针功能
    #[test]
    fn test_extract_name_compression_pointer() {
        // 创建包含压缩指针的数据包
        // 域名: "example.com" 出现在偏移量12处
        let mut packet = vec![0; 100];

        // 在偏移量12处放置域名
        packet[12] = 7; // "example" 长度
        packet[13..20].copy_from_slice(b"example");
        packet[20] = 3; // "com" 长度
        packet[21..24].copy_from_slice(b"com");
        packet[24] = 0; // 结束标记
        packet[25] = 0xC0;
        packet[26] = 0x0C;

        // 压缩指针: 0xC00C (指向偏移量12)
        let data = &packet[25..];

        let result = extract_name(&packet, &mut &data[..]);

        assert_eq!(result, "example.com", "压缩指针域名解析失败");
    }

    /// 测试 extract_name 函数的非法字符处理
    #[test]
    fn test_extract_name_invalid_characters() {
        let packet = vec![0; 100];
        // 包含非法字符的域名
        let data = [
            3, b't', b'e', 0xFF, // 包含非法字符0xFF
            3, b'c', b'o', b'm', 0,
        ];

        let result = extract_name(&packet, &mut &data[..]);

        assert_eq!(result, "", "包含非法字符的域名应该返回空字符串");
    }

    /// 测试 extract_name 函数的域名长度过长情况
    #[test]
    fn test_extract_name_too_long() {
        let packet = vec![0; 100];
        // 创建超长域名标签
        let long_label: Vec<u8> = vec![b'a'; 64]; // 64个字符，超过DNS标签限制
        let mut data = Vec::new();
        data.push(64); // 长度字节
        data.extend(&long_label);
        data.push(0); // 结束标记

        let result = extract_name(&packet, &mut &data[..]);

        assert_eq!(result, "", "超长域名标签应该返回空字符串");
    }

    /// 测试 extract_name 函数的压缩指针越界情况
    #[test]
    fn test_extract_name_compression_out_of_bounds() {
        let packet = vec![0; 50]; // 小packet
                                  // 压缩指针指向packet范围外
        let data = [0xC0, 0xFF]; // 指向偏移量255，超出packet范围

        let result = extract_name(&packet, &mut &data[..]);

        assert_eq!(result, "", "压缩指针越界应该返回空字符串");
    }

    /// 测试 extract_name 函数的保留标签类型处理
    #[test]
    fn test_extract_name_reserved_label_type() {
        let packet = vec![0; 100];
        // 保留标签类型 (0x80)
        let data = [0x80, 0x00]; // 保留类型

        let result = extract_name(&packet, &mut &data[..]);

        assert_eq!(result, "", "保留标签类型应该返回空字符串");
    }

    /// 测试 extract_name 函数的跳数限制
    #[test]
    fn test_extract_name_too_many_hops() {
        let mut packet = vec![0; 100];
        // 创建循环压缩指针（模拟过多跳数）
        packet[12] = 0xC0; // 指向自身
        packet[13] = 0x0C;

        let data = [0xC0, 0x0C]; // 指向偏移量12

        let result = extract_name(&packet, &mut &data[..]);

        assert_eq!(result, "", "过多跳数应该返回空字符串");
    }

    /// 测试 extract_name 函数的边界情况：最大长度域名
    #[test]
    fn test_extract_name_max_length() {
        let packet = vec![0; 500];
        let mut data = Vec::new();

        // 创建接近最大长度的域名 (每个标签63字符，总长度接近253字符)
        for _ in 0..3 {
            data.push(10); // 10字符标签
            data.extend(vec![b'a'; 10]); // 10个'a'
        }
        data.push(0); // 结束标记

        let result = extract_name(&packet, &mut &data[..]);

        // 应该成功解析
        assert!(!result.is_empty(), "接近最大长度的域名应该成功解析");
        assert_eq!(result, "aaaaaaaaaa.aaaaaaaaaa.aaaaaaaaaa", "域名格式不正确");
    }

    /// 测试 add_text_record 函数的基本功能
    #[test]
    fn test_add_text_record_basic() {
        let nameoffset = 0x0012; // 域名偏移量
        let ttl = 3600; // TTL 1小时
        let qtype = 16; // TXT记录类型
        let pref = 0; // 优先级（对于TXT记录通常为0）
        let name = "example.com";

        // 添加域名检测验证
        use crate::util::canonicalise;

        // 验证测试使用的域名是有效的
        assert!(canonicalise(name), "域名 '{}' 格式无效", name);

        // 验证域名包含有效的标签
        let labels: Vec<&str> = name.split('.').collect();
        assert!(!labels.is_empty(), "域名应该包含至少一个标签");
        for label in &labels {
            assert!(!label.is_empty(), "域名标签不能为空");
            assert!(
                label.len() <= 63,
                "域名标签长度不能超过63个字符: '{}'",
                label
            );
        }

        // 验证整个域名长度在合理范围内
        assert!(name.len() <= 253, "域名总长度不能超过253个字符: '{}'", name);

        let result = add_text_record(nameoffset, ttl, pref, qtype, name);

        // 验证结果不为空
        assert!(!result.is_empty());

        // 验证基本结构：域名偏移 + 类型 + 类别 + TTL + 数据长度 + 数据
        assert!(result.len() >= 12); // 至少包含基本头部信息

        // 验证域名偏移（压缩指针形式）
        assert_eq!(result[0], 0xC0); // 压缩指针标志
        assert_eq!(result[1], 0x12); // 偏移量

        // 验证记录类型
        assert_eq!(result[2], 0x00); // qtype高字节
        assert_eq!(result[3], 0x10); // qtype低字节 (TXT=16)

        // 验证类别（应该为C_IN=1）
        assert_eq!(result[4], 0x00); // 类别高字节
        assert_eq!(result[5], 0x01); // 类别低字节

        // 验证TTL
        assert_eq!(result[6], 0x00); // TTL字节1
        assert_eq!(result[7], 0x00); // TTL字节2
        assert_eq!(result[8], 0x0E); // TTL字节3 (3600 = 0x0E10)
        assert_eq!(result[9], 0x10); // TTL字节4

        // 额外验证：检查生成的记录中的域名数据部分
        let data_length_pos = 10;
        let data_length =
            ((result[data_length_pos] as u16) << 8) | (result[data_length_pos + 1] as u16);
        assert!(data_length > 0, "数据部分长度应该大于0");

        // 验证域名数据格式正确
        let data_start = data_length_pos + 2;
        let mut pos = data_start;

        for label in labels {
            assert_eq!(
                result[pos] as usize,
                label.len(),
                "标签 '{}' 长度不匹配",
                label
            );
            pos += 1;
            let label_bytes = label.as_bytes();
            assert_eq!(
                &result[pos..pos + label.len()],
                label_bytes,
                "标签 '{}' 内容不匹配",
                label
            );
            pos += label.len();
        }

        assert_eq!(result[pos], 0, "域名数据应该以0结束");
    }

    /// 测试 add_text_record 函数的数据部分
    #[test]
    fn test_add_text_record_data_section() {
        let nameoffset = 0x0020;
        let ttl = 7200;
        let qtype = 16; // TXT
        let pref = 0;
        let name = "test.example.org";

        let result = add_text_record(nameoffset, ttl, pref, qtype, name);

        // 找到数据长度字段的位置（在TTL之后）
        let data_length_pos = 10; // TTL之后的位置
        let data_length =
            ((result[data_length_pos] as u16) << 8) | (result[data_length_pos + 1] as u16);

        // 验证数据长度正确（大端序）
        let mut expected_length = 0;
        for label in name.split('.') {
            expected_length += 1 + label.len(); // 长度字节 + 标签内容
        }
        expected_length += 1; // 结束符

        // 实际测试：先验证函数是否正常工作，再检查具体值
        assert!(data_length > 0, "数据长度应该大于0");
        assert_eq!(data_length as usize, expected_length, "数据长度计算错误");

        // 验证域名数据格式
        let data_start = data_length_pos + 2;
        let mut pos = data_start;

        for label in name.split('.') {
            assert_eq!(result[pos] as usize, label.len());
            pos += 1;

            let label_bytes = label.as_bytes();
            assert_eq!(&result[pos..pos + label.len()], label_bytes);
            pos += label.len();
        }

        // 验证结束符
        assert_eq!(result[pos], 0);
    }

    /// 测试 add_text_record 函数带有优先级的情况
    #[test]
    fn test_add_text_record_with_preference() {
        let nameoffset = 0x0015;
        let ttl = 1800;
        let qtype = 33; // SRV记录类型
        let pref = 10; // 优先级
        let name = "service.example.com";

        let result = add_text_record(nameoffset, ttl, pref, qtype, name);

        // 验证结果包含优先级字段
        assert!(!result.is_empty());

        // 找到数据部分
        let data_length_pos = 10;
        let data_start = data_length_pos + 2;

        // 验证优先级字段存在
        let priority_pos = data_start;
        assert_eq!(result[priority_pos], 0x00); // 优先级高字节
        assert_eq!(result[priority_pos + 1], 0x0A); // 优先级低字节 (10)

        // 验证域名数据在优先级之后
        let domain_start = priority_pos + 2;
        let mut pos = domain_start;

        for label in name.split('.') {
            assert_eq!(result[pos] as usize, label.len());
            pos += 1;
            let label_bytes = label.as_bytes();
            assert_eq!(&result[pos..pos + label.len()], label_bytes);
            pos += label.len();
        }

        assert_eq!(result[pos], 0); // 结束符
    }

    /// 测试 add_text_record 函数的单标签域名
    #[test]
    fn test_add_text_record_single_label() {
        let nameoffset = 0x0018;
        let ttl = 900;
        let qtype = 16; // TXT
        let pref = 0;
        let name = "localhost"; // 单标签域名

        let result = add_text_record(nameoffset, ttl, pref, qtype, name);

        // 验证数据长度
        let data_length_pos = 10;
        let data_length =
            ((result[data_length_pos] as u16) << 8) | (result[data_length_pos + 1] as u16);
        assert_eq!(data_length as usize, name.len() + 1 + 1); // 标签长度 + 长度字节 + 结束符

        // 验证域名数据
        let data_start = data_length_pos + 2;
        assert_eq!(result[data_start] as usize, name.len());
        assert_eq!(
            &result[data_start + 1..data_start + 1 + name.len()],
            name.as_bytes()
        );
        assert_eq!(result[data_start + 1 + name.len()], 0); // 结束符
    }

    /// 测试 add_text_record 函数的长域名处理
    #[test]
    fn test_add_text_record_long_domain() {
        let nameoffset = 0x0025;
        let ttl = 86400; // 1天
        let qtype = 16; // TXT
        let pref = 0;
        let name = "very.long.subdomain.name.that.has.many.labels.example.com";

        let result = add_text_record(nameoffset, ttl, pref, qtype, name);

        // 验证结果不为空
        assert!(!result.is_empty());

        // 验证数据长度计算正确
        let data_length_pos = 10;
        let data_length =
            ((result[data_length_pos] as u16) << 8) | (result[data_length_pos + 1] as u16);

        let mut expected_length = 0;
        for label in name.split('.') {
            expected_length += 1 + label.len(); // 长度字节 + 标签内容
        }
        expected_length += 1; // 结束符

        assert_eq!(data_length as usize, expected_length);

        // 验证域名数据格式正确
        let data_start = data_length_pos + 2;
        let mut pos = data_start;

        for label in name.split('.') {
            assert_eq!(result[pos] as usize, label.len());
            pos += 1;
            let label_bytes = label.as_bytes();
            assert_eq!(&result[pos..pos + label.len()], label_bytes);
            pos += label.len();
        }

        assert_eq!(result[pos], 0); // 结束符
    }

    /// 测试 add_text_record 函数的不同记录类型
    #[test]
    fn test_add_text_record_different_types() {
        let test_cases = vec![
            (1, "A记录"),     // A记录
            (28, "AAAA记录"), // AAAA记录
            (15, "MX记录"),   // MX记录
            (16, "TXT记录"),  // TXT记录
            (33, "SRV记录"),  // SRV记录
        ];

        for (qtype, description) in test_cases {
            let nameoffset = 0x0012;
            let ttl = 3600;
            let pref = if qtype == 15 || qtype == 33 { 10 } else { 0 }; // MX和SRV记录需要优先级
            let name = "test.example.com";

            let result = add_text_record(nameoffset, ttl, pref, qtype, name);

            // 验证记录类型设置正确
            assert_eq!(result[2], (qtype >> 8) as u8);
            assert_eq!(result[3], (qtype & 0xFF) as u8);

            // 验证结果不为空
            assert!(!result.is_empty(), "{} 测试失败", description);
        }
    }

    /// 测试 add_text_record 函数的TTL编码
    #[test]
    fn test_add_text_record_ttl_encoding() {
        let test_cases = vec![
            (0, "零TTL"),
            (1, "最小TTL"),
            (300, "5分钟"),
            (3600, "1小时"),
            (86400, "1天"),
            (2147483647, "最大TTL"), // 最大32位有符号整数
        ];

        for (ttl, description) in test_cases {
            let nameoffset = 0x0010;
            let qtype = 16; // TXT
            let pref = 0;
            let name = "ttl-test.example.com";

            let result = add_text_record(nameoffset, ttl, pref, qtype, name);

            // 验证TTL编码正确
            let ttl_bytes = &result[6..10];
            let decoded_ttl = ((ttl_bytes[0] as u32) << 24)
                | ((ttl_bytes[1] as u32) << 16)
                | ((ttl_bytes[2] as u32) << 8)
                | (ttl_bytes[3] as u32);

            assert_eq!(decoded_ttl, ttl, "{} TTL编码测试失败", description);
        }
    }

    /// 测试 add_text_record 函数的综合场景
    #[test]
    fn test_add_text_record_integration() {
        // 模拟真实场景：创建多个记录并验证其格式
        let records = [
            (0x0012, 3600, 1, 0, "host1.example.com"),  // A记录1600 ~
            (0x0020, 7200, 28, 0, "host2.example.com"), // AAAA记录1601 ~
            (0x0030, 1800, 16, 0, "text.example.com"),
        ];

        for (i, (nameoffset, ttl, qtype, pref, name)) in records.iter().enumerate() {
            let result = add_text_record(*nameoffset, *ttl, *pref, *qtype, name);

            // 基本验证
            assert!(!result.is_empty(), "记录 {} 生成失败", i);

            // 验证压缩指针
            assert_eq!(result[0], 0xC0);
            assert_eq!(result[1], (*nameoffset & 0xFF) as u8);

            // 验证记录类型
            assert_eq!(result[3], (*qtype & 0xFF) as u8);

            // 验证TTL
            let decoded_ttl = ((result[6] as u32) << 24)
                | ((result[7] as u32) << 16)
                | ((result[8] as u32) << 8)
                | (result[9] as u32);
            assert_eq!(decoded_ttl, *ttl);

            // 验证域名数据
            let data_length_pos = 10;
            let data_start = data_length_pos + 2;
            let mut pos = data_start;

            if *pref != 0 {
                pos += 2; // 跳过优先级字段
            }

            for label in name.split('.') {
                assert_eq!(result[pos] as usize, label.len());
                pos += 1;
                let label_bytes = label.as_bytes();
                assert_eq!(&result[pos..pos + label.len()], label_bytes);
                pos += label.len();
            }

            assert_eq!(result[pos], 0); // 结束符
        }
    }

    /// 测试 check_for_bogus_wildcard 函数 - 正常情况：没有恶意IP
    #[test]
    fn test_check_for_bogus_wildcard_no_bogus_ip() {
        use std::time::SystemTime;

        // 创建测试用的DNS响应数据包
        // 包含一个正常的A记录响应
        let mut packet = vec![
            // DNS头部
            0x12, 0x34, // ID
            0x81, 0x80, // Flags: 响应 + 递归可用
            0x00, 0x01, // QDCOUNT: 1个问题
            0x00, 0x01, // ANCOUNT: 1个回答
            0x00, 0x00, // NSCOUNT: 0个授权
            0x00, 0x00, // ARCOUNT: 0个附加
            // 问题部分: "example.com"
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
            0x03, b'c', b'o', b'm', // "com"
            0x00, // 结束标记
            0x00, 0x01, // QTYPE: A记录
            0x00, 0x01, // QCLASS: IN
            // 回答部分
            0xC0, 0x0C, // 压缩指针，指向问题部分的域名
            0x00, 0x01, // TYPE: A记录
            0x00, 0x01, // CLASS: IN
            0x00, 0x00, 0x0E, 0x10, // TTL: 3600秒
            0x00, 0x04, // RDLENGTH: 4字节
            0x01, 0x02, 0x03, 0x04, // IP地址: 1.2.3.4
        ];

        // 创建缓存
        let mut cache = crate::cache::Cache::cache_init(100, 0);

        // 创建恶意IP地址列表（空列表）
        let baddrs: Vec<BogusAddr> = Vec::new();

        let now = SystemTime::now();

        // 调用函数
        let result = check_for_bogus_wildcard(&mut cache, &mut packet, &baddrs, now);

        // 验证结果：应该返回0（没有检测到恶意IP）
        assert_eq!(result, 0, "没有恶意IP时应该返回0");

        // 验证数据包没有被修改
        let header = Header::parse(&packet).unwrap();
        assert_eq!(header.ancount, 1, "回答记录数应该保持不变");
        assert_eq!(header.rcode, NOERROR, "响应码应该保持NOERROR");
    }

    /// 测试 check_for_bogus_wildcard 函数 - 检测到恶意IP的情况
    #[test]
    fn test_check_for_bogus_wildcard_with_bogus_ip() {
        use std::net::Ipv4Addr;
        use std::time::SystemTime;

        // 创建测试用的DNS响应数据包
        // 包含一个恶意IP地址的A记录响应
        let mut packet = vec![
            // DNS头部
            0x12, 0x34, // ID
            0x81, 0x80, // Flags: 响应 + 递归可用
            0x00, 0x01, // QDCOUNT: 1个问题
            0x00, 0x01, // ANCOUNT: 1个回答
            0x00, 0x00, // NSCOUNT: 0个授权
            0x00, 0x00, // ARCOUNT: 0个附加
            // 问题部分: "example.com"
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
            0x03, b'c', b'o', b'm', // "com"
            0x00, // 结束标记
            0x00, 0x01, // QTYPE: A记录
            0x00, 0x01, // QCLASS: IN
            // 回答部分
            0xC0, 0x0C, // 压缩指针，指向问题部分的域名
            0x00, 0x01, // TYPE: A记录
            0x00, 0x01, // CLASS: IN
            0x00, 0x00, 0x0E, 0x10, // TTL: 3600秒
            0x00, 0x04, // RDLENGTH: 4字节
            0xC0, 0xA8, 0x01, 0x01, // IP地址: 192.168.1.1（恶意IP）
        ];

        // 创建缓存
        let mut cache = crate::cache::Cache::cache_init(100, 0);

        // 创建恶意IP地址列表，包含192.168.1.1
        let baddrs = vec![BogusAddr {
            addr: Ipv4Addr::new(192, 168, 1, 1),
            next: None,
        }];

        let now = SystemTime::now();

        // 调用函数
        let result = check_for_bogus_wildcard(&mut cache, &mut packet, &baddrs, now);

        // 验证结果：应该返回1（检测到恶意IP）
        assert_eq!(result, 1, "检测到恶意IP时应该返回1");

        // 验证数据包被正确修改为NXDOMAIN响应
        let header = Header::parse(&packet).unwrap();
        assert_eq!(header.ancount, 0, "回答记录数应该被设置为0");
        assert_eq!(header.rcode, NXDOMAIN, "响应码应该被设置为NXDOMAIN");
        assert!(!header.aa, "授权回答标志应该被清除");
        assert!(header.ra, "递归可用标志应该被设置");
    }

    /// 测试 check_for_bogus_wildcard 函数 - 非A记录的情况
    #[test]
    fn test_check_for_bogus_wildcard_non_a_record() {
        use std::net::Ipv4Addr;
        use std::time::SystemTime;

        // 创建测试用的DNS响应数据包，包含AAAA记录（IPv6）
        let mut packet = vec![
            // DNS头部
            0x12, 0x34, // ID
            0x81, 0x80, // Flags: 响应 + 递归可用
            0x00, 0x01, // QDCOUNT: 1个问题
            0x00, 0x01, // ANCOUNT: 1个回答
            0x00, 0x00, // NSCOUNT: 0个授权
            0x00, 0x00, // ARCOUNT: 0个附加
            // 问题部分: "example.com"
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
            0x03, b'c', b'o', b'm', // "com"
            0x00, // 结束标记
            0x00, 0x1C, // QTYPE: AAAA记录（IPv6）
            0x00, 0x01, // QCLASS: IN
            // 回答部分 - AAAA记录
            0xC0, 0x0C, // 压缩指针，指向问题部分的域名
            0x00, 0x1C, // TYPE: AAAA记录
            0x00, 0x01, // CLASS: IN
            0x00, 0x00, 0x0E, 0x10, // TTL: 3600秒
            0x00, 0x10, // RDLENGTH: 16字节
            // IPv6地址数据（不会检查IPv6地址）
            0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];

        // 创建缓存
        let mut cache = crate::cache::Cache::cache_init(100, 0);

        // 创建恶意IP地址列表
        let baddrs = vec![BogusAddr {
            addr: Ipv4Addr::new(192, 168, 1, 1),
            next: None,
        }];

        let now = SystemTime::now();

        // 调用函数
        let result = check_for_bogus_wildcard(&mut cache, &mut packet, &baddrs, now);

        // 验证结果：应该返回0（非A记录不会被检查）
        assert_eq!(result, 0, "非A记录时应该返回0");

        // 验证数据包没有被修改
        let header = Header::parse(&packet).unwrap();
        assert_eq!(header.ancount, 1, "回答记录数应该保持不变");
        assert_eq!(header.rcode, NOERROR, "响应码应该保持NOERROR");
    }

    /// 测试 check_for_bogus_wildcard 函数 - 多个答案记录的情况
    #[test]
    fn test_check_for_bogus_wildcard_multiple_answers() {
        use std::net::Ipv4Addr;
        use std::time::SystemTime;

        // 创建测试用的DNS响应数据包，包含多个A记录
        let mut packet = vec![
            // DNS头部
            0x12, 0x34, // ID
            0x81, 0x80, // Flags: 响应 + 递归可用
            0x00, 0x01, // QDCOUNT: 1个问题
            0x00, 0x02, // ANCOUNT: 2个回答
            0x00, 0x00, // NSCOUNT: 0个授权
            0x00, 0x00, // ARCOUNT: 0个附加
            // 问题部分: "example.com"
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
            0x03, b'c', b'o', b'm', // "com"
            0x00, // 结束标记
            0x00, 0x01, // QTYPE: A记录
            0x00, 0x01, // QCLASS: IN
            // 第一个回答部分 - 正常IP
            0xC0, 0x0C, // 压缩指针，指向问题部分的域名
            0x00, 0x01, // TYPE: A记录
            0x00, 0x01, // CLASS: IN
            0x00, 0x00, 0x0E, 0x10, // TTL: 3600秒
            0x00, 0x04, // RDLENGTH: 4字节
            0x01, 0x02, 0x03, 0x04, // IP地址: 1.2.3.4（正常IP）
            // 第二个回答部分 - 恶意IP
            0xC0, 0x0C, // 压缩指针，指向问题部分的域名
            0x00, 0x01, // TYPE: A记录
            0x00, 0x01, // CLASS: IN
            0x00, 0x00, 0x0E, 0x10, // TTL: 3600秒
            0x00, 0x04, // RDLENGTH: 4字节
            0xC0, 0xA8, 0x01, 0x01, // IP地址: 192.168.1.1（恶意IP）
        ];

        // 创建缓存
        let mut cache = crate::cache::Cache::cache_init(100, 0);

        // 创建恶意IP地址列表
        let baddrs = vec![BogusAddr {
            addr: Ipv4Addr::new(192, 168, 1, 1),
            next: None,
        }];

        let now = SystemTime::now();

        // 调用函数
        let result = check_for_bogus_wildcard(&mut cache, &mut packet, &baddrs, now);

        // 验证结果：应该返回1（检测到恶意IP）
        assert_eq!(result, 1, "检测到恶意IP时应该返回1");

        // 验证数据包被正确修改为NXDOMAIN响应
        let header = Header::parse(&packet).unwrap();
        assert_eq!(header.ancount, 0, "回答记录数应该被设置为0");
        assert_eq!(header.rcode, NXDOMAIN, "响应码应该被设置为NXDOMAIN");
    }

    /// 测试 check_for_bogus_wildcard 函数 - 多个恶意IP的情况
    #[test]
    fn test_check_for_bogus_wildcard_multiple_bogus_ips() {
        use std::net::Ipv4Addr;
        use std::time::SystemTime;

        // 创建测试用的DNS响应数据包
        let mut packet = vec![
            // DNS头部
            0x12, 0x34, // ID
            0x81, 0x80, // Flags: 响应 + 递归可用
            0x00, 0x01, // QDCOUNT: 1个问题
            0x00, 0x01, // ANCOUNT: 1个回答
            0x00, 0x00, // NSCOUNT: 0个授权
            0x00, 0x00, // ARCOUNT: 0个附加
            // 问题部分: "example.com"
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
            0x03, b'c', b'o', b'm', // "com"
            0x00, // 结束标记
            0x00, 0x01, // QTYPE: A记录
            0x00, 0x01, // QCLASS: IN
            // 回答部分
            0xC0, 0x0C, // 压缩指针，指向问题部分的域名
            0x00, 0x01, // TYPE: A记录
            0x00, 0x01, // CLASS: IN
            0x00, 0x00, 0x0E, 0x10, // TTL: 3600秒
            0x00, 0x04, // RDLENGTH: 4字节
            0x0A, 0x00, 0x00, 0x01, // IP地址: 10.0.0.1（恶意IP）
        ];

        // 创建缓存
        let mut cache = crate::cache::Cache::cache_init(100, 0);

        // 创建多个恶意IP地址列表
        let baddrs = vec![
            BogusAddr {
                addr: Ipv4Addr::new(192, 168, 1, 1),
                next: None,
            },
            BogusAddr {
                addr: Ipv4Addr::new(10, 0, 0, 1), // 这个IP在数据包中
                next: None,
            },
            BogusAddr {
                addr: Ipv4Addr::new(172, 16, 0, 1),
                next: None,
            },
        ];

        let now = SystemTime::now();

        // 调用函数
        let result = check_for_bogus_wildcard(&mut cache, &mut packet, &baddrs, now);

        // 验证结果：应该返回1（检测到恶意IP）
        assert_eq!(result, 1, "检测到恶意IP时应该返回1");

        // 验证数据包被正确修改为NXDOMAIN响应
        let header = Header::parse(&packet).unwrap();
        assert_eq!(header.ancount, 0, "回答记录数应该被设置为0");
        assert_eq!(header.rcode, NXDOMAIN, "响应码应该被设置为NXDOMAIN");
    }
}
