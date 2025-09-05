/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use crate::*;
use byteorder::{ByteOrder, NetworkEndian};
use std::time::SystemTime;

pub type InAddrT = u32;

const F_IPV4: u32 = 128;
const F_FORWARD: u32 = 8;
const F_NEG: u32 = 32;
const F_NXDOMAIN: u32 = 4096;
const F_CONFIG: u32 = 2;

// 检查DNS响应数据包中是否存在虚假的IP地址
pub fn check_for_bogus_wildcard(
    header: &[u8],
    qlen: usize,
    name: &mut [u8],
    baddr: Option<Box<BogusAddr>>,
    now: SystemTime,
    caches: &mut Cache,
) -> bool {
    // 跳过问题部分
    let mut p = match skip_questions(header, qlen) {
        Some(p) => p,
        None => return false, // 无效的数据包
    };

    // 获取回答部分数量
    let ancount = NetworkEndian::read_u16(&header[6..8]) as usize;

    // 遍历回答部分
    for _ in 0..ancount {
        if !extract_name(header, qlen, &mut p, name, true) {
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
                    let mut header_mut = header.to_vec();
                    header_mut[2] &= 0b0111_1111; // 清除 AA 位
                    header_mut[3] |= 0b1000_0000; // 设置 RA 位
                    NetworkEndian::write_u16(&mut header_mut[8..10], 0); // nscount = 0
                    NetworkEndian::write_u16(&mut header_mut[10..12], 0); // arcount = 0
                    NetworkEndian::write_u16(&mut header_mut[6..8], 0); // ancount = 0
                    header_mut[3] = (header_mut[3] & 0b1111_0000) | 3; // rcode = NXDOMAIN

                    cache_start_insert(caches);
                    cache_insert(
                        name,
                        None,
                        now,
                        ttl,
                        F_IPV4 | F_FORWARD | F_NEG | F_NXDOMAIN | F_CONFIG,
                    );
                    cache_end_insert();

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
fn skip_questions(header: &[u8], plen: usize) -> Option<&[u8]> {
    let qdcount = NetworkEndian::read_u16(&header[4..6]);
    let mut ansp = &header[12..];

    for _ in 0..qdcount {
        loop {
            if ansp.is_empty() || (ansp.as_ptr() as usize - header.as_ptr() as usize) >= plen {
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

    if (ansp.as_ptr() as usize - header.as_ptr() as usize) > plen {
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

fn cache_insert(_name: &[u8], _data: Option<&[u8]>, _now: SystemTime, _ttl: u32, _flags: u32) {
    // 插入缓存的占位实现
}

fn cache_end_insert() {
    // 结束插入缓存的占位实现
}
