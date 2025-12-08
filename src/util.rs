/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use crate::*;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::ffi::CString;
use std::fs;
use std::io::Read;
use std::net::SocketAddr;
use std::net::{SocketAddrV4, SocketAddrV6};
use std::process;
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

fn get_seed() -> u64 {
    // 读取RANDFILE中的数据
    let rand_file_path = "/dev/urandom";
    // 读取8字节
    let mut buffer = [0u8; 8];

    if let Ok(mut file) = fs::File::open(rand_file_path) {
        if file.read_exact(&mut buffer).is_ok() {
            // 成功读取文件
            return u64::from_le_bytes(buffer);
        }
    }

    // 如果文件不可用，使用当前时间和进程ID生成
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let pid = process::id() as u64;

    // 将时间和进程ID组合为一个64位整数
    time ^ pid
}

pub fn rand16() -> u16 {
    let seed = get_seed();

    // 初始化随机数生成器
    let mut rng: StdRng = SeedableRng::seed_from_u64(seed);

    // 生成随机数并保留高位部分（去除低15位和最高位）
    let random_number: u32 = rng.gen();
    ((random_number >> 16) & 0x7FFF) as u16 // 高位取15位，忽略最高位
}

pub fn canonicalise(s: &str) -> Option<String> {
    // 移除末尾的点号
    let s = s.trim_end_matches('.');

    // 遍历字符串中的每个字符，检查是否合法
    for c in s.chars() {
        // 如果字符不在合法字符范围内，返回 None
        if !(c.is_ascii_alphanumeric() || c == '-' || c == '/' || c == '_') {
            return None;
        }
    }

    Some(s.to_string())
}

pub fn safe_string_alloc(cp: &str) -> *mut i8 {
    // 检查输入字符串是否有效且非空
    if cp.is_empty() {
        return ptr::null_mut(); // 返回空指针
    }

    // 分配与输入字符串长度匹配的内存，并将字符串复制到新分配的内存中
    let c_string = CString::new(cp).unwrap(); // 将Rust字符串转换为C风格字符串
    let cv: Vec<u8> = c_string.into_bytes_with_nul();
    let mut tmp: Vec<i8> = cv.into_iter().map(|c| c as i8).collect(); // 将 Vec<u8> 转换为 Vec<i8>
    let c_ptr: *mut i8 = tmp.as_mut_ptr();

    // 返回该内存地址
    c_ptr
}

// 检查地址是否与接口相等的函数
// pub fn sockaddr_isequal(addr1: &MySockAddr, addr2: &MySockAddr) -> bool {
//     unsafe {
//         println!("xxxxxxxxxxxxxxxxxxxxxaddr1.sa.sa_family={:?}  ", addr1.sa.sa_family);
//         println!("xxxxxxxxxxxxxxxxxxxxxaddr2.sa.sa_family={:?}  ", addr2.sa.sa_family);
//         println!("xxxxxxxxxxxxxxxxxxxxxaddr1.in_.sin_addr.s_addr={:?}  ", addr1.in_.sin_addr.s_addr);
//         println!("xxxxxxxxxxxxxxxxxxxxxaddr2.in_.sin_addr.s_addr={:?}  ", addr2.in_.sin_addr.s_addr);
//         match (addr1.sa.sa_family, addr2.sa.sa_family) {
//             (2, 2) => addr1.in_.sin_addr.s_addr == addr2.in_.sin_addr.s_addr, // AF_INET
//             (10, 10) => {
//                 let in6_addr1 = &addr1.in6;
//                 let in6_addr2 = &addr2.in6;
//                 in6_addr1.sin6_addr.s6_addr == in6_addr2.sin6_addr.s6_addr // AF_INET6
//             }
//             _ => false,
//         }
//     }
// }
pub fn sockaddr_isequal(s1: &MySockAddr, s2: &MySockAddr) -> bool {
    unsafe {
        if s1.sa.sa_family == s2.sa.sa_family {
            match s1.sa.sa_family {
                AF_INET => {
                    let addr_match = s1.in_.sin_addr == s2.in_.sin_addr;
                    let port_match = s1.in_.sin_port == s2.in_.sin_port;
                    addr_match && port_match
                }
                AF_INET6 => {
                    s1.in6.sin6_port == s2.in6.sin6_port
                        && s1.in6.sin6_flowinfo == s2.in6.sin6_flowinfo
                        && s1.in6.sin6_addr == s2.in6.sin6_addr
                }
                _ => false,
            }
        } else {
            false
        }
    }
}

// 计算 socket 地址的长度
pub fn sa_len(addr: &SocketAddr) -> usize {
    match addr {
        SocketAddr::V4(_) => {
            // IPv4 地址结构的长度
            std::mem::size_of::<SocketAddrV4>()
        }
        SocketAddr::V6(_) => {
            // IPv6 地址结构的长度
            std::mem::size_of::<SocketAddrV6>()
        }
    }
}

pub fn hostname_isequal(a: &str, b: &str) -> bool {
    /*
        检查两个字符串是否相等，忽略大小写和空格
    */
    a.eq_ignore_ascii_case(b)
}

pub fn safe_malloc(size: usize) -> Vec<u8> {
    let mut vec = Vec::with_capacity(size);
    if vec.capacity() < size {
        eprintln!("Out of memory");
        std::process::exit(1);
    }
    vec.resize(size, 0); // Initialize with zeroes
    vec
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_hostname_isequal() {
        assert!(hostname_isequal("Rust", "rust"));
        assert!(hostname_isequal("Rust", "Rust"));
        assert!(!hostname_isequal("Rust", "rusty"));
        assert!(!hostname_isequal("Rust", "Ru"));
        assert!(!hostname_isequal("Rust", "r"));
        assert!(hostname_isequal("R", "r"));
    }

    #[test]
    fn sa_len_v4() {
        let addr_v4: SocketAddrV4 = "127.0.0.1:8080".parse().unwrap();
        let addr = SocketAddr::V4(addr_v4);
        assert_eq!(sa_len(&addr), std::mem::size_of::<SocketAddrV4>());
    }

    // #[test]
    // fn sa_len_v6() {
    //     let addr_v6: SocketAddrV6 = "::1:8080".parse().unwrap();
    //     let addr = SocketAddr::V6(addr_v6);
    //     assert_eq!(sa_len(&addr), std::mem::size_of::<SocketAddrV6>());
    // }

    // #[test]
    // fn canonicalise_valid_string() {
    //     // 测试一个有效的字符串
    //     let result = canonicalise("valid-string123");
    //     assert_eq!(result, 1);
    // }

    // #[test]
    // fn canonicalise_string_with_trailing_dot() {
    //     // 测试一个带有末尾点号的字符串
    //     let result = canonicalise("valid-string123.");
    //     assert_eq!(result, 1);
    // }

    // #[test]
    // fn canonicalise_string_with_illegal_character() {
    //     // 测试一个含有非法字符的字符串
    //     let result = canonicalise("invalid string!");
    //     assert_eq!(result, 0);
    // }

    // #[test]
    // fn canonicalise_empty_string() {
    //     // 测试一个空字符串
    //     let result = canonicalise("");
    //     assert_eq!(result, 1);
    // }

    // #[test]
    // fn canonicalise_string_with_multiple_illegal_characters() {
    //     // 测试一个含有多个非法字符的字符串
    //     let result = canonicalise("invalid string!!!");
    //     assert_eq!(result, 0);
    // }

    // #[test]
    // fn canonicalise_string_with_special_characters() {
    //     // 测试一个含有特殊字符但仍然合法的字符串
    //     let result = canonicalise("valid-string_123");
    //     assert_eq!(result, 1);
    // }
}
