/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

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

pub fn canonicalise(s: &str) -> i32 {
    // 移除末尾的点号
    let s = s.trim_end_matches('.');

    // 遍历字符串中的每个字符，检查是否合法
    for c in s.chars() {
        // 如果字符不在合法字符范围内，返回 0
        if !(c.is_ascii_alphanumeric() || c == '-' || c == '/' || c == '_') {
            return 0;
        }
    }

    1
}

pub fn safe_string_alloc(cp: &str) -> *mut i8 {
    // 检查输入字符串是否有效且非空
    if cp.is_empty() {
        return ptr::null_mut(); // 返回空指针
    }

    // 分配与输入字符串长度匹配的内存，并将字符串复制到新分配的内存中
    let c_string = CString::new(cp).unwrap(); // 将Rust字符串转换为C风格字符串
    let c_ptr = c_string.into_raw(); // 获取指向分配内存的指针

    // 返回该内存地址
    c_ptr
}

pub fn sockaddr_isequal(addr1: &SocketAddr, addr2: &SocketAddr) -> i32 {
    match (addr1, addr2) {
        // 如果都是 IPv4 地址
        (SocketAddr::V4(v4_1), SocketAddr::V4(v4_2)) => {
            if v4_1.ip() == v4_2.ip() && v4_1.port() == v4_2.port() {
                1 // IPv4 地址相同
            } else {
                0 // IPv4 地址不相同
            }
        }
        // 如果都是 IPv6 地址
        (SocketAddr::V6(v6_1), SocketAddr::V6(v6_2)) => {
            if v6_1.ip() == v6_2.ip()
                && v6_1.port() == v6_2.port()
                && v6_1.flowinfo() == v6_2.flowinfo()
                && v6_1.scope_id() == v6_2.scope_id()
            {
                1 // IPv6 地址相同
            } else {
                0 // IPv6 地址不相同
            }
        }
        // 地址类型不同
        _ => 0,
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

pub fn hostname_isequal(s1: &str, s2: &str) -> i32 {
    // 检查字符串的长度是否相同
    if s1.len() != s2.len() {
        return 0;
    }

    if s1.to_lowercase() != s2.to_lowercase() {
        return 0; // 发现字符不相等，返回0
    }

    // 如果所有字符都相同，返回1
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_hostname_isequal() {
        assert_eq!(hostname_isequal("Rust", "rust"), 1);
        assert_eq!(hostname_isequal("Rust", "Rust"), 1);
        assert_eq!(hostname_isequal("Rust", "rusty"), 0);
        assert_eq!(hostname_isequal("Rust", "Ru"), 0);
        assert_eq!(hostname_isequal("Rust", "r"), 0);
        assert_eq!(hostname_isequal("R", "r"), 1);
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

    #[test]
    fn canonicalise_valid_string() {
        // 测试一个有效的字符串
        let result = canonicalise("valid-string123");
        assert_eq!(result, 1);
    }

    #[test]
    fn canonicalise_string_with_trailing_dot() {
        // 测试一个带有末尾点号的字符串
        let result = canonicalise("valid-string123.");
        assert_eq!(result, 1);
    }

    #[test]
    fn canonicalise_string_with_illegal_character() {
        // 测试一个含有非法字符的字符串
        let result = canonicalise("invalid string!");
        assert_eq!(result, 0);
    }

    #[test]
    fn canonicalise_empty_string() {
        // 测试一个空字符串
        let result = canonicalise("");
        assert_eq!(result, 1);
    }

    #[test]
    fn canonicalise_string_with_multiple_illegal_characters() {
        // 测试一个含有多个非法字符的字符串
        let result = canonicalise("invalid string!!!");
        assert_eq!(result, 0);
    }

    #[test]
    fn canonicalise_string_with_special_characters() {
        // 测试一个含有特殊字符但仍然合法的字符串
        let result = canonicalise("valid-string_123");
        assert_eq!(result, 1);
    }
}
