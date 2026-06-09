/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use socket2::Socket;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::process;
use std::sync::{Mutex, Once};
use std::time::{SystemTime, UNIX_EPOCH};

const RANDFILE: &str = "/dev/urandom"; // 或根据实际需要修改

// 使用Once确保只初始化一次
static INIT: Once = Once::new();
// 使用Mutex保护RNG的状态
static RNG: Mutex<Option<StdRng>> = Mutex::new(None);

fn init_rng() {
    let mut seed = [0u8; 32]; // 使用32字节种子

    // 尝试从文件读取种子
    if let Ok(mut file) = fs::File::open(RANDFILE) {
        if io::Read::read_exact(&mut file, &mut seed).is_ok() {
            // 成功从文件读取种子
            let rng = StdRng::from_seed(seed);
            *RNG.lock().unwrap() = Some(rng);
            return;
        }
    }

    // 备用种子：时间 + 进程ID
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let badseed = now.as_secs() ^ now.subsec_nanos() as u64 ^ ((process::id() as u64) << 16);

    // 将8字节的badseed转换为32字节的数组
    let mut seed_bytes = [0u8; 32];
    let badseed_bytes = badseed.to_le_bytes();
    seed_bytes[..8].copy_from_slice(&badseed_bytes);

    let rng = StdRng::from_seed(seed_bytes);

    *RNG.lock().unwrap() = Some(rng);
    println!("seed from time/pid: {}", badseed);
}

pub fn rand16() -> u16 {
    INIT.call_once(|| {
        init_rng();
    });

    let mut rng_guard = RNG.lock().unwrap();
    let rng = rng_guard.as_mut().expect("RNG should be initialized");

    // 生成随机数并右移，只保留高16位（去掉最高位）
    let rand_val: u32 = rng.gen();
    (rand_val >> 15) as u16
}

pub fn legal_char(c: char) -> bool {
    if c.is_ascii_alphanumeric() || c == '-' || c == '/' || c == '_' {
        return true;
    }
    false
}
// 检查域名合法性
pub fn canonicalise(s: &str) -> bool {
    // 移除末尾的点号
    let s = s.trim_end_matches('.');

    // 遍历字符串中的每个字符，检查是否合法
    for c in s.chars() {
        // 如果字符不在合法字符范围内，返回 None
        if c != '.' && !legal_char(c) {
            return false;
        }
    }

    true
}

// 判断是否能转换为数字
pub fn is_decimal<T: std::str::FromStr>(s: &str) -> Option<T> {
    match s.parse::<T>() {
        Ok(num) => Some(num),
        Err(_) => None,
    }
}

pub fn is_valid_char(c: char) -> bool {
    c == '.' || c.is_whitespace() || c.is_ascii_digit()
}

// ipv4 & 掩码
pub trait ToIpv4 {
    fn to_ipv4(self) -> Option<Ipv4Addr>;
}

impl ToIpv4 for IpAddr {
    fn to_ipv4(self) -> Option<Ipv4Addr> {
        match self {
            IpAddr::V4(ipv4) => Some(ipv4),
            _ => None,
        }
    }
}

impl ToIpv4 for Ipv4Addr {
    fn to_ipv4(self) -> Option<Ipv4Addr> {
        Some(self)
    }
}

// ipv6 特征
pub trait ToIpv6 {
    fn to_ipv6(self) -> Option<Ipv6Addr>;
}

impl ToIpv6 for IpAddr {
    fn to_ipv6(self) -> Option<Ipv6Addr> {
        match self {
            IpAddr::V6(ipv6) => Some(ipv6),
            _ => None,
        }
    }
}

impl ToIpv6 for Ipv6Addr {
    fn to_ipv6(self) -> Option<Ipv6Addr> {
        Some(self)
    }
}

pub fn ipv4_and_mask<I: ToIpv4>(ip: I, mask: Ipv4Addr) -> Option<IpAddr> {
    if let Some(ipv4) = ip.to_ipv4() {
        let ip_u32 = u32::from(ipv4);
        let mask_u32 = u32::from(mask);
        let result_u32 = ip_u32 & mask_u32;
        Some(IpAddr::V4(Ipv4Addr::from(result_u32)))
    } else {
        None
    }
}

// 判断主机名是否相等
pub fn hostname_isequal(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

// 计算时间差，返回以秒为单位的差值
pub fn difftime(now: SystemTime, ttd: SystemTime) -> i64 {
    match now.duration_since(ttd) {
        Ok(duration) => duration.as_secs() as i64, // 正常情况返回秒数
        Err(_) => -(ttd.duration_since(now).unwrap().as_secs() as i64), // 如果时间倒置，返回负数
    }
}

// 类型转换  SystemTime -> u64
pub fn system_time_to_u64(t: SystemTime) -> Option<u64> {
    t.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}

pub fn socket_is_eq(socket1: &Socket, socket2: &Socket) -> bool {
    if socket1.as_raw_fd() == socket2.as_raw_fd() {
        return true;
    }

    false
}

const NS_INT16SZ: usize = 2;
const NS_INT32SZ: usize = 4;
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

pub fn put_long(l: u32, cp: &mut Vec<u8>) {
    // 将 32 位整数按大端序追加到 `cp` 的末尾
    cp.push((l >> 24) as u8); // 写入高 8 位
    cp.push((l >> 16) as u8); // 写入次高 8 位
    cp.push((l >> 8) as u8); // 写入次低 8 位
    cp.push((l & 0xff) as u8); // 写入低 8 位
}

pub fn put_short(s: u16, cp: &mut Vec<u8>) {
    cp.push((s >> 8) as u8); // 写入次低 8 位
    cp.push((s & 0xff) as u8); // 写入低 8 位
}

// 测试函数
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rand16_distribution() {
        let n_samples = 1000;
        let values: Vec<u16> = (0..n_samples).map(|_| rand16()).collect();

        // 2. 统计唯一值的数量
        let unique_count = values
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        let uniqueness_ratio = unique_count as f64 / n_samples as f64;

        // 期望大多数值是唯一的
        assert!(
            uniqueness_ratio > 0.95,
            "Uniqueness ratio too low: {}/{} = {}",
            unique_count,
            n_samples,
            uniqueness_ratio
        );

        // 3. 验证值不全是0或全是最大值
        let all_zeros = values.iter().all(|&x| x == 0);
        let all_max = values.iter().all(|&x| x == 0xFFFF);
        assert!(!all_zeros && !all_max, "All values are the same");

        // 4. 验证平均分布（粗略检查）
        let mean = values.iter().map(|&x| x as f64).sum::<f64>() / n_samples as f64;
        // 均匀分布的期望均值是 32767.5
        let expected_mean = 32767.5;
        let deviation = (mean - expected_mean).abs() / expected_mean;

        assert!(
            deviation < 0.1, // 允许10%的偏差
            "Mean deviation too large: {} (expected ~{})",
            mean,
            expected_mean
        );
    }

    #[test]
    fn test_get_short_basic() {
        let data = [0x12, 0x34];
        let mut slice = &data[..];
        let result = get_short(&mut slice);
        assert_eq!(result, 0x1234);
        assert_eq!(slice.len(), 0);
    }

    #[test]
    fn test_get_short_multiple_reads() {
        let data = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
        let mut slice = &data[..];

        let first = get_short(&mut slice);
        assert_eq!(first, 0x1234);
        assert_eq!(slice.len(), 4);

        let second = get_short(&mut slice);
        assert_eq!(second, 0x5678);
        assert_eq!(slice.len(), 2);

        let third = get_short(&mut slice);
        assert_eq!(third, 0x9ABC);
        assert_eq!(slice.len(), 0);
    }

    #[test]
    fn test_get_short_endianness() {
        // 测试大端序字节序
        let data = [0x00, 0x01]; // 应该等于 1
        let mut slice = &data[..];
        let result = get_short(&mut slice);
        assert_eq!(result, 1);

        let data = [0x01, 0x00]; // 应该等于 256
        let mut slice = &data[..];
        let result = get_short(&mut slice);
        assert_eq!(result, 256);

        let data = [0xFF, 0xFF]; // 应该等于 65535
        let mut slice = &data[..];
        let result = get_short(&mut slice);
        assert_eq!(result, 65535);
    }

    #[test]
    #[should_panic(expected = "Not enough data to read 16 bits value")]
    fn test_get_short_insufficient_data() {
        let data = [0x12]; // 只有1个字节，不够2个字节
        let mut slice = &data[..];
        get_short(&mut slice);
    }

    #[test]
    #[should_panic(expected = "Not enough data to read 16 bits value")]
    fn test_get_short_empty_slice() {
        let data: [u8; 0] = [];
        let mut slice = &data[..];
        get_short(&mut slice);
    }

    #[test]
    fn test_get_long_basic() {
        let data = [0x12, 0x34, 0x56, 0x78];
        let mut slice = &data[..];
        let result = get_long(&mut slice);
        assert_eq!(result, 0x12345678);
        assert_eq!(slice.len(), 0);
    }

    #[test]
    fn test_get_long_multiple_reads() {
        let data = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let mut slice = &data[..];

        let first = get_long(&mut slice);
        assert_eq!(first, 0x12345678);
        assert_eq!(slice.len(), 4);

        let second = get_long(&mut slice);
        assert_eq!(second, 0x9ABCDEF0);
        assert_eq!(slice.len(), 0);
    }

    #[test]
    fn test_get_long_endianness() {
        // 测试大端序字节序
        let data = [0x00, 0x00, 0x00, 0x01]; // 应该等于 1
        let mut slice = &data[..];
        let result = get_long(&mut slice);
        assert_eq!(result, 1);

        let data = [0x00, 0x00, 0x01, 0x00]; // 应该等于 256
        let mut slice = &data[..];
        let result = get_long(&mut slice);
        assert_eq!(result, 256);

        let data = [0x00, 0x01, 0x00, 0x00]; // 应该等于 65536
        let mut slice = &data[..];
        let result = get_long(&mut slice);
        assert_eq!(result, 65536);

        let data = [0x01, 0x00, 0x00, 0x00]; // 应该等于 16777216
        let mut slice = &data[..];
        let result = get_long(&mut slice);
        assert_eq!(result, 16777216);

        let data = [0xFF, 0xFF, 0xFF, 0xFF]; // 应该等于 4294967295
        let mut slice = &data[..];
        let result = get_long(&mut slice);
        assert_eq!(result, 4294967295);
    }

    #[test]
    #[should_panic(expected = "Not enough data to read 32 bits value")]
    fn test_get_long_insufficient_data() {
        let data = [0x12, 0x34, 0x56]; // 只有3个字节，不够4个字节
        let mut slice = &data[..];
        get_long(&mut slice);
    }

    #[test]
    #[should_panic(expected = "Not enough data to read 32 bits value")]
    fn test_get_long_empty_slice() {
        let data: [u8; 0] = [];
        let mut slice = &data[..];
        get_long(&mut slice);
    }

    #[test]
    fn test_get_short_and_get_long_mixed() {
        let data = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
        let mut slice = &data[..];

        // 先读一个short
        let short = get_short(&mut slice);
        assert_eq!(short, 0x1234);
        assert_eq!(slice.len(), 4);

        // 再读一个long
        let long = get_long(&mut slice);
        assert_eq!(long, 0x56789ABC);
        assert_eq!(slice.len(), 0);
    }

    #[test]
    fn test_get_short_boundary_values() {
        // 测试边界值
        let data = [0x00, 0x00]; // 最小值
        let mut slice = &data[..];
        assert_eq!(get_short(&mut slice), 0);

        let data = [0xFF, 0xFF]; // 最大值
        let mut slice = &data[..];
        assert_eq!(get_short(&mut slice), 65535);
    }

    #[test]
    fn test_get_long_boundary_values() {
        // 测试边界值
        let data = [0x00, 0x00, 0x00, 0x00]; // 最小值
        let mut slice = &data[..];
        assert_eq!(get_long(&mut slice), 0);

        let data = [0xFF, 0xFF, 0xFF, 0xFF]; // 最大值
        let mut slice = &data[..];
        assert_eq!(get_long(&mut slice), 4294967295);
    }

    #[test]
    fn test_put_short_basic() {
        let mut buffer = Vec::new();
        put_short(0x1234, &mut buffer);
        assert_eq!(buffer, [0x12, 0x34]);
    }

    #[test]
    fn test_put_short_multiple_writes() {
        let mut buffer = Vec::new();
        put_short(0x1234, &mut buffer);
        put_short(0x5678, &mut buffer);
        put_short(0x9ABC, &mut buffer);
        assert_eq!(buffer, [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]);
    }

    #[test]
    fn test_put_short_endianness() {
        let mut buffer = Vec::new();

        // 测试最小值
        put_short(0, &mut buffer);
        assert_eq!(buffer, [0x00, 0x00]);
        buffer.clear();

        // 测试中间值
        put_short(1, &mut buffer);
        assert_eq!(buffer, [0x00, 0x01]);
        buffer.clear();

        // 测试256 (0x0100)
        put_short(256, &mut buffer);
        assert_eq!(buffer, [0x01, 0x00]);
        buffer.clear();

        // 测试最大值
        put_short(65535, &mut buffer);
        assert_eq!(buffer, [0xFF, 0xFF]);
    }

    #[test]
    fn test_put_short_boundary_values() {
        let mut buffer = Vec::new();

        // 测试边界值
        put_short(0, &mut buffer); // 最小值
        put_short(32767, &mut buffer); // 中间值
        put_short(65535, &mut buffer); // 最大值

        assert_eq!(buffer, [0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_put_long_basic() {
        let mut buffer = Vec::new();
        put_long(0x12345678, &mut buffer);
        assert_eq!(buffer, [0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_put_long_multiple_writes() {
        let mut buffer = Vec::new();
        put_long(0x12345678, &mut buffer);
        put_long(0x9ABCDEF0, &mut buffer);
        assert_eq!(buffer, [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]);
    }

    #[test]
    fn test_put_long_endianness() {
        let mut buffer = Vec::new();

        // 测试最小值
        put_long(0, &mut buffer);
        assert_eq!(buffer, [0x00, 0x00, 0x00, 0x00]);
        buffer.clear();

        // 测试1
        put_long(1, &mut buffer);
        assert_eq!(buffer, [0x00, 0x00, 0x00, 0x01]);
        buffer.clear();

        // 测试256 (0x00000100)
        put_long(256, &mut buffer);
        assert_eq!(buffer, [0x00, 0x00, 0x01, 0x00]);
        buffer.clear();

        // 测试65536 (0x00010000)
        put_long(65536, &mut buffer);
        assert_eq!(buffer, [0x00, 0x01, 0x00, 0x00]);
        buffer.clear();

        // 测试16777216 (0x01000000)
        put_long(16777216, &mut buffer);
        assert_eq!(buffer, [0x01, 0x00, 0x00, 0x00]);
        buffer.clear();

        // 测试最大值
        put_long(4294967295, &mut buffer);
        assert_eq!(buffer, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_put_long_boundary_values() {
        let mut buffer = Vec::new();

        // 测试边界值
        put_long(0, &mut buffer); // 最小值
        put_long(2147483647, &mut buffer); // 中间值 (2^31-1)
        put_long(4294967295, &mut buffer); // 最大值

        assert_eq!(
            buffer,
            [
                0x00, 0x00, 0x00, 0x00, // 0
                0x7F, 0xFF, 0xFF, 0xFF, // 2147483647
                0xFF, 0xFF, 0xFF, 0xFF // 4294967295
            ]
        );
    }

    #[test]
    fn test_put_short_and_put_long_mixed() {
        let mut buffer = Vec::new();

        // 混合写入short和long
        put_short(0x1234, &mut buffer);
        put_long(0x56789ABC, &mut buffer);
        put_short(0xDEF0, &mut buffer);

        assert_eq!(
            buffer,
            [
                0x12, 0x34, // 0x1234
                0x56, 0x78, 0x9A, 0xBC, // 0x56789ABC
                0xDE, 0xF0 // 0xDEF0
            ]
        );
    }

    #[test]
    fn test_put_and_get_roundtrip() {
        // 测试put_short和get_short的往返
        let mut buffer = Vec::new();
        put_short(0x1234, &mut buffer);
        let mut slice = &buffer[..];
        let result = get_short(&mut slice);
        assert_eq!(result, 0x1234);
        assert_eq!(slice.len(), 0);

        // 测试put_long和get_long的往返
        buffer.clear();
        put_long(0x56789ABC, &mut buffer);
        let mut slice = &buffer[..];
        let result = get_long(&mut slice);
        assert_eq!(result, 0x56789ABC);
        assert_eq!(slice.len(), 0);

        // 测试混合往返
        buffer.clear();
        put_short(0x1234, &mut buffer);
        put_long(0x56789ABC, &mut buffer);
        put_short(0xDEF0, &mut buffer);

        let mut slice = &buffer[..];
        let short1 = get_short(&mut slice);
        let long = get_long(&mut slice);
        let short2 = get_short(&mut slice);

        assert_eq!(short1, 0x1234);
        assert_eq!(long, 0x56789ABC);
        assert_eq!(short2, 0xDEF0);
        assert_eq!(slice.len(), 0);
    }

    #[test]
    fn test_to_ipv6_trait() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        // 测试IpAddr::V6
        let ipv6_addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let ip_addr = IpAddr::V6(ipv6_addr);
        assert_eq!(ip_addr.to_ipv6(), Some(ipv6_addr));

        // 测试IpAddr::V4 (应该返回None)
        let ipv4_addr = Ipv4Addr::new(192, 168, 1, 1);
        let ip_addr = IpAddr::V4(ipv4_addr);
        assert_eq!(ip_addr.to_ipv6(), None);

        // 测试Ipv6Addr直接调用to_ipv6
        let ipv6_addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        assert_eq!(ipv6_addr.to_ipv6(), Some(ipv6_addr));

        // 测试IPv6环回地址
        let loopback_ipv6 = Ipv6Addr::LOCALHOST;
        let ip_addr = IpAddr::V6(loopback_ipv6);
        assert_eq!(ip_addr.to_ipv6(), Some(loopback_ipv6));

        // 测试IPv4映射的IPv6地址
        let ipv4_mapped = Ipv4Addr::new(192, 168, 1, 1).to_ipv6_mapped();
        let ip_addr = IpAddr::V6(ipv4_mapped);
        assert_eq!(ip_addr.to_ipv6(), Some(ipv4_mapped));
    }

    #[test]
    fn test_to_ipv4_trait() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        // 测试IpAddr::V4
        let ipv4_addr = Ipv4Addr::new(192, 168, 1, 1);
        let ip_addr = IpAddr::V4(ipv4_addr);
        assert_eq!(ip_addr.to_ipv4(), Some(ipv4_addr));

        // 测试IpAddr::V6 (应该返回None)
        let ipv6_addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let ip_addr = IpAddr::V6(ipv6_addr);
        assert_eq!(ip_addr.to_ipv4(), None);

        // 测试Ipv4Addr直接调用to_ipv4
        let ipv4_addr = Ipv4Addr::new(192, 168, 1, 1);
        assert_eq!(ipv4_addr.to_ipv4(), Some(ipv4_addr));
    }
}
