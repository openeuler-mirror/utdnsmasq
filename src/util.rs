use libc::{malloc, sockaddr, sockaddr_in, sockaddr_in6, AF_INET, AF_INET6};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::ffi::CString;
use std::fs;
use std::io::Read;
use std::mem;
use std::net::SocketAddr;
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

pub unsafe fn safe_string_alloc(cp: *const i8) -> *mut i8 {
    // 检查输入是否为 NULL（空指针）
    if cp.is_null() {
        return ptr::null_mut();
    }

    // 将输入指针转换为 &str
    let c_str = CString::from_raw(cp as *mut i8);

    // 检查字符串是否非空
    if c_str.to_str().unwrap().is_empty() {
        return ptr::null_mut();
    }

    // 分配与输入字符串长度匹配的内存
    let len = c_str.as_bytes().len();
    let new_mem = malloc(len + 1) as *mut i8;

    // 检查内存分配是否成功
    if new_mem.is_null() {
        return ptr::null_mut();
    }

    // 将 cp 复制到新分配的内存中
    ptr::copy_nonoverlapping(cp, new_mem, len);
    *new_mem.add(len) = 0;

    // 返回新字符串的指针
    new_mem
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

pub unsafe fn sa_len(addr: *const sockaddr) -> usize {
    // 获取地址类型
    let addr_family = (*addr).sa_family as i32;

    // 检查地址类型
    match addr_family {
        AF_INET6 => mem::size_of::<sockaddr_in6>(), // 如果是IPv6地址，返回IPv6结构大小
        AF_INET => mem::size_of::<sockaddr_in>(),   // 如果是IPv4地址，返回IPv4结构大小
        _ => mem::size_of::<sockaddr_in>(),         // 默认返回IPv4地址结构大小
    }
}

pub fn hostname_isequal(s1: &str, s2: &str) -> i32 {
    // 检查字符串的长度是否相同
    if s1.len() != s2.len() {
        return 0;
    }

    // 逐字符比较两个字符串
    for (c1, c2) in s1.chars().zip(s2.chars()) {
        // 将大写字母转换为小写字母后进行比较
        if c1.to_ascii_lowercase() != c2.to_ascii_lowercase() {
            return 0; // 发现字符不相等，返回0
        }
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
    fn sa_len_ipv4() {
        let mut sockaddr: sockaddr = unsafe { mem::zeroed() };
        sockaddr.sa_family = AF_INET as u16;

        let len = unsafe { sa_len(&sockaddr as *const sockaddr) };
        assert_eq!(len, mem::size_of::<sockaddr_in>());
    }

    #[test]
    fn sa_len_ipv6() {
        let mut sockaddr: sockaddr = unsafe { mem::zeroed() };
        sockaddr.sa_family = AF_INET6 as u16;

        let len = unsafe { sa_len(&sockaddr as *const sockaddr) };
        assert_eq!(len, mem::size_of::<sockaddr_in6>());
    }

    #[test]
    fn sa_len_unknown_family() {
        let mut sockaddr: sockaddr = unsafe { mem::zeroed() };
        sockaddr.sa_family = 0xFFFF; // 一个未知的地址

        let len = unsafe { sa_len(&sockaddr as *const sockaddr) };
        assert_eq!(len, mem::size_of::<sockaddr_in>());
    }

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
