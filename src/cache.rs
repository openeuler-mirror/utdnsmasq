/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use crate::util::*;
use crate::*;
use std::fs::File;
use std::io::{self, BufRead};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr::null_mut;
use std::str;
use std::time::Duration;
use std::time::SystemTime;

const MAXDNAME: usize = 1025;
const SMALLDNAME: usize = 40;
const OPT_NO_HOSTS: u32 = 2;
const HOSTSFILE: &str = "/etc/hosts";
const F_ADDN: u32 = 1;
pub const F_HOSTS: u32 = 64;
pub const F_DHCP: u32 = 16;
pub const F_BIGNAME: u32 = 512;
pub const F_IMMORTAL: u32 = 128;
pub const F_FORWARD: u32 = 256;
const F_REVERSE: u32 = 512;
pub const F_IPV4: u32 = 4;
pub const F_IPV6: u32 = 6;
const OPT_EXPAND: u32 = 1;
pub const F_NEG: u32 = 32;
pub const INADDRSZ: usize = 4;
pub const IN6ADDRSZ: usize = 16;
const F_CONFIG: u32 = 0x10;
const F_UPSTREAM: u32 = 0x40;
pub const F_NXDOMAIN: u32 = 0x08;
const F_SERVER: u32 = 0x80;
const F_QUERY: u32 = 0x100;
static mut INSERT_ERROR: bool = false;
static mut ADDN_FILE: Option<String> = None;

#[derive(Debug, Clone, PartialEq)]
pub enum AllAddr {
    Addr4(Ipv4Addr),
    Addr6(Ipv6Addr),
}

// 定义 Bigname 结构体
#[derive(Clone, Debug, PartialEq)]
pub struct BigName {
    pub name: [char; MAXDNAME],     // 示例大名称
    pub next: Option<Box<BigName>>, // 自由列表
}

#[derive(Debug, Clone, PartialEq)]
pub enum Name {
    Sname([char; SMALLDNAME]),
    Bname(Box<BigName>),
    Namep(Box<String>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Crec {
    pub next: Option<*mut Crec>,
    pub prev: Option<*mut Crec>,
    pub hash_next: Option<*mut Crec>,
    pub ttd: SystemTime,
    pub addr: AllAddr,
    pub flags: u32,
    pub name: Name,
}

#[derive(Debug)]
pub struct Cache {
    pub cache_size: usize,
    pub cache_head: Option<*mut Crec>,
    pub cache_tail: Option<*mut Crec>,
    pub dhcp_inuse: Option<*mut Crec>,
    pub dhcp_spare: Option<*mut Crec>,
    pub new_chain: Option<*mut Crec>,
    pub big_free: Option<Box<BigName>>,
    pub bignames_left: usize,
    pub log_queries: u32,
    pub cache_inserted: usize,
    pub cache_live_freed: usize,
    pub hash_table: Vec<Option<*mut Crec>>,
    pub hash_size: usize,
}

impl Cache {
    pub fn new(size: usize, logq: u32) -> Self {
        let mut cache = Cache {
            cache_size: size,
            cache_head: None,
            cache_tail: None,
            dhcp_inuse: None,
            dhcp_spare: None,
            new_chain: None,
            big_free: None,
            bignames_left: size / 10,
            log_queries: logq,
            cache_inserted: 0,
            cache_live_freed: 0,
            hash_table: Vec::new(),
            hash_size: 64,
        };

        // 预分配缓存记录
        if cache.cache_size > 0 {
            let mut crec_vec = Vec::with_capacity(size);
            for _ in 0..size {
                let mut crec = Box::new(Crec {
                    next: None,
                    prev: None,
                    hash_next: None,
                    ttd: SystemTime::now(),
                    addr: AllAddr::Addr4("0.0.0.0".parse().unwrap()),
                    flags: 0,
                    name: Name::Sname(['\0'; SMALLDNAME]),
                });

                cache.cache_link(&mut crec);
                crec.flags = 0;
                crec_vec.push(Box::into_raw(crec));
            }
        }

        // 调整哈希表大小：确保哈希表的大小至少为缓存大小的 1/10，并且是 2 的幂次
        while cache.hash_size < cache.cache_size / 10 {
            cache.hash_size <<= 1;
        }
        // 初始化哈希表
        cache.hash_table = vec![None; cache.hash_size];
        cache
    }

    fn cache_link(&mut self, crec: &mut Crec) {
        // 将一个 Crec 结构体实例插入到双向链表的头部，并更新链表的头尾指针
        crec.next = self.cache_head;
        if let Some(head) = self.cache_head {
            unsafe {
                (*head).prev = Some(crec);
            }
        }
        self.cache_head = Some(crec);
        if self.cache_tail.is_none() {
            self.cache_tail = Some(crec);
        }
    }
    fn cache_unlink(&mut self, crec: *mut Crec) {
        // 从双向链表中移除一个节点
        unsafe {
            // 如果有前驱节点，更新前驱节点的 next 指针
            if let Some(prev) = (*crec).prev {
                (*prev).next = (*crec).next;
            } else {
                // 如果没有前驱节点，说明这是链表头
                self.cache_head = (*crec).next;
            }

            // 如果有后继节点，更新后继节点的 prev 指针
            if let Some(next) = (*crec).next {
                (*next).prev = (*crec).prev;
            } else {
                // 如果没有后继节点，说明这是链表尾
                self.cache_tail = (*crec).prev;
            }

            // 清除当前节点的前驱和后继指针
            (*crec).next = None;
            (*crec).prev = None;
        }
    }
}

// 缓存重新加载
pub fn cache_reload(
    caches: &mut Cache,
    opts: u32,
    mut buff: &mut Vec<u8>,
    mut domain_suffix: &mut Option<String>,
    addn_hosts: Option<String>,
) {
    // 清除缓存逻辑
    for i in 0..caches.hash_size {
        let up: Option<*mut Crec> = caches.hash_table[i];
        let mut current: Option<*mut Crec> = up;

        while let Some(cache_ptr) = current {
            // 安全解引用指针
            let cache = unsafe { &mut *cache_ptr };

            current = cache.hash_next; // 保存下一个元素

            // 处理 F_HOSTS 标志
            if cache.flags & F_HOSTS != 0 {
                // 移除 F_HOSTS 标志的项
                cache.hash_next; // 移除当前元素
                unsafe {
                    let _ = Box::from_raw(cache_ptr);
                } // 释放当前缓存项
            } else if cache.flags & F_DHCP == 0 {
                // 不是 DHCP 项，重置标志
                cache.hash_next; // 继续移除
                if cache.flags & F_BIGNAME != 0 {
                    // 处理 BIGNAME 逻辑
                    if let Name::Bname(ref mut bname) = cache.name {
                        bname.next = caches.big_free.clone(); // 假设 big_free 是全局变量
                        caches.big_free = Some(bname.clone()); // 更新 big_free
                    }
                }
                cache.flags = 0; // 清除标志
            } else {
                cache.hash_next; // 更新指针
            }
        }
    }

    // 如果有 OPT_NO_HOSTS 选项且没有附加 hosts 文件
    if (opts & OPT_NO_HOSTS != 0) && addn_hosts.is_none() {
        if caches.cache_size > 0 {
            complain("Cleared cache", "");
        }
        return;
    }

    // 处理主 hosts 文件
    if opts & OPT_NO_HOSTS == 0 {
        if let Err(err) = read_hostsfile(caches, HOSTSFILE, opts, &mut buff, &mut domain_suffix, 0)
        {
            complain("Error reading hosts file: {}", &err.to_string());
        }
    }

    // 处理附加 hosts 文件
    if let Some(addn_hosts) = addn_hosts {
        if let Err(err) = read_hostsfile(
            caches,
            &addn_hosts,
            opts,
            &mut buff,
            &mut domain_suffix,
            F_ADDN.try_into().unwrap(),
        ) {
            complain("Error reading additional hosts file: {}", &err.to_string());
        }
        unsafe { ADDN_FILE = Some(addn_hosts) };
    }
}

// 读取主机文件（如 /etc/hosts），并解析其中的内容
fn read_hostsfile(
    caches: &mut Cache,
    filename: &str,
    opts: u32,
    buff: &mut Vec<u8>,
    _domain_suffix: &mut Option<String>,
    addn_flag: u16,
) -> io::Result<()> {
    let file = File::open(filename)?;
    let reader = io::BufReader::new(file);
    let mut count = 0;
    let mut lineno = 0;

    for line in reader.lines() {
        let line = line?;
        lineno += 1;

        // 将当前行内容转换为字节并推送到缓冲区
        buff.clear();
        buff.extend_from_slice(line.as_bytes());

        // 使用空白字符分割行并获取第一个 token
        let mut tokens = line.split_whitespace();
        let first_token = tokens.next();

        if let Some(token) = first_token {
            if token.starts_with('#') {
                continue;
            }

            // 尝试解析 IP 地址
            let addr = if let Ok(ipv4) = token.parse::<Ipv4Addr>() {
                Some(AllAddr::Addr4(ipv4))
            } else if let Ok(ipv6) = token.parse::<Ipv6Addr>() {
                Some(AllAddr::Addr6(ipv6))
            } else {
                None
            };

            if let Some(addr) = addr {
                let mut flags = F_HOSTS | F_IMMORTAL | F_FORWARD | F_REVERSE;
                let addrlen = match addr {
                    AllAddr::Addr4(_) => {
                        flags |= F_IPV4;
                        std::mem::size_of::<Ipv4Addr>()
                    }
                    AllAddr::Addr6(_) => {
                        flags |= F_IPV6;
                        std::mem::size_of::<Ipv6Addr>()
                    }
                };

                // 遍历其他 token
                for token in tokens {
                    if token.starts_with('#') {
                        break;
                    }

                    if let Some(canonical_name) = canonicalise(token) {
                        count += 1;
                        let name_field = if canonical_name.len() < SMALLDNAME {
                            // 使用小名称数组
                            let mut sname = ['\0'; SMALLDNAME];
                            for (i, c) in canonical_name.chars().enumerate() {
                                sname[i] = c;
                            }
                            Name::Sname(sname)
                        } else {
                            // 使用动态分配的字符串
                            Name::Namep(Box::new(canonical_name.clone()))
                        };

                        // 如果需要扩展名称，添加带默认域名的版本
                        if (opts & OPT_EXPAND != 0) && !canonical_name.contains('.') {
                            let mut cache = Crec {
                                next: None,
                                prev: None,
                                hash_next: None,
                                ttd: SystemTime::now(),
                                addr: addr.clone(),
                                flags: flags | addn_flag as u32,
                                name: name_field.clone(),
                            };
                            add_hosts_entry(
                                caches,
                                &mut cache,
                                &addr,
                                addrlen,
                                flags | addn_flag as u32,
                            );
                            flags &= !F_REVERSE;
                        }

                        let mut cache = Crec {
                            next: None,
                            prev: None,
                            hash_next: None,
                            ttd: SystemTime::now(),
                            addr: addr.clone(),
                            flags: flags | addn_flag as u32,
                            name: name_field,
                        };
                        add_hosts_entry(
                            caches,
                            &mut cache,
                            &addr,
                            addrlen,
                            flags | addn_flag as u32,
                        );
                        flags &= !F_REVERSE;
                    } else {
                        // 处理无效的名称
                        eprintln!("Invalid name at {} line {}", filename, lineno);
                    }
                }
            }
        }
    }

    println!("Read {} - {} addresses", filename, count);
    Ok(())
}

// 计算时间差，返回以秒为单位的差值
pub fn difftime(now: SystemTime, ttd: SystemTime) -> i64 {
    match now.duration_since(ttd) {
        Ok(duration) => duration.as_secs() as i64, // 正常情况返回秒数
        Err(_) => -(ttd.duration_since(now).unwrap().as_secs() as i64), // 如果时间倒置，返回负数
    }
}

// 计算字符串的哈希值
pub fn hash_bucket<'a>(name: &'a str, cache: &'a mut Cache) -> &'a mut Option<*mut Crec> {
    let mut val: u32 = 0;

    // 计算哈希值
    for c in name.bytes() {
        val += if (b'A'..=b'Z').contains(&c) {
            c + (b'a' - b'A') as u8
        } else {
            c
        } as u32;
    }

    // 通过哈希值获取哈希桶索引
    let index = (val & (cache.hash_size as u32 - 1)) as usize;

    // 返回哈希表中的桶
    &mut cache.hash_table[index]
}

// 将一个 Crec 结构体指针插入到缓存的哈希表中
pub fn cache_hash(cache: &mut Cache, crecp: Option<*mut Crec>) {
    if let Some(crecp_ptr) = crecp {
        // 如果 crecp 是 Some，则继续处理
        let name = cache_get_name(Some(crecp_ptr));
        let bucket = hash_bucket(&name, cache);

        unsafe {
            // 将 crecp_ptr 插入到哈希桶链表的头部
            (*crecp_ptr).hash_next = bucket.clone(); // 从 bucket 中取出原有值，赋给 hash_next
            *bucket = Some(crecp_ptr); // 将 crecp_ptr 设置为 bucket 的新值
        }
    }
    // 如果 crecp 是 None，什么都不做
}

// 处理Crec结构体，返回相关字段
pub fn cache_get_name(crecp: Option<*mut Crec>) -> String {
    if let Some(crecp_ptr) = crecp {
        unsafe {
            // 解引用指针并检查 flags 以决定返回哪种名称
            let crec = &*crecp_ptr;
            match &crec.name {
                Name::Bname(bname) if crec.flags & F_BIGNAME != 0 => {
                    // 将字符数组转换为字符串
                    bname
                        .name
                        .iter()
                        .collect::<String>()
                        .trim_end_matches('\0')
                        .to_string()
                }
                Name::Namep(namep) if crec.flags & F_DHCP != 0 => *namep.clone(),
                Name::Sname(sname) => {
                    // 将字符数组转换为字符串
                    sname
                        .iter()
                        .collect::<String>()
                        .trim_end_matches('\0')
                        .to_string()
                }
                _ => String::new(),
            }
        }
    } else {
        // 如果 crecp 是 None，则返回空字符串
        String::new()
    }
}

// 根据名称查找缓存记录
pub fn cache_find_by_name(
    cache: &mut Cache,
    crecp: Option<*mut Crec>,
    name: &str,
    now: SystemTime,
    prot: u32,
) -> Option<*mut Crec> {
    let mut ans: Option<*mut Crec> = None;

    if let Some(crecp_ptr) = crecp {
        // 如果 crecp 不为 None，直接返回 crecp 的 next 项
        unsafe {
            ans = (*crecp_ptr).next;
        }
    } else {
        // 第一次查找：遍历哈希链表
        let mut chainp = &mut ans;
        let mut insert: Option<*mut Crec> = None;

        // 遍历链表的所有节点
        let mut current_opt = cache.cache_head;
        while let Some(current_ptr) = current_opt {
            let current = unsafe { &mut *current_ptr };

            // 检查是否过期
            if (current.flags & F_IMMORTAL != 0) || difftime(now, current.ttd) < 0 {
                if (current.flags & F_FORWARD != 0)
                    && (current.flags & prot != 0)
                    && hostname_isequal(&cache_get_name(Some(current)), name)
                {
                    if current.flags & (F_HOSTS | F_DHCP) != 0 {
                        *chainp = Some(current_ptr);
                        chainp = unsafe { &mut (*current_ptr).next };
                    } else {
                        // 将当前节点移到链表头部
                        Cache::cache_unlink(cache, current_ptr);
                        Cache::cache_link(cache, unsafe { &mut *Box::from_raw(current_ptr) });
                    }

                    // 实现轮循：将匹配的节点移动到链表顶部
                    if insert.is_none() {
                        insert = Some(current_ptr);
                    } else {
                        // 分离 `next` 的取值和赋值操作
                        let next_ptr = unsafe { (*current_ptr).next.clone() };
                        unsafe {
                            (*current_ptr).next = insert; // 更新 `current.next`
                        }
                        insert = Some(current_ptr);
                        current_opt = next_ptr; // 更新循环控制变量
                        continue;
                    }
                } else {
                    // 继续遍历下一个节点
                    current_opt = unsafe { (*current_ptr).next };
                    continue;
                }
            } else {
                // 条目过期，从链表中移除
                Cache::cache_unlink(cache, current_ptr);
                current_opt = unsafe { (*current_ptr).next };
                continue;
            }
        }
    }

    if let Some(ans_ptr) = ans {
        let ans_ref = unsafe { &mut *ans_ptr };
        if (ans_ref.flags & F_FORWARD != 0)
            && (ans_ref.flags & prot != 0)
            && hostname_isequal(&cache_get_name(Some(ans_ref)), name)
        {
            return Some(ans_ptr);
        }
    }

    None
}

// 根据地址查找缓存中的条目
pub fn cache_find_by_addr(
    cache: &mut Cache,
    crecp: Option<*mut Crec>,
    addr: &AllAddr,
    now: SystemTime,
    prot: u32,
) -> Option<*mut Crec> {
    let _addrlen = if prot == F_IPV6 { IN6ADDRSZ } else { INADDRSZ };

    // 定义一个可选的结果
    let mut ans: Option<*mut Crec>;

    // 如果在迭代中
    if let Some(current_crec_ptr) = crecp {
        ans = unsafe { (*current_crec_ptr).next }; // 获取下一个条目
    } else {
        // 第一次查找，遍历哈希表
        ans = None; // 初始化答案

        for i in 0..cache.hash_size {
            let mut current_ptr = cache.hash_table[i]; // 获取当前哈希桶的条目

            while let Some(current_crec_ptr) = current_ptr {
                let current = unsafe { &mut *current_crec_ptr }; // 解引用裸指针

                // 检查条目是否过期
                if (current.flags & F_IMMORTAL != 0)
                    || now
                        .duration_since(current.ttd)
                        .unwrap_or(Duration::new(0, 0))
                        .as_secs()
                        > 0
                {
                    // 条目过期，移除
                    current_ptr = current.hash_next; // 更新链表指针
                                                     // 在这里实现解绑和释放逻辑
                    Cache::cache_unlink(cache, current_crec_ptr);
                    unsafe { cache_free(cache, current_crec_ptr) };
                } else {
                    // 检查反向标志和地址匹配
                    if (current.flags & F_REVERSE != 0)
                        && (current.flags & prot != 0)
                        && current.addr == *addr
                    {
                        // 有效条目
                        ans = Some(current_crec_ptr); // 找到条目，保存结果
                    }
                    current_ptr = current.hash_next; // 更新链表指针
                }
            }
        }
    }

    // 最后检查返回的答案
    if let Some(ans_ptr) = ans {
        let ans_ref = unsafe { &mut *ans_ptr };
        if (ans_ref.flags & F_REVERSE != 0) && (ans_ref.flags & prot != 0) && &ans_ref.addr == addr
        {
            return Some(ans_ptr);
        }
    }

    None
}

// 将一个缓存条目 crecp 释放并重新插入到缓存链表中
pub unsafe fn cache_free(cache: &mut Cache, crecp: *mut Crec) {
    // 将 crecp 转换为可变引用
    let crecp_ref = &mut *crecp;

    // 清除转发和反向标志
    crecp_ref.flags &= !F_FORWARD;
    crecp_ref.flags &= !F_REVERSE;

    // 将条目添加到缓存尾部
    if let Some(tail_ptr) = cache.cache_tail {
        let tail_ref = &mut *tail_ptr; // 解引用尾部
        tail_ref.next = Some(crecp); // 设置当前条目为新的下一个
    } else {
        cache.cache_head = Some(crecp); // 如果缓存为空，将其设为头部
    }

    crecp_ref.prev = cache.cache_tail; // 将前驱设置为当前尾部
    crecp_ref.next = Some(null_mut()); // 设置下一个为 null
    cache.cache_tail = Some(crecp); // 更新尾部为当前条目

    // 处理大名称的存储
    if crecp_ref.flags & F_BIGNAME != 0 {
        if let Name::Bname(ref mut big_name) = crecp_ref.name {
            big_name.next = cache.big_free.clone(); // 取出现有的空闲大名称
            cache.big_free = Some(big_name.clone()); // 将当前的 big_name 赋值给空闲列表
            crecp_ref.flags &= !F_BIGNAME; // 清除大名称标志
        }
    }
}

// 缓存中添加主机条目
pub fn add_hosts_entry(
    caches: &mut Cache,
    cache: &mut Crec,
    addr: &AllAddr,
    addrlen: usize,
    flags: u32,
) {
    let _ = addrlen;

    // 获取名称键值
    let name_key = match &cache.name {
        Name::Sname(chars) => chars.iter().collect::<String>(),
        Name::Namep(boxed_name) => *boxed_name.clone(),
        Name::Bname(bname) => bname.name.iter().collect::<String>(),
    };

    // 查找是否存在重复项
    if let Some(lookup) = cache_find_by_name(
        caches,
        None,
        &name_key,
        SystemTime::now(),
        flags & (F_IPV4 | F_IPV6),
    ) {
        // 使用 `unsafe` 解引用并借用字段，而不是移动
        unsafe {
            if (*lookup).flags & F_HOSTS != 0 && addr == &(*lookup).addr {
                // 如果找到匹配的条目，则直接返回
                return;
            }
        }
    }

    // 设置标志和地址
    cache.flags = flags;
    cache.addr = addr.clone();

    // 添加到缓存中
    cache_hash(caches, Some(cache));
}

// 向缓存中添加新的条目
pub fn cache_add_dhcp_entry(
    host_name: &str,
    host_address: InAddr,
    ttd: u64,
    flags: u32,
    caches: &mut Cache,
) {
    unsafe {
        // 查找已存在的条目
        if let Some(crecp) = cache_find_by_name(caches, None, host_name, SystemTime::now(), F_IPV4)
        {
            // 如果找到相同主机名的 DHCP 条目
            if let Some(crec) = crecp.as_mut() {
                let current_crec = &mut *crec; // 解引用裸指针
                if current_crec.flags & F_NEG != 0 {
                    // 如果有负缓存条目，先释放
                    cache_scan_free(caches, Some(host_name), None, SystemTime::now(), F_IPV4);
                } else {
                    // 找到相同主机名的 DHCP 条目，直接返回
                    println!(
                        "Ignoring DHCP lease for {} because it clashes with an existing entry.",
                        host_name
                    );
                    return;
                }
            }
        }

        // 查找地址中的条目
        if let Some(crecp) = cache_find_by_addr(
            caches,
            None,
            &AllAddr::Addr4(host_address.to_ipv4_addr()),
            SystemTime::now(),
            F_IPV4,
        ) {
            // 如果找到相同地址的 DHCP 条目
            if let Some(crec) = crecp.as_mut() {
                let current_crec = &mut *crec; // 解引用裸指针
                if current_crec.flags & F_NEG != 0 {
                    cache_scan_free(
                        caches,
                        None,
                        Some(&AllAddr::Addr4(host_address.to_ipv4_addr())),
                        SystemTime::now(),
                        F_IPV4,
                    );
                }
            }
        }

        // 创建新条目
        let crec: *mut Crec = if let Some(spare) = caches.dhcp_spare {
            caches.dhcp_spare = None; // 清空备用条目
            spare // 使用备用条目
        } else {
            // 分配新条目
            let new_crec = Box::new(Crec {
                next: None,
                prev: None,
                hash_next: None,
                ttd: SystemTime::now(),
                addr: AllAddr::Addr4(Ipv4Addr::new(0, 0, 0, 0)), // 初始化为一个有效的 IPv4 地址
                flags: 0,
                name: Name::Sname(['\0'; SMALLDNAME]), // 默认初始化
            });
            Box::into_raw(new_crec) // 转换为裸指针
        };

        // 更新条目内容
        if !crec.is_null() {
            let current_crec = &mut *crec; // 解引用裸指针
            current_crec.flags = F_DHCP | F_FORWARD | F_IPV4 | flags;
            if ttd == 0 {
                current_crec.flags |= F_IMMORTAL;
            } else {
                current_crec.ttd = SystemTime::now() + std::time::Duration::from_secs(ttd);
            }
            current_crec.addr = AllAddr::Addr4(host_address.to_ipv4_addr()); // 直接使用地址
            current_crec.name = Name::Namep(Box::new(host_name.to_string())); // 转换为 String

            current_crec.prev = caches.dhcp_inuse; // 连接到当前 DHCP 使用的条目
            caches.dhcp_inuse = Some(crec); // 更新当前使用的 DHCP 条目
        }
    }
}

// 清理缓存中的过期或匹配特定条件的条目
pub fn cache_scan_free(
    cache: &mut Cache,
    name: Option<&str>,
    addr: Option<&AllAddr>,
    now: SystemTime,
    flags: u32,
) {
    unsafe {
        let flags = flags & (F_FORWARD | F_REVERSE | F_IPV4 | F_IPV6);

        // 处理 F_FORWARD 标志
        if flags & F_FORWARD != 0 {
            let up = hash_bucket(name.unwrap_or("*"), cache); // 获取对应的哈希桶指针
            let mut crecp = *up;

            while let Some(current_ptr) = crecp {
                let current = &mut *current_ptr; // 解引用 Box

                // 检查条目是否过期
                if (!current.flags & F_IMMORTAL != 0
                    && now
                        .duration_since(current.ttd)
                        .unwrap_or(Duration::new(1, 0))
                        .as_secs()
                        > 0)
                    || (flags
                        == (current.flags
                            & (F_HOSTS | F_DHCP | F_FORWARD | F_REVERSE | F_IPV4 | F_IPV6))
                        && hostname_isequal(&cache_get_name(Some(current)), name.unwrap_or("")))
                {
                    // 将下一个条目存储在临时变量中
                    let next_ptr = current.hash_next; // 先保存下一个条目

                    // 解除当前条目的链接
                    Cache::cache_unlink(cache, current_ptr); // 从缓存中移除条目
                                                             // cache_free(current_ptr); // 释放条目内存

                    // 更新当前指针到下一个条目
                    crecp = next_ptr; // 更新指向下一个条目
                } else {
                    crecp = current.hash_next; // 继续遍历下一个条目
                }
            }
        } else {
            // 处理没有 F_FORWARD 标志的情况
            for i in 0..cache.hash_size {
                let mut crecp = cache.hash_table[i].clone(); // 获取当前哈希桶的条目
                while let Some(current_ptr) = crecp {
                    let current = &mut *current_ptr; // 解引用 Box

                    // 检查条目是否过期
                    if (!current.flags & F_IMMORTAL != 0
                        && now
                            .duration_since(current.ttd)
                            .unwrap_or(Duration::new(1, 0))
                            .as_secs()
                            > 0)
                        || (flags
                            == (current.flags
                                & (F_HOSTS | F_DHCP | F_FORWARD | F_REVERSE | F_IPV4 | F_IPV6))
                            && addr.is_some()
                            && current.addr == *addr.unwrap())
                    {
                        // 保存下一个条目
                        let next_ptr = current.hash_next; // 先保存下一个条目

                        // 解除当前条目的链接
                        Cache::cache_unlink(cache, current_ptr); // 从缓存中移除条目
                                                                 // cache_free(current_ptr); // 释放条目内存

                        // 更新当前指针到下一个条目
                        crecp = next_ptr; // 更新指向下一个条目
                    } else {
                        crecp = current.hash_next; // 继续遍历下一个条目
                    }
                }
                let up = &mut cache.hash_table[i];
                // 将当前哈希桶的条目重新放回 hash_table 中
                *up = crecp;
            }
        }
    }
}

//从缓存中移除所有 DHCP 条目
pub fn cache_unhash_dhcp(cache: &mut Cache) {
    // 从哈希表中移除所有 DHCP 条目
    for i in 0..cache.hash_size {
        let mut current = cache.hash_table[i].clone(); // 获取当前哈希桶的条目
        let mut up = &mut cache.hash_table[i]; // 指向当前哈希桶的指针

        while let Some(crecp) = current {
            // 解引用 crecp 为 Box<Crec>，并访问字段
            unsafe {
                if (*crecp).flags & F_DHCP != 0 {
                    // 移除 DHCP 条目
                    current = (*crecp).hash_next.clone(); // 更新到下一个条目
                    *up = (*crecp).next.clone(); // 从链表中移除
                } else {
                    up = &mut (*crecp).hash_next; // 更新指向当前条目的下一个
                    current = (*crecp).hash_next; // 继续遍历下一个条目
                }
            }
        }
    }

    // 将当前 DHCP 条目移动到备用列表
    let mut current = cache.dhcp_inuse.clone(); // 获取当前 DHCP 条目
    cache.dhcp_inuse = None; // 清空当前 DHCP 条目

    while let Some(crecp_ptr) = current {
        // 使用 unsafe 解引用裸指针
        let crecp = unsafe { &mut *crecp_ptr };
        current = crecp.next.clone(); // 保存下一个条目

        // 将当前条目添加到备用列表
        crecp.next = cache.dhcp_spare.clone(); // 将当前条目链接到备用列表
        cache.dhcp_spare = Some(crecp_ptr); // 更新备用列表
    }
}

pub fn dump_cache(debug: i32, cache: &Cache) {
    unsafe {
        let cache_size = cache.cache_size;
        let cache_live_freed = cache.cache_live_freed;
        let cache_inserted = cache.cache_inserted;

        syslog!(
            LOG_INFO,
            "Cache size {:?}, {:?}/{:?} cache insertions re-used unexpired cache entries.",
            cache_size,
            cache_live_freed,
            cache_inserted
        );

        if debug != 0 {
            syslog!(
                LOG_DEBUG,
                "Host                                     Address                        Flags     Expires",
            );

            // 遍历哈希表
            for entry in &cache.hash_table {
                let mut cache_entry = *entry; // 解引用以获得指针
                while let Some(c) = cache_entry {
                    let c_ref: &Crec = &*c; // 解引用获取 Crec 结构体

                    // 获取地址的字符串表示
                    let addrbuff = match c_ref.addr {
                        AllAddr::Addr4(addr) => format!("{}", addr),
                        AllAddr::Addr6(addr) => format!("{}", addr),
                    };

                    // 构建标志字符串
                    let flags_str = format!(
                        "{}{}{}{}{}{}{}{}{}{}",
                        if c_ref.flags & 128 != 0 { "4" } else { "" }, // F_IPV4
                        if c_ref.flags & 256 != 0 { "6" } else { "" }, // F_IPV6
                        if c_ref.flags & 8 != 0 { "F" } else { " " },  // F_FORWARD
                        if c_ref.flags & 4 != 0 { "R" } else { " " },  // F_REVERSE
                        if c_ref.flags & 1 != 0 { "I" } else { " " },  // F_IMMORTAL
                        if c_ref.flags & 16 != 0 { "D" } else { " " }, // F_DHCP
                        if c_ref.flags & 32 != 0 { "N" } else { " " }, // F_NEG
                        if c_ref.flags & 64 != 0 { "H" } else { " " }, // F_HOSTS
                        if c_ref.flags & 8192 != 0 { "X" } else { " " }, // F_NXDOMAIN
                        if c_ref.flags & 16384 != 0 { "A" } else { " " }, // F_ADDN
                    );

                    // 获取名称的字符串表示
                    let name_str = match &c_ref.name {
                        Name::Sname(name) => name.iter().collect::<String>(),
                        Name::Bname(bigname) => bigname.name.iter().collect::<String>(),
                        Name::Namep(name) => *name.clone(),
                    };

                    // 打印缓存条目信息
                    syslog!(LOG_DEBUG, "{:<40} {:<30} {}", name_str, addrbuff, flags_str);

                    // 获取下一个缓存条目
                    cache_entry = c_ref.hash_next;
                }
            }
        }
    }
}

// 清理缓存中的未提交节点
pub fn cache_start_insert(caches: &mut Cache) {
    unsafe {
        // 清理未提交的节点
        while let Some(node) = caches.new_chain.clone() {
            let next_node = (*node).next.clone();
            cache_free(caches, node); // 在这里调用 `cache_free` 以处理每个节点
            caches.new_chain = next_node;
        }
        caches.new_chain = None;
        INSERT_ERROR = false;
    }
}

// 将一条缓存记录插入到缓存中
pub fn cache_insert(
    caches: &mut Cache,
    name: &[u8],
    data: Option<&[u8]>,
    now: SystemTime,
    ttl: u32,
    flags: u32,
) {
    let mut flags = flags;
    let mut freed_all = flags & F_REVERSE != 0;

    log_query(caches, flags | F_UPSTREAM, name, data);

    // CONFIG 位仅用于日志记录，无需在插入时使用
    flags &= !F_CONFIG;

    // 如果上次插入失败，则直接返回
    unsafe {
        if INSERT_ERROR {
            return;
        }
    }

    // 将 `name` 从字节数组转换为字符串
    let name_str = match str::from_utf8(name) {
        Ok(valid_str) => Some(valid_str),
        Err(_) => None, // 如果转换失败，忽略此字符串
    };

    let addr_converted = if let Some(data) = data {
        if data.len() == INADDRSZ {
            let ipv4 = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
            Some(AllAddr::Addr4(ipv4))
        } else if data.len() == IN6ADDRSZ {
            let segments: [u8; 16] = data.try_into().unwrap();
            let ipv6 = Ipv6Addr::from(segments);
            Some(AllAddr::Addr6(ipv6))
        } else {
            None
        }
    } else {
        None
    };

    // 删除过期条目以及当前插入的名称/地址的条目
    cache_scan_free(caches, name_str, addr_converted.as_ref(), now, flags);

    // 从 LRU 列表的末尾获取缓存条目
    loop {
        if caches.cache_tail.is_none() {
            // 没有剩余条目，缓存太小，放弃
            unsafe {
                INSERT_ERROR = true;
            }
            return;
        }

        let new = unsafe { &mut *caches.cache_tail.unwrap() };

        // 如果 LRU 列表末尾仍在使用中
        if new.flags & (F_FORWARD | F_REVERSE) != 0 {
            if freed_all {
                cache_scan_free(caches, name_str, Some(&new.addr), now, new.flags);
            } else {
                cache_scan_free(caches, None, None, now, 0);
                freed_all = true;
            }
            continue;
        }

        // 检查是否需要为长名称分配额外内存
        let mut big_name = None;
        if name.len() > SMALLDNAME - 1 {
            if let Some(free) = caches.big_free.clone() {
                big_name = Some(free);
            } else if caches.bignames_left == 0 {
                unsafe {
                    INSERT_ERROR = true;
                }
                return;
            } else {
                big_name = Some(Box::new(BigName {
                    name: ['\0'; MAXDNAME],
                    next: None,
                }));
                caches.bignames_left -= 1;
            }
        }

        Cache::cache_unlink(caches, new);
        break;
    }

    // 创建新的缓存条目
    let new_entry = Box::new(Crec {
        next: None,
        prev: None,
        hash_next: None,
        ttd: now + Duration::new(ttl as u64, 0),
        addr: addr_converted.expect("Address conversion failed"),
        flags,
        name: if name.len() > SMALLDNAME - 1 {
            // 如果名称长度超过 SMALLDNAME，则使用 Bigname
            let mut big_name = BigName {
                name: ['\0'; MAXDNAME],
                next: None,
            };
            for (i, &byte) in name.iter().enumerate().take(MAXDNAME) {
                big_name.name[i] = byte as char;
            }
            Name::Bname(Box::new(big_name))
        } else {
            // 使用 Sname，适用于短名称
            let mut sname = ['\0'; SMALLDNAME];
            for (i, &byte) in name.iter().enumerate().take(SMALLDNAME) {
                sname[i] = byte as char;
            }
            Name::Sname(sname)
        },
    });

    // 插入新条目到缓存链表
    let new_entry_ptr = Box::into_raw(new_entry);
    unsafe {
        if let Some(chain) = caches.new_chain {
            (*new_entry_ptr).next = Some(chain);
        }
        caches.new_chain = Some(new_entry_ptr);
    }
}

// 记录 DNS 查询的日志信息
pub fn log_query(caches: &mut Cache, flags: u32, name: &[u8], addr: Option<&[u8]>) {
    let mut source = "cached";
    let mut verb = "is";
    let mut addrbuff = String::new();

    // 如果日志查询标志没有开启，则直接返回
    if caches.log_queries == 0 {
        return;
    }

    // 处理 `name`，将其转换为字符串
    let name_str = match str::from_utf8(name) {
        Ok(valid_str) => valid_str,
        Err(_) => "<invalid name>",
    };

    // 处理地址部分
    if let Some(addr_bytes) = addr {
        if addr_bytes.len() == 4 {
            // IPv4 地址
            let ipv4 = Ipv4Addr::new(addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]);
            addrbuff = ipv4.to_string();
        } else if addr_bytes.len() == 16 {
            // IPv6 地址
            let segments: [u8; 16] = match addr_bytes.try_into() {
                Ok(segments) => segments,
                Err(_) => {
                    addrbuff = "<invalid address>".to_string();
                    syslog!(LOG_DEBUG, "{} {} {} {}", source, name_str, verb, addrbuff);
                    return;
                }
            };
            let ipv6 = Ipv6Addr::from(segments);
            addrbuff = ipv6.to_string();
        } else {
            addrbuff = "<invalid address>".to_string();
        }
    } else {
        addrbuff = "<no address>".to_string();
    }

    // 根据标志位设置 source 和 verb
    if flags & F_NEG != 0 {
        if flags & F_REVERSE != 0 {
            addrbuff = format!(
                "<{}>-{}",
                if flags & F_NXDOMAIN != 0 {
                    "NXDOMAIN"
                } else {
                    "NODATA"
                },
                addrbuff
            );
        }

        if flags & F_IPV4 != 0 {
            addrbuff.push_str("IPv4");
        } else {
            addrbuff.push_str("IPv6");
        }
    }

    if flags & F_DHCP != 0 {
        source = "DHCP";
    } else if flags & F_HOSTS != 0 {
        unsafe {
            if flags & F_ADDN != 0 {
                source = ADDN_FILE.as_deref().unwrap_or("default_file");
            } else {
                source = HOSTSFILE;
            }
        }
    } else if flags & F_CONFIG != 0 {
        source = "config";
    } else if flags & F_UPSTREAM != 0 {
        source = "reply";
    } else if flags & F_SERVER != 0 {
        source = "forwarded";
        verb = "to";
    } else if flags & F_QUERY != 0 {
        source = "query";
        verb = "from";
    }

    // 根据标志位输出日志信息
    if (flags & F_FORWARD != 0) || (flags & F_NEG != 0) {
        syslog!(LOG_DEBUG, "{} {} {} {}", source, name_str, verb, addrbuff);
    } else if flags & F_REVERSE != 0 {
        syslog!(LOG_DEBUG, "{} {} is {}", source, addrbuff, name_str);
    }
}

// 在缓存链表的末尾插入新节点
pub fn cache_end_insert(caches: &mut Cache) {
    unsafe {
        if INSERT_ERROR {
            return;
        }

        while let Some(current) = caches.new_chain {
            let tmp = (*current).next;
            cache_hash(caches, Some(&mut *current));
            Cache::cache_link(caches, &mut *current);
            caches.new_chain = tmp;
            caches.cache_inserted += 1;
        }

        caches.new_chain = None;
    }
}