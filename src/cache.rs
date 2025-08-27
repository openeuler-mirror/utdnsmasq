/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use crate::util::*;
use std::fs::File;
use std::io::{self, BufRead};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

const MAXDNAME: usize = 1025;
const SMALLDNAME: usize = 40;
const OPT_NO_HOSTS: u32 = 2;
const HOSTSFILE: &str = "/etc/hosts";
const F_ADDN: u32 = 1;
const F_HOSTS: u32 = 64; // 标志，表示是 hosts
const F_DHCP: u32 = 16; // 标志，表示是 DHCP
const F_BIGNAME: u32 = 512;
const F_IMMORTAL: u32 = 128;
const F_FORWARD: u32 = 256;
const F_REVERSE: u32 = 512;
const F_IPV4: u32 = 1024;
const F_IPV6: u32 = 2048;
const OPT_EXPAND: u32 = 1;

#[derive(Debug, Clone, PartialEq)]
pub enum AllAddr {
    Addr4(Ipv4Addr),
    Addr6(Ipv6Addr),
}

// 定义 Bigname 结构体
#[derive(Clone, Debug)]
pub struct BigName {
    pub name: [char; MAXDNAME],     // 示例大名称
    pub next: Option<Box<BigName>>, // 自由列表
}

#[derive(Debug, Clone)]
pub enum Name {
    Sname([char; SMALLDNAME]),
    Bname(Box<BigName>),
    Namep(Box<String>),
}

#[derive(Debug, Clone)]
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
    mut domain_suffix: Option<String>,
    addn_hosts: Option<&str>,
) {
    // 清除缓存逻辑
    for i in 0..caches.hash_size {
        let mut up: Option<*mut Crec> = caches.hash_table[i];
        let mut current: Option<*mut Crec> = up;

        while let Some(cache_ptr) = current {
            // 安全解引用指针
            let cache = unsafe { &mut *cache_ptr };

            current = cache.hash_next; // 保存下一个元素

            // 处理 F_HOSTS 标志
            if cache.flags & F_HOSTS != 0 {
                // 移除 F_HOSTS 标志的项
                up = cache.hash_next; // 移除当前元素
                unsafe {
                    let _ = Box::from_raw(cache_ptr);
                } // 释放当前缓存项
            } else if cache.flags & F_DHCP == 0 {
                // 不是 DHCP 项，重置标志
                up = cache.hash_next; // 继续移除
                if cache.flags & F_BIGNAME != 0 {
                    // 处理 BIGNAME 逻辑
                    if let Name::Bname(ref mut bname) = cache.name {
                        bname.next = caches.big_free.take(); // 假设 big_free 是全局变量
                        caches.big_free = Some(bname.clone()); // 更新 big_free
                    }
                }
                cache.flags = 0; // 清除标志
            } else {
                up = cache.hash_next; // 更新指针
            }
        }
    }

    // 如果有 OPT_NO_HOSTS 选项且没有附加 hosts 文件
    if (opts & OPT_NO_HOSTS != 0) && addn_hosts.is_none() {
        if caches.cache_size > 0 {
            // err("Cleared cache");
        }
        return;
    }

    // 处理主 hosts 文件
    if opts & OPT_NO_HOSTS == 0 {
        if let Err(err) = read_hostsfile(caches, HOSTSFILE, opts, &mut buff, &mut domain_suffix, 0)
        {
            // err("Error reading hosts file: {}", err);
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
            // eer("Error reading additional hosts file: {}", err);
        }
    }
}

// 读取主机文件（如 /etc/hosts），并解析其中的内容
fn read_hostsfile(
    caches: &mut Cache,
    filename: &str,
    opts: u32,
    buff: &mut Vec<u8>,
    domain_suffix: &mut Option<String>,
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
            (*crecp_ptr).hash_next = bucket.take(); // 从 bucket 中取出原有值，赋给 hash_next
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
                        let next_ptr = unsafe { (*current_ptr).next.take() };
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
