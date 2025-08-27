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

#[derive(Debug, Clone)]
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

#[derive(Debug)]
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

    fn cache_link(&mut self, crec: &mut Box<Crec>) {
        // 将一个 Crec 结构体实例插入到双向链表的头部，并更新链表的头尾指针
        crec.next = self.cache_head;
        if let Some(head) = self.cache_head {
            unsafe {
                (*head).prev = Some(&mut **crec);
            }
        }
        self.cache_head = Some(&mut **crec);
        if self.cache_tail.is_none() {
            self.cache_tail = Some(&mut **crec);
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
    opts: u32,
    mut buff: String,
    domain_suffix: &str,
    addn_hosts: Option<&str>,
    caches: &mut Cache,
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
        if let Err(err) = read_hostsfile(HOSTSFILE, opts, &mut buff, domain_suffix, 0) {
            // err("Error reading hosts file: {}", err);
        }
    }

    // 处理附加 hosts 文件
    if let Some(addn_hosts) = addn_hosts {
        if let Err(err) = read_hostsfile(
            addn_hosts,
            opts,
            &mut buff,
            domain_suffix,
            F_ADDN.try_into().unwrap(),
        ) {
            // eer("Error reading additional hosts file: {}", err);
        }
    }
}

// 读取主机文件（如 /etc/hosts），并解析其中的内容
fn read_hostsfile(
    filename: &str,
    opts: u32,
    buff: &mut String,
    domain_suffix: &str,
    addn_flag: u16,
) -> io::Result<()> {
    let file = File::open(filename)?;
    let reader = io::BufReader::new(file);
    let mut count = 0;
    let mut lineno = 0;

    for line in reader.lines() {
        let line = line?;
        lineno += 1;

        // 清空缓冲区并设置当前行内容
        buff.clear();
        buff.push_str(&line);

        // 分割行并获取第一个 token
        let mut tokens = buff.split_whitespace();
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

                // 设置地址相关的标志
                if let AllAddr::Addr4(_) = addr {
                    flags |= F_IPV4;
                } else {
                    flags |= F_IPV6;
                }

                // 遍历其他 token
                for token in tokens {
                    if token.starts_with('#') {
                        break;
                    }

                    let canonical_name = canonicalise(token);
                    if canonical_name.is_some() {
                        count += 1;
                        let name_field = if canonical_name.as_ref().unwrap().len() < SMALLDNAME {
                            // 使用小名称数组
                            let mut sname = ['\0'; SMALLDNAME];
                            for (i, c) in canonical_name.as_ref().unwrap().chars().enumerate() {
                                sname[i] = c;
                            }
                            Name::Sname(sname)
                        } else {
                            // 使用动态分配的字符串
                            Name::Namep(Box::new(canonical_name.clone().unwrap()))
                        };

                        if (opts & OPT_EXPAND != 0)
                            && !canonical_name.as_ref().unwrap().contains('.')
                        {
                            let _extended_name =
                                format!("{}.{}", canonical_name.clone().unwrap(), domain_suffix);
                            let cache = Crec {
                                next: None,
                                prev: None,
                                hash_next: None,
                                ttd: SystemTime::now(),
                                addr: addr.clone(),
                                flags: flags | addn_flag as u32,
                                name: name_field.clone(),
                            };
                            add_hosts_entry(&cache);
                            flags &= !F_REVERSE;
                        }

                        let cache = Crec {
                            next: None,
                            prev: None,
                            hash_next: None,
                            ttd: SystemTime::now(),
                            addr: addr.clone(),
                            flags: flags | addn_flag as u32,
                            name: name_field,
                        };
                        add_hosts_entry(&cache);
                        flags &= !F_REVERSE;
                    } else {
                        // err("Invalid name at {} line {}", filename, lineno);
                    }
                }
            }
        }
    }

    // info("Read {} - {} addresses", filename, count);
    Ok(())
}

fn add_hosts_entry(crec: &Crec) {
    println!("Adding host entry: {:?}", crec);
}
