/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use crate::config::{Config, HOSTSFILE};
use crate::dnsmasq::{
    AllAddr, Crec, F_ADDN, F_CONFIG, F_DHCP, F_FORWARD, F_HOSTS, F_IMMORTAL, F_IPV4, F_IPV6, F_NEG,
    F_NXDOMAIN, F_QUERY, F_REVERSE, F_SERVER, F_UPSTREAM, OPT_EXPAND, OPT_NO_HOSTS,
};
use crate::logs::{LOG_DEBUG, LOG_ERR, LOG_INFO, LOG_WARNING};
use crate::syslog;
use crate::util::{canonicalise, difftime, hostname_isequal};
use lazy_static::lazy_static;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::rc::Rc;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

lazy_static! {
    static ref INSERT_ERROR: Mutex<bool> = Mutex::new(false);
    static ref ADDN_FILE: Mutex<String> = Mutex::new(String::new());
}

// 存储find_by_name函数查找到的符合记录的条目
#[derive(Debug, Clone, Default)]
struct MatchNameItem {
    match_recoder: Vec<Rc<RefCell<Crec>>>, // 存储条目
    index: usize,                          // 索引
}

// 存储find_by_addr函数查找到的符合记录的条目
#[derive(Debug, Clone, Default)]
struct MatchAddrItem {
    match_recoder: Vec<Rc<RefCell<Crec>>>, // 存储条目
    index: usize,                          // 索引
}

#[derive(Debug, Clone)]
pub struct Cache {
    pub cache_size: usize, // 缓存容量
    pub length: usize,     // 缓存长度
    // 双向链表头尾指针
    pub head: Option<Rc<RefCell<Crec>>>,
    pub tail: Option<Rc<RefCell<Crec>>>,
    pub dhcp_inuse: Vec<Crec>, // dncp正在使用的链表
    pub new_chain: Vec<Rc<RefCell<Crec>>>,
    pub log_queries: u32,
    pub cache_inserted: usize,
    pub cache_live_freed: usize,
    pub hash_table: HashMap<usize, Vec<Rc<RefCell<Crec>>>>, // 哈希列表
    pub hash_size: usize,                                   // 哈希大小
    // 用于 round-robin 机制的索引记录
    pub round_robin_indices: HashMap<String, usize>,
    match_name: MatchNameItem,
    match_addr: MatchAddrItem,
}

impl Cache {
    pub fn cache_init(size: usize, logq: u32) -> Self {
        let mut cache = Cache {
            cache_size: size,
            length: 0,
            head: None,
            tail: None,
            dhcp_inuse: Vec::new(),
            new_chain: Vec::new(),
            log_queries: logq,
            cache_inserted: 0,
            cache_live_freed: 0,
            hash_table: HashMap::new(),
            hash_size: 64,
            round_robin_indices: HashMap::new(),
            match_name: MatchNameItem::default(),
            match_addr: MatchAddrItem::default(),
        };

        // 不需要预分配空间

        // 调整哈希表大小：确保哈希表的大小至少为缓存大小的 1/10，并且是 2 的幂次
        while cache.hash_size < cache.cache_size / 10 {
            cache.hash_size <<= 1;
        }

        // 初始化哈希表
        for i in 0..cache.hash_size {
            cache.hash_table.entry(i).or_default();
        }

        cache
    }

    // 将节点添加到链表头部
    fn cache_link(&mut self, crec_rc: Rc<RefCell<Crec>>) {
        let mut crec = crec_rc.borrow_mut();

        if let Some(head) = &self.head {
            head.borrow_mut().prev = Some(Rc::downgrade(&crec_rc));
        }
        crec.next = self.head.take();
        crec.prev = None;
        self.head = Some(Rc::clone(&crec_rc));

        if self.tail.is_none() {
            self.tail = Some(Rc::clone(&crec_rc));
        }
    }

    // 从链表中移除节点
    fn cache_unlink(&mut self, crec_rc: Rc<RefCell<Crec>>) {
        let prev = crec_rc.borrow().prev.as_ref().and_then(|p| p.upgrade());
        let next = crec_rc.borrow().next.clone();

        // 更新前驱节点的 next 指针
        if let Some(prev_rc) = &prev {
            prev_rc.borrow_mut().next = next.clone();
        } else {
            // 如果是头节点
            self.head = next.clone();
        }

        // 更新后继节点的 prev 指针
        if let Some(next_rc) = &next {
            next_rc.borrow_mut().prev = prev.as_ref().map(Rc::downgrade);
        } else {
            // 如果是尾节点
            self.tail = prev;
        }

        // 清理被移除节点的指针
        crec_rc.borrow_mut().prev = None;
        crec_rc.borrow_mut().next = None;
    }

    // 计算字符串的哈希值
    fn hash_bucket(&self, name: &str) -> usize {
        let mut val = 0u32;

        // 计算哈希值（不依赖 LOCALE）
        let name_lower = name.to_ascii_lowercase(); // 大写转小写
        for c in name_lower.bytes() {
            val += c as u32;
        }

        // 计算桶索引（hash_size 是 2 的幂）
        (val as usize) & (self.hash_size - 1)
    }

    // 添加到哈希桶      将一个 Crec 结构体指针插入到缓存的哈希表中
    fn cache_hash(&mut self, crec_rc: Rc<RefCell<Crec>>) {
        let name = cache_get_name(&crec_rc);
        let hash = self.hash_bucket(&name);
        self.hash_table
            .entry(hash)
            .or_default()
            .push(Rc::clone(&crec_rc));

        // 哈希桶中添加一个内容，缓存数量就+1
        self.length += 1;
    }

    // 删除特定的 Crec
    pub fn remove_crec(&mut self, crec_rc: Rc<RefCell<Crec>>) {
        let name = crec_rc.borrow().name.clone();
        let hash = self.hash_bucket(&name);

        // 从链表中移除
        self.cache_unlink(Rc::clone(&crec_rc));

        // 从哈希桶中移除 不能移除哈希桶
        if let Some(bucket) = self.hash_table.get_mut(&hash) {
            bucket.retain(|x| !Rc::ptr_eq(x, &crec_rc));
        }

        self.length -= 1;
    }

    // 扫描去除过期条目
    /*
       If （flags & F_FORWARD）则删除name的任何forward条目和任何过期条目，但仅在与name相同的哈希桶中。
       If （flags & F_REVERSE）则删除整个缓存中addr的所有反向项和所有过期项。
       If （flags == 0）删除整个缓存中所有过期的条目。
    */
    fn cache_scan_free(
        &mut self,
        name: Option<&str>,
        addr: Option<AllAddr>,
        now: SystemTime,
        flags: u16,
    ) {
        let f_cachestatus = F_HOSTS | F_DHCP | F_FORWARD | F_REVERSE | F_IPV4 | F_IPV6;
        let flags = flags & (F_FORWARD | F_REVERSE | F_IPV6 | F_IPV4);

        // 收集要删除的条目，避免借用冲突
        let mut to_remove = Vec::new();

        if flags & F_FORWARD != 0 {
            // F_FORWARD: 删除name的任何forward条目和任何过期条目，但仅在与name相同的哈希桶中
            let name = name.unwrap();
            let index = self.hash_bucket(name);

            if let Some(bucket) = self.hash_table.get(&index) {
                for crec_rc in bucket.iter() {
                    let crecp = crec_rc.borrow();

                    // 检查是否过期或与name匹配的forward条目
                    let is_expired = crecp.flags & F_IMMORTAL == 0 && difftime(now, crecp.ttd) > 0;
                    let is_matching_forward = (flags == crecp.flags & f_cachestatus)
                        && hostname_isequal(&crecp.name, name);

                    if (is_expired || is_matching_forward)
                        && (crecp.flags & (F_HOSTS | F_DHCP) == 0)
                    {
                        to_remove.push(Rc::clone(crec_rc));
                    }
                }
            }
        } else {
            // F_REVERSE: 删除整个缓存中addr的所有反向项和所有过期项
            for i in 0..self.hash_size {
                if let Some(bucket) = self.hash_table.get(&i) {
                    for crec_rc in bucket.iter() {
                        let crecp = crec_rc.borrow();

                        // 检查是否过期或与addr匹配的reverse条目
                        let is_expired =
                            crecp.flags & F_IMMORTAL == 0 && difftime(now, crecp.ttd) > 0;
                        let is_matching_reverse =
                            (flags == crecp.flags & f_cachestatus) && crecp.addr == addr;

                        if (is_expired || is_matching_reverse)
                            && (crecp.flags & (F_HOSTS | F_DHCP) == 0)
                        {
                            to_remove.push(Rc::clone(crec_rc));
                        }
                    }
                }
            }
        }

        // 删除收集到的条目
        for crec_rc in to_remove {
            self.remove_crec(crec_rc);
        }
    }

    /*
       注：正常插入顺序为
       cache_start_insert
       Cache_insert * n
       cache_end_insert

       但是，中止可能会导致错过cache_end_insert
       在这种情况下，下一个cache_start_insert可以清理这些东西。
    */
    // 释放在最后一次插入时由于错误而没有提交的任何项。 清空new_chain
    pub fn cache_start_insert(&mut self) {
        let mut insert_error = INSERT_ERROR.lock().unwrap();

        self.new_chain = Vec::new();
        *insert_error = false;
    }

    // 添加缓存，将缓存添加到一个新的列表中
    pub fn cache_insert(
        &mut self,
        mut name: Option<&str>,
        addr: Option<AllAddr>,
        now: SystemTime,
        ttl: u32,
        flags: u16,
    ) {
        let mut insert_error = INSERT_ERROR.lock().unwrap();
        let mut freed_all = flags & F_REVERSE;
        let mut new: Crec = Crec::default();

        log_query(self, flags | F_UPSTREAM, name.unwrap(), addr);
        if flags & F_NEG != 0 && flags & F_REVERSE != 0 {
            name = None;
        }
        let flags = flags & !F_CONFIG;

        // 如果先前的插入失败，现在放弃。
        if *insert_error {
            return;
        }

        // 删除过期条目 和 与本次插入同名的条目
        self.cache_scan_free(name, addr, now, flags);

        // 缓存满 删除策略  如果缓存已满 首先进行过期条目删除，其次强制删除
        loop {
            // 一次插入的缓存数量超过缓存容量
            if self.new_chain.len() > self.cache_size {
                *insert_error = true;
                return;
            }

            // 缓存剩余空间不够本次添加  首先进行过期条目删除，其次强制删除末尾项
            if self.length + self.new_chain.len() >= self.cache_size {
                // 已尝试过全局清理，执行强制删除
                if freed_all != 1 {
                    if let Some(tail_rc) = self.tail.take() {
                        let tail = tail_rc.borrow();
                        self.cache_scan_free(Some(&tail.name), tail.addr, now, tail.flags);
                    }
                    self.cache_live_freed += 1; // 强制删除数目 +1
                } else {
                    self.cache_scan_free(None, None, now, 0);
                    freed_all = 1;
                }
                continue;
            }
            break;
        }

        new.flags = flags;
        if let Some(t_name) = name {
            new.name = t_name.to_string();
        } else {
            new.name = String::new();
        }
        new.addr = addr;
        new.ttd = now + Duration::from_secs(ttl as u64);

        let new_rc = Rc::new(RefCell::new(new));
        self.new_chain.push(new_rc);
    }

    // 添加项目的最后阶段，写入链表和哈希表
    pub fn cache_end_insert(&mut self) {
        let insert_error = INSERT_ERROR.lock().unwrap();
        if *insert_error {
            return;
        }

        for tmp in self.new_chain.clone() {
            // 添加到链表
            self.cache_link(Rc::clone(&tmp));
            // 添加到哈希表
            self.cache_hash(tmp);

            self.cache_inserted += 1;
        }

        self.new_chain = Vec::new();
    }

    // 将节点移动到链表头部
    fn move_to_front(&mut self, crec_rc: Rc<RefCell<Crec>>) {
        self.cache_unlink(Rc::clone(&crec_rc));
        self.cache_link(Rc::clone(&crec_rc));
    }

    // 循环单个查找
    pub fn cache_find_by_name(
        &mut self,
        crecp: Option<Rc<RefCell<Crec>>>,
        name: &str,
        now: SystemTime,
        prot: u16,
    ) -> Option<Rc<RefCell<Crec>>> {
        // 如果提供了 crecp 参数，逐个返回所有匹配的记录
        let ans: Option<Rc<RefCell<Crec>>>;
        let mut chain: Option<Rc<RefCell<Crec>>> = None;
        if crecp.is_some() {
            self.match_name.index += 1; // 从索引为1开始返回，索引为0的从crecp为None的时候返回了
            if self.match_name.index < self.match_name.match_recoder.len() {
                let result: Rc<RefCell<Crec>> =
                    Rc::clone(&self.match_name.match_recoder[self.match_name.index]);
                // 移动到链表头部
                if result.borrow().flags & (F_HOSTS | F_DHCP) == 0 {
                    self.move_to_front(Rc::clone(&result));
                }
                ans = Some(result);
            } else {
                // 已经返回了所有记录，返回 None
                ans = None;
            }
        } else {
            let hash = self.hash_bucket(name);
            // 收集要删除的过期条目，避免借用冲突
            let mut to_remove = Vec::new();

            // 获取所有符合的节点
            self.match_name.match_recoder = Vec::new(); // 每次查找新的内容之前删除
            if let Some(bucket) = self.hash_table.get(&hash) {
                for crec_rc in bucket {
                    let crecp = crec_rc.borrow();
                    if crecp.flags & F_IMMORTAL != 0 || difftime(now, crecp.ttd) < 0 {
                        // 条目永不过期 或 没有到过期时间
                        if crecp.flags & F_FORWARD != 0
                            && crecp.flags & prot != 0
                            && hostname_isequal(&cache_get_name(crec_rc), name)
                        {
                            self.match_name.match_recoder.push(Rc::clone(crec_rc));
                            // 添加匹配链表
                        }
                    } else if crecp.flags & (F_HOSTS | F_DHCP) != 0 {
                        // 在hosts或者dhcp文件中的 直接构建链表，不用lru策略
                        chain = Some(Rc::clone(crec_rc));
                    } else {
                        // 过期条目清理
                        // 非静态条目 清理
                        to_remove.push(Rc::clone(crec_rc));
                    }
                }
            }

            // 删除收集到的过期条目
            for crec_rc in to_remove {
                self.remove_crec(crec_rc);
            }

            // 如果没有匹配的记录，返回 None
            if chain.is_some() {
                ans = chain;
            } else if self.match_name.match_recoder.is_empty() {
                // 如果没有匹配的记录，返回 None
                ans = None;
            } else {
                // 如果没有提供 crecp，使用 round-robin 索引
                let current_index = self
                    .round_robin_indices
                    .entry(name.to_string())
                    .or_insert(0);

                // 如果索引超出范围，重置为0
                if *current_index >= self.match_name.match_recoder.len() {
                    *current_index = 0;
                }

                // 根据 round-robin 索引选择记录
                let result: Rc<RefCell<Crec>> =
                    Rc::clone(&self.match_name.match_recoder[*current_index]);

                // 更新 round-robin 索引（循环到下一个）
                let next_index = (*current_index + 1) % self.match_name.match_recoder.len();
                *current_index = next_index;

                // 非静态 移动到链表头部
                if result.borrow().flags & (F_HOSTS | F_DHCP) == 0 {
                    self.move_to_front(Rc::clone(&result));
                }

                ans = Some(result);
            }
        }

        if let Some(ref ret) = ans {
            if ret.borrow().flags & F_FORWARD != 0
                && ret.borrow().flags & prot != 0
                && hostname_isequal(&cache_get_name(ret), name)
            {
                return ans;
            }
        }
        None
    }

    pub fn cache_find_by_addr(
        &mut self,
        crecp: Option<Rc<RefCell<Crec>>>,
        addr: Option<AllAddr>,
        now: SystemTime,
        prot: u16,
    ) -> Option<Rc<RefCell<Crec>>> {
        // 如果提供了 crecp 参数，逐个返回所有匹配的记录
        let ans: Option<Rc<RefCell<Crec>>>;
        let mut chain: Option<Rc<RefCell<Crec>>> = None;
        if crecp.is_some() {
            self.match_addr.index += 1; // 从索引为1开始返回，索引为0的从crecp为None的时候返回了
            if self.match_addr.index < self.match_addr.match_recoder.len() {
                let result: Rc<RefCell<Crec>> =
                    Rc::clone(&self.match_addr.match_recoder[self.match_addr.index]);
                // 移动到链表头部
                if result.borrow().flags & (F_HOSTS | F_DHCP) == 0 {
                    self.move_to_front(Rc::clone(&result));
                }
                ans = Some(result);
            } else {
                // 已经返回了所有记录，返回 None
                ans = None;
            }
        } else {
            // 收集要删除的过期条目，避免借用冲突
            let mut to_remove = Vec::new();

            // 获取所有符合的节点（需要遍历所有哈希桶，因为地址没有哈希索引）
            self.match_addr.match_recoder = Vec::new(); // 每次查找新的内容之前删除
            for i in 0..self.hash_size {
                if let Some(bucket) = self.hash_table.get(&i) {
                    for crec_rc in bucket {
                        let crecp = crec_rc.borrow();
                        if crecp.flags & F_IMMORTAL != 0 || difftime(now, crecp.ttd) < 0 {
                            // 条目永不过期 或 没有到过期时间
                            if crecp.flags & F_REVERSE != 0
                                && crecp.flags & prot != 0
                                && crecp.addr == addr
                            {
                                self.match_addr.match_recoder.push(Rc::clone(crec_rc));
                                // 添加匹配链表
                            }
                        } else if crecp.flags & (F_HOSTS | F_DHCP) != 0 {
                            // 在hosts或者dhcp文件中的 直接构建链表，不用lru策略
                            chain = Some(Rc::clone(crec_rc));
                        } else {
                            // 过期条目清理
                            // 非静态条目 清理
                            to_remove.push(Rc::clone(crec_rc));
                        }
                    }
                }
            }

            // 删除收集到的过期条目
            for crec_rc in to_remove {
                self.remove_crec(crec_rc);
            }

            // 如果没有匹配的记录，返回 None
            if chain.is_some() {
                ans = chain;
            } else if self.match_addr.match_recoder.is_empty() {
                ans = None;
            } else {
                // 直接返回第一个匹配的记录（去除 round-robin 机制）
                let result: Rc<RefCell<Crec>> = Rc::clone(&self.match_addr.match_recoder[0]);

                // 非静态 移动到链表头部
                if result.borrow().flags & (F_HOSTS | F_DHCP) == 0 {
                    self.move_to_front(Rc::clone(&result));
                }

                ans = Some(result);
            }
        }

        if let Some(ref ret) = ans {
            if ret.borrow().flags & F_REVERSE != 0
                && ret.borrow().flags & prot != 0
                && ret.borrow().addr == addr
            {
                return ans;
            }
        }
        None
    }
}

fn cache_get_name(crec_rc: &Rc<RefCell<Crec>>) -> String {
    crec_rc.borrow().name.clone()
}

fn add_hosts_entry(cache: &mut Cache, crecp: Rc<RefCell<Crec>>, addr: AllAddr, flags: u16) {
    let name = crecp.borrow().name.clone();
    let prot = flags & (F_IPV4 | F_IPV6);

    // 检查是否已存在相同的hosts条目
    match cache.cache_find_by_name(None, &name, UNIX_EPOCH, prot) {
        Some(existing_rc) => {
            let existing = existing_rc.borrow();
            // 如果已存在相同的hosts条目且地址相同，则跳过添加
            if existing.flags & F_HOSTS != 0 && existing.addr == Some(addr) {
                return;
            }
            // 否则添加新条目
            cache.cache_hash(crecp);
        }
        None => {
            // 没有找到匹配条目，直接添加
            let crc_rc = crecp.clone();
            {
                let mut crc = crc_rc.borrow_mut();
                crc.addr = Some(addr);
                crc.flags = flags;
            }
            cache.cache_hash(crc_rc);
        }
    }
}

fn read_hostsfile(
    cache: &mut Cache,
    file_name: &Path,
    opts: u32,
    domain_suffix: &Option<String>,
    addn_flag: u16,
) {
    let mut count = 0;

    match File::open(file_name) {
        Ok(file) => {
            let reader = io::BufReader::new(file);

            for (lineno, line) in reader.lines().enumerate() {
                let flags: u16;
                let line = line.unwrap();

                // 跳过空行和注释
                if line.starts_with('#') || line.is_empty() {
                    continue;
                }
                // 分割字符
                let re = regex::Regex::new(r"[ |\t|\n|\r]").unwrap();
                let tokens: Vec<&str> = re.split(&line).filter(|s| !s.is_empty()).collect();

                // Parse the first token as IP address
                if tokens.is_empty() {
                    continue;
                }

                // 解析IP地址
                let ip_str = tokens[0];
                let addr: AllAddr = match ip_str.parse::<IpAddr>() {
                    Ok(addr) => {
                        match addr {
                            IpAddr::V4(_) => {
                                flags = F_HOSTS | F_IMMORTAL | F_FORWARD | F_REVERSE | F_IPV4;
                            }
                            IpAddr::V6(_) => {
                                flags = F_HOSTS | F_IMMORTAL | F_FORWARD | F_REVERSE | F_IPV6;
                            }
                        }
                        addr
                    }
                    Err(_) => {
                        // Skip lines that don't start with a valid IP address
                        continue;
                    }
                };

                // 解析主机名
                for token in &tokens[1..] {
                    // Skip empty tokens and comments
                    if token.is_empty() || token.starts_with('#') {
                        continue;
                    }
                    // 检查域名合法性
                    if canonicalise(token) {
                        count += 1;
                        // 添加带域名的
                        if opts & OPT_EXPAND != 0 && domain_suffix.is_some() && !token.contains(".")
                        {
                            let mut crecp: Crec = Crec::default();
                            let name = format!("{}.{}", token, domain_suffix.as_ref().unwrap());
                            crecp.name = name;
                            let crecp_rc = Rc::new(RefCell::new(crecp));
                            add_hosts_entry(cache, crecp_rc, addr, flags | addn_flag);
                        }
                        // 添加不带域名的
                        let crecp: Crec = Crec {
                            name: token.to_string(),
                            ..Default::default()
                        };
                        // crecp.name = token.to_string();
                        let crecp_rc = Rc::new(RefCell::new(crecp));
                        add_hosts_entry(cache, crecp_rc, addr, flags | addn_flag);
                    } else {
                        syslog!(LOG_ERR, "bad name at {:?} line {}", file_name, lineno);
                    }
                }
            }
        }

        Err(e) => {
            syslog!(
                LOG_ERR,
                "failed to load names from {:?}, err {}",
                file_name,
                e
            );
        }
    }

    syslog!(LOG_INFO, "read {:?} - {} addresses", file_name, count);
}

pub fn cache_reload(config: &mut Config, cache: &mut Cache) {
    let opts = config.options;
    let domain_suffix = config.domain_suffix.clone();
    let addn_hosts = config.addn_hosts.clone();
    let cache_size = config.cache_size;

    // 收集要删除的过期条目，避免借用冲突
    let mut to_remove = Vec::new();

    for i in 0..cache.hash_size {
        if let Some(bucket) = cache.hash_table.get(&i) {
            for crec_rc in bucket {
                let crecp = crec_rc.borrow();

                // 不含有F_DHCP标志的全部删除
                if crecp.flags & F_DHCP != 0 {
                    continue;
                }
                to_remove.push(Rc::clone(crec_rc));
            }
        }
    }
    // 删除收集到的过期条目
    for crec_rc in to_remove {
        cache.remove_crec(crec_rc);
    }

    if opts & OPT_NO_HOSTS != 0 && addn_hosts.is_empty() {
        if cache_size > 0 {
            syslog!(LOG_INFO, "cleared cache");
        }
        return;
    }

    if opts & OPT_NO_HOSTS == 0 {
        read_hostsfile(
            cache,
            std::path::Path::new(HOSTSFILE),
            opts,
            &domain_suffix,
            0,
        );
    }
    if !addn_hosts.is_empty() {
        let add_host = addn_hosts[0].clone();
        read_hostsfile(
            cache,
            std::path::Path::new(&add_host),
            opts,
            &domain_suffix,
            F_ADDN,
        );
        let mut addn_file = ADDN_FILE.lock().unwrap();
        *addn_file = add_host;
    }
}

// 在哈希列表中移除有F_DHCP标志的条目，清空dhcp_inuse列表
pub fn cache_unhash_dhcp(cache: &mut Cache) {
    // 遍历所有哈希桶，移除DHCP条目
    for i in 0..cache.hash_size {
        if let Some(bucket) = cache.hash_table.get_mut(&i) {
            // 使用retain方法过滤掉DHCP条目
            let original_len = bucket.len();
            bucket.retain(|crec_rc| {
                let crecp = crec_rc.borrow();
                // 保留非DHCP条目，移除DHCP条目
                crecp.flags & F_DHCP == 0
            });

            // 更新缓存长度
            let removed_count = original_len - bucket.len();
            cache.length -= removed_count;
        }
    }

    // 清空DHCP使用列表
    cache.dhcp_inuse.clear();
}

// 添加dhcp条目
pub fn cache_add_dhcp_entry(
    cache: &mut Cache,
    host_name: &str,
    host_address: Ipv4Addr,
    ttd: SystemTime,
    flags: u16,
) {
    // 是否需要创建新条目
    let new_entry_need: bool = true;
    let mut crec_rc = cache.cache_find_by_name(None, host_name, UNIX_EPOCH, F_IPV4);

    // 正向查找冲突检测
    if let Some(crec_ref) = crec_rc {
        let crec = crec_ref.borrow();
        if crec.flags & F_HOSTS != 0 {
            // 主机名已存在且来自hosts文件，忽略DHCP条目并警告
            syslog!(
                LOG_WARNING,
                "Ignoring DHCP lease for {} because it clashes with an /etc/hosts entry.",
                host_name
            );
            return;
        } else if crec.flags & F_DHCP == 0 {
            // 主机名已存在且不是DHCP来源，警告并忽略
            if crec.flags & F_NEG != 0 {
                // 主机名有负向缓存(F_NEG)，删除后继续添加
                // 只有这一种情况需要创建新条目，其余情况均需要直接返回
                cache.cache_scan_free(Some(host_name), None, UNIX_EPOCH, F_IPV4 | F_FORWARD);
                // new_entry_need = true;
            } else {
                let name = cache_get_name(&crec_ref);
                syslog!(
                    LOG_WARNING,
                    "Ignoring DHCP lease for {} because it clashes with a cached name.",
                    name
                );
                return;
            }
        } else {
            return;
        }
    }

    // new_entry_need = true; // 需要创建新条目
    // 反向查找 冲突检测
    crec_rc = cache.cache_find_by_addr(None, Some(IpAddr::V4(host_address)), UNIX_EPOCH, F_IPV4);
    if let Some(crec_ref) = crec_rc {
        let crec = crec_ref.borrow();
        if crec.flags & F_NEG != 0 {
            cache.cache_scan_free(
                None,
                Some(IpAddr::V4(host_address)),
                UNIX_EPOCH,
                F_IPV4 | F_FORWARD,
            );
        }
    }

    if new_entry_need {
        let mut crecp = Crec {
            flags: F_DHCP | F_FORWARD | F_IPV4 | flags,
            name: host_name.to_string(),
            ..Default::default()
        };
        // crecp.flags = F_DHCP | F_FORWARD | F_IPV4 | flags;
        if ttd == UNIX_EPOCH {
            crecp.flags |= F_IMMORTAL;
        } else {
            crecp.ttd = ttd;
        }
        // crecp.name = host_name.to_string();

        // 添加到dhcp链表
        cache.dhcp_inuse.push(crecp.clone());
        // 添加到哈希链表
        let crecp_rc = Rc::new(RefCell::new(crecp));
        cache.cache_hash(crecp_rc);
    }
}

pub fn dump_cache(debug: u32, cache: &mut Cache) {
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
    }

    for (_, hash) in cache.hash_table.iter() {
        for current_rc in hash {
            let current = current_rc.borrow();
            let addrbuff: String = if current.flags & F_NEG != 0 && current.flags & F_FORWARD != 0 {
                String::new()
            } else {
                current.addr.unwrap().to_string()
            };

            // 构建标志字符串
            let flags_str = format!(
                "{}{}{}{}{}{}{}{}{}{}",
                if current.flags & F_IPV4 != 0 { "4" } else { "" }, // F_IPV4
                if current.flags & F_IPV6 != 0 { "6" } else { "" }, // F_IPV6
                if current.flags & F_FORWARD != 0 {
                    "F"
                } else {
                    " "
                }, // F_FORWARD
                if current.flags & F_REVERSE != 0 {
                    "R"
                } else {
                    " "
                }, // F_REVERSE
                if current.flags & F_IMMORTAL != 0 {
                    "I"
                } else {
                    " "
                }, // F_IMMORTAL
                if current.flags & F_DHCP != 0 {
                    "D"
                } else {
                    " "
                }, // F_DHCP
                if current.flags & F_NEG != 0 { "N" } else { " " }, // F_NEG
                if current.flags & F_NXDOMAIN != 0 {
                    "H"
                } else {
                    " "
                }, // F_HOSTS
                if current.flags & F_HOSTS != 0 {
                    "X"
                } else {
                    " "
                }, // F_NXDOMAIN
                if current.flags & F_ADDN != 0 {
                    "A"
                } else {
                    " "
                }, // F_ADDN,
            );
            let ttd = if current.flags & F_IMMORTAL != 0 {
                String::from("\n")
            } else {
                let datetime: chrono::DateTime<chrono::Local> = current.ttd.into();
                datetime.format("%a %b %e %T %Y").to_string()
            };

            // 提取name值以避免宏解析问题
            let name = &current.name;

            // 打印缓存条目信息
            syslog!(
                LOG_DEBUG,
                "{:<40} {:<30} {} {}",
                name,
                addrbuff,
                flags_str,
                ttd
            );
        }
    }
}

// 日志查询
pub fn log_query(cache: &mut Cache, flags: u16, name: &str, addr: Option<AllAddr>) {
    let addn_file = ADDN_FILE.lock().unwrap();

    let mut source = "cached";
    let mut verb = "is";
    let mut addrbuff: String;
    let mut reverse_name = name.to_string();

    // 如果日志查询标志没有开启，则直接返回
    if cache.log_queries == 0 {
        return;
    }

    if flags & F_NEG != 0 {
        // 对于反向解析，通过addr获取name，但不需要修改原始name参数
        if flags & F_REVERSE != 0 {
            reverse_name = addr.unwrap().to_string();
        }

        if flags & F_NXDOMAIN != 0 {
            addrbuff = String::from("<NXDOMAIN>-");
        } else {
            addrbuff = String::from("<NODATA>-");
        }

        if flags & F_IPV4 != 0 {
            addrbuff.push_str("IPv4");
        } else {
            addrbuff.push_str("IPv6");
        }
    } else {
        addrbuff = addr.unwrap().to_string();
    }

    if flags & F_DHCP != 0 {
        source = "DHCP";
    } else if flags & F_HOSTS != 0 {
        if flags & F_ADDN != 0 {
            source = &(*addn_file);
        } else {
            source = HOSTSFILE;
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
        syslog!(
            LOG_DEBUG,
            "{} {} {} {}",
            source,
            reverse_name,
            verb,
            addrbuff
        );
    } else if flags & F_REVERSE != 0 {
        syslog!(LOG_DEBUG, "{} {} is {}", source, addrbuff, reverse_name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn test_cache_scan_free_forward_expired() {
        let mut cache = Cache::cache_init(100, 0);

        // 创建一些测试记录
        cache.cache_start_insert();

        let name = "example.com";
        let addr = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

        // 插入一个已过期的记录
        let expired_time = SystemTime::now() - Duration::from_secs(3600); // 1小时前
        cache.cache_insert(Some(name), addr, expired_time, 1, F_FORWARD | F_IPV4);

        // 插入一个未过期的记录
        let future_time = SystemTime::now() + Duration::from_secs(3600); // 1小时后
        cache.cache_insert(
            Some("test.com"),
            addr,
            future_time,
            3600,
            F_FORWARD | F_IPV4,
        );

        cache.cache_end_insert();

        let original_length = cache.length;

        // 执行扫描删除，使用F_FORWARD标志
        cache.cache_scan_free(Some(name), None, SystemTime::now(), F_FORWARD);

        // 验证过期记录被删除，未过期记录保留
        assert_eq!(
            cache.length,
            original_length - 1,
            "Expired record should be removed"
        );
    }

    #[test]
    fn test_cache_scan_free_forward_matching_name() {
        let mut cache = Cache::cache_init(100, 0);

        // 创建一些测试记录
        cache.cache_start_insert();

        let name = "example.com";
        let addr1 = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let addr2 = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));

        // 插入两个相同域名的记录
        cache.cache_insert(
            Some(name),
            addr1,
            SystemTime::now(),
            3600,
            F_FORWARD | F_IPV4,
        );
        cache.cache_insert(
            Some(name),
            addr2,
            SystemTime::now(),
            3600,
            F_FORWARD | F_IPV4,
        );

        // 插入另一个域名的记录
        cache.cache_insert(
            Some("other.com"),
            addr1,
            SystemTime::now(),
            3600,
            F_FORWARD | F_IPV4,
        );

        cache.cache_end_insert();

        let original_length = cache.length;

        // 执行扫描删除，删除指定域名的所有forward记录 flags标志必须相同
        cache.cache_scan_free(Some(name), None, SystemTime::now(), F_FORWARD | F_IPV4);

        // 验证指定域名的记录被删除，其他记录保留
        assert_eq!(
            cache.length,
            original_length - 2,
            "Matching name records should be removed"
        );
    }

    #[test]
    fn test_cache_scan_free_reverse_expired() {
        let mut cache = Cache::cache_init(100, 0);

        // 创建一些测试记录
        cache.cache_start_insert();

        let addr = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let reverse_name = "1.1.168.192.in-addr.arpa";

        // 插入一个已过期的反向记录
        let expired_time = SystemTime::now() - Duration::from_secs(3600);
        cache.cache_insert(
            Some(reverse_name),
            addr,
            expired_time,
            1,
            F_REVERSE | F_IPV4,
        );

        // 插入一个未过期的反向记录
        let future_time = SystemTime::now() + Duration::from_secs(3600);
        cache.cache_insert(
            Some("2.1.168.192.in-addr.arpa"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))),
            future_time,
            3600,
            F_REVERSE | F_IPV4,
        );

        cache.cache_end_insert();

        let original_length = cache.length;

        // 执行扫描删除，使用F_REVERSE标志
        cache.cache_scan_free(None, addr, SystemTime::now(), F_REVERSE);

        // 验证过期反向记录被删除，未过期记录保留
        assert_eq!(
            cache.length,
            original_length - 1,
            "Expired reverse record should be removed"
        );
    }

    #[test]
    fn test_cache_scan_free_reverse_matching_addr() {
        let mut cache = Cache::cache_init(100, 0);

        // 创建一些测试记录
        cache.cache_start_insert();

        let addr = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let reverse_name1 = "1.1.168.192.in-addr.arpa";
        let reverse_name2 = "test.1.168.192.in-addr.arpa";

        // 插入两个相同地址的反向记录
        cache.cache_insert(
            Some(reverse_name1),
            addr,
            SystemTime::now(),
            3600,
            F_REVERSE | F_IPV4,
        );
        cache.cache_insert(
            Some(reverse_name2),
            addr,
            SystemTime::now(),
            3600,
            F_REVERSE | F_IPV4,
        );

        // 插入另一个地址的反向记录
        let other_addr = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
        cache.cache_insert(
            Some("2.1.168.192.in-addr.arpa"),
            other_addr,
            SystemTime::now(),
            3600,
            F_REVERSE | F_IPV4,
        );

        cache.cache_end_insert();

        let original_length = cache.length;

        // 执行扫描删除，删除指定地址的所有反向记录
        cache.cache_scan_free(None, addr, SystemTime::now(), F_REVERSE | F_IPV4);

        // 验证指定地址的记录被删除，其他记录保留
        assert_eq!(
            cache.length,
            original_length - 2,
            "Matching address records should be removed"
        );
    }

    #[test]
    fn test_cache_scan_free_all_expired() {
        let mut cache = Cache::cache_init(100, 0);

        // 创建一些测试记录
        cache.cache_start_insert();

        let expired_time = SystemTime::now() - Duration::from_secs(3600);
        let future_time = SystemTime::now() + Duration::from_secs(3600);

        // 插入已过期的记录
        cache.cache_insert(
            Some("expired1.com"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            expired_time,
            1,
            F_FORWARD | F_IPV4,
        );
        cache.cache_insert(
            Some("expired2.com"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))),
            expired_time,
            1,
            F_FORWARD | F_IPV4,
        );

        // 插入未过期的记录
        cache.cache_insert(
            Some("valid.com"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3))),
            future_time,
            3600,
            F_FORWARD | F_IPV4,
        );

        cache.cache_end_insert();

        let original_length = cache.length;

        // 执行全局扫描删除所有过期记录
        cache.cache_scan_free(None, None, SystemTime::now(), 0);

        // 验证只有过期记录被删除
        assert_eq!(
            cache.length,
            original_length - 2,
            "All expired records should be removed"
        );
    }

    #[test]
    fn test_cache_scan_free_immortal_records() {
        let mut cache = Cache::cache_init(100, 0);

        // 创建一些测试记录
        cache.cache_start_insert();

        // 插入永不过期的记录
        cache.cache_insert(
            Some("immortal.com"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            UNIX_EPOCH,
            0,
            F_FORWARD | F_IPV4 | F_IMMORTAL,
        );

        // 插入普通过期记录
        let expired_time = SystemTime::now() - Duration::from_secs(3600);
        cache.cache_insert(
            Some("mortal.com"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))),
            expired_time,
            1,
            F_FORWARD | F_IPV4,
        );

        cache.cache_end_insert();

        let original_length = cache.length;

        // 执行扫描删除
        cache.cache_scan_free(None, None, SystemTime::now(), 0);

        // 验证永不过期记录保留，普通过期记录被删除
        assert_eq!(
            cache.length,
            original_length - 1,
            "Only mortal records should be removed"
        );
    }

    #[test]
    fn test_cache_scan_free_hosts_dhcp_records() {
        let mut cache = Cache::cache_init(100, 0);

        // 创建一些测试记录
        cache.cache_start_insert();

        // 插入hosts文件记录（应该不被删除）
        cache.cache_insert(
            Some("hosts.com"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            SystemTime::now() - Duration::from_secs(3600),
            1,
            F_FORWARD | F_IPV4 | F_HOSTS,
        );

        // 插入DHCP记录（应该不被删除）
        cache.cache_insert(
            Some("dhcp.com"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))),
            SystemTime::now() - Duration::from_secs(3600),
            1,
            F_FORWARD | F_IPV4 | F_DHCP,
        );

        // 插入普通过期记录
        cache.cache_insert(
            Some("normal.com"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3))),
            SystemTime::now() - Duration::from_secs(3600),
            1,
            F_FORWARD | F_IPV4,
        );

        cache.cache_end_insert();

        let original_length = cache.length;

        // 执行扫描删除
        cache.cache_scan_free(None, None, SystemTime::now(), 0);

        // 验证只有普通记录被删除，hosts和DHCP记录保留
        assert_eq!(
            cache.length,
            original_length - 1,
            "Only normal records should be removed"
        );
    }

    #[test]
    fn test_cache_scan_free_ipv6_records() {
        let mut cache = Cache::cache_init(100, 0);

        // 创建一些测试记录
        cache.cache_start_insert();

        let ipv6_addr = Some(IpAddr::V6("2001:db8::1".parse().unwrap()));

        // 插入IPv6记录
        cache.cache_insert(
            Some("ipv6.example.com"),
            ipv6_addr,
            SystemTime::now() - Duration::from_secs(3600),
            1,
            F_FORWARD | F_IPV6,
        );

        // 插入IPv4记录
        cache.cache_insert(
            Some("ipv4.example.com"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            SystemTime::now() - Duration::from_secs(3600),
            1,
            F_FORWARD | F_IPV4,
        );

        cache.cache_end_insert();

        let original_length = cache.length;

        // 执行扫描删除，只针对IPv6记录
        cache.cache_scan_free(
            Some("ipv6.example.com"),
            None,
            SystemTime::now(),
            F_FORWARD | F_IPV6,
        );

        // 验证只有IPv6记录被删除
        assert_eq!(
            cache.length,
            original_length - 1,
            "Only IPv6 records should be removed"
        );
    }

    #[test]
    fn test_cache_scan_free_empty_cache() {
        let mut cache = Cache::cache_init(100, 0);

        let original_length = cache.length;

        // 在空缓存上执行扫描删除
        cache.cache_scan_free(Some("example.com"), None, SystemTime::now(), F_FORWARD);

        // 验证缓存长度不变
        assert_eq!(
            cache.length, original_length,
            "Empty cache should remain unchanged"
        );
    }

    #[test]
    fn test_cache_find_by_name_basic() {
        let mut cache = Cache::cache_init(100, 0);

        // 插入测试记录
        cache.cache_start_insert();
        cache.cache_insert(
            Some("example.com"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            SystemTime::now(),
            3600,
            F_FORWARD | F_IPV4,
        );
        cache.cache_end_insert();

        // 查找记录
        let result = cache.cache_find_by_name(None, "example.com", SystemTime::now(), F_IPV4);

        // 验证找到记录
        assert!(result.is_some(), "Should find the record");
        let binding = result.unwrap();
        let crec = binding.borrow();
        assert_eq!(crec.name, "example.com", "Record name should match");
        assert_eq!(
            crec.addr,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            "Record address should match"
        );
        assert_eq!(crec.flags, F_FORWARD | F_IPV4, "Record flags should match");
    }

    #[test]
    fn test_cache_find_by_name_not_found() {
        let mut cache = Cache::cache_init(100, 0);

        // 查找不存在的记录
        let result = cache.cache_find_by_name(None, "nonexistent.com", SystemTime::now(), F_IPV4);

        // 验证没有找到记录
        assert!(result.is_none(), "Should not find nonexistent record");
    }

    #[test]
    fn test_cache_find_by_name_multiple_records() {
        let mut cache = Cache::cache_init(100, 0);

        // 插入多个相同域名的记录（模拟DNS轮询）
        cache.cache_start_insert();
        cache.cache_insert(
            Some("example.com"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            SystemTime::now(),
            3600,
            F_FORWARD | F_IPV4,
        );
        cache.cache_insert(
            Some("example.com"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))),
            SystemTime::now(),
            3600,
            F_FORWARD | F_IPV4,
        );
        cache.cache_insert(
            Some("example.com"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3))),
            SystemTime::now(),
            3600,
            F_FORWARD | F_IPV4,
        );
        cache.cache_end_insert();

        // 第一次查找应该返回第一个记录（轮询索引为0）
        let result1 = cache.cache_find_by_name(None, "example.com", SystemTime::now(), F_IPV4);
        assert!(result1.is_some(), "Should find first record");
        {
            let binding1 = result1.as_ref().unwrap();
            let crec1 = binding1.borrow();
            assert_eq!(
                crec1.addr,
                Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                "First lookup should return first address"
            );
        } // crec1 and binding1 are dropped here

        // 第二次查找应该返回第二个记录（轮询索引为1）
        let result2 =
            cache.cache_find_by_name(result1.clone(), "example.com", SystemTime::now(), F_IPV4);
        assert!(result2.is_some(), "Should find second record");
        {
            let binding2 = result2.as_ref().unwrap();
            let crec2 = binding2.borrow();
            assert_eq!(
                crec2.addr,
                Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))),
                "Second lookup should return second address"
            );
        } // crec2 and binding2 are dropped here

        // 第三次查找应该返回第三个记录（轮询索引为2）
        let result3 =
            cache.cache_find_by_name(result2.clone(), "example.com", SystemTime::now(), F_IPV4);
        assert!(result3.is_some(), "Should find third record");
        {
            let binding3 = result3.as_ref().unwrap();
            let crec3 = binding3.borrow();
            assert_eq!(
                crec3.addr,
                Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3))),
                "Third lookup should return third address"
            );
        } // crec3 and binding3 are dropped here

        // 第四次查找应该循环回到第一个记录（轮询索引为0）
        let result4 =
            cache.cache_find_by_name(result3.clone(), "example.com", SystemTime::now(), F_IPV4);
        assert!(result4.is_none(), "Should find first record again");
    }

    #[test]
    fn test_cache_find_by_name_expired_records() {
        let mut cache = Cache::cache_init(100, 0);

        // 插入已过期的记录
        cache.cache_start_insert();
        let expired_time = SystemTime::now() - Duration::from_secs(3600); // 1小时前
        cache.cache_insert(
            Some("expired.com"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            expired_time,
            1, // 1秒TTL，已过期
            F_FORWARD | F_IPV4,
        );
        cache.cache_end_insert();

        // 查找过期记录
        let result = cache.cache_find_by_name(None, "expired.com", SystemTime::now(), F_IPV4);

        // 验证过期记录被自动清理，找不到记录
        assert!(result.is_none(), "Should not find expired record");
        assert_eq!(
            cache.length, 0,
            "Expired record should be removed from cache"
        );
    }

    #[test]
    fn test_cache_find_by_name_immortal_records() {
        let mut cache = Cache::cache_init(100, 0);

        // 插入永不过期的记录
        cache.cache_start_insert();
        cache.cache_insert(
            Some("immortal.com"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            UNIX_EPOCH,
            0, // 永不过期
            F_FORWARD | F_IPV4 | F_IMMORTAL,
        );
        cache.cache_end_insert();

        // 查找永不过期记录
        let result = cache.cache_find_by_name(None, "immortal.com", SystemTime::now(), F_IPV4);

        // 验证找到永不过期记录
        assert!(result.is_some(), "Should find immortal record");
        let binding = result.unwrap();
        let crec = binding.borrow();
        assert_eq!(crec.name, "immortal.com", "Record name should match");
        assert!(crec.flags & F_IMMORTAL != 0, "Record should be immortal");
    }

    #[test]
    fn test_cache_find_by_name_case_insensitive() {
        let mut cache = Cache::cache_init(100, 0);

        // 插入小写域名记录
        cache.cache_start_insert();
        cache.cache_insert(
            Some("example.com"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            SystemTime::now(),
            3600,
            F_FORWARD | F_IPV4,
        );
        cache.cache_end_insert();

        // 使用大写域名查找
        let result = cache.cache_find_by_name(None, "EXAMPLE.COM", SystemTime::now(), F_IPV4);

        // 验证不区分大小写查找成功
        assert!(
            result.is_some(),
            "Should find record with case-insensitive search"
        );
        let binding = result.unwrap();
        let crec = binding.borrow();
        assert_eq!(crec.name, "example.com", "Record name should match");
    }

    #[test]
    fn test_cache_find_by_name_with_crecp_parameter() {
        let mut cache = Cache::cache_init(100, 0);

        // 插入多个记录
        cache.cache_start_insert();
        cache.cache_insert(
            Some("example.com"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            SystemTime::now(),
            3600,
            F_FORWARD | F_IPV4,
        );
        cache.cache_insert(
            Some("example.com"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))),
            SystemTime::now(),
            3600,
            F_FORWARD | F_IPV4,
        );
        cache.cache_end_insert();

        // 第一次查找（crecp为None）
        let result1 = cache.cache_find_by_name(None, "example.com", SystemTime::now(), F_IPV4);
        assert!(result1.is_some(), "Should find first record");

        // 使用第一个记录作为crecp参数进行第二次查找
        let result2 =
            cache.cache_find_by_name(result1.clone(), "example.com", SystemTime::now(), F_IPV4);
        assert!(result2.is_some(), "Should find second record");

        // 使用第二个记录作为crecp参数进行第三次查找
        let result3 =
            cache.cache_find_by_name(result2.clone(), "example.com", SystemTime::now(), F_IPV4);
        assert!(
            result3.is_none(),
            "Should not find more records after all are returned"
        );
    }

    #[test]
    fn test_cache_find_by_name_move_to_front() {
        let mut cache = Cache::cache_init(100, 0);

        // 插入多个记录
        cache.cache_start_insert();
        cache.cache_insert(
            Some("test1.com"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            SystemTime::now(),
            3600,
            F_FORWARD | F_IPV4,
        );
        cache.cache_insert(
            Some("test2.com"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))),
            SystemTime::now(),
            3600,
            F_FORWARD | F_IPV4,
        );
        cache.cache_insert(
            Some("test3.com"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3))),
            SystemTime::now(),
            3600,
            F_FORWARD | F_IPV4,
        );
        cache.cache_end_insert();

        // 记录初始链表顺序
        let original_head = cache.head.as_ref().unwrap().borrow().name.clone();

        // 查找第二个记录
        let result = cache.cache_find_by_name(None, "test2.com", SystemTime::now(), F_IPV4);
        assert!(result.is_some(), "Should find test2.com");

        // 验证被访问的记录被移动到链表头部
        let new_head = cache.head.as_ref().unwrap().borrow().name.clone();
        assert_eq!(
            new_head, "test2.com",
            "Accessed record should be moved to front"
        );
        assert_ne!(original_head, new_head, "Head should have changed");
    }

    #[test]
    fn test_cache_find_by_name_hosts_dhcp_records() {
        let mut cache = Cache::cache_init(100, 0);

        // 插入hosts文件记录
        cache.cache_start_insert();
        cache.cache_insert(
            Some("hosts.com"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            SystemTime::now(),
            3600,
            F_FORWARD | F_IPV4 | F_HOSTS,
        );
        cache.cache_insert(
            Some("dhcp.com"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))),
            SystemTime::now(),
            3600,
            F_FORWARD | F_IPV4 | F_DHCP,
        );
        cache.cache_end_insert();

        // 查找hosts记录
        let hosts_result = cache.cache_find_by_name(None, "hosts.com", SystemTime::now(), F_IPV4);
        assert!(hosts_result.is_some(), "Should find hosts record");
        let hosts_binding = hosts_result.unwrap();
        let hosts_crec = hosts_binding.borrow();
        assert!(hosts_crec.flags & F_HOSTS != 0, "Should be hosts record");

        // 查找DHCP记录
        let dhcp_result = cache.cache_find_by_name(None, "dhcp.com", SystemTime::now(), F_IPV4);
        assert!(dhcp_result.is_some(), "Should find DHCP record");
        let dhcp_binding = dhcp_result.unwrap();
        let dhcp_crec = dhcp_binding.borrow();
        assert!(dhcp_crec.flags & F_DHCP != 0, "Should be DHCP record");
    }

    #[test]
    fn test_cache_link_single_node() {
        let mut cache = Cache::cache_init(100, 0);

        // 创建一个测试记录
        // 创建三个测试记录并链接
        let crec1 = Crec {
            name: "test.com".to_string(),
            addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            flags: F_FORWARD | F_IPV4,
            ..Crec::default()
        };
        let crec_rc = Rc::new(RefCell::new(crec1));

        // 初始状态验证
        assert!(cache.head.is_none(), "Head should be None initially");
        assert!(cache.tail.is_none(), "Tail should be None initially");
        assert_eq!(cache.length, 0, "Length should be 0 initially");

        // 调用cache_link
        cache.cache_link(Rc::clone(&crec_rc));

        // 验证链表状态
        assert!(cache.head.is_some(), "Head should be set after linking");
        assert!(cache.tail.is_some(), "Tail should be set after linking");
        assert_eq!(cache.length, 0, "Length should not change in cache_link");

        // 验证节点指针
        let head_rc = cache.head.as_ref().unwrap();
        let tail_rc = cache.tail.as_ref().unwrap();

        // 在单节点情况下，head和tail应该指向同一个节点
        assert!(
            Rc::ptr_eq(head_rc, tail_rc),
            "Head and tail should point to same node for single node"
        );
        assert!(
            Rc::ptr_eq(head_rc, &crec_rc),
            "Head should point to the linked node"
        );

        // 验证节点内部指针
        let node = head_rc.borrow();
        assert!(node.prev.is_none(), "Single node should have no previous");
        assert!(node.next.is_none(), "Single node should have no next");
    }

    #[test]
    fn test_cache_link_multiple_nodes() {
        let mut cache = Cache::cache_init(100, 0);

        // 创建三个测试记录并链接
        let crec1 = Crec {
            name: "test1.com".to_string(),
            addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            flags: F_FORWARD | F_IPV4,
            ..Crec::default()
        };
        let crec1_rc = Rc::new(RefCell::new(crec1));

        let crec2 = Crec {
            name: "test2.com".to_string(),
            addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))),
            flags: F_FORWARD | F_IPV4,
            ..Crec::default()
        };
        let crec2_rc = Rc::new(RefCell::new(crec2));

        let crec3 = Crec {
            name: "test3.com".to_string(),
            addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3))),
            flags: F_FORWARD | F_IPV4,
            ..Crec::default()
        };
        let crec3_rc = Rc::new(RefCell::new(crec3));

        // 链接第一个节点
        cache.cache_link(Rc::clone(&crec1_rc));

        // 链接第二个节点（应该成为新的头部）
        cache.cache_link(Rc::clone(&crec2_rc));

        // 验证链表结构：2 -> 1
        assert!(cache.head.is_some(), "Head should be set");
        assert!(cache.tail.is_some(), "Tail should be set");

        {
            let head_rc = cache.head.as_ref().unwrap();
            let tail_rc = cache.tail.as_ref().unwrap();

            // 验证头部指向第二个节点
            let head_node = head_rc.borrow();
            assert_eq!(head_node.name, "test2.com", "Head should be test2.com");

            // 验证尾部指向第一个节点
            let tail_node = tail_rc.borrow();
            assert_eq!(tail_node.name, "test1.com", "Tail should be test1.com");

            // 验证节点2指向节点1
            assert!(head_node.next.is_some(), "Head should have next pointer");
            let next_rc = head_node.next.as_ref().unwrap();
            let next_node = next_rc.borrow();
            assert_eq!(next_node.name, "test1.com", "Next should be test1.com");

            // 验证节点1指向节点2（通过prev）
            assert!(
                tail_node.prev.is_some(),
                "Tail should have previous pointer"
            );
            let prev_weak = tail_node.prev.as_ref().unwrap();
            let prev_rc = prev_weak
                .upgrade()
                .expect("Previous pointer should be valid");
            let prev_node = prev_rc.borrow();
            assert_eq!(prev_node.name, "test2.com", "Previous should be test2.com");
        } // 这里释放所有借用

        // 链接第三个节点（应该成为新的头部）
        cache.cache_link(Rc::clone(&crec3_rc));

        {
            // 验证链表结构：3 -> 2 -> 1
            let new_head_rc = cache.head.as_ref().unwrap();
            let new_head_node = new_head_rc.borrow();
            assert_eq!(
                new_head_node.name, "test3.com",
                "New head should be test3.com"
            );

            // 验证节点3指向节点2
            assert!(
                new_head_node.next.is_some(),
                "New head should have next pointer"
            );
            let new_next_rc = new_head_node.next.as_ref().unwrap();
            let new_next_node = new_next_rc.borrow();
            assert_eq!(new_next_node.name, "test2.com", "Next should be test2.com");

            // 验证节点2指向节点1
            assert!(
                new_next_node.next.is_some(),
                "Second node should have next pointer"
            );
            let new_next_next_rc = new_next_node.next.as_ref().unwrap();
            let new_next_next_node = new_next_next_rc.borrow();
            assert_eq!(
                new_next_next_node.name, "test1.com",
                "Third should be test1.com"
            );

            // 验证节点1指向节点2（通过prev）
            assert!(
                new_next_next_node.prev.is_some(),
                "Tail should have previous pointer"
            );
            let new_prev_weak = new_next_next_node.prev.as_ref().unwrap();
            let new_prev_rc = new_prev_weak
                .upgrade()
                .expect("Previous pointer should be valid");
            let new_prev_node = new_prev_rc.borrow();
            assert_eq!(
                new_prev_node.name, "test2.com",
                "Tail's previous should be test2.com"
            );
        }
    }

    #[test]
    fn test_cache_unlink_single_node() {
        let mut cache = Cache::cache_init(100, 0);

        // 创建一个测试记录并链接
        let crec = Crec {
            name: "test.com".to_string(),
            addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            flags: F_FORWARD | F_IPV4,
            ..Crec::default()
        };
        let crec_rc = Rc::new(RefCell::new(crec));

        cache.cache_link(Rc::clone(&crec_rc));

        // 验证链接后的状态
        assert!(cache.head.is_some(), "Head should be set after linking");
        assert!(cache.tail.is_some(), "Tail should be set after linking");

        // 调用cache_unlink
        cache.cache_unlink(Rc::clone(&crec_rc));

        // 验证链表状态
        assert!(
            cache.head.is_none(),
            "Head should be None after unlinking single node"
        );
        assert!(
            cache.tail.is_none(),
            "Tail should be None after unlinking single node"
        );

        // 验证节点指针被清理
        let node = crec_rc.borrow();
        assert!(
            node.prev.is_none(),
            "Node should have no previous after unlinking"
        );
        assert!(
            node.next.is_none(),
            "Node should have no next after unlinking"
        );
    }

    #[test]
    fn test_cache_unlink_head_node() {
        let mut cache = Cache::cache_init(100, 0);

        // 创建三个测试记录并链接
        let crec1 = Crec {
            name: "test1.com".to_string(),
            addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            flags: F_FORWARD | F_IPV4,
            ..Crec::default()
        };
        let crec1_rc = Rc::new(RefCell::new(crec1));

        let crec2 = Crec {
            name: "test2.com".to_string(),
            addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))),
            flags: F_FORWARD | F_IPV4,
            ..Crec::default()
        };
        let crec2_rc = Rc::new(RefCell::new(crec2));

        let crec3 = Crec {
            name: "test3.com".to_string(),
            addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3))),
            flags: F_FORWARD | F_IPV4,
            ..Crec::default()
        };
        let crec3_rc = Rc::new(RefCell::new(crec3));

        cache.cache_link(Rc::clone(&crec1_rc));
        cache.cache_link(Rc::clone(&crec2_rc));
        cache.cache_link(Rc::clone(&crec3_rc));

        // 验证初始链表结构：3 -> 2 -> 1
        let initial_head = cache.head.as_ref().unwrap().borrow().name.clone();
        assert_eq!(
            initial_head, "test3.com",
            "Initial head should be test3.com"
        );

        // 移除头部节点（test3.com）
        cache.cache_unlink(Rc::clone(&crec3_rc));

        // 验证新的链表结构：2 -> 1
        assert!(cache.head.is_some(), "Head should still be set");
        assert!(cache.tail.is_some(), "Tail should still be set");

        let new_head_rc = cache.head.as_ref().unwrap();
        let new_head_node = new_head_rc.borrow();
        assert_eq!(
            new_head_node.name, "test2.com",
            "New head should be test2.com"
        );

        // 验证节点2指向节点1
        assert!(
            new_head_node.next.is_some(),
            "New head should have next pointer"
        );
        let next_rc = new_head_node.next.as_ref().unwrap();
        let next_node = next_rc.borrow();
        assert_eq!(next_node.name, "test1.com", "Next should be test1.com");

        // 验证节点1指向节点2（通过prev）
        let tail_rc = cache.tail.as_ref().unwrap();
        let tail_node = tail_rc.borrow();
        assert_eq!(
            tail_node.name, "test1.com",
            "Tail should still be test1.com"
        );
        assert!(
            tail_node.prev.is_some(),
            "Tail should have previous pointer"
        );

        // 验证被移除节点的指针被清理
        let removed_node = crec3_rc.borrow();
        assert!(
            removed_node.prev.is_none(),
            "Removed node should have no previous"
        );
        assert!(
            removed_node.next.is_none(),
            "Removed node should have no next"
        );
    }

    #[test]
    fn test_cache_unlink_tail_node() {
        let mut cache = Cache::cache_init(100, 0);

        // 创建三个测试记录并链接
        let crec1 = Crec {
            name: "test1.com".to_string(),
            addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            flags: F_FORWARD | F_IPV4,
            ..Crec::default()
        };
        let crec1_rc = Rc::new(RefCell::new(crec1));

        let crec2 = Crec {
            name: "test2.com".to_string(),
            addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))),
            flags: F_FORWARD | F_IPV4,
            ..Crec::default()
        };
        let crec2_rc = Rc::new(RefCell::new(crec2));

        let crec3 = Crec {
            name: "test3.com".to_string(),
            addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3))),
            flags: F_FORWARD | F_IPV4,
            ..Crec::default()
        };
        let crec3_rc = Rc::new(RefCell::new(crec3));

        cache.cache_link(Rc::clone(&crec1_rc));
        cache.cache_link(Rc::clone(&crec2_rc));
        cache.cache_link(Rc::clone(&crec3_rc));

        // 验证初始链表结构：3 -> 2 -> 1
        let initial_tail = cache.tail.as_ref().unwrap().borrow().name.clone();
        assert_eq!(
            initial_tail, "test1.com",
            "Initial tail should be test1.com"
        );

        // 移除尾部节点（test1.com）
        cache.cache_unlink(Rc::clone(&crec1_rc));

        // 验证新的链表结构：3 -> 2
        assert!(cache.head.is_some(), "Head should still be set");
        assert!(cache.tail.is_some(), "Tail should still be set");

        let new_tail_rc = cache.tail.as_ref().unwrap();
        let new_tail_node = new_tail_rc.borrow();
        assert_eq!(
            new_tail_node.name, "test2.com",
            "New tail should be test2.com"
        );

        // 验证头部仍然是test3.com
        let new_head_rc = cache.head.as_ref().unwrap();
        let new_head_node = new_head_rc.borrow();
        assert_eq!(
            new_head_node.name, "test3.com",
            "Head should still be test3.com"
        );

        // 验证节点3指向节点2
        assert!(
            new_head_node.next.is_some(),
            "Head should have next pointer"
        );
        let next_rc = new_head_node.next.as_ref().unwrap();
        let next_node = next_rc.borrow();
        assert_eq!(next_node.name, "test2.com", "Next should be test2.com");

        // 验证节点2指向节点3（通过prev）
        assert!(
            new_tail_node.prev.is_some(),
            "Tail should have previous pointer"
        );
        let prev_weak = new_tail_node.prev.as_ref().unwrap();
        let prev_rc = prev_weak
            .upgrade()
            .expect("Previous pointer should be valid");
        let prev_node = prev_rc.borrow();
        assert_eq!(
            prev_node.name, "test3.com",
            "Tail's previous should be test3.com"
        );

        // 验证被移除节点的指针被清理
        let removed_node = crec1_rc.borrow();
        assert!(
            removed_node.prev.is_none(),
            "Removed node should have no previous"
        );
        assert!(
            removed_node.next.is_none(),
            "Removed node should have no next"
        );
    }

    #[test]
    fn test_cache_unlink_middle_node() {
        let mut cache = Cache::cache_init(100, 0);

        // 创建三个测试记录并链接
        let crec1 = Crec {
            name: "test1.com".to_string(),
            addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            flags: F_FORWARD | F_IPV4,
            ..Crec::default()
        };
        let crec1_rc = Rc::new(RefCell::new(crec1));

        let crec2 = Crec {
            name: "test2.com".to_string(),
            addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))),
            flags: F_FORWARD | F_IPV4,
            ..Crec::default()
        };

        let crec2_rc = Rc::new(RefCell::new(crec2));

        let crec3 = Crec {
            name: "test3.com".to_string(),
            addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3))),
            flags: F_FORWARD | F_IPV4,
            ..Crec::default()
        };
        let crec3_rc = Rc::new(RefCell::new(crec3));

        cache.cache_link(Rc::clone(&crec1_rc));
        cache.cache_link(Rc::clone(&crec2_rc));
        cache.cache_link(Rc::clone(&crec3_rc));

        // 验证初始链表结构：3 -> 2 -> 1
        let initial_head = cache.head.as_ref().unwrap().borrow().name.clone();
        assert_eq!(
            initial_head, "test3.com",
            "Initial head should be test3.com"
        );

        // 移除中间节点（test2.com）
        cache.cache_unlink(Rc::clone(&crec2_rc));

        // 验证新的链表结构：3 -> 1
        assert!(cache.head.is_some(), "Head should still be set");
        assert!(cache.tail.is_some(), "Tail should still be set");

        let new_head_rc = cache.head.as_ref().unwrap();
        let new_head_node = new_head_rc.borrow();
        assert_eq!(
            new_head_node.name, "test3.com",
            "Head should still be test3.com"
        );

        let new_tail_rc = cache.tail.as_ref().unwrap();
        let new_tail_node = new_tail_rc.borrow();
        assert_eq!(
            new_tail_node.name, "test1.com",
            "Tail should still be test1.com"
        );

        // 验证节点3指向节点1
        assert!(
            new_head_node.next.is_some(),
            "Head should have next pointer"
        );
        let next_rc = new_head_node.next.as_ref().unwrap();
        let next_node = next_rc.borrow();
        assert_eq!(next_node.name, "test1.com", "Next should be test1.com");

        // 验证节点1指向节点3（通过prev）
        assert!(
            new_tail_node.prev.is_some(),
            "Tail should have previous pointer"
        );
        let prev_weak = new_tail_node.prev.as_ref().unwrap();
        let prev_rc = prev_weak
            .upgrade()
            .expect("Previous pointer should be valid");
        let prev_node = prev_rc.borrow();
        assert_eq!(
            prev_node.name, "test3.com",
            "Tail's previous should be test3.com"
        );

        // 验证被移除节点的指针被清理
        let removed_node = crec2_rc.borrow();
        assert!(
            removed_node.prev.is_none(),
            "Removed node should have no previous"
        );
        assert!(
            removed_node.next.is_none(),
            "Removed node should have no next"
        );
    }
}
