/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

 use std::net::{Ipv4Addr, Ipv6Addr};
 use std::time::SystemTime;
 
 const MAXDNAME: usize = 256; // 后续需要调整
 const SMALLDNAME: usize = 128; // 后续需要调整
 
 #[derive(Debug)]
 pub enum AllAddr {
     Addr4(Ipv4Addr),
     #[cfg(feature = "ipv6")]
     Addr6(Ipv6Addr),
 }
 
 #[derive(Debug)]
 struct BogusAddr {
     addr: Ipv4Addr,
     next: Option<Box<BogusAddr>>,
 }
 
 #[derive(Debug)]
 pub enum BigName {
     Name([char; MAXDNAME]),
     Next(Box<BigName>), // freelist
 }
 
 #[derive(Debug)]
 pub enum Name {
     Sname([char; SMALLDNAME]),
     Bname(Box<BigName>),
     Namep(Box<String>),
 }
 
 #[derive(Debug)]
 pub struct Crec {
     next: Option<*mut Crec>,
     prev: Option<*mut Crec>,
     hash_next: Option<*mut Crec>,
     ttd: SystemTime,
     addr: AllAddr,
     flags: u16,
     name: Name,
 }
 
 #[derive(Debug)]
 pub struct Cache {
     cache_size: usize,
     cache_head: Option<*mut Crec>,
     cache_tail: Option<*mut Crec>,
     dhcp_inuse: Option<*mut Crec>,
     dhcp_spare: Option<*mut Crec>,
     new_chain: Option<*mut Crec>,
     big_free: Option<Box<BigName>>,
     bignames_left: usize,
     log_queries: u32,
     cache_inserted: usize,
     cache_live_freed: usize,
     hash_table: Vec<Option<*mut Crec>>,
     hash_size: usize,
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
 
