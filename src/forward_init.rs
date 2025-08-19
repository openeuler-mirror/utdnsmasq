/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

 use crate::*;

 pub struct FRec {
     source: crate::MySockAddr,
     sentto: Option<Box<Server>>,
     orig_id: u16,
     new_id: u16,
     fd: i32,
     time: std::time::SystemTime,
     next: Option<Box<FRec>>,
 }
 
 static mut FREC_LIST: Option<Box<FRec>> = None;
 
 pub fn forward_init(first: bool) {
     unsafe {
         // 初始化链表头部
         if first {
             FREC_LIST = None; // 首次调用，清空链表
         }
 
         // 遍历链表并重置每个节点的 new_id 字段
         let mut current = &mut FREC_LIST;
         while let Some(ref mut node) = *current {
             node.new_id = 0;
             current = &mut node.next;
         }
     }
 }
 