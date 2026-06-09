/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use std::net::{IpAddr, Ipv4Addr};
use std::rc::Rc;
use std::time::SystemTime;
use utdnsmasq::cache::Cache;
use utdnsmasq::dnsmasq::{F_FORWARD, F_HOSTS, F_IPV4, F_REVERSE};

#[test]
fn test_cache_start_insert() {
    let mut cache = Cache::cache_init(100, 0);

    // 测试 cache_start_insert 清空 new_chain
    cache.cache_start_insert();
    assert!(
        cache.new_chain.is_empty(),
        "cache_start_insert should clear new_chain"
    );
}

#[test]
fn test_cache_insert_basic() {
    let mut cache = Cache::cache_init(100, 0);

    // 测试基本插入流程
    cache.cache_start_insert();

    let name = "example.com";
    let addr = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    let now = SystemTime::now();
    let ttl = 3600;
    let flags = F_FORWARD | F_IPV4;

    cache.cache_insert(Some(name), addr, now, ttl, flags);

    // 验证记录被添加到 new_chain
    assert_eq!(
        cache.new_chain.len(),
        1,
        "cache_insert should add one item to new_chain"
    );

    // 验证记录内容
    {
        let inserted_crec = &cache.new_chain[0];
        let crec = inserted_crec.borrow();
        // 注意：在 cache_insert 中，name 可能被设置为空字符串，除非是特定条件
        // 这里我们主要验证记录被正确添加
        assert_eq!(crec.addr, addr, "Address should match");
        assert_eq!(crec.flags, flags, "Flags should match");
    }
}

#[test]
fn test_cache_end_insert() {
    let mut cache = Cache::cache_init(100, 0);

    // 测试完整的插入流程
    cache.cache_start_insert();

    let name = "example.com";
    let addr = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    let now = SystemTime::now();
    let ttl = 3600;
    let flags = F_FORWARD | F_IPV4;

    cache.cache_insert(Some(name), addr, now, ttl, flags);

    let original_length = cache.length;
    cache.cache_end_insert();

    // 验证记录被移动到主缓存
    assert_eq!(
        cache.length,
        original_length + 1,
        "cache_end_insert should add item to main cache"
    );
    assert!(
        cache.new_chain.is_empty(),
        "cache_end_insert should clear new_chain"
    );
}

#[test]
fn test_cache_insert_multiple() {
    let mut cache = Cache::cache_init(100, 0);

    // 测试插入多个记录
    cache.cache_start_insert();

    let now = SystemTime::now();

    // 插入第一个记录
    cache.cache_insert(
        Some("test1.com"),
        Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        now,
        3600,
        F_FORWARD | F_IPV4,
    );
    // 插入第二个记录
    cache.cache_insert(
        Some("test2.com"),
        Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))),
        now,
        3600,
        F_FORWARD | F_IPV4,
    );

    assert_eq!(cache.new_chain.len(), 2, "Should have 2 items in new_chain");

    let original_length = cache.length;
    cache.cache_end_insert();

    // 验证两个记录都被添加
    assert_eq!(
        cache.length,
        original_length + 2,
        "Should add 2 items to main cache"
    );
}

#[test]
fn test_cache_insert_reverse() {
    let mut cache = Cache::cache_init(100, 0);

    // 测试反向记录插入
    cache.cache_start_insert();

    let reverse_name = "1.1.168.192.in-addr.arpa";
    let addr = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    let now = SystemTime::now();
    let ttl = 3600;
    let flags = F_REVERSE | F_IPV4;

    cache.cache_insert(Some(reverse_name), addr, now, ttl, flags);

    // 验证反向记录被添加
    assert_eq!(
        cache.new_chain.len(),
        1,
        "Reverse record should be added to new_chain"
    );

    {
        let inserted_crec = &cache.new_chain[0];
        let crec = inserted_crec.borrow();
        assert_eq!(crec.addr, addr, "Reverse record address should match");
        assert_eq!(crec.flags, flags, "Reverse record flags should match");
    }

    cache.cache_end_insert();
}

#[test]
fn test_cache_link_functionality() {
    let mut cache = Cache::cache_init(100, 0);

    // 测试cache_link功能通过cache_end_insert间接测试
    cache.cache_start_insert();

    // 插入第一个记录
    cache.cache_insert(
        Some("test1.com"),
        Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        SystemTime::now(),
        3600,
        F_FORWARD | F_IPV4,
    );

    // 验证记录在new_chain中但不在主链表中
    assert_eq!(cache.new_chain.len(), 1, "Record should be in new_chain");
    assert_eq!(
        cache.length, 0,
        "Main cache should be empty before cache_end_insert"
    );
    assert!(
        cache.head.is_none(),
        "Head should be None before cache_end_insert"
    );
    assert!(
        cache.tail.is_none(),
        "Tail should be None before cache_end_insert"
    );

    // 执行cache_end_insert，这会调用cache_link
    cache.cache_end_insert();

    // 验证记录被移动到主链表
    assert_eq!(
        cache.new_chain.len(),
        0,
        "new_chain should be empty after cache_end_insert"
    );
    assert_eq!(cache.length, 1, "Main cache should have one record");
    assert!(
        cache.head.is_some(),
        "Head should be set after cache_end_insert"
    );
    assert!(
        cache.tail.is_some(),
        "Tail should be set after cache_end_insert"
    );

    // 验证链表结构正确
    let head_rc = cache.head.as_ref().unwrap();
    let tail_rc = cache.tail.as_ref().unwrap();

    // 在只有一个节点的情况下，head和tail应该指向同一个节点
    assert!(
        Rc::ptr_eq(head_rc, tail_rc),
        "Head and tail should point to same node when only one record exists"
    );

    // 验证节点指针
    let node = head_rc.borrow();
    assert!(node.prev.is_none(), "Single node should have no previous");
    assert!(node.next.is_none(), "Single node should have no next");
}

#[test]
fn test_cache_link_multiple_records() {
    let mut cache = Cache::cache_init(100, 0);

    // 测试多个记录的链表连接功能
    cache.cache_start_insert();

    // 插入三个记录
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

    assert_eq!(
        cache.new_chain.len(),
        3,
        "Should have 3 records in new_chain"
    );

    // 执行cache_end_insert，这会调用cache_link三次
    cache.cache_end_insert();

    // 验证记录被正确链接
    assert_eq!(cache.new_chain.len(), 0, "new_chain should be empty");
    assert_eq!(cache.length, 3, "Main cache should have 3 records");

    // 验证链表结构：3 -> 2 -> 1 (后插入的在前)
    assert!(cache.head.is_some(), "Head should be set");
    assert!(cache.tail.is_some(), "Tail should be set");

    let head_rc = cache.head.as_ref().unwrap();
    let tail_rc = cache.tail.as_ref().unwrap();

    // 验证头部指向最后一个插入的记录（test3.com）
    let head_node = head_rc.borrow();
    assert_eq!(
        head_node.name, "test3.com",
        "Head should point to last inserted record"
    );

    // 验证尾部指向第一个插入的记录（test1.com）
    let tail_node = tail_rc.borrow();
    assert_eq!(
        tail_node.name, "test1.com",
        "Tail should point to first inserted record"
    );

    // 验证链表连接正确
    // 节点3应该指向节点2
    assert!(
        head_node.next.is_some(),
        "Head node should have next pointer"
    );
    let next_rc = head_node.next.as_ref().unwrap();
    let next_node = next_rc.borrow();
    assert_eq!(
        next_node.name, "test2.com",
        "Second node should be test2.com"
    );

    // 节点2应该指向节点1
    assert!(
        next_node.next.is_some(),
        "Second node should have next pointer"
    );
    let next_next_rc = next_node.next.as_ref().unwrap();
    let next_next_node = next_next_rc.borrow();
    assert_eq!(
        next_next_node.name, "test1.com",
        "Third node should be test1.com"
    );

    // 节点1应该是尾部，没有next
    assert!(
        next_next_node.next.is_none(),
        "Tail node should have no next"
    );

    // 验证反向指针
    // 节点1的prev应该指向节点2
    assert!(
        next_next_node.prev.is_some(),
        "Tail node should have previous pointer"
    );
    let prev_weak = next_next_node.prev.as_ref().unwrap();
    let prev_rc = prev_weak
        .upgrade()
        .expect("Previous pointer should be valid");
    let prev_node = prev_rc.borrow();
    assert_eq!(
        prev_node.name, "test2.com",
        "Tail's previous should be test2.com"
    );

    // 节点2的prev应该指向节点3
    assert!(
        next_node.prev.is_some(),
        "Second node should have previous pointer"
    );
    let prev_weak2 = next_node.prev.as_ref().unwrap();
    let prev_rc2 = prev_weak2
        .upgrade()
        .expect("Previous pointer should be valid");
    let prev_node2 = prev_rc2.borrow();
    assert_eq!(
        prev_node2.name, "test3.com",
        "Second node's previous should be test3.com"
    );

    // 节点3应该是头部，没有prev
    assert!(
        head_node.prev.is_none(),
        "Head node should have no previous"
    );
}

#[test]
fn test_move_to_front_functionality() {
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
    let initial_head = cache.head.as_ref().unwrap().borrow().name.clone();
    let initial_tail = cache.tail.as_ref().unwrap().borrow().name.clone();

    // 验证初始顺序：3 -> 2 -> 1
    assert_eq!(
        initial_head, "test3.com",
        "Initial head should be test3.com"
    );
    assert_eq!(
        initial_tail, "test1.com",
        "Initial tail should be test1.com"
    );

    // 通过cache_find_by_name触发move_to_front（非静态记录会被移动）
    let result = cache.cache_find_by_name(None, "test2.com", SystemTime::now(), F_IPV4);
    assert!(result.is_some(), "Should find test2.com");

    // 验证被访问的记录被移动到链表头部
    let new_head = cache.head.as_ref().unwrap().borrow().name.clone();
    assert_eq!(
        new_head, "test2.com",
        "Accessed record should be moved to front"
    );
    assert_ne!(initial_head, new_head, "Head should have changed");

    // 验证链表结构：2 -> 3 -> 1
    let head_rc = cache.head.as_ref().unwrap();
    let head_node = head_rc.borrow();

    // 头部应该是test2.com
    assert_eq!(head_node.name, "test2.com", "Head should be test2.com");

    // 验证下一个节点是test3.com
    assert!(head_node.next.is_some(), "Head should have next pointer");
    let next_rc = head_node.next.as_ref().unwrap();
    let next_node = next_rc.borrow();
    assert_eq!(next_node.name, "test3.com", "Next should be test3.com");

    // 验证下一个节点是test1.com
    assert!(
        next_node.next.is_some(),
        "Second node should have next pointer"
    );
    let next_next_rc = next_node.next.as_ref().unwrap();
    let next_next_node = next_next_rc.borrow();
    assert_eq!(
        next_next_node.name, "test1.com",
        "Third should be test1.com"
    );

    // 验证尾部仍然是test1.com
    let tail_rc = cache.tail.as_ref().unwrap();
    let tail_node = tail_rc.borrow();
    assert_eq!(
        tail_node.name, "test1.com",
        "Tail should still be test1.com"
    );
}

#[test]
fn test_move_to_front_multiple_accesses() {
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

    // 第一次访问test1.com
    let result1 = cache.cache_find_by_name(None, "test1.com", SystemTime::now(), F_IPV4);
    assert!(result1.is_some(), "Should find test1.com");
    let head1 = cache.head.as_ref().unwrap().borrow().name.clone();
    assert_eq!(
        head1, "test1.com",
        "First access should move test1.com to front"
    );

    // 第二次访问test3.com
    let result2 = cache.cache_find_by_name(None, "test3.com", SystemTime::now(), F_IPV4);
    assert!(result2.is_some(), "Should find test3.com");
    let head2 = cache.head.as_ref().unwrap().borrow().name.clone();
    assert_eq!(
        head2, "test3.com",
        "Second access should move test3.com to front"
    );

    // 第三次访问test2.com
    let result3 = cache.cache_find_by_name(None, "test2.com", SystemTime::now(), F_IPV4);
    assert!(result3.is_some(), "Should find test2.com");
    let head3 = cache.head.as_ref().unwrap().borrow().name.clone();
    assert_eq!(
        head3, "test2.com",
        "Third access should move test2.com to front"
    );

    // 验证最终链表结构：2 -> 3 -> 1
    let head_rc = cache.head.as_ref().unwrap();
    let head_node = head_rc.borrow();
    assert_eq!(head_node.name, "test2.com", "Head should be test2.com");

    let next_rc = head_node.next.as_ref().unwrap();
    let next_node = next_rc.borrow();
    assert_eq!(next_node.name, "test3.com", "Next should be test3.com");

    let next_next_rc = next_node.next.as_ref().unwrap();
    let next_next_node = next_next_rc.borrow();
    assert_eq!(
        next_next_node.name, "test1.com",
        "Third should be test1.com"
    );

    let tail_rc = cache.tail.as_ref().unwrap();
    let tail_node = tail_rc.borrow();
    assert_eq!(tail_node.name, "test1.com", "Tail should be test1.com");
}

#[test]
fn test_move_to_front_hosts_records() {
    let mut cache = Cache::cache_init(100, 0);

    // 插入hosts记录（静态记录，不应该被移动）
    cache.cache_start_insert();
    cache.cache_insert(
        Some("hosts.com"),
        Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        SystemTime::now(),
        3600,
        F_FORWARD | F_IPV4 | F_HOSTS,
    );
    cache.cache_insert(
        Some("normal.com"),
        Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))),
        SystemTime::now(),
        3600,
        F_FORWARD | F_IPV4,
    );
    cache.cache_end_insert();

    // 记录初始链表顺序
    let initial_head = cache.head.as_ref().unwrap().borrow().name.clone();
    assert_eq!(
        initial_head, "normal.com",
        "Initial head should be normal.com"
    );

    // 访问hosts记录（静态记录不应该被移动）
    let result = cache.cache_find_by_name(None, "hosts.com", SystemTime::now(), F_IPV4);
    assert!(result.is_some(), "Should find hosts.com");

    // 验证hosts记录没有被移动到头部（因为它是静态记录）
    let new_head = cache.head.as_ref().unwrap().borrow().name.clone();
    assert_eq!(
        new_head, "normal.com",
        "Hosts record should not be moved to front (static record)"
    );

    // 访问普通记录（应该被移动）
    let result2 = cache.cache_find_by_name(None, "normal.com", SystemTime::now(), F_IPV4);
    assert!(result2.is_some(), "Should find normal.com");

    // 验证普通记录被移动到头部
    let final_head = cache.head.as_ref().unwrap().borrow().name.clone();
    assert_eq!(
        final_head, "normal.com",
        "Normal record should be moved to front"
    );
}

#[test]
fn test_cache_find_by_name_with_while_loop() {
    let mut cache = Cache::cache_init(100, 0);

    // 插入多个相同域名的记录
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

    // 使用while循环遍历所有匹配的记录
    let mut results = Vec::new();
    let mut current_result =
        cache.cache_find_by_name(None, "example.com", SystemTime::now(), F_IPV4);

    // 使用while循环收集所有结果
    while let Some(crec_rc) = current_result {
        // 记录找到的结果（先提取需要的信息）
        let addr = {
            let crec = crec_rc.borrow();
            crec.addr
        }; // crec的借用在这里结束

        results.push(addr);

        // 使用当前结果作为参数继续查找下一个记录
        current_result =
            cache.cache_find_by_name(Some(crec_rc), "example.com", SystemTime::now(), F_IPV4);
    }

    // 验证找到了所有三个记录
    assert_eq!(results.len(), 3, "Should find all 3 records");

    // 验证每个记录的地址都不同
    let unique_addrs: std::collections::HashSet<_> = results.iter().collect();
    assert_eq!(unique_addrs.len(), 3, "All addresses should be unique");

    // 验证具体的IP地址
    let expected_addrs = vec![
        Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))),
        Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3))),
    ];

    for expected_addr in expected_addrs {
        assert!(
            results.contains(&expected_addr),
            "Should contain address {:?}",
            expected_addr
        );
    }
}
