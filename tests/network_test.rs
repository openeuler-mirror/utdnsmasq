/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use utdnsmasq::config::Config;
use utdnsmasq::dnsmasq::{
    Server, SERV_FOR_NODOTS, SERV_FROM_RESOLV, SERV_HAS_DOMAIN, SERV_LITERAL_ADDRESS, SERV_NO_ADDR,
};
use utdnsmasq::network::check_servers;

#[test]
fn test_check_servers_basic() {
    let config = Config::default();
    let mut sfds = Vec::new();

    // 创建一个简单的服务器列表
    let server1 = utdnsmasq::dnsmasq::Server {
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
        source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
        flags: 0,
        ..Default::default()
    };

    let server2 = utdnsmasq::dnsmasq::Server {
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
        source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
        flags: 0,
        ..Default::default()
    };

    let mut new_servers = Some(Box::new(server1));
    new_servers.as_mut().unwrap().next = Some(Box::new(server2));

    // 调用check_servers函数
    let result = check_servers(&mut new_servers, &config, &mut sfds);

    // 验证结果不为空
    assert!(result.is_some(), "check_servers should return Some servers");

    // 验证服务器数量正确
    let mut count = 0;
    let mut current = &result;
    while let Some(server) = current {
        count += 1;
        current = &server.next;
    }
    assert_eq!(count, 2, "Should have 2 servers in result");
}

#[test]
fn test_check_servers_with_domain_flag() {
    let config = Config::default();
    let mut sfds = Vec::new();

    // 创建一个带有域标志的服务器
    let server = utdnsmasq::dnsmasq::Server {
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
        source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
        flags: SERV_HAS_DOMAIN,
        domain: "example.com".to_string(),
        ..Default::default()
    };

    let mut new_servers = Some(Box::new(server));

    // 调用check_servers函数
    let result = check_servers(&mut new_servers, &config, &mut sfds);

    // 验证结果不为空
    assert!(
        result.is_some(),
        "Server with domain flag should be accepted"
    );

    // 验证服务器标志和域正确
    if let Some(ref server) = result {
        assert_eq!(
            server.flags & SERV_HAS_DOMAIN,
            SERV_HAS_DOMAIN,
            "Should have domain flag"
        );
        assert_eq!(server.domain, "example.com", "Domain should be preserved");
    }
}

#[test]
fn test_check_servers_with_nodots_flag() {
    let config = Config::default();
    let mut sfds = Vec::new();

    // 创建一个带有无点标志的服务器
    let server = utdnsmasq::dnsmasq::Server {
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
        source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
        flags: SERV_FOR_NODOTS,
        ..Default::default()
    };

    let mut new_servers = Some(Box::new(server));

    // 调用check_servers函数
    let result = check_servers(&mut new_servers, &config, &mut sfds);

    // 验证结果不为空
    assert!(
        result.is_some(),
        "Server with nodots flag should be accepted"
    );

    // 验证服务器标志正确
    if let Some(ref server) = result {
        assert_eq!(
            server.flags & SERV_FOR_NODOTS,
            SERV_FOR_NODOTS,
            "Should have nodots flag"
        );
    }
}

#[test]
fn test_check_servers_with_literal_address() {
    let config = Config::default();
    let mut sfds = Vec::new();

    // 创建一个带有字面地址标志的服务器
    let server = utdnsmasq::dnsmasq::Server {
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
        source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
        flags: SERV_LITERAL_ADDRESS,
        ..Default::default()
    };

    let mut new_servers = Some(Box::new(server));

    // 调用check_servers函数
    let result = check_servers(&mut new_servers, &config, &mut sfds);

    // 验证结果不为空
    assert!(
        result.is_some(),
        "Server with literal address flag should be accepted"
    );

    // 验证服务器标志正确
    if let Some(ref server) = result {
        assert_eq!(
            server.flags & SERV_LITERAL_ADDRESS,
            SERV_LITERAL_ADDRESS,
            "Should have literal address flag"
        );
    }
}

#[test]
fn test_check_servers_with_no_addr() {
    let config = Config::default();
    let mut sfds = Vec::new();

    // 创建一个带有无地址标志的服务器
    let server = utdnsmasq::dnsmasq::Server {
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
        source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
        flags: SERV_NO_ADDR,
        domain: "local.example.com".to_string(),
        ..Default::default()
    };

    let mut new_servers = Some(Box::new(server));

    // 调用check_servers函数
    let result = check_servers(&mut new_servers, &config, &mut sfds);

    // 验证结果不为空
    assert!(
        result.is_some(),
        "Server with no-addr flag should be accepted"
    );

    // 验证服务器标志正确
    if let Some(ref server) = result {
        assert_eq!(
            server.flags & SERV_NO_ADDR,
            SERV_NO_ADDR,
            "Should have no-addr flag"
        );
        assert_eq!(
            server.domain, "local.example.com",
            "Domain should be preserved"
        );
    }
}

#[test]
fn test_check_servers_mixed_flags() {
    let config = Config::default();
    let mut sfds = Vec::new();

    // 创建多个不同标志的服务器
    let server1 = Server {
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
        source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
        flags: SERV_HAS_DOMAIN,
        domain: "domain1.com".to_string(),
        ..Server::default()
    };

    let server2 = Server {
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
        source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
        flags: SERV_FOR_NODOTS,
        ..Server::default()
    };

    let server3 = Server {
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 53),
        source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
        flags: SERV_LITERAL_ADDRESS,
        ..Server::default()
    };

    let mut new_servers = Some(Box::new(server1));
    new_servers.as_mut().unwrap().next = Some(Box::new(server2));
    new_servers.as_mut().unwrap().next.as_mut().unwrap().next = Some(Box::new(server3));

    // 调用check_servers函数
    let result = check_servers(&mut new_servers, &config, &mut sfds);

    // 验证结果不为空
    assert!(result.is_some(), "Mixed flag servers should be accepted");

    // 验证服务器数量和标志正确
    let mut count = 0;
    let mut current = &result;
    while let Some(server) = current {
        count += 1;
        match count {
            3 => {
                assert_eq!(
                    server.flags & SERV_HAS_DOMAIN,
                    SERV_HAS_DOMAIN,
                    "First server should have domain flag"
                );
                assert_eq!(
                    server.domain, "domain1.com",
                    "First server domain should be correct"
                );
            }
            2 => {
                assert_eq!(
                    server.flags & SERV_FOR_NODOTS,
                    SERV_FOR_NODOTS,
                    "Second server should have nodots flag"
                );
            }
            1 => {
                assert_eq!(
                    server.flags & SERV_LITERAL_ADDRESS,
                    SERV_LITERAL_ADDRESS,
                    "Third server should have literal address flag"
                );
            }
            _ => {}
        }
        current = &server.next;
    }
    assert_eq!(count, 3, "Should have 3 servers in result");
}

#[test]
fn test_check_servers_empty_input() {
    let config = Config::default();
    let mut sfds = Vec::new();

    // 空输入
    let mut new_servers = None;

    // 调用check_servers函数
    let result = check_servers(&mut new_servers, &config, &mut sfds);

    // 验证结果为空
    assert!(result.is_none(), "Empty input should return None");
}

#[test]
fn test_check_servers_from_resolv_flag() {
    let config = Config::default();
    let mut sfds = Vec::new();

    // 创建一个来自resolv文件的服务器
    let server = Server {
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
        source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
        flags: SERV_FROM_RESOLV,
        ..Server::default()
    };

    let mut new_servers = Some(Box::new(server));

    // 调用check_servers函数
    let result = check_servers(&mut new_servers, &config, &mut sfds);

    // 验证结果不为空
    assert!(
        result.is_some(),
        "Server with from-resolv flag should be accepted"
    );

    // 验证服务器标志正确
    if let Some(ref server) = result {
        assert_eq!(
            server.flags & SERV_FROM_RESOLV,
            SERV_FROM_RESOLV,
            "Should have from-resolv flag"
        );
    }
}

#[test]
fn test_check_servers_reverse_order() {
    let config = Config::default();
    let mut sfds = Vec::new();

    // 创建多个服务器，每个都有不同的IP地址以便区分
    let server1 = Server {
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
        source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
        flags: 0,
        ..Server::default()
    };

    let server2 = Server {
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), 53),
        source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
        flags: 0,
        ..Server::default()
    };

    let server3 = Server {
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3)), 53),
        source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
        flags: 0,
        ..Server::default()
    };

    // 构建输入链表: server1 -> server2 -> server3
    let mut new_servers = Some(Box::new(server1));
    new_servers.as_mut().unwrap().next = Some(Box::new(server2));
    new_servers.as_mut().unwrap().next.as_mut().unwrap().next = Some(Box::new(server3));

    // 保存输入链表的IP地址顺序用于比较
    let input_ips: Vec<String> = {
        let mut ips = Vec::new();
        let mut current = &new_servers;
        while let Some(server) = current {
            ips.push(server.addr.ip().to_string());
            current = &server.next;
        }
        ips
    };

    // 调用check_servers函数
    let result = check_servers(&mut new_servers, &config, &mut sfds);

    // 验证结果不为空
    assert!(result.is_some(), "check_servers should return Some servers");

    // 获取结果链表的IP地址顺序
    let result_ips: Vec<String> = {
        let mut ips = Vec::new();
        let mut current = &result;
        while let Some(server) = current {
            ips.push(server.addr.ip().to_string());
            current = &server.next;
        }
        ips
    };

    // 验证结果链表是输入链表的反序
    assert_eq!(
        result_ips.len(),
        input_ips.len(),
        "Input and result should have same number of servers"
    );

    // 检查反序关系: 输入 [1.1.1.1, 2.2.2.2, 3.3.3.3] 应该变成 [3.3.3.3, 2.2.2.2, 1.1.1.1]
    for i in 0..input_ips.len() {
        assert_eq!(
            result_ips[i],
            input_ips[input_ips.len() - 1 - i],
            "Server at position {} in result should be server at position {} in input",
            i,
            input_ips.len() - 1 - i
        );
    }

    // 也可以直接比较具体的IP地址顺序
    assert_eq!(
        result_ips[0], "3.3.3.3",
        "First server in result should be last server in input"
    );
    assert_eq!(
        result_ips[1], "2.2.2.2",
        "Second server in result should be second server in input"
    );
    assert_eq!(
        result_ips[2], "1.1.1.1",
        "Third server in result should be first server in input"
    );
}

#[test]
fn test_check_servers_single_server_reverse() {
    let config = Config::default();
    let mut sfds = Vec::new();

    // 创建单个服务器
    let server = Server {
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
        source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
        flags: 0,
        ..Server::default()
    };

    let mut new_servers = Some(Box::new(server));

    // 保存输入服务器的IP地址
    let input_ip = new_servers.as_ref().unwrap().addr.ip().to_string();

    // 调用check_servers函数
    let result = check_servers(&mut new_servers, &config, &mut sfds);

    // 验证结果不为空
    assert!(result.is_some(), "Single server should be accepted");

    // 验证单个服务器的顺序保持不变（单个元素的反序还是它自己）
    if let Some(ref result_server) = result {
        assert_eq!(
            result_server.addr.ip().to_string(),
            input_ip,
            "Single server should remain the same after reverse"
        );
        assert!(
            result_server.next.is_none(),
            "Single server should not have next"
        );
    }
}
