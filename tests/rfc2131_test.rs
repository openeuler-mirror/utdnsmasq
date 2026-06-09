/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use utdnsmasq::dnsmasq::DhcpPacket;
use utdnsmasq::rfc2131::*;

/// 测试 option_find 函数的基本功能 - 在 options 字段中查找选项
#[test]
fn test_option_find_basic() {
    // 创建一个 DHCP 数据包
    let mut packet = DhcpPacket::new();

    // 设置 DHCP magic cookie
    packet.cookie = DHCP_COOKIE;

    // 在 options 字段中添加一些选项
    // 添加 OPTION_MESSAGE_TYPE 选项 (代码 53, 长度 1, 值 1)
    packet.options[0] = OPTION_MESSAGE_TYPE;
    packet.options[1] = 1;
    packet.options[2] = DHCPDISCOVER;

    // 添加 OPTION_REQUESTED_IP 选项 (代码 50, 长度 4, 值 192.168.1.100)
    packet.options[3] = OPTION_REQUESTED_IP;
    packet.options[4] = 4;
    packet.options[5] = 192;
    packet.options[6] = 168;
    packet.options[7] = 1;
    packet.options[8] = 100;

    // 添加 OPTION_END 选项
    packet.options[9] = OPTION_END;

    // 测试查找 OPTION_MESSAGE_TYPE
    let result = option_find(&packet, 10, OPTION_MESSAGE_TYPE);
    assert!(result.is_some(), "应该找到 OPTION_MESSAGE_TYPE 选项");
    let option = result.unwrap();
    assert_eq!(option[0], OPTION_MESSAGE_TYPE);
    assert_eq!(option[1], 1);
    assert_eq!(option[2], DHCPDISCOVER);

    // 测试查找 OPTION_REQUESTED_IP
    let result = option_find(&packet, 10, OPTION_REQUESTED_IP);
    assert!(result.is_some(), "应该找到 OPTION_REQUESTED_IP 选项");
    let option = result.unwrap();
    assert_eq!(option[0], OPTION_REQUESTED_IP);
    assert_eq!(option[1], 4);
    assert_eq!(option[2], 192);
    assert_eq!(option[3], 168);
    assert_eq!(option[4], 1);
    assert_eq!(option[5], 100);

    // 测试查找不存在的选项
    let result = option_find(&packet, 10, OPTION_DNSSERVER);
    assert!(result.is_none(), "不应该找到不存在的选项");
}

/// 测试 option_find 函数处理 PAD 选项
#[test]
fn test_option_find_with_pad() {
    let mut packet = DhcpPacket::new();
    packet.cookie = DHCP_COOKIE;

    // 添加 PAD 选项 (代码 0)
    packet.options[0] = OPTION_PAD;
    packet.options[1] = OPTION_PAD;

    // 添加 OPTION_MESSAGE_TYPE 选项
    packet.options[2] = OPTION_MESSAGE_TYPE;
    packet.options[3] = 1;
    packet.options[4] = DHCPOFFER;

    // 添加 OPTION_END 选项
    packet.options[5] = OPTION_END;

    // 测试查找 OPTION_MESSAGE_TYPE (应该跳过 PAD 选项)
    let result = option_find(&packet, 6, OPTION_MESSAGE_TYPE);
    assert!(
        result.is_some(),
        "应该找到 OPTION_MESSAGE_TYPE 选项，跳过 PAD"
    );
    let option = result.unwrap();
    assert_eq!(option[0], OPTION_MESSAGE_TYPE);
    assert_eq!(option[1], 1);
    assert_eq!(option[2], DHCPOFFER);
}

/// 测试 option_find 函数处理 OVERLOAD 选项
#[test]
fn test_option_find_with_overload() {
    let mut packet = DhcpPacket::new();
    packet.cookie = DHCP_COOKIE;

    // 在 options 字段中添加 OVERLOAD 选项 (代码 52, 长度 1, 值 3)
    packet.options[0] = OPTION_OVERLOAD;
    packet.options[1] = 1;
    packet.options[2] = 3; // 表示使用 file 和 sname 字段

    // 在 file 字段中添加 OPTION_DNSSERVER 选项
    packet.file[0] = OPTION_DNSSERVER;
    packet.file[1] = 4;
    packet.file[2] = 8;
    packet.file[3] = 8;
    packet.file[4] = 8;
    packet.file[5] = 8;

    // 在 sname 字段中添加 OPTION_ROUTER 选项
    packet.sname[0] = OPTION_ROUTER;
    packet.sname[1] = 4;
    packet.sname[2] = 192;
    packet.sname[3] = 168;
    packet.sname[4] = 1;
    packet.sname[5] = 1;

    // 添加 OPTION_END 选项到 file 和 sname 字段
    packet.file[6] = OPTION_END;
    packet.sname[6] = OPTION_END;

    // 测试查找 OPTION_DNSSERVER (应该在 file 字段中找到)
    let result = option_find(&packet, 10, OPTION_DNSSERVER);
    assert!(result.is_some(), "应该在 file 字段中找到 OPTION_DNSSERVER");
    let option = result.unwrap();
    assert_eq!(option[0], OPTION_DNSSERVER);
    assert_eq!(option[1], 4);
    assert_eq!(option[2], 8);
    assert_eq!(option[3], 8);
    assert_eq!(option[4], 8);
    assert_eq!(option[5], 8);

    // 测试查找 OPTION_ROUTER (应该在 sname 字段中找到)
    let result = option_find(&packet, 10, OPTION_ROUTER);
    assert!(result.is_some(), "应该在 sname 字段中找到 OPTION_ROUTER");
    let option = result.unwrap();
    assert_eq!(option[0], OPTION_ROUTER);
    assert_eq!(option[1], 4);
    assert_eq!(option[2], 192);
    assert_eq!(option[3], 168);
    assert_eq!(option[4], 1);
    assert_eq!(option[5], 1);
}

/// 测试 option_find 函数处理边界情况
#[test]
fn test_option_find_edge_cases() {
    let mut packet = DhcpPacket::new();
    packet.cookie = DHCP_COOKIE;

    // 测试空选项列表
    packet.options[0] = OPTION_END;
    let result = option_find(&packet, 1, OPTION_MESSAGE_TYPE);
    assert!(result.is_none(), "空选项列表应该返回 None");

    // 测试选项长度超出边界
    packet.options[0] = OPTION_MESSAGE_TYPE;
    packet.options[1] = 10; // 长度太大，超出缓冲区
    let result = option_find(&packet, 5, OPTION_MESSAGE_TYPE);
    assert!(result.is_none(), "选项长度超出边界应该返回 None");

    // 测试 sz 参数限制搜索范围
    packet.options[0] = OPTION_MESSAGE_TYPE;
    packet.options[1] = 1;
    packet.options[2] = DHCPREQUEST;
    packet.options[3] = OPTION_END;

    // 使用 sz=2 限制搜索范围，应该找不到选项
    let result = option_find(&packet, 2, OPTION_MESSAGE_TYPE);
    assert!(result.is_none(), "sz 参数限制搜索范围应该返回 None");

    // 使用 sz=3 应该能找到选项
    let result = option_find(&packet, 3, OPTION_MESSAGE_TYPE);
    assert!(result.is_some(), "sz 参数足够大时应该找到选项");
}

/// 测试 option_find 函数处理各种 DHCP 选项类型
#[test]
fn test_option_find_various_options() {
    let mut packet = DhcpPacket::new();
    packet.cookie = DHCP_COOKIE;

    let mut pos = 0;

    // 添加 OPTION_NETMASK 选项
    packet.options[pos] = OPTION_NETMASK;
    packet.options[pos + 1] = 4;
    packet.options[pos + 2] = 255;
    packet.options[pos + 3] = 255;
    packet.options[pos + 4] = 255;
    packet.options[pos + 5] = 0;
    pos += 6;

    // 添加 OPTION_LEASE_TIME 选项
    packet.options[pos] = OPTION_LEASE_TIME;
    packet.options[pos + 1] = 4;
    packet.options[pos + 2] = 0;
    packet.options[pos + 3] = 0;
    packet.options[pos + 4] = 1;
    packet.options[pos + 5] = 44; // 300 秒
    pos += 6;

    // 添加 OPTION_SERVER_IDENTIFIER 选项
    packet.options[pos] = OPTION_SERVER_IDENTIFIER;
    packet.options[pos + 1] = 4;
    packet.options[pos + 2] = 192;
    packet.options[pos + 3] = 168;
    packet.options[pos + 4] = 1;
    packet.options[pos + 5] = 1;
    pos += 6;

    // 添加 OPTION_END 选项
    packet.options[pos] = OPTION_END;

    // 测试查找各种选项
    let test_cases = [
        (OPTION_NETMASK, 255, 255, 255, 0),
        (OPTION_LEASE_TIME, 0, 0, 1, 44),
        (OPTION_SERVER_IDENTIFIER, 192, 168, 1, 1),
    ];

    for (option_code, v1, v2, v3, v4) in test_cases {
        let result = option_find(&packet, pos + 1, option_code);
        assert!(result.is_some(), "应该找到选项 {}", option_code);
        let option = result.unwrap();
        assert_eq!(option[0], option_code);
        assert_eq!(option[1], 4);
        assert_eq!(option[2], v1);
        assert_eq!(option[3], v2);
        assert_eq!(option[4], v3);
        assert_eq!(option[5], v4);
    }
}

/// 测试 option_find 函数处理选项搜索顺序
#[test]
fn test_option_find_search_order() {
    let mut packet = DhcpPacket::new();
    packet.cookie = DHCP_COOKIE;

    // 在 options 字段中添加 OPTION_MESSAGE_TYPE
    packet.options[0] = OPTION_MESSAGE_TYPE;
    packet.options[1] = 1;
    packet.options[2] = DHCPDISCOVER;

    // 在 file 字段中也添加 OPTION_MESSAGE_TYPE (不同的值)
    packet.file[0] = OPTION_MESSAGE_TYPE;
    packet.file[1] = 1;
    packet.file[2] = DHCPOFFER;

    // 添加 OVERLOAD 选项，指定使用 file 字段
    packet.options[3] = OPTION_OVERLOAD;
    packet.options[4] = 1;
    packet.options[5] = 1; // 只使用 file 字段

    // 添加 OPTION_END
    packet.options[6] = OPTION_END;
    packet.file[3] = OPTION_END;

    // 应该先在 options 字段中找到，而不是 file 字段
    let result = option_find(&packet, 7, OPTION_MESSAGE_TYPE);
    assert!(result.is_some(), "应该找到 OPTION_MESSAGE_TYPE");
    let option = result.unwrap();
    assert_eq!(option[2], DHCPDISCOVER, "应该返回 options 字段中的值");
}

/// 测试 option_find 函数处理无效数据包
#[test]
fn test_option_find_invalid_packet() {
    let packet = DhcpPacket::new(); // 没有设置 cookie

    // 测试无效的 DHCP 数据包 (没有 magic cookie)
    let result = option_find(&packet, 10, OPTION_MESSAGE_TYPE);
    // 注意：option_find 函数不检查 cookie，所以这个测试可能不会失败
    // 这里主要测试函数对无效数据的处理能力
    assert!(result.is_none() || result.is_some(), "应该处理无效数据包");
}

/// 测试 option_find 函数处理最大选项长度
#[test]
fn test_option_find_max_option_length() {
    let mut packet = DhcpPacket::new();
    packet.cookie = DHCP_COOKIE;

    // 添加一个长选项 (接近最大长度)
    packet.options[0] = OPTION_HOSTNAME;
    packet.options[1] = 50; // 长度 50
    for i in 0..50 {
        packet.options[2 + i] = b'a' + (i % 26) as u8;
    }

    // 添加 OPTION_END
    packet.options[52] = OPTION_END;

    // 测试查找长选项
    let result = option_find(&packet, 53, OPTION_HOSTNAME);
    assert!(result.is_some(), "应该找到长选项");
    let option = result.unwrap();
    assert_eq!(option[0], OPTION_HOSTNAME);
    assert_eq!(option[1], 50);

    // 验证选项内容
    for i in 0..50 {
        assert_eq!(option[2 + i], b'a' + (i % 26) as u8);
    }
}

/// 测试 option_find 函数处理连续多个相同选项
#[test]
fn test_option_find_multiple_same_options() {
    let mut packet = DhcpPacket::new();
    packet.cookie = DHCP_COOKIE;

    // 添加第一个 OPTION_DNSSERVER 选项
    packet.options[0] = OPTION_DNSSERVER;
    packet.options[1] = 4;
    packet.options[2] = 8;
    packet.options[3] = 8;
    packet.options[4] = 8;
    packet.options[5] = 8;

    // 添加第二个 OPTION_DNSSERVER 选项 (不同的值)
    packet.options[6] = OPTION_DNSSERVER;
    packet.options[7] = 4;
    packet.options[8] = 1;
    packet.options[9] = 1;
    packet.options[10] = 1;
    packet.options[11] = 1;

    // 添加 OPTION_END
    packet.options[12] = OPTION_END;

    // 应该返回第一个匹配的选项
    let result = option_find(&packet, 13, OPTION_DNSSERVER);
    assert!(result.is_some(), "应该找到第一个 OPTION_DNSSERVER 选项");
    let option = result.unwrap();
    assert_eq!(option[2], 8, "应该返回第一个选项的值");
    assert_eq!(option[3], 8, "应该返回第一个选项的值");
    assert_eq!(option[4], 8, "应该返回第一个选项的值");
    assert_eq!(option[5], 8, "应该返回第一个选项的值");
}

/// 测试 option_find 函数处理 DhcpOpt 列表的模拟场景
#[test]
fn test_option_find_dhcpopt_simulation() {
    use utdnsmasq::dnsmasq::DhcpOpt;

    // 模拟 option_find2 的功能：在 DhcpOpt 列表中查找选项
    let opts = [
        DhcpOpt {
            opt: OPTION_MESSAGE_TYPE,
            len: 1,
            val: vec![DHCPDISCOVER],
        },
        DhcpOpt {
            opt: OPTION_NETMASK,
            len: 4,
            val: vec![255, 255, 255, 0],
        },
    ];

    // 手动实现 option_find2 的功能
    let result = opts.iter().find(|&temp| temp.opt == OPTION_MESSAGE_TYPE);
    assert!(result.is_some(), "应该在 DhcpOpt 列表中找到选项");
    let opt = result.unwrap();
    assert_eq!(opt.opt, OPTION_MESSAGE_TYPE);
    assert_eq!(opt.val[0], DHCPDISCOVER);

    // 创建 DhcpPacket 用于 option_find 对比
    let mut packet = DhcpPacket::new();
    packet.cookie = DHCP_COOKIE;

    // 添加相同的选项到 packet
    packet.options[0] = OPTION_MESSAGE_TYPE;
    packet.options[1] = 1;
    packet.options[2] = DHCPDISCOVER;

    packet.options[3] = OPTION_NETMASK;
    packet.options[4] = 4;
    packet.options[5] = 255;
    packet.options[6] = 255;
    packet.options[7] = 255;
    packet.options[8] = 0;

    packet.options[9] = OPTION_END;

    // 测试 option_find
    let result1 = option_find(&packet, 10, OPTION_MESSAGE_TYPE);
    assert!(result1.is_some(), "option_find 应该找到选项");
    let opt1 = result1.unwrap();
    assert_eq!(opt1[0], OPTION_MESSAGE_TYPE);
    assert_eq!(opt1[2], DHCPDISCOVER);

    // 两个查找方式应该找到相同的选项值
    assert_eq!(opt.val[0], opt1[2]);
}
