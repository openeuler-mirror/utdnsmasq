/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use crate::*;

const ETHER_ADDR_LEN: usize = 6;

// DHCP 配置列表中查找与给定参数匹配的配置项
pub fn find_config(
    configs: &mut Option<Box<DhcpConfig>>,
    context: Option<&DhcpContext>,
    clid: Vec<u8>,                 // 客户端标识符
    clid_len: usize,               // 客户端标识符长度
    hwaddr: &[u8; ETHER_ADDR_LEN], // 硬件地址
    hostname: Option<&str>,        // 主机名
) -> Option<Box<DhcpConfig>> {
    let mut config_ptr = configs.as_mut();

    // 查找基于 clid
    if clid_len > 0 {
        while let Some(config) = config_ptr {
            // 检查 clid 是否匹配
            if config.clid_len == clid_len && config.clid == clid {
                if is_addr_in_context(context, config) {
                    return Some(config.clone()); // 返回匹配的配置
                }
            }

            // 处理 ASCII client ID 的前缀问题
            if clid[0] == 0 && config.clid_len == clid_len - 1 && &config.clid[..] == &clid[1..] {
                if is_addr_in_context(context, config) {
                    return Some(config.clone()); // 返回匹配的配置
                }
            }

            config_ptr = config.next.as_mut(); // 移动到下一个配置
        }
    }

    // 查找基于 hwaddr
    config_ptr = configs.as_mut();
    while let Some(config) = config_ptr {
        if &config.hwaddr == hwaddr && is_addr_in_context(context, config) {
            return Some(config.clone()); // 返回匹配的配置
        }
        config_ptr = config.next.as_mut(); // 移动到下一个配置
    }

    // 查找基于 hostname
    if let Some(host) = hostname {
        config_ptr = configs.as_mut();
        while let Some(config) = config_ptr {
            if let Some(ref config_hostname) = config.hostname {
                if config_hostname == host && is_addr_in_context(context, config) {
                    return Some(config.clone()); // 返回匹配的配置
                }
            }
            config_ptr = config.next.as_mut(); // 移动到下一个配置
        }
    }

    None // 如果没有找到，返回 None
}

//判断一个 DHCP 配置的地址是否在给定的上下文中
pub fn is_addr_in_context(context: Option<&DhcpContext>, config: &DhcpConfig) -> bool {
    // 如果没有上下文，返回 true
    if context.is_none() {
        return true;
    }

    let context = context.unwrap();

    // 如果配置的地址为 0.0.0.0，返回 true
    if config.addr == Ipv4Addr::new(0, 0, 0, 0) {
        return true;
    }

    // 检查地址是否在上下文中
    let addr_masked = config
        .addr
        .octets()
        .iter()
        .zip(context.netmask.octets().iter())
        .map(|(&a, &m)| a & m)
        .collect::<Vec<u8>>();

    let start_masked = context
        .start
        .octets()
        .iter()
        .zip(context.netmask.octets().iter())
        .map(|(&s, &m)| s & m)
        .collect::<Vec<u8>>();

    addr_masked == start_masked // 返回是否相等
}
