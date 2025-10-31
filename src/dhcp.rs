/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use crate::*;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::Packet;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

const PACKETSZ: usize = 1500; // 数据包的最大大小
const DHCP_SERVER_PORT: u16 = 67; // DHCP服务器端口
const DHCP_CLIENT_PORT: u16 = 68; // DHCP客户端端口
const ETHERTYPE_IP: u16 = 0x0800;
const ETHER_ADDR_LEN: usize = 6;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ip {
    pub version_and_header_length: u8,
    pub tos: u8,
    pub total_length: u16,
    pub id: u16,
    pub flags_and_fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UdpHdr {
    pub uh_sport: u16,
    pub uh_dport: u16,
    pub uh_ulen: u16,
    pub uh_sum: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DhcpPacket {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: [u8; 16],
    pub sname: [u8; 64],
    pub file: [u8; 128],
    pub cookie: u32,
    pub options: [u8; 308],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UdpDhcpPacket {
    pub ip: Ip,
    pub udp: UdpHdr,
    pub data: DhcpPacket,
}
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

// 处理 DHCP 数据包
pub fn dhcp_packet(
    caches: &mut Cache,
    context: Option<&mut DhcpContext>,
    packet: &mut Vec<u8>,
    dhcp_opts: Option<Box<DhcpOpt>>,
    dhcp_configs: Option<Box<DhcpConfig>>,
    now: SystemTime,
    namebuff: &mut [u8],
    domain_suffix: Option<String>,
    dhcp_file: &mut Option<&mut String>,
    dhcp_sname: &mut Option<&mut String>,
    dhcp_next_server: Ipv4Addr,
) {
    // 将接收到的数据转换为 UdpDhcpPacket 结构体
    let rawpacket = unsafe { &mut *(packet.as_mut_ptr() as *mut UdpDhcpPacket) };

    // 如果有 DHCP 上下文则继续处理
    if let Some(context) = context {
        // 使用标准库的 `UdpSocket` 接收 DHCP 请求
        let socket = UdpSocket::bind(SocketAddr::new(
            Ipv4Addr::UNSPECIFIED.into(),
            DHCP_SERVER_PORT,
        ))
        .expect("Failed to bind to DHCP server port");

        let sz = socket.recv(packet).expect("Failed to receive packet");

        // 检查数据包是否为有效大小
        if sz > (std::mem::size_of::<DhcpPacket>()) {
            lease_prune(None, now); // 清除过期租约

            // 提前处理 dhcp_file 和 dhcp_sname，以避免所有权问题
            let mut default_file = String::new();
            let dhcp_file_ref = dhcp_file.as_deref_mut().unwrap_or(&mut default_file);

            let mut default_sname = String::new();
            let dhcp_sname_ref = dhcp_sname.as_deref_mut().unwrap_or(&mut default_sname);

            let newlen = dhcp_reply(
                context,
                &mut rawpacket.data,
                sz,
                now,
                namebuff,
                &dhcp_opts.unwrap(),
                &dhcp_configs.unwrap(),
                domain_suffix.unwrap_or_default(),
                dhcp_file_ref,
                dhcp_sname_ref,
                dhcp_next_server,
            );

            let _ = lease_update_dns(caches, 0); // 更新 DNS 租约

            if newlen != 0 {
                let mut broadcast = (u16::from_be(rawpacket.data.flags) & 0x8000) != 0;

                if newlen < 0 {
                    broadcast = true;
                }

                // 判断是否需要发送到网关或客户端地址
                if !rawpacket.data.giaddr.is_unspecified()
                    || !rawpacket.data.ciaddr.is_unspecified()
                {
                    let dest = SocketAddr::new(
                        if !rawpacket.data.giaddr.is_unspecified() {
                            std::net::IpAddr::V4(rawpacket.data.giaddr)
                        } else {
                            std::net::IpAddr::V4(rawpacket.data.ciaddr)
                        },
                        if !rawpacket.data.giaddr.is_unspecified() {
                            DHCP_SERVER_PORT
                        } else {
                            DHCP_CLIENT_PORT
                        },
                    );

                    socket
                        .send_to(&packet[..newlen as usize], dest)
                        .expect("Failed to send DHCP packet");
                } else {
                    // 使用 `pnet` 库构建并发送广播包
                    if broadcast {
                        let mut ethernet_buffer = [0u8; 42]; // 42字节是以太网帧头的大小
                        let mut ethernet_packet =
                            MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
                        ethernet_packet.set_destination([0xff; 6].into());
                        ethernet_packet.set_source(context.hwaddr.into());
                        ethernet_packet
                            .set_ethertype(pnet::packet::ethernet::EtherType(ETHERTYPE_IP));

                        let mut ipv4_buffer = [0u8; 20]; // 20字节是IPv4头的大小
                        let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
                        ipv4_packet.set_version(4);
                        ipv4_packet.set_header_length(5);
                        ipv4_packet.set_total_length((20 + newlen as u16) as u16);
                        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
                        ipv4_packet.set_source(context.serv_addr);
                        ipv4_packet.set_destination(Ipv4Addr::BROADCAST);
                        ipv4_packet.set_checksum(ipv4_checksum(&ipv4_packet));

                        let mut udp_buffer = [0u8; 8 + PACKETSZ]; // 8字节是UDP头的大小
                        let mut udp_packet =
                            MutableUdpPacket::new(&mut udp_buffer[..8 + newlen as usize]).unwrap();
                        udp_packet.set_source(DHCP_SERVER_PORT);
                        udp_packet.set_destination(DHCP_CLIENT_PORT);
                        udp_packet.set_length((8 + newlen as u16) as u16);
                        udp_packet.set_payload(&packet[..newlen as usize]);

                        let _ = socket.send(&ethernet_packet.packet());
                    }
                }
            }
        }
    }
}

// 计算 IPv4 数据包的校验和
fn ipv4_checksum(packet: &MutableIpv4Packet) -> u16 {
    let mut sum = 0u32;

    // 将 IPv4 报头数据逐个 16 位进行累加
    for i in (0..packet.packet().len()).step_by(2) {
        let word = ((packet.packet()[i] as u32) << 8) + packet.packet()[i + 1] as u32;
        sum += word;
    }

    // 把进位加回去
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // 返回反码
    !(sum as u16)
}
