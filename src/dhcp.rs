/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use crate::cache::Cache;
use crate::config::{DHCP_CLIENT_PORT, DHCP_SERVER_PORT};
use crate::dnsmasq::{
    DhcpConfig, DhcpContext, DhcpOpt, DhcpPacket, ETHER_ADDR_LEN, IPVERSION, PACKETSZ,
};
use crate::lease::{lease_find_by_addr, lease_prune, lease_update_dns};
use crate::logs::LOG_ERR;
use crate::rfc2131::{dncp_reply, DncpReplyArgs};
use crate::syslog;
use libc::{htons, AF_PACKET, ETH_P_IP};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::util::ipv4_checksum;
use pnet::packet::Packet;
use pnet::util;
use socket2::{SockAddr, SockAddrStorage};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub struct DhcpPacketArgs<'a> {
    pub c_lease_file: &'a PathBuf,
    pub dhcp_configs: &'a [DhcpConfig],
    pub domain_suffix: &'a Option<String>,
    pub dhcp_file: &'a Path,
    pub dhcp_sname: &'a Option<String>,
    pub dhcp_next_server: Ipv4Addr,
    pub dhcp_options: &'a [DhcpOpt],
    pub cache: &'a mut Cache,
    pub now: SystemTime,
}

pub fn dhcp_packet(context: &mut DhcpContext, args: DhcpPacketArgs<'_>) {
    let DhcpPacketArgs {
        c_lease_file,
        dhcp_configs,
        domain_suffix,
        dhcp_file,
        dhcp_sname,
        dhcp_next_server,
        dhcp_options,
        cache,
        now,
    } = args;
    let sz: usize;
    let mut newlen: i32;
    let mut packet = [0u8; PACKETSZ - 20 + 8]; // 20 is the size of IPv4 header
    let udp_socket: std::net::UdpSocket;
    // 接收数据
    if let Some(fd_socket) = &context.fd_socket {
        // 转换为UdpSocket以便接收数据
        udp_socket = match fd_socket.try_clone() {
            Ok(socket) => socket.into(),
            Err(_) => return,
        };

        sz = match udp_socket.recv_from(&mut packet) {
            Ok((n, _)) => {
                // Process the received packet here
                n
            }
            Err(_) => 0,
        }
    } else {
        return;
    }

    // 数据转换为mess类型
    if let Ok(mut parsed_packet) = DhcpPacket::parse(&packet) {
        let mess = &mut parsed_packet;
        if sz > 236 {
            // 236 DHCP 协议数据包本体，固定格式部分（共 236 字节）
            lease_prune(None, now);

            newlen = dncp_reply(DncpReplyArgs {
                context: Some(context),
                mess,
                dhcp_configs,
                domain_suffix,
                dhcp_file,
                dhcp_sname,
                dhcp_next_server,
                dhcp_options,
                sz,
                now,
            }); // 解析数据

            lease_update_dns(c_lease_file, cache, false);

            if newlen != 0 {
                let mut broadcast = mess.flags & 0x8000; // 是否需要广播

                if newlen < 0 {
                    // 广播消息
                    broadcast = 1;
                    newlen = -newlen
                }

                if !mess.giaddr.is_unspecified() || !mess.ciaddr.is_unspecified() {
                    let dest = if !mess.giaddr.is_unspecified() {
                        SocketAddrV4::new(mess.giaddr, DHCP_SERVER_PORT)
                    } else {
                        SocketAddrV4::new(mess.ciaddr, DHCP_CLIENT_PORT)
                    };

                    let _ = udp_socket.send_to(&mess.to_vec(), dest);
                } else {
                    let mut dest = libc::sockaddr_ll {
                        sll_family: AF_PACKET as u16,
                        sll_protocol: htons(ETH_P_IP as u16),
                        sll_ifindex: context.ifindex as i32,
                        sll_hatype: 0,
                        sll_pkttype: 0,
                        sll_halen: ETHER_ADDR_LEN as u8,
                        sll_addr: [0u8; 8],
                    };

                    // 够建发送IP层一下的数据包，绕过内核ip 客户端首次请求ip时，服务端无法通过ip地址和客户端通信
                    // 1. 计算各层长度
                    let ip_header_len: usize = 20; // IP 头部标准长度 (5 * 4 = 20 字节)
                    let udp_header_len: usize = 8; // UDP 头部标准长度
                    let total_len = ip_header_len + udp_header_len + newlen as usize;

                    // 2. 分配缓冲区 dhcp返回数据包，dhcp头 + udp头 + data数据
                    let mut buffer = vec![0u8; total_len];

                    // 使用 split_at_mut 创建非重叠的可变切片
                    let (ip_slice, rest) = buffer.split_at_mut(ip_header_len);
                    let (udp_slice, dhcp_slice) = rest.split_at_mut(udp_header_len);

                    // 3. 填充 IP 头部
                    let mut ip_packet = MutableIpv4Packet::new(ip_slice).unwrap();
                    if broadcast != 0 {
                        dest.sll_addr = [255, 255, 255, 255, 255, 255, 0, 0];
                        ip_packet.set_destination([0xff; 4].into());
                    } else {
                        let mut addr = [0u8; 8];
                        addr[0..6].copy_from_slice(&mess.chaddr[0..6]);
                        dest.sll_addr = addr;
                        ip_packet.set_destination(mess.yiaddr);
                    }
                    // 设置基本字段
                    ip_packet.set_version(IPVERSION); // 版本 IPv4
                    ip_packet.set_header_length(5); // // 头长度 5 * 4 = 20 字节
                    ip_packet.set_total_length(total_len as u16); // 总长度
                    ip_packet.set_ttl(64); // 默认 TTL (IPDEFTTL)
                    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp); // 协议字段
                    ip_packet.set_source(context.serv_addr); // 源地址
                    ip_packet.set_identification(0); // ID = 0
                    ip_packet.set_flags(Ipv4Flags::DontFragment); // 偏移 Don't Fragment (0x4000)
                    ip_packet.set_fragment_offset(0);
                    ip_packet.set_dscp(0); // DSCP = 0
                    ip_packet.set_ecn(0); // ECN = 0

                    // 计算校验和
                    ip_packet.set_checksum(0); // 先清空校验和
                    let checksum = util::checksum(ip_packet.packet(), 30); // skipword 为跳过某个字的计算，全部计算就选择一个大点的数
                    ip_packet.set_checksum(checksum);

                    // 4. 填充 DHCP 数据
                    {
                        // 只复制实际接收到的数据，而不是整个packet数组
                        dhcp_slice[..newlen as usize]
                            .copy_from_slice(&mess.to_vec()[..newlen as usize]);
                    }

                    // 5. 填充 UDP 头部
                    {
                        let mut udp_packet = MutableUdpPacket::new(udp_slice).unwrap();

                        udp_packet.set_source(DHCP_SERVER_PORT);
                        udp_packet.set_destination(DHCP_CLIENT_PORT);
                        udp_packet.set_length((udp_header_len + newlen as usize) as u16);
                        udp_packet.set_checksum(0); // UDP 校验和可选，设为 0

                        // 如果需要计算 UDP 校验和（包含伪头部）
                        // 注意：DHCP 通常使用 UDP 校验和
                        let checksum = calculate_udp_checksum_for_dhcp(
                            &mut udp_packet,
                            &ip_packet.get_source(),
                            &ip_packet.get_destination(),
                            &dhcp_slice[..newlen as usize],
                        );
                        udp_packet.set_checksum(checksum);
                    }

                    let sock_addr = sockaddr_ll_to_sockaddr(&dest);
                    if let Some(socket) = &context.rawfd {
                        let _ = socket.send_to(&buffer, &sock_addr);
                    }
                }
            }
        }
    } else {
        syslog!(LOG_ERR, "DhcpPacket parse error");
    }
}

// 判断地址是否为可用地址
pub fn address_available(context: &DhcpContext, taddr: Ipv4Addr) -> bool {
    let start = context.start;
    let end = context.end;

    // 小于开始地址，大于结束地址， 在租约文件中  表示地址为不可用地址
    if taddr < start || taddr > end || lease_find_by_addr(taddr).is_some() {
        return false;
    }

    true
}
/*
 * 顺序分配算法：从上次分配的地址开始，逐个递增查找可用地址
 * 循环查找：当到达地址池末尾时，回到起始位置继续查找
 * 避免冲突：确保分配的地址不在现有租约中，也不在预留配置中
*/
pub fn address_allocate(
    context: &mut DhcpContext,
    configs: &[DhcpConfig],
    addrp: &mut Ipv4Addr,
) -> Option<Ipv4Addr> {
    let start = context.last;
    let mut is_reserved: bool;
    loop {
        if context.last == context.end {
            // 指针指向末尾
            context.last = context.start // 从start地址开始查找
        } else {
            let ip_as_u32: u32 = u32::from(context.last);
            let next_ip = Ipv4Addr::from(ip_as_u32 + 1); // ip地址 +1
            context.last = next_ip;
        }

        if lease_find_by_addr(context.last).is_none() {
            // 查找是否被占用   未被占用  执行下面代码
            is_reserved = false;
            // 查看是否在配置文件中预留地址
            for config in configs.iter() {
                if config.addr == context.last {
                    // 是否为预留项
                    is_reserved = true;
                    break; // 是预留项 进行下一个ip查找
                }
            }

            // 没被占用，也不在预留项中
            if !is_reserved {
                *addrp = context.last;
                return Some(context.last);
            }
        }

        // 检查是否已经遍历完所有地址
        if context.last == start {
            break;
        }
    }

    None
}

// ip地址是否在指定的DHCP上下文中
fn is_addr_in_context(context: Option<&DhcpContext>, config: Option<&DhcpConfig>) -> bool {
    if context.is_none() {
        return true;
    }

    if let Some(conf) = config {
        // 地址未指明
        if conf.addr.is_unspecified() {
            return true;
        }

        if let Some(cont) = context {
            if conf.addr & cont.netmask == cont.start & cont.netmask {
                return true;
            }
        }
    }

    false
}

pub fn find_config(
    configs: &[DhcpConfig],
    context: Option<&DhcpContext>,
    clid: &[u8],
    clid_len: usize,
    hwaddr: [u8; 6],
    hostname: Option<String>,
) -> Option<DhcpConfig> {
    if clid_len != 0 {
        for config in configs.iter() {
            if config.clid_len == clid_len
                && config.clid == clid
                && is_addr_in_context(context, Some(config))
            {
                return Some(config.clone());
            }

            // dhcpcd将ASCII客户端id前缀为0，这是错误的，但我们在这里尝试解决这个问题
            // 这里应该可以优化，理解ASCII客户端id前缀为0是什么情况后再进行优化
            if !clid.is_empty()
                && clid[0] == 0
                && config.clid_len == clid_len - 1
                && clid.len() > 1
                && config.clid.len() >= clid_len - 1
                && clid[1..] == config.clid[..clid_len - 1]
                && is_addr_in_context(context, Some(config))
            {
                return Some(config.clone());
            }
        }
    }

    // 硬件地址
    for config in configs.iter() {
        if config.hwaddr == hwaddr && is_addr_in_context(context, Some(config)) {
            return Some(config.clone());
        }
    }

    // 主机名
    if let Some(host_name) = hostname {
        for config in configs.iter() {
            if let Some(ref c_hostname) = config.hostname {
                if c_hostname == &host_name && is_addr_in_context(context, Some(config)) {
                    return Some(config.clone());
                }
            }
        }
    }
    None
}

/// 计算 UDP 校验和（包含伪头部）
fn calculate_udp_checksum_for_dhcp(
    udp_packet: &mut MutableUdpPacket,
    source_ip: &Ipv4Addr,
    dest_ip: &Ipv4Addr,
    data: &[u8],
) -> u16 {
    // 关键步骤：将 UDP 头中的校验和字段先设置为 0
    udp_packet.set_checksum(0);

    // 2. 调用 pnet 的 ipv4_checksum 函数
    // 这个函数会自动构建伪首部，并对整个 UDP 报文（包括你的 DHCP 负载）进行计算
    let udp_checksum = ipv4_checksum(
        data,
        1024,
        udp_packet.packet(),
        source_ip,
        dest_ip,
        IpNextHeaderProtocols::Udp, // 指定上层协议为 UDP (17)
    );

    udp_checksum
}

/// 将 sockaddr_ll 转换为 SockAddr
pub fn sockaddr_ll_to_sockaddr(addr: &libc::sockaddr_ll) -> SockAddr {
    let len = std::mem::size_of::<libc::sockaddr_ll>();
    let mut storage = std::mem::MaybeUninit::<SockAddrStorage>::uninit();

    // SAFETY: `storage` 指向一块足够大的未初始化内存；`addr` 指向有效的 `sockaddr_ll`；
    // 复制的字节数与 `sockaddr_ll` 的实际大小一致，且两者不重叠。
    unsafe {
        std::ptr::copy_nonoverlapping(
            (addr as *const libc::sockaddr_ll).cast::<u8>(),
            storage.as_mut_ptr().cast::<u8>(),
            len,
        );
        SockAddr::new(storage.assume_init(), len as u32)
    }
}
