/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use crate::cache::{cache_add_dhcp_entry, cache_unhash_dhcp, Cache};
use crate::dhcp::find_config;
use crate::dnsmasq::F_REVERSE;
use crate::logs::die;
use crate::util::{difftime, hostname_isequal, system_time_to_u64};
use crate::{config::Config, dnsmasq::DhcpLease};
use lazy_static::lazy_static;
use std::fs::OpenOptions;
use std::io::{self, BufRead, Write};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

lazy_static! {
    pub static ref LEASES: Mutex<Vec<DhcpLease>> = Mutex::new(Vec::new());
    static ref DNS_DIRTY: Mutex<bool> = Mutex::new(false);
    static ref FILE_DIRTY: Mutex<bool> = Mutex::new(false);
}

pub fn lease_init(config: &mut Config, now: SystemTime) -> i32 {
    let mut has_old: bool = false;

    // let now_unix = now.duration_since(UNIX_EPOCH).unwrap().as_secs();

    let mut leases: MutexGuard<'_, Vec<DhcpLease>> = LEASES.lock().unwrap();

    // 以追加模式打开文件
    match OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(&config.lease_file)
    {
        Ok(file) => {
            let reader = io::BufReader::new(&file);

            // 逐行读取租约文件
            for line in reader.lines() {
                let line = line.unwrap();
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() != 5 {
                    continue; // 忽略格式不正确的行
                }

                // 解析租约信息
                let ei: u64 = parts[0].parse().unwrap(); // 租约时间
                let hwaddr = parts[1]; // mac地址
                let addr = match Ipv4Addr::from_str(parts[2]) {
                    Ok(ip) => ip,
                    Err(_) => {
                        println!("租约文件解析错误，ip地址解析错误");
                        return 0;
                    }
                }; // ip地址
                let buff = parts[3]; // 主机名
                let buff2 = parts[4]; // 客户端标识符

                // 检查租约是否过期
                let expires = UNIX_EPOCH + std::time::Duration::from_secs(ei);
                if ei != 0 && difftime(now, expires) > 0 {
                    has_old = true;
                    continue; // 跳过过期的租约
                }

                let (clid_len, clid) = if buff2 == "*" {
                    (0, Vec::new())
                } else {
                    let mut cli_bytes = Vec::with_capacity(4);
                    let cli_parts: Vec<&str> = buff2.split(":").collect();
                    if cli_parts.len() == 4 {
                        for part in cli_parts {
                            if let Ok(byte) = u8::from_str_radix(part, 16) {
                                cli_bytes.push(byte);
                            } else {
                                cli_bytes.push(0);
                            }
                        }
                    }
                    (cli_bytes.len(), cli_bytes)
                };
                // Parse MAC address from string to [u8; 6]
                let mut hwaddr_bytes = [0u8; 6];
                let hwaddr_parts: Vec<&str> = hwaddr.split(':').collect();
                if hwaddr_parts.len() == 6 {
                    for (i, part) in hwaddr_parts.iter().enumerate() {
                        hwaddr_bytes[i] = u8::from_str_radix(part, 16).unwrap_or(0);
                    }
                }

                let mut lease = DhcpLease {
                    clid_len,
                    clid,
                    hwaddr: hwaddr_bytes,
                    hostname: None,
                    fqdn: None,
                    addr,
                    expires,
                    // next: None,
                };

                if buff != "*" {
                    lease_set_hostname(&mut lease, buff, &config.domain_suffix, &mut leases);
                }

                leases.push(lease);
            }

            let mut dns_dity = DNS_DIRTY.lock().unwrap();
            let mut file_dity = FILE_DIRTY.lock().unwrap();
            *dns_dity = true;
            *file_dity = has_old;

            // Process leases to set hostnames from DHCP config
            let mut leases_to_update: Vec<(usize, String)> = Vec::new();

            for (i, lease) in leases.iter().enumerate() {
                let dchp_config = find_config(
                    &config.dhcp_configs,
                    None,
                    &lease.clid,
                    lease.clid_len,
                    lease.hwaddr,
                    None,
                );
                if let Some(d_config) = dchp_config {
                    if let Some(d_hostname) = &d_config.hostname {
                        leases_to_update.push((i, d_hostname.clone()));
                    }
                }
            }

            // Apply hostname updates after collecting them
            for (i, hostname) in leases_to_update {
                if let Some(lease) = leases.get_mut(i) {
                    lease_set_hostname_single(lease, &hostname, &config.domain_suffix);
                }
            }

            file.as_raw_fd()
        }

        Err(_) => {
            die(
                "cannot open or create leases file:",
                config.lease_file.to_str().unwrap(),
            );
            0
        }
    }
}

// 更新 DHCP 租约文件（如果有更改）。
// 更新与 DHCP 租约相关的 DNS 缓存。
pub fn lease_update_dns(c_lease_file: &PathBuf, cache: &mut Cache, force_dns: bool) {
    let mut dns_dity = DNS_DIRTY.lock().unwrap();
    let mut file_dity = FILE_DIRTY.lock().unwrap();
    let mut leases = LEASES.lock().unwrap();

    if *file_dity {
        // 打开或创建文件
        let mut lease_file = OpenOptions::new()
            .write(true)
            .truncate(true) // 打开时自动清空文件
            .open(c_lease_file)
            .expect("租约文件打开失败");

        for lease in leases.iter_mut() {
            let expires = system_time_to_u64(lease.expires).unwrap();
            write!(
                lease_file,
                "{} {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} {} {} ",
                expires,
                lease.hwaddr[0],
                lease.hwaddr[1],
                lease.hwaddr[2],
                lease.hwaddr[3],
                lease.hwaddr[4],
                lease.hwaddr[5],
                lease.addr,
                lease.hostname.as_deref().unwrap_or("*")
            )
            .expect("租约文件写入失败");

            if lease.clid_len > 0 {
                // Convert Vec<u8> to hex string for writing to file
                let clid_hex: String = lease
                    .clid
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<String>>()
                    .join(":");
                writeln!(lease_file, "{}", clid_hex).expect("租约文件写入客户端id失败");
            } else {
                writeln!(lease_file, "*").expect("租约文件写入 客户端 * 失败");
            }
        }

        lease_file.flush().expect("刷新租约文件文件内容到磁盘失败"); // 刷新文件内容到磁盘
        lease_file.sync_all().expect("同步租约文件内容失败"); // 同步文件内容
        *file_dity = false;
    }

    //  更新dns缓存
    if *dns_dity || force_dns {
        cache_unhash_dhcp(cache); // 清除旧的 DHCP DNS 缓存

        for lease in leases.iter_mut() {
            if let Some(fqdn) = &lease.fqdn {
                cache_add_dhcp_entry(cache, fqdn, lease.addr, lease.expires, F_REVERSE);
                if let Some(hostname) = &lease.hostname {
                    cache_add_dhcp_entry(cache, hostname, lease.addr, lease.expires, 0);
                }
            } else if let Some(hostname) = &lease.hostname {
                cache_add_dhcp_entry(cache, hostname, lease.addr, lease.expires, F_REVERSE);
            }
        }

        *dns_dity = false;
    }
}

// 清理过期或指定的dhcp租约
pub fn lease_prune(target: Option<&DhcpLease>, now: SystemTime) {
    let mut leases = LEASES.lock().unwrap();
    let mut file_dirty = FILE_DIRTY.lock().unwrap();
    let mut dns_dirty = DNS_DIRTY.lock().unwrap();

    let mut removed_any = false;

    // 无论target是否为空，都先清理所有过期租约
    leases.retain(|lease| {
        let should_retain = lease.expires == UNIX_EPOCH || lease.expires > now;
        if !should_retain {
            removed_any = true;
            // 检查被删除的租约是否有hostname
            if lease.hostname.is_some() {
                *dns_dirty = true;
            }
        }
        should_retain
    });

    // 如果指定了target，再清理指定的租约
    if let Some(target_lease) = target {
        if let Some(pos) = leases.iter().position(|lease| {
            lease.hwaddr == target_lease.hwaddr && lease.addr == target_lease.addr
        }) {
            let removed_lease = &leases[pos];
            // 检查被删除的租约是否有hostname
            if removed_lease.hostname.is_some() {
                *dns_dirty = true;
            }
            leases.remove(pos);
            removed_any = true;
        }
    }

    // 如果有租约被移除，标记文件为脏状态
    if removed_any {
        *file_dirty = true;
    }
}

// 根据客户端IP地址或硬件地址在保存的ip地址中查找是否有客户端租约信息的记录
pub fn lease_find_by_client(clid: &[u8], clid_len: usize) -> Option<DhcpLease> {
    let leases = LEASES.lock().unwrap();

    if clid_len > 0 {
        for lease in leases.iter() {
            if !lease.clid.is_empty() && lease.clid_len == clid_len && lease.clid.as_slice() == clid
            {
                return Some(lease.clone());
            }
        }
    } else {
        for lease in leases.iter() {
            if lease.clid.is_empty() && lease.hwaddr == clid {
                return Some(lease.clone());
            }
        }
    }

    None
}

// 根据IP地址查找租约
pub fn lease_find_by_addr(addr: Ipv4Addr) -> Option<DhcpLease> {
    let leases = LEASES.lock().unwrap();
    leases.iter().find(|lease| lease.addr == addr).cloned()
}

// 设置租约时间
pub fn lease_set_expires(lease: &mut DhcpLease, exp: SystemTime) {
    let mut dns_dity = DNS_DIRTY.lock().unwrap();
    let mut file_dity = FILE_DIRTY.lock().unwrap();

    if lease.expires != exp {
        *dns_dity = true;
        *file_dity = true;
    }

    lease.expires = exp;
}

// 设置硬件地址（mac地址）
pub fn lease_set_hwaddr(lease: &mut DhcpLease, hwaddr: &[u8]) {
    let mut file_dity = FILE_DIRTY.lock().unwrap();

    // Convert slice to array for comparison and assignment
    if hwaddr.len() >= 6 {
        let hwaddr_array: [u8; 6] = [
            hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5],
        ];

        if lease.hwaddr != hwaddr_array {
            *file_dity = true;
            lease.hwaddr = hwaddr_array;
        }
    }
}

// 设置租约文件中主机名（需要检查重复）
pub fn lease_set_hostname(
    lease: &mut DhcpLease,
    name: &str,
    suffix: &Option<String>,
    leases: &mut MutexGuard<'_, Vec<DhcpLease>>,
) {
    let mut dns_dity = DNS_DIRTY.lock().unwrap();
    let mut file_dity = FILE_DIRTY.lock().unwrap();

    if !name.is_empty() {
        if let Some(hostname) = &lease.hostname {
            if hostname == name {
                // 新旧名字相同
                return;
            }
        }
    } else if lease.hostname.is_none() {
        return;
    }

    /*
     * 防止在不同网络中出现重复的主机名。
     * 如果发现同一主机名存在于其他租约中，则将该主机名（及其FQDN）清除，
     * 以确保主机名在所有租约中是唯一的。
     */
    let mut new_name: Option<String> = None;
    let mut new_fqdn: Option<String> = None;
    if !name.is_empty() {
        for lease_tmp in leases.iter_mut() {
            if lease_tmp.hostname.is_some()
                && hostname_isequal(&lease_tmp.hostname.clone().unwrap(), name)
            {
                new_name = lease_tmp.hostname.clone();
                lease_tmp.hostname = None;

                if lease_tmp.fqdn.is_some() {
                    new_fqdn = lease_tmp.fqdn.clone();
                    lease_tmp.fqdn = None;
                }
            }
        }
    }

    if new_name.is_none() {
        new_name = Some(name.to_string());
    }
    if suffix.is_some() && new_fqdn.is_none() {
        let fqdn_str = name.to_string() + "." + suffix.as_ref().unwrap();
        new_fqdn = Some(fqdn_str);
    }

    lease.hostname = new_name;
    lease.fqdn = new_fqdn;

    // 标记配置文件和DNS条目为脏状态，提示需要更新
    *file_dity = true;
    *dns_dity = true;
}

// 设置租约文件中主机名（单个租约，不检查重复）
fn lease_set_hostname_single(lease: &mut DhcpLease, name: &str, suffix: &Option<String>) {
    let mut dns_dity = DNS_DIRTY.lock().unwrap();
    let mut file_dity = FILE_DIRTY.lock().unwrap();

    if !name.is_empty() {
        if let Some(hostname) = &lease.hostname {
            if hostname == name {
                // 新旧名字相同
                return;
            }
        }
    } else if lease.hostname.is_none() {
        return;
    }

    let new_name = Some(name.to_string());
    let new_fqdn = if suffix.is_some() {
        Some(name.to_string() + "." + suffix.as_ref().unwrap())
    } else {
        None
    };

    lease.hostname = new_name;
    lease.fqdn = new_fqdn;

    // 标记配置文件和DNS条目为脏状态，提示需要更新
    *file_dity = true;
    *dns_dity = true;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnsmasq::ETHER_ADDR_LEN;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn test_lease_prune_keeps_infinite_lease() {
        let mut leases = LEASES.lock().unwrap();
        leases.clear();
        leases.push(DhcpLease {
            clid_len: 0,
            clid: Vec::new(),
            hostname: Some(String::from("infinite")),
            fqdn: None,
            expires: UNIX_EPOCH,
            hwaddr: [0; ETHER_ADDR_LEN],
            addr: "192.168.200.70".parse().unwrap(),
        });
        leases.push(DhcpLease {
            clid_len: 0,
            clid: Vec::new(),
            hostname: Some(String::from("expired")),
            fqdn: None,
            expires: SystemTime::now() - Duration::from_secs(1),
            hwaddr: [1; ETHER_ADDR_LEN],
            addr: "192.168.200.71".parse().unwrap(),
        });
        drop(leases);

        lease_prune(None, SystemTime::now());

        let leases = LEASES.lock().unwrap();
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].hostname.as_deref(), Some("infinite"));
    }
}
