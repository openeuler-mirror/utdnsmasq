/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use crate::*;
const OPTION_END: u8 = 255;
const OPTION_PAD: u8 = 0;
const OPTION_OVERLOAD: u8 = 52;
// 在 DHCP 数据包中查找指定的选项
pub fn option_find(packet: &DhcpPacket, sz: usize, option: u8) -> Option<&[u8]> {
    // 内部辅助函数，用于查找指定的 DHCP 选项
    fn find<'a>(data: &'a [u8], end: usize, option: u8, overload: &mut u8) -> Option<&'a [u8]> {
        let mut i = 0;
        while i < data.len() {
            if data[i] == OPTION_END {
                break; // 找到选项结束标志
            } else if data[i] == OPTION_PAD {
                i += 1; // 跳过填充字节
                continue;
            } else if data[i] == OPTION_OVERLOAD {
                // 检查是否越界
                if i + 2 >= data.len() || i + 2 >= end {
                    return None; // 数据包格式错误
                }
                *overload = data[i + 2]; // 记录 overload 值
                i += 3; // 跳过 overload 选项及其值
            } else {
                // 检查是否越界
                if i + 1 >= data.len() || i + 1 >= end {
                    return None; // 数据包格式错误
                }
                let opt_len = data[i + 1] as usize; // 获取选项长度
                                                    // 再次检查是否越界
                if i + 2 + opt_len > data.len() || i + 2 + opt_len > end {
                    return None; // 数据包格式错误
                }
                if data[i] == option {
                    return Some(&data[i..i + 2 + opt_len]); // 找到目标选项
                }
                i += 2 + opt_len; // 跳过当前选项及其值
            }
        }
        None // 未找到目标选项
    }

    let mut overload: u8 = 0;
    let size_limit = sz.min(packet.options.len()); // 限制搜索范围为 options 的长度

    // 在 options 字段中查找目标选项
    if let Some(result) = find(&packet.options, size_limit, option, &mut overload) {
        return Some(result);
    }

    // 如果 overload 指定了 file 字段，继续查找
    if (overload & 1) != 0 {
        if let Some(result) = find(&packet.file, packet.file.len(), option, &mut overload) {
            return Some(result);
        }
    }

    // 如果 overload 指定了 sname 字段，继续查找
    if (overload & 2) != 0 {
        if let Some(result) = find(&packet.sname, packet.sname.len(), option, &mut overload) {
            return Some(result);
        }
    }

    None // 未找到目标选项
}
