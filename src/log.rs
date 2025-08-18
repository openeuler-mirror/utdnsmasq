/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub enum LogLevel {
    Info,
    Warning,
    Error,
}

pub struct Logger {
    log_file: Option<String>,
}

impl Logger {
    // 创建一个新的 Logger
    pub fn new(log_file: Option<String>) -> Self {
        Logger { log_file }
    }

    // 记录日志
    pub fn log(&self, level: LogLevel, message: &str) {
        // 获取当前的时间戳
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        // 格式化日志消息
        let log_message = format!(
            "[{}] [{}] {}",
            timestamp,
            Self::level_to_string(&level),
            message
        );

        // 打印到控制台
        println!("{}", log_message);

        // 如果配置了日志文件，将日志写入文件
        if let Some(ref file_path) = self.log_file {
            if let Err(e) = self.log_to_file(file_path, &log_message) {
                eprintln!("Failed to write to log file: {}", e);
            }
        }
    }

    // 将日志写入文件
    pub fn log_to_file(&self, file_path: &str, message: &str) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_path)?;

        writeln!(file, "{}", message)?;

        Ok(())
    }

    // 将日志级别转换为字符串
    pub fn level_to_string(level: &LogLevel) -> &str {
        match level {
            LogLevel::Info => "INFO",
            LogLevel::Warning => "WARNING",
            LogLevel::Error => "ERROR",
        }
    }

    // 提供不同级别的日志接口
    pub fn info(&self, message: &str) {
        self.log(LogLevel::Info, message);
    }

    pub fn warning(&self, message: &str) {
        self.log(LogLevel::Warning, message);
    }

    pub fn error(&self, message: &str) {
        self.log(LogLevel::Error, message);
    }
}
