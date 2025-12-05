/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use crate::VERSION;
use clap::{ArgAction, Parser};
use std::process;

#[derive(Debug, Parser)]
#[command(version, long_about = None, disable_help_flag = true, disable_version_flag = true)]
struct Cli {
    /// Specify local address(es) to listen on.
    #[arg(short = 'a', long = "listen-address", value_name = "ipaddr", action = ArgAction::Append)]
    pub listen_address: Option<Vec<String>>,

    /// Return ipaddr for all hosts in specified domains.
    #[arg(short = 'A', long, value_name = "/domain/ipaddr")]
    pub address: Option<Vec<String>>,

    /// Fake reverse lookups for RFC1918 private address ranges.
    #[arg(short = 'b', long = "bogus-priv")]
    pub bogus_priv: bool,

    /// Treat ipaddr as NXDOMAIN (defeats Verisign wildcard).
    #[arg(short = 'B', long = "bogus-nxdomain", value_name = "ipaddr")]
    pub bogus_nxdomain: Option<Vec<String>>,

    /// Specify the size of the cache in entries (defaults to %d).
    #[arg(short = 'c', long = "cache-size", value_name = "cachesize")]
    pub cache_size: Option<i32>,

    /// Specify configuration file (defaults to " CONFFILE ").
    #[arg(short = 'C', long = "conf-file")]
    pub conf_file: Option<String>,

    /// Do NOT fork into the background: run in debug mode.
    #[arg(short = 'd', long = "no-daemon")]
    pub no_daemon: bool,

    /// Do NOT forward queries with no domain part.
    #[arg(short = 'D', long = "domain-needed")]
    pub domain_needed: bool,

    /// Return self-pointing MX records for local hosts.
    #[arg(short = 'e', long)]
    pub selfmx: bool,

    /// Expand simple names in /etc/hosts with domain-suffix.
    #[arg(short = 'E', long = "expand-hosts")]
    pub expand_hosts: bool,

    /// Enable DHCP in the range given with lease duration.
    #[arg(short = 'F', long = "dhcp-range", value_name = "ipaddr,ipaddr,time")]
    pub dhcp_range: Option<String>,

    /// Don't forward spurious DNS requests from Windows hosts.
    #[arg(short = 'f', long)]
    pub filterwin2k: bool,

    /// Change to this group after startup (defaults to " CHGRP ").
    #[arg(short = 'g', long, value_name = "groupname")]
    pub group: Option<String>,

    /// Set address or hostname for a specified machine.
    #[arg(short = 'G', long = "dhcp-host", value_name = "hostspec")]
    pub dhcp_host: Option<String>,

    /// Do NOT load " HOSTSFILE " file.
    #[arg(short = 'h', long = "no-hosts")]
    pub no_hosts: bool,

    /// Specify a hosts file to be read in addition to " HOSTSFILE ".
    #[arg(short = 'H', long = "addn-hosts", value_name = "path")]
    pub hosts: Option<Vec<String>>,

    /// Specify interface(s) to listen on.
    #[arg(short = 'i', long, value_name = "interface")]
    pub interface: Option<Vec<String>>,

    /// Specify interface(s) NOT to listen on.
    #[arg(short = 'I', long = "except-interface", value_name = "int")]
    pub except_interface: Option<Vec<String>>,

    /// Specify where to store DHCP leases (defaults to " LEASEFILE ").
    #[arg(short = 'l', long = "dhcp-leasefile", value_name = "path")]
    pub leasefile: Option<String>,

    /// Return MX records for local hosts.
    #[arg(short = 'L', long)]
    pub localmx: bool,

    /// Specify the MX name to reply to.
    #[arg(short = 'm', long = "mx-host", value_name = "host_name ")]
    pub mx_host: Option<String>,

    /// Specify BOOTP options to DHCP server.
    #[arg(short = 'M', long = "dhcp-boot", value_name = "bootp opts")]
    pub dhcp_boot: Option<String>,

    /// Do NOT poll " RESOLVFILE " file, reload only on SIGHUP.
    #[arg(short = 'n', long = "no-poll")]
    pub no_poll: bool,

    /// Do NOT cache failed search results.
    #[arg(short = 'N', long = "no-negcache")]
    pub no_negcache: bool,

    /// Use nameservers strictly in the order given in " RESOLVFILE ".
    #[arg(short = 'o', long = "strict-order")]
    pub strict_order: bool,

    /// Set extra options to be set to DHCP clients.
    #[arg(short = 'O', long = "dhcp-option", value_name = "optspec")]
    pub dhcp_option: Option<String>,

    /// Specify port to listen for DNS requests on (defaults to 53).
    #[arg(short = 'p', long = "port", value_name = "number")]
    pub port: Option<u16>,

    /// Log queries.
    #[arg(short = 'q', long = "log-queries")]
    pub log_queries: bool,

    /// Force the originating port for upstream queries.
    #[arg(short = 'Q', long = "query-port", value_name = "number")]
    pub query_port: Option<u16>,

    /// Do NOT read resolv.conf.
    #[arg(short = 'R', long = "no-resolv")]
    pub no_resolv: bool,

    /// Specify path to resolv.conf (defaults to " RESOLVFILE ").
    #[arg(short = 'r', long = "resolv-file", value_name = "path")]
    pub resolv_file: Option<String>,

    ///Specify address(es) of upstream servers with optional domains.
    #[arg(short = 'S', long, value_name = "/domain/ipaddr", action = ArgAction::Append )]
    pub server: Option<Vec<String>>,

    /// Never forward queries to specified domains.
    #[arg(long = "local", value_name = "domain")]
    pub local: Option<String>,

    /// Specify the domain to be assigned in DHCP leases.
    #[arg(short = 's', long = "domain", value_name = "domain")]
    pub local_domain: Option<String>,

    /// Specify the host in an MX reply.
    #[arg(short = 't', long = "mx-target", value_name = "host_name ")]
    pub mx_target: Option<String>,

    /// Specify time-to-live in seconds for replies from /etc/hosts.
    #[arg(short = 'T', long = "local-ttl", value_name = "time")]
    pub local_ttl: Option<u32>,

    /// Change to this user after startup. (defaults to " CHUSER ").
    #[arg(short = 'u', long = "user", value_name = "username")]
    pub user: Option<String>,

    /// Display dnsmasq version.
    #[arg(short = 'v', long)]
    pub version: bool,

    /// Display this message.
    #[arg(short = 'w', long = "help")]
    pub help: bool,

    /// Specify path of PID file. (defaults to " RUNFILE ").
    #[arg(short = 'x', long = "pid-file", value_name = "path")]
    pub pid_file: Option<String>,
}

pub fn parse_args() {
    let cli = Cli::parse();

    /* -w --help 显示帮助 */
    if cli.help {
        display_usage();
        process::exit(0);
    }

    /* -v --version显示版本信息 */
    if cli.version {
        println!("utdnsmasq version {}", VERSION);
        process::exit(0);
    }
}

fn display_usage() {
    println!("{}", USAGE);
}

/* 帮助信息 */
const USAGE: &str = r#"
Usage: utdnsmasq [options]
Valid options are :
    listen-address=ipaddr         Specify local address(es) to listen on.
    address=/domain/ipaddr        Return ipaddr for all hosts in specified domains.
    bogus-priv                    Fake reverse lookups for RFC1918 private address ranges.
    bogus-nxdomain=ipaddr         Treat ipaddr as NXDOMAIN (defeats Verisign wildcard).
    cache-size=cachesize          Specify the size of the cache in entries (defaults to %d).
    conf-file=path                Specify configuration file (defaults to " CONFFILE ").
    no-daemon                     Do NOT fork into the background: run in debug mode.
    domain-needed                 Do NOT forward queries with no domain part.
    selfmx                        Return self-pointing MX records for local hosts.
    expand-hosts                  Expand simple names in /etc/hosts with domain-suffix.
    filterwin2k                   Don't forward spurious DNS requests from Windows hosts.
    dhcp-range=ipaddr,ipaddr,time Enable DHCP in the range given with lease duration.
    group=groupname               Change to this group after startup (defaults to " CHGRP ").
    dhcp-host=<hostspec>          Set address or hostname for a specified machine.
    no-hosts                      Do NOT load " HOSTSFILE " file.
    addn-hosts=path               Specify a hosts file to be read in addition to " HOSTSFILE ".
    interface=interface           Specify interface(s) to listen on.
    except-interface=int          Specify interface(s) NOT to listen on.
    dhcp-leasefile=path           Specify where to store DHCP leases (defaults to " LEASEFILE ").
    localmx                       Return MX records for local hosts.
    mx-host=host_name             Specify the MX name to reply to.
    dhcp-boot=<bootp opts>        Specify BOOTP options to DHCP server.
    no-poll                       Do NOT poll " RESOLVFILE " file, reload only on SIGHUP.
    no-negcache                   Do NOT cache failed search results.
    strict-order                  Use nameservers strictly in the order given in " RESOLVFILE ".
    dhcp-option=<optspec>         Set extra options to be set to DHCP clients.
    port=number                   Specify port to listen for DNS requests on (defaults to 53).
    log-queries                   Log queries.
    query-port=number             Force the originating port for upstream queries.
    no-resolv                     Do NOT read resolv.conf.
    resolv-file=path              Specify path to resolv.conf (defaults to " RESOLVFILE ").
    server=/domain/ipaddr         Specify address(es) of upstream servers with optional domains.
    local=/domain/                Never forward queries to specified domains.
    domain=domain                 Specify the domain to be assigned in DHCP leases.
    mx-target=host_name           Specify the host in an MX reply.
    local-ttl=time                Specify time-to-live in seconds for replies from /etc/hosts.
    user=username                 Change to this user after startup. (defaults to " CHUSER ").
    version                       Display utdnsmasq version.
    help                          Display this message.
    pid-file=path                 Specify path of PID file. (defaults to " RUNFILE ").
"#;
