use crate::config::TargetConfig;

pub fn generate_pac(proxy_host: &str, proxy_port: u16, targets: &[TargetConfig]) -> String {
    let proxy_addr = format!("PROXY {}:{}", proxy_host, proxy_port);

    let domains: Vec<String> = targets
        .iter()
        .map(|t| format!("\"*.{}\"", t.host))
        .collect();

    let domain_checks = if domains.is_empty() {
        String::new()
    } else {
        domains
            .iter()
            .map(|d| {
                format!(
                    "    if (shExpMatch(host, {})) return \"{}\";\n",
                    d, proxy_addr
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    format!(
        r#"function FindProxyForURL(url, host) {{
    // Local and private addresses bypass the proxy (direct connection)
    if (isPlainHostName(host) ||
        shExpMatch(host, "localhost") ||
        shExpMatch(host, "127.*") ||
        shExpMatch(host, "10.*") ||
        shExpMatch(host, "192.168.*") ||
        isInNet(host, "172.16.0.0", "255.240.0.0")) {{
        return "DIRECT";
    }}
{domain_checks}    return "DIRECT";
}}
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TargetConfig;

    #[test]
    fn test_generate_pac_empty() {
        let pac = generate_pac("proxy.local", 8443, &[]);
        assert!(pac.contains("FindProxyForURL"));
        assert!(pac.contains("DIRECT"));
        assert!(pac.contains("localhost"));
        assert!(!pac.contains("PROXY"));
    }

    #[test]
    fn test_generate_pac_with_targets() {
        let targets = vec![
            TargetConfig {
                host: "api.deepseek.com".into(),
                port: 443,
                tls: true,
            },
            TargetConfig {
                host: "api.openai.com".into(),
                port: 443,
                tls: true,
            },
        ];
        let pac = generate_pac("proxy.local", 8443, &targets);
        assert!(pac.contains("PROXY proxy.local:8443"));
        assert!(pac.contains("*.api.deepseek.com"));
        assert!(pac.contains("*.api.openai.com"));
    }

    #[test]
    fn test_generate_pac_content_type() {
        let targets = vec![TargetConfig {
            host: "api.deepseek.com".into(),
            port: 443,
            tls: true,
        }];
        let pac = generate_pac("127.0.0.1", 8443, &targets);
        assert!(pac.contains("shExpMatch(host, \"*.api.deepseek.com\")"));
        assert!(pac.contains("PROXY 127.0.0.1:8443"));
    }

    #[test]
    fn test_pac_bypasses_localhost() {
        let pac = generate_pac("127.0.0.1", 8443, &[]);
        // Must include localhost and private range bypass
        assert!(pac.contains("localhost"));
        assert!(pac.contains("127.*"));
        assert!(pac.contains("192.168.*"));
        assert!(pac.contains("isInNet"));
    }
}
