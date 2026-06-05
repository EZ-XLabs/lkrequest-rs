#[derive(Clone, Debug, Default)]
pub struct FfiDiagnostics {
    pub dns_ms: Option<u64>,
    pub tcp_ms: Option<u64>,
    pub tls_ms: Option<u64>,
    pub ttfb_ms: Option<u64>,
    pub total_ms: Option<u64>,
    pub remote_addr: Option<String>,
    pub protocol: Option<String>,
    pub cipher_suite: Option<String>,
}

impl FfiDiagnostics {
    pub fn with_total_ms(mut self, total_ms: u64) -> Self {
        self.total_ms = Some(total_ms);
        self
    }

    pub fn with_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }

    pub fn to_json_bytes(&self) -> Vec<u8> {
        let value = serde_json::json!({
            "schema_version": 1,
            "dns_ms": self.dns_ms,
            "tcp_ms": self.tcp_ms,
            "tls_ms": self.tls_ms,
            "ttfb_ms": self.ttfb_ms,
            "total_ms": self.total_ms,
            "remote_addr": self.remote_addr,
            "protocol": self.protocol,
            "cipher_suite": self.cipher_suite,
        });

        let mut bytes = serde_json::to_vec(&value).expect("serialize diagnostics");
        bytes.push(0);
        bytes
    }
}

impl From<lkrequest::diagnostics::RequestDiagnostics> for FfiDiagnostics {
    fn from(value: lkrequest::diagnostics::RequestDiagnostics) -> Self {
        Self {
            dns_ms: value.dns_ms,
            tcp_ms: value.tcp_ms,
            tls_ms: value.tls_ms,
            ttfb_ms: value.ttfb_ms,
            total_ms: value.total_ms,
            remote_addr: value.remote_addr,
            protocol: value.protocol,
            cipher_suite: value.cipher_suite,
        }
    }
}
