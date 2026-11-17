//! TLS certificate policy for both the RD Gateway and the RDP host.
//!
//! IronRDP's defaults accept *any* certificate. Bastion replaces that with:
//! 1. Full WebPKI validation against system roots + hostname check.
//! 2. If that fails: accept only if the leaf matches a user-approved pin ([`TrustStore`]).
//! 3. Otherwise the handshake is aborted and the certificate is surfaced to the UI as a
//!    [`CertificateRejection`], so the user can inspect the fingerprint and decide. On approval
//!    the pin is stored and the connection is retried.
//!
//! Signature verification (proof of private-key possession) is always performed, even for
//! pinned certificates, so a pin cannot be satisfied by a replayed certificate.
//!
//! The per-profile "allow insecure" switch bypasses all of this (lab use only) but still logs
//! the fingerprint.

use std::sync::{Arc, Mutex};

use bastion_core::trust::{EndpointKind, TrustStatus, TrustStore, fingerprint_sha256};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tracing::{info, warn};

/// A certificate that failed validation and needs a user decision.
#[derive(Debug, Clone)]
pub struct CertificateRejection {
    pub kind: EndpointKind,
    /// "host:port" the pin is keyed on.
    pub endpoint: String,
    pub der: Vec<u8>,
    pub fingerprint: String,
    /// Why strict validation failed (e.g. "UnknownIssuer", "NotValidForName").
    pub reason: String,
    /// `Some(old)` if a *different* certificate was previously pinned — possible MITM.
    pub previous_fingerprint: Option<String>,
    pub subject: String,
    pub issuer: String,
    pub not_after: String,
}

impl CertificateRejection {
    fn new(kind: EndpointKind, endpoint: &str, der: &[u8], reason: String, status: TrustStatus) -> Self {
        let (subject, issuer, not_after) = describe_cert(der);
        Self {
            kind,
            endpoint: endpoint.to_owned(),
            der: der.to_vec(),
            fingerprint: fingerprint_sha256(der),
            reason,
            previous_fingerprint: match status {
                TrustStatus::Mismatch { pinned } => Some(pinned),
                _ => None,
            },
            subject,
            issuer,
            not_after,
        }
    }
}

fn describe_cert(der: &[u8]) -> (String, String, String) {
    use x509_cert::der::Decode as _;
    match x509_cert::Certificate::from_der(der) {
        Ok(c) => {
            let tbs = c.tbs_certificate();
            (tbs.subject().to_string(), tbs.issuer().to_string(), tbs.validity().not_after.to_string())
        }
        Err(_) => ("<unparseable>".into(), "<unparseable>".into(), String::new()),
    }
}

/// Shared slot the verifier writes into when it rejects a certificate.
pub type RejectionSlot = Arc<Mutex<Option<CertificateRejection>>>;

pub fn crypto_provider() -> Arc<CryptoProvider> {
    CryptoProvider::get_default().cloned().unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
}

/// Installs the process-wide rustls provider (call once at startup).
pub fn install_default_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn system_roots() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    let result = rustls_native_certs::load_native_certs();
    for e in &result.errors {
        warn!(error = %e, "Error loading a system root certificate");
    }
    let (added, ignored) = roots.add_parsable_certificates(result.certs);
    tracing::debug!(added, ignored, "Loaded system root certificates");
    roots
}

#[derive(Debug)]
pub struct PinningVerifier {
    webpki: Option<Arc<rustls::client::WebPkiServerVerifier>>,
    provider: Arc<CryptoProvider>,
    trust: Arc<Mutex<TrustStore>>,
    kind: EndpointKind,
    endpoint: String,
    insecure: bool,
    rejected: RejectionSlot,
}

impl PinningVerifier {
    pub fn new(
        trust: Arc<Mutex<TrustStore>>,
        kind: EndpointKind,
        endpoint: String,
        insecure: bool,
        rejected: RejectionSlot,
    ) -> Self {
        let provider = crypto_provider();
        let webpki =
            rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(system_roots()), provider.clone())
                .build()
                .map_err(|e| warn!(error = %e, "No usable system trust anchors; relying on pinning only"))
                .ok();
        Self { webpki, provider, trust, kind, endpoint, insecure, rejected }
    }

    /// Decides on a leaf certificate that failed strict validation.
    fn decide_untrusted(&self, der: &[u8], reason: String) -> bool {
        let status = self.trust.lock().map(|t| t.check(self.kind, &self.endpoint, der)).unwrap_or(TrustStatus::Unknown);
        if status == TrustStatus::Pinned {
            info!(endpoint = %self.endpoint, "Certificate accepted via user pin");
            return true;
        }
        warn!(endpoint = %self.endpoint, %reason, fingerprint = %fingerprint_sha256(der), ?status, "Certificate not trusted");
        if let Ok(mut slot) = self.rejected.lock() {
            *slot = Some(CertificateRejection::new(self.kind, &self.endpoint, der, reason, status));
        }
        false
    }

    /// Adapter for `ironrdp_mstsgu`, which validates strictly itself and calls this only on failure.
    pub fn gateway_callback(self: Arc<Self>) -> ironrdp_tls::CertificateValidationCallback {
        Arc::new(move |leaf_der: &[u8], _endpoint: &str, err: &str| self.decide_untrusted(leaf_der, err.to_owned()))
    }

    pub fn into_client_config(self: Arc<Self>) -> rustls::ClientConfig {
        let mut cfg = rustls::ClientConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .expect("provider supports default protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(self)
            .with_no_client_auth();
        // CredSSP binds to the TLS public key; resumption brings nothing and complicates that.
        cfg.resumption = rustls::client::Resumption::disabled();
        cfg
    }
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.insecure {
            warn!(
                endpoint = %self.endpoint,
                fingerprint = %fingerprint_sha256(end_entity),
                "INSECURE MODE: certificate validation skipped for this connection"
            );
            return Ok(ServerCertVerified::assertion());
        }
        let strict = match &self.webpki {
            Some(v) => v.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now),
            None => Err(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)),
        };
        match strict {
            Ok(ok) => Ok(ok),
            Err(e) => {
                if self.decide_untrusted(end_entity, e.to_string()) {
                    Ok(ServerCertVerified::assertion())
                } else {
                    Err(e)
                }
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Performs the TLS upgrade of the RDP stream using [`PinningVerifier`].
///
/// Returns the TLS stream and the raw `subjectPublicKey` bytes CredSSP must bind to.
pub async fn upgrade<S>(
    stream: S,
    server_name: &str,
    verifier: Arc<PinningVerifier>,
) -> std::io::Result<(tokio_rustls::client::TlsStream<S>, Vec<u8>)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use x509_cert::der::Decode as _;

    let config = Arc::new(verifier.into_client_config());
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let mut tls = tokio_rustls::TlsConnector::from(config).connect(name, stream).await?;
    {
        use tokio::io::AsyncWriteExt as _;
        tls.flush().await?;
    }
    let (_, conn) = tls.get_ref();
    let leaf = conn
        .peer_certificates()
        .and_then(|c| c.first())
        .ok_or_else(|| std::io::Error::other("server sent no certificate"))?;
    let cert = x509_cert::Certificate::from_der(leaf).map_err(std::io::Error::other)?;
    let key = cert
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| std::io::Error::other("server public key is not byte-aligned"))?
        .to_vec();
    if let (Some(v), Some(c)) = (conn.protocol_version(), conn.negotiated_cipher_suite()) {
        info!(version = ?v, cipher = ?c.suite(), "TLS established with RDP host");
    }
    Ok((tls, key))
}
