#[cfg(feature = "tpm")]
mod tpm_impl {
    use std::path::Path;

    use sha2::{Digest as _, Sha256};
    use tss_esapi::{
        attributes::ObjectAttributesBuilder,
        handles::KeyHandle,
        interface_types::{algorithm::HashingAlgorithm, resource_handles::Hierarchy},
        structures::{
            Auth, Digest, EccPoint, EccScheme, HashScheme, Public,
            PublicEccParametersBuilder, Signature, SymmetricDefinitionObject,
        },
        tcti_ldr::TctiNameConf,
        traits::{Marshall, UnMarshall},
        Context,
    };

    const KEY_FILE: &str = "/var/lib/labyrinth/tpm_signing_key.bin";

    fn ecc_curve() -> tss_esapi::interface_types::ecc::EccCurve {
        tss_esapi::interface_types::ecc::EccCurve::NistP256
    }

    fn build_signing_key_template() -> Result<Public, String> {
        let attrs = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_sign_encrypt(true)
            .build()
            .map_err(|e| format!("ObjectAttributes: {e}"))?;

        let params = PublicEccParametersBuilder::new()
            .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
            .with_curve(ecc_curve())
            .with_is_signing_key(true)
            .build()
            .map_err(|e| format!("EccParameters: {e}"))?;

        Public::builder(tss_esapi::interface_types::algorithm::PublicAlgorithm::Ecc)
            .with_object_attributes(attrs)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_ecc_parameters(params)
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .map_err(|e| format!("Public::build: {e}"))
    }

    fn build_primary_template() -> Result<Public, String> {
        let attrs = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_restricted(true)
            .with_decrypt(true)
            .build()
            .map_err(|e| format!("primary attrs: {e}"))?;

        let sym = SymmetricDefinitionObject::Aes {
            key_bits: tss_esapi::interface_types::key_bits::AesKeyBits::Aes128,
            mode: tss_esapi::interface_types::algorithm::SymmetricMode::Cfb,
        };

        let params = tss_esapi::structures::PublicRsaParametersBuilder::new()
            .with_symmetric(sym)
            .with_scheme(tss_esapi::structures::RsaScheme::Null)
            .with_key_bits(tss_esapi::interface_types::key_bits::RsaKeyBits::Rsa2048)
            .with_exponent(tss_esapi::structures::RsaExponent::default())
            .with_is_decryption_key(true)
            .with_is_restricted(true)
            .build()
            .map_err(|e| format!("primary params: {e}"))?;

        Public::builder(tss_esapi::interface_types::algorithm::PublicAlgorithm::Rsa)
            .with_object_attributes(attrs)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_rsa_parameters(params)
            .with_rsa_unique_identifier(tss_esapi::structures::PublicKeyRsa::default())
            .build()
            .map_err(|e| format!("primary Public::build: {e}"))
    }

    fn extract_pub_key_bytes(public: &Public) -> Option<Vec<u8>> {
        if let Public::Ecc { unique, .. } = public {
            let x = unique.x().as_bytes();
            let y = unique.y().as_bytes();
            let mut out = Vec::with_capacity(65);
            out.push(0x04);
            out.extend_from_slice(x);
            out.extend_from_slice(y);
            Some(out)
        } else {
            None
        }
    }

    fn encode_ecdsa_der(sig: &Signature) -> Result<Vec<u8>, String> {
        let (r_bytes, s_bytes) = match sig {
            Signature::EcDsa { signature_r, signature_s, .. } => {
                (signature_r.as_bytes().to_vec(), signature_s.as_bytes().to_vec())
            }
            _ => return Err("expected ECDSA signature".into()),
        };

        fn encode_integer(n: &[u8]) -> Vec<u8> {
            let trimmed: &[u8] = {
                let start = n.iter().position(|&b| b != 0).unwrap_or(n.len() - 1);
                &n[start..]
            };
            let needs_pad = trimmed[0] & 0x80 != 0;
            let mut out = Vec::with_capacity(2 + trimmed.len() + if needs_pad { 1 } else { 0 });
            out.push(0x02);
            out.push((trimmed.len() + if needs_pad { 1 } else { 0 }) as u8);
            if needs_pad { out.push(0x00); }
            out.extend_from_slice(trimmed);
            out
        }

        let r_der = encode_integer(&r_bytes);
        let s_der = encode_integer(&s_bytes);
        let inner_len = r_der.len() + s_der.len();
        let mut out = Vec::with_capacity(2 + inner_len);
        out.push(0x30);
        out.push(inner_len as u8);
        out.extend_from_slice(&r_der);
        out.extend_from_slice(&s_der);
        Ok(out)
    }

    fn open_context() -> Result<Context, String> {
        let tcti = TctiNameConf::from_environment_variable().unwrap_or_else(|_| {
            TctiNameConf::Device(tss_esapi::tcti_ldr::DeviceConfig::default())
        });
        Context::new(tcti).map_err(|e| format!("TPM Context: {e}"))
    }

    pub struct TpmIdentity {
        ctx: Context,
        key_handle: KeyHandle,
        pub_key_bytes: Vec<u8>,
    }

    impl TpmIdentity {
        pub fn new_or_load() -> Result<Self, String> {
            let mut ctx = open_context()?;

            let primary_pub = build_primary_template()?;
            let (primary_handle, _, _, _) = ctx
                .execute_with_nullauth_session(|ctx| {
                    ctx.create_primary(Hierarchy::Owner, primary_pub, None, None, None, None)
                })
                .map_err(|e| format!("create_primary: {e}"))?;

            let (private_bytes, public_bytes, pub_key_bytes) =
                if Path::new(KEY_FILE).exists() {
                    let raw = std::fs::read(KEY_FILE)
                        .map_err(|e| format!("read {KEY_FILE}: {e}"))?;
                    if raw.len() < 8 {
                        return Err("corrupt key file".into());
                    }
                    let priv_len = u32::from_le_bytes(raw[..4].try_into().unwrap()) as usize;
                    let pub_len = u32::from_le_bytes(raw[4..8].try_into().unwrap()) as usize;
                    if raw.len() < 8 + priv_len + pub_len {
                        return Err("corrupt key file (truncated)".into());
                    }
                    let priv_b = raw[8..8 + priv_len].to_vec();
                    let pub_b = raw[8 + priv_len..8 + priv_len + pub_len].to_vec();
                    let public = tss_esapi::structures::Private::unmarshall(&priv_b)
                        .map_err(|e| format!("unmarshal private: {e}"))
                        .and_then(|_| {
                            Public::unmarshall(&pub_b).map_err(|e| format!("unmarshal public: {e}"))
                        })?;
                    let pk = extract_pub_key_bytes(&public)
                        .ok_or("key is not ECC")?;
                    (priv_b, pub_b, pk)
                } else {
                    let key_pub = build_signing_key_template()?;
                    let (private, public, _, _, _) = ctx
                        .execute_with_nullauth_session(|ctx| {
                            ctx.create(primary_handle, key_pub, None, None, None, None)
                        })
                        .map_err(|e| format!("create key: {e}"))?;
                    let pk = extract_pub_key_bytes(&public)
                        .ok_or("created key is not ECC")?;
                    let priv_b = private.marshall().map_err(|e| format!("marshal priv: {e}"))?;
                    let pub_b = public.marshall().map_err(|e| format!("marshal pub: {e}"))?;
                    if let Some(parent) = Path::new(KEY_FILE).parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let mut blob = Vec::with_capacity(8 + priv_b.len() + pub_b.len());
                    blob.extend_from_slice(&(priv_b.len() as u32).to_le_bytes());
                    blob.extend_from_slice(&(pub_b.len() as u32).to_le_bytes());
                    blob.extend_from_slice(&priv_b);
                    blob.extend_from_slice(&pub_b);
                    std::fs::write(KEY_FILE, &blob)
                        .map_err(|e| format!("write {KEY_FILE}: {e}"))?;
                    (priv_b, pub_b, pk)
                };

            let private = tss_esapi::structures::Private::unmarshall(&private_bytes)
                .map_err(|e| format!("unmarshal private for load: {e}"))?;
            let public = Public::unmarshall(&public_bytes)
                .map_err(|e| format!("unmarshal public for load: {e}"))?;

            let key_handle = ctx
                .execute_with_nullauth_session(|ctx| ctx.load(primary_handle, private, public))
                .map_err(|e| format!("TPM load key: {e}"))?;

            Ok(Self { ctx, key_handle, pub_key_bytes })
        }

        pub fn sign(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
            let hash = Sha256::digest(data);
            let digest = Digest::try_from(hash.as_slice())
                .map_err(|e| format!("digest: {e}"))?;
            let scheme = tss_esapi::structures::SignatureScheme::EcDsa {
                hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
            };
            let validation = tss_esapi::structures::HashcheckTicket::default();
            let sig = self
                .ctx
                .execute_with_nullauth_session(|ctx| {
                    ctx.sign(self.key_handle, &digest, scheme, validation)
                })
                .map_err(|e| format!("TPM sign: {e}"))?;
            encode_ecdsa_der(&sig)
        }

        pub fn verify_with_pub(pub_key_bytes: &[u8], data: &[u8], sig_der: &[u8]) -> Result<bool, String> {
            use p256::ecdsa::{signature::DigestVerifier, Signature, VerifyingKey};
            let vk = VerifyingKey::from_sec1_bytes(pub_key_bytes)
                .map_err(|e| format!("pub key: {e}"))?;
            let sig = Signature::from_der(sig_der)
                .map_err(|e| format!("signature: {e}"))?;
            let hasher = Sha256::new_with_prefix(data);
            Ok(vk.verify_digest(hasher, &sig).is_ok())
        }

        pub fn seal_secret(&mut self, secret: &[u8]) -> Result<Vec<u8>, String> {
            use tss_esapi::{
                interface_types::session_handles::PolicySession,
                structures::{PcrSelectionListBuilder, SensitiveData},
            };

            let pcr_sel = PcrSelectionListBuilder::new()
                .with_selection(
                    HashingAlgorithm::Sha256,
                    &[
                        tss_esapi::structures::PcrSlot::Slot0,
                        tss_esapi::structures::PcrSlot::Slot7,
                    ],
                )
                .build()
                .map_err(|e| format!("PcrSelectionList: {e}"))?;

            let (_, pcr_values) = self
                .ctx
                .execute_without_session(|ctx| ctx.pcr_read(pcr_sel.clone()))
                .map_err(|e| format!("pcr_read: {e}"))?;

            let trial_session = self
                .ctx
                .start_auth_session(
                    None,
                    None,
                    None,
                    tss_esapi::interface_types::SessionType::Trial,
                    tss_esapi::structures::SymmetricDefinition::Null,
                    HashingAlgorithm::Sha256,
                )
                .map_err(|e| format!("start trial session: {e}"))?;

            let policy_session = PolicySession::try_from(trial_session.unwrap())
                .map_err(|e| format!("policy_session: {e}"))?;

            self.ctx
                .policy_pcr(policy_session, Default::default(), pcr_sel.clone())
                .map_err(|e| format!("policy_pcr: {e}"))?;

            let policy_digest = self
                .ctx
                .policy_get_digest(policy_session)
                .map_err(|e| format!("policy_get_digest: {e}"))?;

            let sealed_attrs = ObjectAttributesBuilder::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_no_da(true)
                .with_admin_with_policy(true)
                .build()
                .map_err(|e| format!("sealed attrs: {e}"))?;

            let sealed_pub = Public::builder(tss_esapi::interface_types::algorithm::PublicAlgorithm::KeyedHash)
                .with_object_attributes(sealed_attrs)
                .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
                .with_auth_policy(policy_digest)
                .with_keyed_hash_parameters(tss_esapi::structures::PublicKeyedHashParameters::new(
                    tss_esapi::structures::KeyedHashScheme::Null,
                ))
                .with_keyed_hash_unique_identifier(tss_esapi::structures::KeyedHashUnique::default())
                .build()
                .map_err(|e| format!("sealed Public: {e}"))?;

            let secret_data = SensitiveData::try_from(secret.to_vec())
                .map_err(|e| format!("SensitiveData: {e}"))?;

            let primary_pub = build_primary_template()?;
            let (primary_handle, _, _, _) = self
                .ctx
                .execute_with_nullauth_session(|ctx| {
                    ctx.create_primary(Hierarchy::Owner, primary_pub, None, None, None, None)
                })
                .map_err(|e| format!("create_primary for seal: {e}"))?;

            let (private, public, _, _, _) = self
                .ctx
                .execute_with_nullauth_session(|ctx| {
                    ctx.create(primary_handle, sealed_pub, None, Some(secret_data), None, None)
                })
                .map_err(|e| format!("create sealed: {e}"))?;

            let priv_b = private.marshall().map_err(|e| format!("marshal sealed priv: {e}"))?;
            let pub_b = public.marshall().map_err(|e| format!("marshal sealed pub: {e}"))?;
            let mut out = Vec::with_capacity(8 + priv_b.len() + pub_b.len());
            out.extend_from_slice(&(priv_b.len() as u32).to_le_bytes());
            out.extend_from_slice(&(pub_b.len() as u32).to_le_bytes());
            out.extend_from_slice(&priv_b);
            out.extend_from_slice(&pub_b);
            Ok(out)
        }

        pub fn unseal(&mut self, blob: &[u8]) -> Result<Vec<u8>, String> {
            use tss_esapi::{
                interface_types::session_handles::PolicySession,
                structures::PcrSelectionListBuilder,
            };

            if blob.len() < 8 {
                return Err("blob too short".into());
            }
            let priv_len = u32::from_le_bytes(blob[..4].try_into().unwrap()) as usize;
            let pub_len = u32::from_le_bytes(blob[4..8].try_into().unwrap()) as usize;
            if blob.len() < 8 + priv_len + pub_len {
                return Err("blob truncated".into());
            }
            let private = tss_esapi::structures::Private::unmarshall(&blob[8..8 + priv_len])
                .map_err(|e| format!("unmarshal sealed priv: {e}"))?;
            let public = Public::unmarshall(&blob[8 + priv_len..8 + priv_len + pub_len])
                .map_err(|e| format!("unmarshal sealed pub: {e}"))?;

            let primary_pub = build_primary_template()?;
            let (primary_handle, _, _, _) = self
                .ctx
                .execute_with_nullauth_session(|ctx| {
                    ctx.create_primary(Hierarchy::Owner, primary_pub, None, None, None, None)
                })
                .map_err(|e| format!("create_primary for unseal: {e}"))?;

            let sealed_handle = self
                .ctx
                .execute_with_nullauth_session(|ctx| ctx.load(primary_handle, private, public))
                .map_err(|e| format!("load sealed: {e}"))?;

            let pcr_sel = PcrSelectionListBuilder::new()
                .with_selection(
                    HashingAlgorithm::Sha256,
                    &[
                        tss_esapi::structures::PcrSlot::Slot0,
                        tss_esapi::structures::PcrSlot::Slot7,
                    ],
                )
                .build()
                .map_err(|e| format!("PcrSelectionList: {e}"))?;

            let policy_session = self
                .ctx
                .start_auth_session(
                    None,
                    None,
                    None,
                    tss_esapi::interface_types::SessionType::Policy,
                    tss_esapi::structures::SymmetricDefinition::Null,
                    HashingAlgorithm::Sha256,
                )
                .map_err(|e| format!("start policy session: {e}"))?;

            let ps = PolicySession::try_from(policy_session.unwrap())
                .map_err(|e| format!("policy_session: {e}"))?;

            self.ctx
                .policy_pcr(ps, Default::default(), pcr_sel)
                .map_err(|e| format!("policy_pcr: {e}"))?;

            let auth_session = tss_esapi::structures::AuthSession::try_from(
                tss_esapi::interface_types::session_handles::AuthSession::from(ps),
            )
            .map_err(|e| format!("auth_session: {e}"))?;

            let sensitive_data = self
                .ctx
                .execute_with_session(Some(auth_session), |ctx| {
                    ctx.unseal(sealed_handle)
                })
                .map_err(|e| format!("unseal: {e}"))?;

            Ok(sensitive_data.to_vec())
        }

        pub fn pub_key_bytes(&self) -> &[u8] {
            &self.pub_key_bytes
        }
    }
}

#[cfg(feature = "tpm")]
pub use tpm_impl::TpmIdentity;

#[cfg(not(feature = "tpm"))]
pub struct TpmIdentity;

#[cfg(not(feature = "tpm"))]
impl TpmIdentity {
    pub fn new_or_load() -> Result<Self, String> {
        Err("tpm feature not enabled (compile with --features tpm)".into())
    }

    pub fn sign(&mut self, _data: &[u8]) -> Result<Vec<u8>, String> {
        Err("tpm feature not enabled".into())
    }

    pub fn verify_with_pub(_pub_key: &[u8], _data: &[u8], _sig: &[u8]) -> Result<bool, String> {
        Err("tpm feature not enabled".into())
    }

    pub fn seal_secret(&mut self, _secret: &[u8]) -> Result<Vec<u8>, String> {
        Err("tpm feature not enabled".into())
    }

    pub fn unseal(&mut self, _blob: &[u8]) -> Result<Vec<u8>, String> {
        Err("tpm feature not enabled".into())
    }

    pub fn pub_key_bytes(&self) -> &[u8] {
        &[]
    }
}
