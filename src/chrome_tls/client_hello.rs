use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::PublicKey as KemPublicKey;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public};

const GREASE_VALUES: &[u16] = &[
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
];

pub fn random_grease() -> u16 {
    GREASE_VALUES[(rand::random::<u8>() % 16) as usize]
}

pub struct KeyMaterial {
    pub x25519_secret: Option<EphemeralSecret>,
    pub kyber_sk: kyber768::SecretKey,
    pub random: [u8; 32],
    pub session_id: [u8; 32],
    pub grease: u16,
}

pub fn prepare_key_material(server_name: &str) -> (KeyMaterial, Vec<u8>) {
    let mut random = [0u8; 32];
    let mut session_id = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut session_id);

    let grease = random_grease();
    let x25519_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let x25519_pub = X25519Public::from(&x25519_secret);
    let (kyber_pk, kyber_sk) = kyber768::keypair();

    let ch = build_client_hello(
        grease,
        &random,
        &session_id,
        x25519_pub.as_bytes(),
        kyber_pk.as_bytes(),
        server_name,
    );

    let mat = KeyMaterial {
        x25519_secret: Some(x25519_secret),
        kyber_sk,
        random,
        session_id,
        grease,
    };

    (mat, ch)
}

fn u16be(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn u24be(buf: &mut Vec<u8>, v: u32) {
    buf.push((v >> 16) as u8);
    buf.push((v >> 8) as u8);
    buf.push(v as u8);
}

fn len_u8(buf: &mut Vec<u8>, data: &[u8]) {
    buf.push(data.len() as u8);
    buf.extend_from_slice(data);
}

fn len_u16(buf: &mut Vec<u8>, data: &[u8]) {
    u16be(buf, data.len() as u16);
    buf.extend_from_slice(data);
}

fn ext(buf: &mut Vec<u8>, typ: u16, data: &[u8]) {
    u16be(buf, typ);
    len_u16(buf, data);
}

fn build_client_hello(
    grease: u16,
    random: &[u8; 32],
    session_id: &[u8; 32],
    x25519_pub: &[u8; 32],
    kyber_pub: &[u8],
    server_name: &str,
) -> Vec<u8> {
    let mut exts = Vec::new();

    ext(&mut exts, grease, &[0x00]);

    {
        let name = server_name.as_bytes();
        let mut inner = Vec::new();
        let entry_len = (3 + name.len()) as u16;
        u16be(&mut inner, entry_len);
        inner.push(0x00);
        len_u16(&mut inner, name);
        ext(&mut exts, 0x0000, &inner);
    }

    ext(&mut exts, 0x0017, &[]);
    ext(&mut exts, 0xff01, &[0x00]);

    {
        let mut list = Vec::new();
        for g in &[grease, 0x6399u16, 0x001d, 0x0017, 0x0018] {
            u16be(&mut list, *g);
        }
        let mut data = Vec::new();
        len_u16(&mut data, &list);
        ext(&mut exts, 0x000a, &data);
    }

    ext(&mut exts, 0x000b, &[0x01, 0x00]);
    ext(&mut exts, 0x0023, &[]);

    {
        let mut proto_list = Vec::new();
        len_u8(&mut proto_list, b"h2");
        len_u8(&mut proto_list, b"http/1.1");
        let mut data = Vec::new();
        len_u16(&mut data, &proto_list);
        ext(&mut exts, 0x0010, &data);
    }

    ext(&mut exts, 0x0005, &[0x01, 0x00, 0x00, 0x00, 0x00]);

    {
        let algs: &[u16] = &[
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805,
            0x0501, 0x0806, 0x0601,
        ];
        let mut list = Vec::new();
        for a in algs { u16be(&mut list, *a); }
        let mut data = Vec::new();
        len_u16(&mut data, &list);
        ext(&mut exts, 0x000d, &data);
    }

    ext(&mut exts, 0x0012, &[]);

    {
        let mut shares = Vec::new();
        let hybrid: Vec<u8> = x25519_pub.iter().chain(kyber_pub.iter()).copied().collect();
        u16be(&mut shares, 0x6399);
        len_u16(&mut shares, &hybrid);
        u16be(&mut shares, 0x001d);
        len_u16(&mut shares, x25519_pub);
        let mut data = Vec::new();
        len_u16(&mut data, &shares);
        ext(&mut exts, 0x0033, &data);
    }

    ext(&mut exts, 0x002d, &[0x01, 0x01]);
    ext(&mut exts, 0x002b, &[0x04, 0x03, 0x04, 0x03, 0x03]);
    ext(&mut exts, 0x001b, &[0x04, 0x00, 0x02, 0x00, 0x01]);

    {
        let mut inner = Vec::new();
        len_u8(&mut inner, b"h2");
        let mut data = Vec::new();
        len_u16(&mut data, &inner);
        ext(&mut exts, 0x4469, &data);
    }

    {
        let grease2 = loop {
            let g = random_grease();
            if g != grease { break g; }
        };
        ext(&mut exts, grease2, &[0x00]);
    }

    let ciphers: &[u16] = &[
        grease,
        0x1301, 0x1302, 0x1303,
        0xc02b, 0xc02f, 0xc02c, 0xc030,
        0xcca9, 0xcca8,
        0xc013, 0xc014,
        0x009c, 0x009d, 0x002f, 0x0035,
        0x00ff,
    ];
    let mut cipher_bytes = Vec::new();
    for c in ciphers { u16be(&mut cipher_bytes, *c); }

    let mut body = Vec::new();
    u16be(&mut body, 0x0303);
    body.extend_from_slice(random);
    len_u8(&mut body, session_id);
    len_u16(&mut body, &cipher_bytes);
    body.extend_from_slice(&[0x01, 0x00]);
    len_u16(&mut body, &exts);

    let mut hs = Vec::new();
    hs.push(0x01u8);
    u24be(&mut hs, body.len() as u32);
    hs.extend_from_slice(&body);
    hs
}
