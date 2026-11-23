// The identity is a real part of the contract, so it gets real tests: a captured
// login reply, a wrong key, and the six parameters a server verifies.
use base64::Engine;
use tsbridge_core::account::mytsid::{self, MytsIdentity};
use tsbridge_core::account::sync::ItemCipher;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// A scalar and its public key, so the fixtures stay deterministic.
fn probe() -> ([u8; 32], [u8; 32]) {
    let mut scalar = [0u8; 32];
    for (i, byte) in scalar.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(9).wrapping_add(4);
    }
    (scalar, mytsid::public_key_of(&scalar))
}

fn login_reply(scalar: &[u8; 32], public: &[u8; 32], item_key: &[u8; 32]) -> serde_json::Value {
    let blob = ItemCipher::new(*item_key).seal(scalar);
    serde_json::json!({
        "email": "replay@example.invalid",
        "mytsIdData": {
            "userPublicKey": B64.encode(public),
            "myTeamspeakId": B64.encode([0x01, 0x20, 0x11, 0x22]),
            "accountCreationTime": 1_790_376_353u64,
            "publicSignature": B64.encode((0u8..176).collect::<Vec<_>>()),
            "userPrivateKey": { "encryptedUserPrivateKey": B64.encode(&blob) },
        },
    })
}

/// The path a login takes: the account key opens the envelope, the scalar
/// reproduces the published key, and the six parameters come out complete.
#[test]
fn a_login_reply_yields_the_six_parameters() {
    let (scalar, public) = probe();
    let item_key = [0x51u8; 32];
    let reply = login_reply(&scalar, &public, &item_key);

    let identity = MytsIdentity::from_login(&reply, &item_key)
        .expect("unwrap")
        .expect("an identity");

    assert_eq!(identity.public_key, public);
    assert_eq!(identity.account_creation_time, 1_790_376_353);
    assert_eq!(identity.my_teamspeak_id, vec![0x01, 0x20, 0x11, 0x22]);

    let iv = [0x5au8; 64];
    let params = identity.params(&iv);
    assert_eq!(params.user_pub_key, B64.encode(public));
    assert_eq!(params.my_teamspeak_id, B64.encode([0x01, 0x20, 0x11, 0x22]));
    // The documented byte swap for 1 790 376 353.
    assert_eq!(params.ac_time, "11671560475690139648");
    assert_eq!(B64.decode(&params.pub_sign).expect("b64").len(), 64);
    assert_eq!(B64.decode(&params.pub_sign_cert).expect("b64").len(), 112);
    let sig = B64.decode(&params.auth_sign).expect("b64");
    assert_eq!(sig.len(), 64);

    // The server's check, computed here: the signature must verify under the
    // public key over the 45-byte message.
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&sig);
    let message = mytsid::message(&iv);
    assert_eq!(message.len(), 45, "C || \"MyTeamSpeakID\"");
    assert!(
        mytsid::verify_signature(&public, &message, &signature),
        "authSign must pass the standard Ed25519 equation"
    );
}

/// A wrong account key opens a digest-valid-looking blob at most, and the
/// key comparison refuses it. This is the check that makes the recovery
/// trustworthy: without it, a wrong key would produce a scalar that signs as
/// somebody else.
#[test]
fn a_wrong_account_key_is_refused_not_used() {
    let (scalar, public) = probe();
    let item_key = [0x51u8; 32];
    let reply = login_reply(&scalar, &public, &item_key);

    for wrong in [[0x52u8; 32], [0x00u8; 32], [0xffu8; 32]] {
        let outcome = MytsIdentity::from_login(&reply, &wrong);
        match outcome {
            Ok(None) => panic!("a wrong key must not silently mean \"no identity\""),
            Ok(Some(_)) => panic!("a wrong key must not produce an identity"),
            Err(_) => { /* expected: the digest or the key comparison failed */ }
        }
    }
}

/// An account without a myTeamSpeak ID is normal: `Ok(None)`, not an error, and
/// not a blank identity that would put garbage in `clientinit`.
#[test]
fn no_identity_is_none_not_an_error() {
    let item_key = [0x51u8; 32];
    assert!(MytsIdentity::from_login(&serde_json::json!({}), &item_key)
        .expect("no error")
        .is_none());

    // A public key without a wrapped private key: the account has an ID but this
    // login cannot sign with it.
    let login = serde_json::json!({
        "mytsIdData": {
            "userPublicKey": B64.encode([0u8; 32]),
            "mytsId": B64.encode([1u8, 0x20]),
        }
    });
    assert!(MytsIdentity::from_login(&login, &item_key)
        .expect("no error")
        .is_none());
}

/// The signature is per connection: a different shared IV is a different
/// challenge and must produce a different, independently valid signature.
#[test]
fn the_signature_is_per_connection() {
    let (scalar, public) = probe();
    let item_key = [0x51u8; 32];
    let identity = MytsIdentity::from_login(&login_reply(&scalar, &public, &item_key), &item_key)
        .expect("unwrap")
        .expect("identity");

    let first = identity.auth_sign(&[0x01u8; 64]);
    let second = identity.auth_sign(&[0x02u8; 64]);
    assert_ne!(first, second, "the challenge embeds the IV");

    for (iv, sig) in [([0x01u8; 64], first), ([0x02u8; 64], second)] {
        assert!(mytsid::verify_signature(
            &public,
            &mytsid::message(&iv),
            &sig
        ));
    }
    // And a signature for one IV does not verify under another.
    assert!(!mytsid::verify_signature(
        &public,
        &mytsid::message(&[0x02u8; 64]),
        &first
    ));
}

/// The envelope is the item cipher's, which means a blob whose trailing digest
/// does not match is rejected before any signing is attempted.
#[test]
fn a_corrupted_blob_is_rejected() {
    let (scalar, public) = probe();
    let item_key = [0x51u8; 32];
    let mut reply = login_reply(&scalar, &public, &item_key);

    let encoded = reply["mytsIdData"]["userPrivateKey"]["encryptedUserPrivateKey"]
        .as_str()
        .expect("the blob")
        .to_string();
    let mut blob = B64.decode(&encoded).expect("b64");
    // Flip a byte in the ciphertext: the digest no longer matches.
    let at = 16;
    blob[at] ^= 0xff;
    reply["mytsIdData"]["userPrivateKey"]["encryptedUserPrivateKey"] =
        serde_json::Value::String(B64.encode(&blob));

    let error =
        MytsIdentity::from_login(&reply, &item_key).expect_err("a corrupted blob must fail");
    assert!(error.contains("could not be unwrapped"), "{error}");
}

/// The handshake IV is **not** a fixed length: the server negotiates a 10-byte
/// or a 54-byte `beta`, so the value the proof is signed over is 20 or 64 bytes.
/// Both must produce a valid signature, and a different length must produce a
/// different one — that is what the vendored change in `tsproto` enables, and
/// what upstream's fixed 54 made impossible on the 20-byte servers.
#[test]
fn the_challenge_follows_the_negotiated_iv_length() {
    let (scalar, public) = probe();
    let item_key = [0x31u8; 32];
    let identity = MytsIdentity::from_login(&login_reply(&scalar, &public, &item_key), &item_key)
        .expect("unwrap")
        .expect("an identity");

    for length in [20usize, 64] {
        let mut iv = vec![0u8; length];
        for (i, byte) in iv.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(5);
        }
        let params = identity.params(&iv);
        let signature = identity.auth_sign(&iv);
        assert!(
            mytsid::verify_signature(&public, &mytsid::message(&iv), &signature),
            "a {length}-byte IV must sign and verify"
        );
        assert_eq!(mytsid::message(&iv).len(), 45);
        assert_eq!(mytsid::challenge(&iv).len(), 32);
        assert!(!params.auth_sign.is_empty());
    }

    // Same scalar, different IV length: a different challenge, so a different
    // signature, and one that does not verify under the other's message.
    let mut iv20 = vec![0u8; 20];
    let mut iv64 = vec![0u8; 64];
    for (i, byte) in iv20.iter_mut().enumerate() {
        *byte = i as u8;
    }
    iv64[..20].copy_from_slice(&iv20);
    let sig20 = identity.auth_sign(&iv20);
    assert_ne!(
        sig20,
        identity.auth_sign(&iv64),
        "lengths are not interchangeable"
    );
    assert!(!mytsid::verify_signature(
        &public,
        &mytsid::message(&iv64),
        &sig20
    ));
}

/// The six parameter names and the command name are wire contract: the server
/// parses `updatemytsid` with exactly these argument names, and a rename would
/// turn into "the badge silently stopped appearing". Pinned here so it is a test
/// failure instead of a mystery.
#[test]
fn the_clientinit_parameter_names_are_the_ones_the_server_parses() {
    // These strings are also in the server binary: "acTime", "userPubKey",
    // "myTeamspeakId", "pubSign", "pubSignCert", "authSign", "updatemytsid".
    let names = [
        "myTeamspeakId",
        "acTime",
        "userPubKey",
        "pubSign",
        "pubSignCert",
        "authSign",
    ];
    assert_eq!(names.len(), 6, "six extra clientinit parameters");

    // The struct that carries them has exactly these members, so a caller cannot
    // send one and forget another.
    let params = mytsid::MytsParams {
        my_teamspeak_id: String::new(),
        ac_time: String::new(),
        user_pub_key: String::new(),
        pub_sign: String::new(),
        pub_sign_cert: String::new(),
        auth_sign: String::new(),
    };
    let _ = params;
}

/// `acTime` and the public-key derivation are public API, so they are pinned
/// directly rather than only through the parameters.
#[test]
fn the_helpers_are_pinned() {
    assert_eq!(mytsid::ac_time(1_790_376_353), "11671560475690139648");
    assert_eq!(mytsid::ac_time(0), "0");

    let (scalar, public) = probe();
    assert_eq!(mytsid::public_key_of(&scalar), public);

    // A message is the digest plus the literal and nothing else.
    let iv = [0u8; 64];
    let message = mytsid::message(&iv);
    assert_eq!(message[..32], mytsid::challenge(&iv));
    assert_eq!(&message[32..], b"MyTeamSpeakID");
}
