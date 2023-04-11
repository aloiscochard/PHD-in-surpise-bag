//  TODO
//  - to read
//    - opsec101.org "Don't start with counter measures"
//  - References
//    - https://github.com/smessmer/crypto-wallet-gen
//    - https://crates.io/crates/novault
//    - spectre.app
//
//  specify
//  - algorithm
//  - usage example
//    - basics
//      km --export
//          export info & metadata in a encrypted and standardized (text) format (libkeymaker)
//      km --create
//      km --import
//                    <-- Must ask default identity (or it will be empty by default)
//                    <-- encrypt and store identity key on disk
//
//      km <name> --identity stallman@fsf.org
//      km <name> --derive [password|phrase:BIP39|key:ssh|]
//      km <name> --revoke [--ticker 2]
//                    <-- if name starts with "$", treats as specially format (use \ to escape)
//                      $anon = anonymous handle (ie. `km $anon --identity stallman@fsf.org`)
//                        == 0x454D50524553
//                        == 0xc00000404b
//      km --info
//                  <-- return all information that must be remembered for usage
//      km --metadata
//                  <-- return path to metadata folder
//
//

// TODO IDEAS REPL
// keymaker [--create|import]
// keymaker [--info|--metadata]
// <ask passphrase>
// <print info/path to metadata>
// keymaker [--identity rms] [--revoke [<generation>]]
// ¤ <name> [--format [password|phrase:BIP39|key:ssh] | [--revoke [<generation>]]
// ¤ gnu.org
// ¤ id --format [ssh|pgp]
// ¤ $anon
// ¤ :id[entity] [rms] [--revoke [<generation>]]
// ¤ :id $anon << NOT NEEDED ANY MORE, this become the prompt!
// ¤ :q[uit]
//
//

// TODO IDEAS CONFIG
// - can decide in the config how to provide passwords/secret:
//      - if no config set, let user decide with a key press
//      - show on prompt
//          - auto-hide (n seconds)
//          - force hide when pressing key
//      - copy in clipboard
//          - prompt for it, copy when key pressed
//          - autoclear clipboard aften N seconds

/*
THINK
- The identity key could be simply hash(passphrase=hash512(passphrase)+hash512(identity_name)+generation, salt=PIN, out=identityKeyLength)
    - in memory: (works like a REPL -- keymaker is the agent (repl for now), km is the client)
        identity keys must be encrypted with PIN, and with them the hash of the passphrase
        we encrypt the last time the passphrase was typed in an other blop, also encrypted with PIN
    - on disk:
        we store only hash(identity_key) for validation

- Where/How to do serialization of the configuration?
    - keymaker-cbor

*/
extern crate keymaker_lib;

extern crate aes;
extern crate constant_time_eq;
extern crate hex;
extern crate ofb;
extern crate rand;
extern crate rustyline;
extern crate zeroize;

use keymaker_lib::{IdentityKey, KeyMaker, DEFAULT_IDENTITY, HASH_LENGTH};

use aes::cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher, StreamCipherSeek};
use aes::Aes256;
use constant_time_eq::constant_time_eq;
use ofb::Ofb;
use rand::rngs::OsRng;
use rand::RngCore;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use zeroize::Zeroize;

const PROMPT_SYMBOL: char = '¤';

// TODO Document in-memory encryption usage in man/README
type Aes256Ofb = Ofb<Aes256>;

fn read_secret(prompt: &str) -> Result<Vec<u8>, Error> {
    let mut secret_str: String = rpassword::prompt_password(prompt).map_err(Error::from_io)?;
    let mut secret: Vec<u8> = secret_str.as_bytes().to_vec();
    secret_str.zeroize();
    Ok(secret)
}

fn nonce_gen() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

#[derive(Debug)]
enum Error {
    IO(std::io::Error),
    KM(keymaker_lib::Error),
}

impl Error {
    fn from_io(err: std::io::Error) -> Error {
        Error::IO(err)
    }
    fn from_km(err: keymaker_lib::Error) -> Error {
        Error::KM(err)
    }
}

// TODO MAKE zeroize a default feature (useful to disable for debugging!)

fn open() -> () {
    // TODO
    // when loading, we use the nonce stored on disk only to validate it's a known identity
    // then we use a fresh nonce for in-memory encryption
    //  TODO ??? -> HOW DO WE CHECK THAT THE PIN IS CORRECT WHEN LOADING IDENTITY?
    // by matching the identity_key_hash!
}

fn import(keymaker: &KeyMaker, identity_name: &mut Vec<u8>) -> Result<Identity, Error> {
    let nonce: [u8; 12] = nonce_gen();

    let mut passphrase: Vec<u8> = read_secret("passphrase: ")?;
    let mut pin: Vec<u8> = read_secret("PIN: ")?;
    let mut passphrase_hash: [u8; HASH_LENGTH] =
        keymaker.hash(&passphrase, &pin).map_err(Error::from_km)?;

    passphrase.zeroize();

    let mut identity_key = keymaker
        .derive_identity_from_raw(
            &passphrase_hash,
            &keymaker
                .hash(&identity_name, &pin)
                .map_err(Error::from_km)?,
            0,
            &pin,
        )
        .map_err(Error::from_km)?;

    let identity_label: [u8; 3] = keymaker
        .identity_label(&passphrase_hash, &identity_name, &pin)
        .map_err(Error::from_km)?;

    passphrase_hash.zeroize();
    identity_name.zeroize();

    // TODO Extract and share key/iv building with `derive`? YES BECAUSE ENCRYPTION/DECRYPTION is
    // FULLY SYMMETRIC
    let mut aes_key: [u8; 32] = [0u8; 32];
    keymaker.hash_to(&pin, &nonce, &mut aes_key);

    let mut aes_iv: [u8; 16] = [0u8; 16];
    keymaker.hash_to(&nonce, &pin, &mut aes_iv);

    pin.zeroize();

    let identity_key_hash = keymaker
        .hash(&identity_key.bytes, &nonce)
        .map_err(Error::from_km)?;

    let mut aes_cipher = Aes256Ofb::new(
        GenericArray::from_mut_slice(&mut aes_key),
        GenericArray::from_mut_slice(&mut aes_iv),
    );
    aes_cipher.apply_keystream(&mut identity_key.bytes);
    aes_key.zeroize();

    Ok(Identity {
        label: identity_label,
        nonce: nonce,
        key_hash: identity_key_hash,
        key_encrypted: identity_key.bytes,
    })
}

fn derive_password(keymaker: &KeyMaker, identity: &Identity, name: &[u8]) -> Result<(), Error> {
    let mut pin: Vec<u8> = read_secret("PIN: ")?;

    let mut aes_key: [u8; 32] = [0u8; 32];
    keymaker.hash_to(&pin, &identity.nonce, &mut aes_key);

    let mut aes_iv: [u8; 16] = [0u8; 16];
    keymaker.hash_to(&identity.nonce, &pin, &mut aes_iv);

    let mut aes_cipher = Aes256Ofb::new(
        GenericArray::from_mut_slice(&mut aes_key),
        GenericArray::from_mut_slice(&mut aes_iv),
    );

    let mut identity_key = IdentityKey {
        bytes: identity.key_encrypted.clone(),
    };
    aes_cipher.apply_keystream(&mut identity_key.bytes);
    aes_key.zeroize();

    let mut password: Vec<u8> = keymaker
        .derive_password(&identity_key, name, 0, &pin)
        .map_err(Error::from_km)?;

    pin.zeroize();

    let identity_key_hash = keymaker
        .hash(&identity_key.bytes, &identity.nonce)
        .map_err(Error::from_km)?;
    let authenticated: bool = constant_time_eq(&identity_key_hash, &identity.key_hash);

    identity_key.bytes.zeroize();

    if !authenticated {
        println!("keymaker: Incorrect PIN");
    } else {
        println!("password: {}", String::from_utf8_lossy(&password));
    }

    password.zeroize();

    // TODO
    // ... hash password, put in clipboard, zeroize
    // return password_hash with fresh nonce for monitoring

    Ok(())
}

// TODO IDEA
// -- monitor keyboard for Ctrl+V to clear the clipboard before timeout

// TODO Stealth `--stealth` mode, which read/write nothing on disk
//      (ask for repetition of passphrase and pin when initial import)

/*
IDEA: label for identity
    <hash32 of `passphrase_hash+identity name` using pin as salt>


STORE ON DISK
  .config/keymaker/keymaker.conf (with import <-> export to cbor)
    [keymaker]
    include_symbol = false

  .config/keymaker/identities/<nonce><key_hash>
  .config/keymaker/metadata/<key_hash with salt=hash(identity_data_nonce, salt=pin)>/generation <-- content is salt encrypted generation
                                                                                /nonce <-- salt used is pin encrypted
                                                                                /<name_hash128 (twelwe digits) with salt=nonce> <-- content is salt encrypted generation
*/

// TODO  METAKEY (binary, hash_to from km_lib output textual keys -- no deps)
// key format support thru text only: https://coolaj86.com/articles/openssh-vs-openssl-key-formats/
// TODO IDEA
// when asking for a password, once computed firsh show:
// password: ********
// do you want to (S)how the password, or (C)opy it to the clipboard?
// show it only for N seconds, same for clipboard, keep it only for N seconds in the clipboard

struct Identity {
    label: [u8; 3],
    nonce: [u8; 12],
    key_hash: [u8; HASH_LENGTH],
    key_encrypted: Vec<u8>,
}

// TODO Colors
// - read prompt: passphrase in red, pin in orange,
// - symbol prompt: red when password in clipboard (and not blinking, if keep press clear clipboard
// and go to next green state), otherwise green
// TODO Remove ALL magic numbers
// TODO Metadata serde should be in keymaker_lib as well
//      - support a file format to export/backup everything
//
// TODO Create `open` method.
// TODO Auto-clear clipboard after Ns if still contains password
// TODO Support encrypted line history (per identity) in metadata

// MVP
// - clipboard output (see idea above)
// - metakey integration

fn main() {
    let keymaker_cfg = keymaker_lib::default();
    let keymaker = KeyMaker::new(&keymaker_cfg).unwrap();

    let mut identity_name: Vec<u8> = DEFAULT_IDENTITY.to_vec();
    let identity = import(&keymaker, &mut identity_name).unwrap();

    let prompt = format!("{} {} ", hex::encode(identity.label), PROMPT_SYMBOL);


    NEXT
        - Proper parsing (do we allow space in name?)
        - Build key with format included when deriving seeds
            id\0ssh-ed25519
            

    let mut rl = Editor::<()>::new();
    loop {
        let readline = rl.readline(&prompt);
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str());
                derive_password(&keymaker, &identity, &line.as_bytes()).unwrap();
            }
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }
}
