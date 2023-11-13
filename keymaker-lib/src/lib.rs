// This file is part of GNU KeyMaker.
// (C) 2022 Theodore Huang <msa42@ctemplar.com>
//
// GNU KeyMaker is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// GNU KeyMaker is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: GPL-3.0-or-later

// TODO ser/deser format for profile + versioning = keymaker-cbor
// TODO Validation test for hash_to and hash function (with hardcoded vector)

#[cfg(feature = "crypto_dumb")]
mod crypto_dumb;
#[cfg(feature = "crypto_dumb")]
extern crate dumb_crypto;
#[cfg(feature = "crypto_dumb")]
use crypto_dumb::scrypt_derive;

#[cfg(feature = "crypto_rust")]
mod crypto_rust;
#[cfg(feature = "crypto_rust")]
extern crate scrypt;
#[cfg(feature = "crypto_rust")]
use crypto_rust::scrypt_derive;

pub const DEFAULT_IDENTITY: [u8; 1] = [0];
pub const HASH_LENGTH: usize = 64; // 512 bits
pub const LABEL_LENGTH: usize = 3; //  24 bits
pub const VERSION: u8 = 1;

const ALPHANUMERIC_CHARSETS: [[u8; 2]; 3] = {
    const CHARSET_NUM: [u8; 2] = [48, 57];
    const CHARSET_LOW: [u8; 2] = [97, 122];
    const CHARSET_UPP: [u8; 2] = [65, 90];

    [CHARSET_NUM, CHARSET_LOW, CHARSET_UPP]
};

const CHARS: [char; 57] = [
    '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'x', 'y', 'w', 'z', 'A', 'B', 'C', 'D', 'E',
    'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
];
const CHARS_AMBIGUOUS: [char; 5] = ['0', '1', 'l', 'I', 'O'];

const CHARS_SYMBOLS: [char; 3] = ['_', '.', '-'];
const CHARS_SYMBOLS_AMBIGUOUS: [char; 29] = [
    '`', '~', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '+', '=', '{', '}', '[', ']', '\\',
    '|', ':', ';', '"', '\'', '<', '>', ',', '?', '/',
];

const HASH_PARAMS: ScryptParams = ScryptParams {
    n: 65536,
    r: 8,
    p: 1,
};

pub struct Profile {
    pub crypto: CryptoProfile,
    pub user: UserProfile,
    pub version: u8,
}

pub struct CryptoProfile {
    pub identity_key_length: u16,
    pub scrypt: ScryptParams,
}

// TODO Validation see dum_crypto::scrypt::Scrypt
pub struct ScryptParams {
    n: usize, // CPU/memory cost
    r: usize, // block size
    p: usize, // parallelization
}

pub struct UserProfile {
    pub password: PasswordSettings,
    pub pin_length: u8,
}

pub struct PasswordSettings {
    pub allow_ambiguous_chars: bool,
    pub include_symbol: bool,
    pub length: u8,
}

pub struct IdentityKey {
    pub bytes: Vec<u8>,
}

// TODO Replace with instances of `Default`
pub fn default() -> Profile {
    Profile {
        crypto: CryptoProfile {
            identity_key_length: 1024,
            scrypt: ScryptParams {
                n: 131072,
                r: 8,
                p: 6,
            },
        },
        user: UserProfile {
            password: PasswordSettings {
                allow_ambiguous_chars: false,
                include_symbol: true,
                length: 12,
            },
            pin_length: 6,
        },
        version: VERSION,
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidParams(),
    InvalidOutputLength(),
}

pub struct KeyMaker<'a> {
    profile: &'a Profile,
}

impl KeyMaker<'_> {
    pub fn new(profile: &Profile) -> Result<KeyMaker, ()> {
        if profile.version == VERSION {
            Ok(KeyMaker { profile: profile })
        } else {
            Err(())
        }
    }

    pub fn derive(&self, input: &[u8], salt: &[u8], out: &mut [u8]) -> Result<(), Error> {
        scrypt_derive(&self.profile.crypto.scrypt, &input, salt, out)
    }

    pub fn derive_identity(
        &self,
        passphrase: &[u8],
        name: &[u8],
        generation: u8,
        pin: &[u8],
    ) -> Result<IdentityKey, Error> {
        self.derive_identity_from_raw(
            &self.hash(passphrase, pin)?,
            &self.hash(name, pin)?,
            generation,
            pin,
        )
    }

    pub fn derive_identity_from_raw(
        &self,
        passphrase_hash: &[u8; HASH_LENGTH],
        name_hash: &[u8; HASH_LENGTH],
        generation: u8,
        pin: &[u8],
    ) -> Result<IdentityKey, Error> {
        let mut input: Vec<u8> = Vec::new();
        let mut bytes: Vec<u8> = vec![0; self.profile.crypto.identity_key_length as usize];
        input.extend(passphrase_hash.to_vec());
        input.extend(name_hash.to_vec());
        input.extend([generation]);
        self.derive(&input, pin, &mut bytes)?;
        Ok(IdentityKey { bytes: bytes })
    }

    pub fn derive_password(
        &self,
        key: &IdentityKey,
        name: &[u8],
        generation: u8,
        pin: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut bytes: Vec<u8> = vec![0; self.profile.user.password.length as usize * 2];
        self.derive_seed(key, pin, name, generation, &mut bytes)?;

        let mut numbers: Vec<u16> = Vec::new();
        for i in 0..self.profile.user.password.length {
            let fst: usize = i as usize * 2;
            let snd: usize = fst + 1;
            let number = ((bytes[fst] as u16) << 8) | bytes[snd] as u16;
            numbers.push(number);
        }

        
        let charsets = charsets_from_settings(&self.profile.user.password);
        Ok(password_encode(&charsets, &numbers))
    }

    pub fn derive_seed(
        &self,
        key: &IdentityKey,
        pin: &[u8],
        name: &[u8],
        generation: u8,
        out: &mut [u8],
    ) -> Result<(), Error> {
        let mut input: Vec<u8> = Vec::new();
        input.extend(key.bytes.clone());
        input.extend(self.hash(name, pin)?.to_vec());
        input.extend([generation]);
        self.derive(&input, pin, out)
    }

    pub fn hash(&self, input: &[u8], salt: &[u8]) -> Result<[u8; HASH_LENGTH], Error> {
        let mut out: [u8; HASH_LENGTH] = [0; HASH_LENGTH];
        self.hash_to(input, salt, &mut out)?;
        Ok(out)
    }

    pub fn hash_to(&self, input: &[u8], salt: &[u8], out: &mut [u8]) -> Result<(), Error> {
        scrypt_derive(&HASH_PARAMS, input, salt, out)
    }

    pub fn identity_label(
        &self,
        passphrase_hash: &[u8; HASH_LENGTH],
        pin: &[u8],
        name: &[u8],
    ) -> Result<[u8; LABEL_LENGTH], Error> {
        let mut input: Vec<u8> = Vec::new();
        input.extend(passphrase_hash.to_vec());
        input.extend(name);
        let mut label: [u8; LABEL_LENGTH] = [0; LABEL_LENGTH];
        self.hash_to(&input, pin, &mut label)?;
        Ok(label)
    }
}

fn chars_by_charsets(chars: &[u8]) -> Vec<Vec<u8>> {
    let mut charsets: Vec<Vec<u8>> = vec![Vec::new(), Vec::new(), Vec::new()];
    let mut symbols: Vec<u8> = Vec::new();

    for &c in chars {
        let mut is_alphanumeric = false;
        for i in 0..ALPHANUMERIC_CHARSETS.len() {
            let charset = ALPHANUMERIC_CHARSETS[i];
            if c >= charset[0] && c <= charset[1] {
                charsets[i].push(c);
                is_alphanumeric = true;
                break;
            }
        }
        if !is_alphanumeric {
            symbols.push(c);
        }
    }
    charsets.push(symbols);

    return charsets;
}

fn chars_from_settings(settings: &PasswordSettings) -> Vec<char> {
    let mut chars = Vec::new();
    chars.extend(CHARS);
    if settings.allow_ambiguous_chars {
        chars.extend(CHARS_AMBIGUOUS);
    }
    if settings.include_symbol {
        chars.extend(CHARS_SYMBOLS);
        if settings.allow_ambiguous_chars {
            chars.extend(CHARS_SYMBOLS_AMBIGUOUS);
        }
    }
    return chars;
}

fn charsets_from_settings(settings: &PasswordSettings) -> Vec<Vec<u8>> {
    let chars: Vec<u8> = chars_from_settings(settings).into_iter().map(|x| x as u8).collect();
    return chars_by_charsets(&chars).into_iter().filter(|cs| !cs.is_empty()).collect();
}

// TODO Second phase
// consider repeating characters, how to have option (opt-in) to avoid them?
// that could work as a second phase!
// TODO Add fuzz/quickcheck test to see
// - if there is always at least one character from each character set is present
// - if the total length is correct
// - if we eventually find a password with more than password_len / 2 for every characters sets
// - if we distibute characters uniformly
fn password_encode(charsets: &[Vec<u8>], numbers: &[u16]) -> Vec<u8> {
    use std::cmp::max;

    let charsets_len: usize = charsets.len();
    let password_len: usize = numbers.len();

    let mut charset_weights_sum: usize = 0;
    let mut charset_weights: Vec<usize> = Vec::new();
    
    // We use the length of the password as unit for weighting, this way we ensure that 
    // the sum of charset weights is bigger than the password length.
    // note: this allow us to use integers (as opposed to floats) during counts computation.
    let unit = password_len;
    for i in 0..charsets_len {
        // We factor the random number according to the size of the charsets, 
        // this is to ensure a uniform distribution of characters.
        let charset_n = charsets[i].len();
        assert!((u16::MAX as usize) <= (usize::MAX / charset_n));
        let weight = unit + (numbers[i] as usize * charset_n);
        charset_weights.push(weight);
        assert!(weight <= (usize::MAX / charset_n));
        charset_weights_sum += weight;
    }
    debug_assert!(charset_weights_sum > password_len);

    let charset_weights_factor: usize = charset_weights_sum / password_len;
    let mut charset_counts: Vec<usize> = Vec::new();
    for weight in charset_weights {
        charset_counts.push(max(1, weight / charset_weights_factor));
    }

    while charset_counts.iter().sum::<usize>() < password_len {
        let i = charset_counts.iter().sum::<usize>();
        charset_counts[numbers[i] as usize % charsets_len] += 1;
    }

    let mut digits: Vec<u8> = Vec::new();
    let mut offset: usize = 0;
    for j in 0..charsets_len {
        let l = charsets[j].len();
        let n = charset_counts[j];
        for k in offset..(offset + n) {
            let number = numbers[k];
            let char_i = charsets[j][number as usize % l];
            digits.push(char_i);
        }
        offset += n;
    }

    debug_assert!(offset == password_len);

    let mut password: Vec<u8> = Vec::new();
    for n in numbers {
        password.push(digits.remove(*n as usize % digits.len()));
    }

    return password;
}

// TODO inline documentation
// https://www.pleacher.com/mp/mlessons/algebra/entropy.html
// FIXME Currently this does not take into account that we use at least one char of each charsets
pub fn password_entropy(settings: &PasswordSettings) -> f64 {
    let mut p: f64 = 0.0;

    let mut chars_count: usize = 0;
    chars_count += CHARS.len();
    if settings.allow_ambiguous_chars {
        chars_count += CHARS_AMBIGUOUS.len();
    }

    if settings.include_symbol {
        p += (chars_count as f64).powf(settings.length as f64 - 1.0);

        let mut symbols_count: usize = 0;

        symbols_count += CHARS_SYMBOLS.len();
        if settings.allow_ambiguous_chars {
            symbols_count += CHARS_SYMBOLS_AMBIGUOUS.len();
        }

        p += (symbols_count * settings.length as usize) as f64;
    } else {
        p += (chars_count as f64).powf(settings.length as f64);
    }

    p.log2()
}

#[test]
fn charsets_from_settings_fixtures() {
    fn fixture(allow_ambiguous_chars: bool, include_symbol: bool, charsets_len: Vec<usize>) -> () {
        let settings =
            PasswordSettings {
                allow_ambiguous_chars: allow_ambiguous_chars,
                include_symbol: include_symbol,
                length: 0,
            }; 
        let charsets = charsets_from_settings(&settings);
        let xs: Vec<usize> = charsets.iter().map(|xs| xs.len()).collect();
        assert_eq!(xs, charsets_len);
    }

    fixture(false, false, vec![8, 25, 24]);
    fixture(false, true, vec![8, 25, 24, 3]);
    fixture(true, false, vec![10, 26, 26]);
    fixture(true, true, vec![10, 26, 26, 32]);
}

