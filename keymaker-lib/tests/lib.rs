extern crate keymaker_lib;

use keymaker_lib::{default, password_entropy, Error, IdentityKey, KeyMaker, DEFAULT_IDENTITY};

// TODO Write test
// - to check changing password length
// - derive seed of different length (hardcoded vector)
// - to check that identity keys are different for different parameters
//      (passphrase, pin, name, generation)
// - to check that seed are different for different parameters
// - to check that using different PIN result in mismatching passwords
// - to check what happen when giving invalid params, or output buffer

fn derive_identity_0(keymaker: &KeyMaker, gen: u8) -> Result<IdentityKey, Error> {
    keymaker.derive_identity(
        b"The idea of free software is that users of computing deserve freedom.",
        &DEFAULT_IDENTITY, // b"rms@gnu.org",
        gen,
        b"St_IGNUcius",
    )
}

#[test]
fn password_entropy_default() {
    let profile = default();
    assert_eq!(password_entropy(&profile.user.password).ceil(), 65.0);
}

#[test]
fn password_entropy_settings0() {
    let mut profile = default().user.password;
    profile.allow_ambiguous_chars = true;
    profile.include_symbol = true;
    assert_eq!(password_entropy(&profile).ceil(), 66.0);
}

// MVP
// investigate fuzz testing
//  - ie. generate password with fuzzing and check they ensure certain property
//      - at least one symbol, ...
// CHECK THAT PASSWORD ARE DIFFERENT PER
// - IDENTITY
// - GENERATION
// - settings0
//
#[test]
fn it_works() {
    let profile = default();

    let keymaker = KeyMaker::new(&profile).unwrap();

    let ref ik = derive_identity_0(&keymaker, 1).unwrap();

    let password_0 = keymaker
        .derive_password(ik, b"fsf.org", 0, b"St_IGNUcius")
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&password_0), "fJbuhqd8-2rS");

    let password_1 = keymaker
        .derive_password(ik, b"fsf.org", 1, b"St_IGNUcius")
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&password_1), "LSdDSuD.KVHg");
}
