extern crate challenge_bypass_ristretto;
extern crate rand;
extern crate sha2;

use core::ptr;
use std::ffi::CStr;
use std::os::raw::c_char;

use challenge_bypass_ristretto::{
    BlindedToken, FixedOutput, SignedToken, SigningKey, Token, TokenPreimage, UnblindedToken,
    VerificationKey, VerificationSignature,
};
use rand::rngs::OsRng;
use sha2::Sha512;

/// Destroy a `TokenPreimage` once you are done with it.
#[no_mangle]
pub unsafe extern "C" fn token_preimage_destroy(t: *mut TokenPreimage) {
    if !t.is_null() {
        drop(Box::from_raw(t));
    }
}

/// Generate a new `Token`
///
/// # Safety
///
/// Make sure you destroy the token with [`token_destroy()`] once you are
/// done with it.
#[no_mangle]
pub unsafe extern "C" fn token_generate() -> *mut Token {
    let mut rng = OsRng::new().unwrap();
    let token = Token::random(&mut rng);
    Box::into_raw(Box::new(token))
}

/// Destroy a `Token` once you are done with it.
#[no_mangle]
pub unsafe extern "C" fn token_destroy(token: *mut Token) {
    if !token.is_null() {
        drop(Box::from_raw(token));
    }
}

/// Take a reference to a `Token` and blind it, returning a `BlindedToken`
///
/// If something goes wrong, this will return a null pointer. Don't forget to
/// destroy the `BlindedToken` once you are done with it!
#[no_mangle]
pub unsafe extern "C" fn token_blind(token: *const Token) -> *mut BlindedToken {
    if token.is_null() {
        return ptr::null_mut();
    }

    Box::into_raw(Box::new((*token).blind()))
}

/// Take a reference to a `Token` and use it to unblind a `SignedToken`, returning an `UnblindedToken`
///
/// If something goes wrong, this will return a null pointer. Don't forget to
/// destroy the `UnblindedToken` once you are done with it!
#[no_mangle]
pub unsafe extern "C" fn token_unblind(
    token: *const Token,
    signed_token: *const SignedToken,
) -> *mut UnblindedToken {
    if token.is_null() {
        return ptr::null_mut();
    }
    if signed_token.is_null() {
        return ptr::null_mut();
    }
    return match (*token).unblind(&*signed_token) {
        Ok(unblinded_token) => Box::into_raw(Box::new(unblinded_token)),
        Err(_) => ptr::null_mut(),
    };
}

/// Destroy a `BlindedToken` once you are done with it.
#[no_mangle]
pub unsafe extern "C" fn blinded_token_destroy(token: *mut BlindedToken) {
    if !token.is_null() {
        drop(Box::from_raw(token));
    }
}

/// Destroy a `SignedToken` once you are done with it.
#[no_mangle]
pub unsafe extern "C" fn signed_token_destroy(token: *mut SignedToken) {
    if !token.is_null() {
        drop(Box::from_raw(token));
    }
}

/// Destroy an `UnblindedToken` once you are done with it.
#[no_mangle]
pub unsafe extern "C" fn unblinded_token_destroy(token: *mut UnblindedToken) {
    if !token.is_null() {
        drop(Box::from_raw(token));
    }
}

/// Take a reference to an `UnblindedToken` and use it to derive a `VerificationKey`
/// using Sha512 as the hash function
///
/// If something goes wrong, this will return a null pointer. Don't forget to
/// destroy the `VerificationKey` once you are done with it!
#[no_mangle]
pub unsafe extern "C" fn unblinded_token_derive_verification_key_sha512(
    token: *const UnblindedToken,
) -> *mut VerificationKey {
    if token.is_null() {
        return ptr::null_mut();
    }
    Box::into_raw(Box::new((*token).derive_verification_key::<Sha512>()))
}

/// Take a reference to an `UnblindedToken` and return the corresponding `TokenPreimage`
///
/// If something goes wrong, this will return a null pointer. Don't forget to
/// destroy the `BlindedToken` once you are done with it!
#[no_mangle]
pub unsafe extern "C" fn unblinded_token_preimage(
    token: *const UnblindedToken,
) -> *mut TokenPreimage {
    if token.is_null() {
        return ptr::null_mut();
    }

    Box::into_raw(Box::new((*token).t))
}

/// Destroy a `VerificationKey` once you are done with it.
#[no_mangle]
pub unsafe extern "C" fn verification_key_destroy(key: *mut VerificationKey) {
    if !key.is_null() {
        drop(Box::from_raw(key));
    }
}

/// Destroy a `VerificationSignature` once you are done with it.
#[no_mangle]
pub unsafe extern "C" fn verification_signature_destroy(
    sig: *mut VerificationSignature<<Sha512 as FixedOutput>::OutputSize>,
) {
    if !sig.is_null() {
        drop(Box::from_raw(sig));
    }
}

/// Take a reference to a `VerificationSignature` and check if it is equal to another
/// `VerificationSignature`
#[no_mangle]
pub unsafe extern "C" fn verification_signature_equals(
    sig1: *mut VerificationSignature<<Sha512 as FixedOutput>::OutputSize>,
    sig2: *mut VerificationSignature<<Sha512 as FixedOutput>::OutputSize>,
) -> bool {
    if !sig1.is_null() && !sig2.is_null() {
        *sig1 == *sig2
    } else {
        false
    }
}

/// Take a reference to a `VerificationKey` and use it to sign a message
/// using Sha512 as the HMAC hash function to obtain a `VerificationSignature`
///
/// If something goes wrong, this will return a null pointer. Don't forget to
/// destroy the `VerificationSignature` once you are done with it!
#[no_mangle]
pub unsafe extern "C" fn verification_key_sign_sha512(
    key: *const VerificationKey,
    message: *const c_char,
) -> *mut VerificationSignature<<Sha512 as FixedOutput>::OutputSize> {
    if key.is_null() {
        return ptr::null_mut();
    }

    let raw = CStr::from_ptr(message);

    let message_as_str = match raw.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };
    Box::into_raw(Box::new((*key).sign::<Sha512>(message_as_str.as_bytes())))
}

/// Generate a new `SigningKey`
///
/// # Safety
///
/// Make sure you destroy the key with [`signing_key_destroy()`] once you are
/// done with it.
#[no_mangle]
pub unsafe extern "C" fn signing_key_generate() -> *mut SigningKey {
    let mut rng = OsRng::new().unwrap();
    let key = SigningKey::random(&mut rng);
    Box::into_raw(Box::new(key))
}

/// Destroy a `SigningKey` once you are done with it.
#[no_mangle]
pub unsafe extern "C" fn signing_key_destroy(key: *mut SigningKey) {
    if !key.is_null() {
        drop(Box::from_raw(key));
    }
}

/// Take a reference to a `SigningKey` and use it to sign a `BlindedToken`, returning a
/// `SignedToken`
///
/// If something goes wrong, this will return a null pointer. Don't forget to
/// destroy the `SignedToken` once you are done with it!
#[no_mangle]
pub unsafe extern "C" fn signing_key_sign(
    key: *const SigningKey,
    token: *const BlindedToken,
) -> *mut SignedToken {
    if key.is_null() {
        return ptr::null_mut();
    }

    if token.is_null() {
        return ptr::null_mut();
    }

    return match (*key).sign(&*token) {
        Ok(signed_token) => Box::into_raw(Box::new(signed_token)),
        Err(_) => ptr::null_mut(),
    };
}

/// Take a reference to a `SigningKey` and use it to rederive an `UnblindedToken`
///
/// If something goes wrong, this will return a null pointer. Don't forget to
/// destroy the `UnblindedToken` once you are done with it!
#[no_mangle]
pub unsafe extern "C" fn signing_key_rederive_unblinded_token(
    key: *const SigningKey,
    t: *const TokenPreimage,
) -> *mut UnblindedToken {
    if key.is_null() {
        return ptr::null_mut();
    }

    if t.is_null() {
        return ptr::null_mut();
    }

    Box::into_raw(Box::new((*key).rederive_unblinded_token(&*t)))
}
