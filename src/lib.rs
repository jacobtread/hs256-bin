use base64ct::{Base64UrlUnpadded, Encoding};
use ring::hmac::{self, HMAC_SHA256};

#[derive(Debug)]
pub enum DecodeError {
    InvalidToken,
    InvalidSignature,
}

impl From<base64ct::Error> for DecodeError {
    fn from(_: base64ct::Error) -> Self {
        Self::InvalidToken
    }
}

/// Tokens interface for creating and validating tokens
pub struct Tokens {
    key: hmac::Key,
}

impl Tokens {
    /// Creates a new tokens interface from the provided
    /// secret key
    ///
    /// `secret` The secret key
    pub fn new(secret: &[u8]) -> Self {
        // Create a new HMAC key using the provided secret
        let key = hmac::Key::new(HMAC_SHA256, secret);
        Self { key }
    }

    /// Encodes the value by base64 encoding the value and a
    /// signature for the value then joining them
    ///
    /// `value` The data to encode as the token value
    pub fn encode(&self, value: &[u8]) -> String {
        // Encode the message
        let msg = Base64UrlUnpadded::encode_string(value);

        // Create a signature from the raw message bytes
        let sig = hmac::sign(&self.key, value);
        let sig = Base64UrlUnpadded::encode_string(sig.as_ref());

        // Join the message and signature to create the token
        [msg, sig].join(".")
    }

    /// Decodes a token claims from the provided token string
    ///
    /// `token` The token to decode
    pub fn decode(&self, token: &str) -> Result<Vec<u8>, DecodeError> {
        // Split the token parts
        let (msg, sig) = match token.split_once('.') {
            Some(value) => value,
            None => return Err(DecodeError::InvalidToken),
        };

        // Decode the message signature
        let msg: Vec<u8> = Base64UrlUnpadded::decode_vec(msg)?;
        let sig: Vec<u8> = Base64UrlUnpadded::decode_vec(sig)?;

        // Verify the signature
        if hmac::verify(&self.key, &msg, &sig).is_err() {
            return Err(DecodeError::InvalidSignature);
        }

        // Decode the verified token claims
        Ok(msg)
    }
}
