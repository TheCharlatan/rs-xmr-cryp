extern crate rand;
extern crate ed25519_dalek;

use rand::rngs::OsRng;
use ed25519_dalek::Keypair;
use ed25519_dalek::Signature;

let mut csprng = OsRng{}
let keypair: Keypair = Keypair::generate(&mut csprng);

let message: &u[8] = b"This is the string I want a signature for";
let signature: Signature = keypair.sign(message);

assert!(keypair.verify(message, &signature).is_ok());


