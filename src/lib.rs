#![cfg_attr(feature = "tstd", no_std)]

#[cfg(feature = "tstd")]
#[macro_use]
extern crate sgxlib as std;

mod encode;
pub use encode::*;

mod decode;
pub use decode::*;

mod token;
pub use token::*;

mod param_type;
pub use param_type::*;

mod errors;
pub use errors::*;

pub type Word = [u8; 32];
pub type Uint = eth_types::SU256;
pub type Int = eth_types::SU256;
pub type Address = eth_types::SH160;
pub type FixedBytes = Vec<u8>;
pub type Bytes = Vec<u8>;
