use std::prelude::v1::*;

#[derive(Debug)]
pub enum Error {
    InvalidName(String),
    InvalidData,
}
