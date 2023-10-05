use std::prelude::v1::*;

use eth_types::HexBytes;

use crate::{Address, Bytes, FixedBytes, Int, ParamType, Uint};

#[derive(Debug, Clone)]
pub enum Token {
    // uintx, x % 8 == 0
    Uint(Uint, usize),
    // intx, x % 8 == 0
    Int(Int, usize),
    // address
    Address(Address),
    // bool(uint8)
    Bool(bool),
    // bytes<M>
    FixedBytes(FixedBytes),
    // <type>[M]
    FixedArray(Vec<Token>, ParamType),
    // bytes
    Bytes(Bytes),
    // string
    String(String),
    // <type>[]
    Array(Vec<Token>, ParamType),
    // (..)
    Tuple(Vec<Token>),
}

impl Token {
    pub fn type_check(&self, param_type: &ParamType) -> bool {
        match *self {
            Token::Address(_) => *param_type == ParamType::Address,
            Token::Bytes(_) => *param_type == ParamType::Bytes,
            Token::Int(_, sz) => {
                matches!(*param_type, ParamType::Int(sz_) if sz == sz_)
            }
            Token::Uint(_, sz) => {
                matches!(*param_type, ParamType::Uint(sz_) if sz == sz_)
            }
            Token::Bool(_) => *param_type == ParamType::Bool,
            Token::String(_) => *param_type == ParamType::String,
            Token::FixedBytes(ref bytes) => {
                if let ParamType::FixedBytes(size) = *param_type {
                    size >= bytes.len()
                } else {
                    false
                }
            }
            Token::Array(ref tokens, ref ty) => {
                if let ParamType::Array(ref param_type) = *param_type {
                    tokens
                        .iter()
                        .all(|t| t.type_check(param_type) && ty == param_type.as_ref())
                } else {
                    false
                }
            }
            Token::FixedArray(ref tokens, ref ty) => {
                if let ParamType::FixedArray(ref param_type, size) = *param_type {
                    size == tokens.len()
                        && tokens
                            .iter()
                            .all(|t| t.type_check(param_type) && ty == param_type.as_ref())
                } else {
                    false
                }
            }
            Token::Tuple(ref tokens) => {
                if let ParamType::Tuple(ref param_type) = *param_type {
                    tokens
                        .iter()
                        .enumerate()
                        .all(|(i, t)| t.type_check(&param_type[i]))
                } else {
                    false
                }
            }
        }
    }

    pub fn type_info(&self) -> ParamType {
        match self {
            Token::Uint(_, sz) => ParamType::Uint(*sz),
            Token::Int(_, sz) => ParamType::Int(*sz),
            Token::Address(_) => ParamType::Address,
            Token::Bool(_) => ParamType::Bool,
            Token::FixedBytes(bytes) => ParamType::FixedBytes(bytes.len()),
            Token::FixedArray(vs, ty) => ParamType::FixedArray(Box::new(ty.clone()), vs.len()),
            Token::Bytes(_) => ParamType::Bytes,
            Token::String(_) => ParamType::String,
            Token::Array(_, ty) => ParamType::Array(Box::new(ty.clone())),
            Token::Tuple(vs) => ParamType::Tuple(vs.iter().map(|v| v.type_info()).collect()),
        }
    }
}

impl std::fmt::Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Token::Bool(b) => write!(f, "{}", b),
            Token::String(s) => write!(f, "{}", s),
            Token::Address(a) => write!(f, "{:?}", a),
            Token::Bytes(bytes) | Token::FixedBytes(bytes) => {
                write!(f, "{}", HexBytes::from_hex(bytes).unwrap())
            }
            Token::Uint(i, _) | Token::Int(i, _) => write!(f, "{}", i),
            Token::Array(arr, _) | Token::FixedArray(arr, _) => {
                let s = arr
                    .iter()
                    .map(|t| format!("{}", t))
                    .collect::<Vec<String>>()
                    .join(",");
                write!(f, "[{}]", s)
            }
            Token::Tuple(s) => {
                let s = s
                    .iter()
                    .map(|t| format!("{}", t))
                    .collect::<Vec<String>>()
                    .join(",");
                write!(f, "({})", s)
            }
        }
    }
}
