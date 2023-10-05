use std::prelude::v1::*;

#[derive(Debug, Clone, PartialEq)]
pub enum ParamType {
    // uint, uint256, uint<M>
    Uint(usize),
    // int, int256, int<M>
    Int(usize),
    // address
    Address,
    // bool(uint8)
    Bool,
    // bytes<M>
    FixedBytes(usize),
    // bytes
    Bytes,
    // string
    String,
    // <type>[M]
    FixedArray(Box<ParamType>, usize),
    // <type>[]
    Array(Box<ParamType>),
    // tuple
    Tuple(Vec<ParamType>),
}

impl ParamType {
    pub fn is_dynamic(&self) -> bool {
        match self {
            ParamType::Bytes | ParamType::String | ParamType::Array(_) => true,
            ParamType::FixedArray(elem_type, _) => elem_type.is_dynamic(),
            ParamType::Tuple(params) => params.iter().any(|param| param.is_dynamic()),
            _ => false,
        }
    }

    pub fn is_array_like(&self) -> bool {
        match self {
            ParamType::FixedArray(_, _) | ParamType::Array(_) | ParamType::Tuple(_) => true,
            _ => false,
        }
    }

    pub fn is_fixed_length(&self) -> bool {
        match self {
            ParamType::FixedArray(_, _) | ParamType::Tuple(_) => true,
            _ => false,
        }
    }
}

impl std::fmt::Display for ParamType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Writer::write(self))
    }
}

pub struct Writer;

impl Writer {
    /// Returns string which is a formatted represenation of param.
    pub fn write(param: &ParamType) -> String {
        Writer::write_for_abi(param, true)
    }

    /// If `serialize_tuple_contents` is `true`, tuples will be represented
    /// as list of inner types in parens, for example `(int256,bool)`.
    /// If it is `false`, tuples will be represented as keyword `tuple`.
    pub fn write_for_abi(param: &ParamType, serialize_tuple_contents: bool) -> String {
        match *param {
            ParamType::Address => "address".to_owned(),
            ParamType::Bytes => "bytes".to_owned(),
            ParamType::FixedBytes(len) => format!("bytes{}", len),
            ParamType::Int(len) => format!("int{}", len),
            ParamType::Uint(len) => format!("uint{}", len),
            ParamType::Bool => "bool".to_owned(),
            ParamType::String => "string".to_owned(),
            ParamType::FixedArray(ref param, len) => {
                format!(
                    "{}[{}]",
                    Writer::write_for_abi(param, serialize_tuple_contents),
                    len
                )
            }
            ParamType::Array(ref param) => {
                format!(
                    "{}[]",
                    Writer::write_for_abi(param, serialize_tuple_contents)
                )
            }
            ParamType::Tuple(ref params) => {
                if serialize_tuple_contents {
                    let formatted = params
                        .iter()
                        .map(|t| Writer::write_for_abi(t, serialize_tuple_contents))
                        .collect::<Vec<String>>()
                        .join(",");
                    format!("({})", formatted)
                } else {
                    "tuple".to_owned()
                }
            }
        }
    }
}
