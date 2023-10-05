use std::prelude::v1::*;

use eth_types::{H160, SU256};

use crate::{Error, ParamType, Token, Word};

// may left some data to decode at the end
pub fn decode(types: &[ParamType], data: &[u8]) -> Result<Vec<Token>, Error> {
    decode_offset(types, data).map(|(tokens, _)| tokens)
}

fn decode_offset(types: &[ParamType], data: &[u8]) -> Result<(Vec<Token>, usize), Error> {
    let mut tokens = vec![];
    let mut offset = 0;

    for param in types {
        let res = decode_param(param, data, offset)?;
        offset = res.new_offset;
        tokens.push(res.token);
    }

    Ok((tokens, offset))
}

#[derive(Debug)]
struct DecodeResult {
    token: Token,
    new_offset: usize,
}

fn decode_param(param: &ParamType, data: &[u8], offset: usize) -> Result<DecodeResult, Error> {
    match param {
        ParamType::Uint(sz) => {
            let slice = peek_32_bytes(data, offset)?;
            let val = SU256::from_big_endian(&slice);
            let res = if *sz % 8 == 0 {
                DecodeResult {
                    token: Token::Uint(val, *sz),
                    new_offset: offset + 32,
                }
            } else {
                return Err(Error::InvalidName(format!("uint{} not aligned", sz)));
            };
            Ok(res)
        }
        ParamType::Int(sz) => {
            let slice = peek_32_bytes(data, offset)?;
            let n = SU256::from_big_endian(&slice);
            let res = if *sz % 8 == 0 {
                DecodeResult {
                    token: Token::Int(n, *sz),
                    new_offset: offset + 32,
                }
            } else {
                return Err(Error::InvalidName(format!("int{} not aligned", sz)));
            };
            Ok(res)
        }
        ParamType::Address => {
            let slice = peek_32_bytes(data, offset)?;
            let val = H160::from_slice(&slice[12..]);
            Ok(DecodeResult {
                token: Token::Address(val.into()),
                new_offset: offset + 32,
            })
        }
        ParamType::Bool => {
            let slice = peek_32_bytes(data, offset)?;
            let val = as_bool(&slice)?;
            Ok(DecodeResult {
                token: Token::Bool(val),
                new_offset: offset + 32,
            })
        }
        ParamType::FixedBytes(len) => {
            if *len > 32 {
                return Err(Error::InvalidName(format!("bytes{} oversized", len)));
            }
            let bytes = take_bytes(data, offset, *len)?;
            Ok(DecodeResult {
                token: Token::FixedBytes(bytes),
                new_offset: offset + 32,
            })
        }
        ParamType::Bytes => {
            let dynamic_offset = as_usize(&peek_32_bytes(data, offset)?)?;
            let len = as_usize(&peek_32_bytes(data, dynamic_offset)?)?;
            let bytes = take_bytes(data, dynamic_offset + 32, len)?;
            Ok(DecodeResult {
                token: Token::Bytes(bytes),
                new_offset: offset + 32,
            })
        }
        ParamType::String => {
            let dynamic_offset = as_usize(&peek_32_bytes(data, offset)?)?;
            let len = as_usize(&peek_32_bytes(data, dynamic_offset)?)?;
            let bytes = take_bytes(data, dynamic_offset + 32, len)?;
            Ok(DecodeResult {
                token: Token::String(String::from_utf8_lossy(&bytes).into()),
                new_offset: offset + 32,
            })
        }
        ParamType::FixedArray(ty, len) => {
            let is_dynamic = param.is_dynamic();

            let (tail, mut new_offset) = if is_dynamic {
                let offset = as_usize(&peek_32_bytes(data, offset)?)?;
                if offset > data.len() {
                    return Err(Error::InvalidData);
                }
                (&data[offset..], 0)
            } else {
                (data, offset)
            };

            let mut tokens = vec![];

            for _ in 0..*len {
                let res = decode_param(ty, tail, new_offset)?;
                new_offset = res.new_offset;
                tokens.push(res.token);
            }

            Ok(DecodeResult {
                token: Token::FixedArray(tokens, *ty.clone()),
                new_offset: if is_dynamic { offset + 32 } else { new_offset },
            })
        }
        ParamType::Array(ty) => {
            let len_offset = as_usize(&peek_32_bytes(data, offset)?)?;
            let len = as_usize(&peek_32_bytes(data, len_offset)?)?;

            let tail_offset = len_offset + 32;
            let tail = &data[tail_offset..];

            let mut tokens = vec![];
            let mut new_offset = 0;

            for _ in 0..len {
                let res = decode_param(ty, tail, new_offset)?;
                new_offset = res.new_offset;
                tokens.push(res.token);
            }

            Ok(DecodeResult {
                token: Token::Array(tokens, *ty.clone()),
                new_offset: offset + 32,
            })
        }
        ParamType::Tuple(t) => {
            let is_dynamic = param.is_dynamic();

            // The first element in a dynamic Tuple is an offset to the Tuple's data
            // For a static Tuple the data begins right away
            let (tail, mut new_offset) = if is_dynamic {
                let offset = as_usize(&peek_32_bytes(data, offset)?)?;
                if offset > data.len() {
                    return Err(Error::InvalidData);
                }
                (&data[offset..], 0)
            } else {
                (data, offset)
            };

            let len = t.len();
            let mut tokens = Vec::with_capacity(len);
            for param in t {
                let res = decode_param(param, tail, new_offset)?;
                new_offset = res.new_offset;
                tokens.push(res.token);
            }

            // The returned new_offset depends on whether the Tuple is dynamic
            // dynamic Tuple -> follows the prefixed Tuple data offset element
            // static Tuple  -> follows the last data element
            Ok(DecodeResult {
                token: Token::Tuple(tokens),
                new_offset: if is_dynamic { offset + 32 } else { new_offset },
            })
        }
    }
}

fn peek(data: &[u8], offset: usize, len: usize) -> Result<&[u8], Error> {
    if offset + len > data.len() {
        Err(Error::InvalidData)
    } else {
        Ok(&data[offset..(offset + len)])
    }
}

fn take_bytes(data: &[u8], offset: usize, len: usize) -> Result<Vec<u8>, Error> {
    peek(data, offset, len).map(|v| v.to_vec())
}

fn peek_32_bytes(data: &[u8], offset: usize) -> Result<Word, Error> {
    peek(data, offset, 32).map(|x| {
        let mut buf = [0_u8; 32];
        buf.copy_from_slice(&x[0..32]);
        buf
    })
}

fn as_bool(slice: &Word) -> Result<bool, Error> {
    if !slice[..31].iter().all(|x| *x == 0) {
        return Err(Error::InvalidData);
    }

    Ok(slice[31] == 1)
}

fn as_usize(slice: &Word) -> Result<usize, Error> {
    if !slice[..28].iter().all(|x| *x == 0) {
        return Err(Error::InvalidData);
    }

    let result = ((slice[28] as usize) << 24)
        + ((slice[29] as usize) << 16)
        + ((slice[30] as usize) << 8)
        + (slice[31] as usize);

    Ok(result)
}

#[cfg(test)]
mod tests {
    use eth_types::HexBytes;

    use crate::{decode, ParamType};

    #[test]
    fn test_solidity_decode_inputs() {
        let ty = ParamType::Array(Box::new(ParamType::Address));
        let input_params = &[ty.clone(), ty.clone()];
        // [0xe93224815f922bd5249dee017d01ba8a97efdaae,0xbe807dddb074639cd9fa61b47676c064fc50d62c]
        // [0x7ddc52c4de30e94be3a6a0a2b259b2850f421989]
        let hex_str = "000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000002000000000000000000000000e93224815f922bd5249dee017d01ba8a97efdaae000000000000000000000000be807dddb074639cd9fa61b47676c064fc50d62c00000000000000000000000000000000000000000000000000000000000000010000000000000000000000007ddc52c4de30e94be3a6a0a2b259b2850f421989";
        let data = HexBytes::from_hex(hex_str.as_bytes()).unwrap();
        let tokens = decode(input_params, data.as_bytes()).unwrap();
        assert_eq!(tokens.len(), 2);
        assert!(tokens[0].type_check(&ty));
        assert!(tokens[1].type_check(&ty));

        let output_params = &[ParamType::Array(Box::new(ParamType::Uint(256)))];
        // [0,10000000000000000000]
        let hex_str = "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008ac7230489e80000";
        let data = HexBytes::from_hex(hex_str.as_bytes()).unwrap();
        let tokens = decode(output_params, data.as_bytes()).unwrap();
        assert_eq!(tokens.len(), 1);
        assert!(tokens[0].type_check(&ParamType::Array(Box::new(ParamType::Uint(256)))));
    }
}
