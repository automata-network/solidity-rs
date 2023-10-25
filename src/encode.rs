use std::prelude::v1::*;

use crypto::keccak_hash;
use eth_types::{SH160, SH256, SU256, U256};

use crate::{ParamType, Token};

#[derive(Debug, Clone)]
pub struct Encoder<'a> {
    name: &'a str,
    args: Vec<EncoderArgument>,
    reloc: Vec<EncoderReloc>,
    data: Vec<u8>,
    static_flag: bool,
}

pub fn encode_eventsig(eventsig: &str) -> SH256 {
    let mut result = SH256::default();
    result.0 = keccak_hash(eventsig.as_bytes());
    result
}

pub trait EncodeArg<T: ?Sized> {
    fn add(&mut self, val: &T);
}

impl<'a> Encoder<'a> {
    pub fn new(name: &'a str) -> Self {
        Self {
            name,
            args: Vec::new(),
            reloc: vec![],
            data: vec![],
            static_flag: true,
        }
    }

    pub fn add_arg(mut self, typ: &str, arg: &[u8]) -> Self {
        assert!(arg.len() <= 32);
        let off = 32 - arg.len();
        let mut buf = [0_u8; 32];
        buf[off..].copy_from_slice(arg);
        self.args.push(EncoderArgument::Word {
            bytes: buf,
            datatype: typ.into(),
        });
        self
    }

    pub fn add_static_tuple(mut self, typ: &str, bytes: Vec<u8>) -> Self {
        self.args.push(EncoderArgument::Tuple {
            bytes,
            datatype: typ.into(),
        });
        self
    }

    pub fn sig(&self) -> String {
        let arg_list = self
            .args
            .iter()
            .map(|x| x.ty().to_owned())
            .filter(|x| x.len() > 0)
            .collect::<Vec<String>>()
            .join(",");
        format!("{}({})", self.name, arg_list)
    }

    pub fn encode(mut self) -> Vec<u8> {
        let arg_size: U256 = (32 * self.args.len()).into();
        for reloc in self.reloc {
            let slice = match reloc.section {
                EncoderRelocSection::Args => match &mut self.args[reloc.index] {
                    EncoderArgument::Word { bytes, datatype: _ } => bytes,
                    _ => panic!("reloc static tuple"),
                },
                EncoderRelocSection::Data => &mut self.data[reloc.index..reloc.index + 32],
            };
            let offset = U256::from_big_endian(slice);
            let fixed = arg_size + offset;
            fixed.to_big_endian(slice);
        }

        let arg_list = self
            .args
            .iter()
            .map(|x| x.ty().to_owned())
            .filter(|x| x.len() > 0)
            .collect::<Vec<String>>()
            .join(",");

        let mut bytes: Vec<u8> = Vec::new();

        if self.name != "" {
            let fn_sig = format!("{}({})", self.name, arg_list);
            bytes.extend_from_slice(&Self::encode_fnsig(&fn_sig));
        }
        for arg in &self.args {
            bytes.extend_from_slice(arg.data());
        }
        bytes.extend(self.data);
        bytes
    }

    pub fn encode_fnsig(fnsig_str: &str) -> [u8; 4] {
        let mut result = [0_u8; 4];
        let msg_hash = keccak_hash(fnsig_str.as_bytes());
        result.copy_from_slice(&msg_hash[..4]);
        result
    }

    pub fn encode_bytes(items: &[u8]) -> Vec<u8> {
        let mut data = Vec::<u8>::new();
        let mut args_buf = [0_u8; 32];
        let array_len: U256 = items.len().into();

        // first 32byte value is the array length in big endian
        array_len.to_big_endian(&mut args_buf);
        data.extend_from_slice(&args_buf);

        data.extend_from_slice(items);

        if data.len() % 32 != 0 {
            let padding = 32 - data.len() % 32;
            let mut padding_bytes: Vec<u8> = Vec::new();
            padding_bytes.resize_with(padding, Default::default);
            data.extend_from_slice(&padding_bytes);
        }

        data
    }

    pub fn encode_address_array(items: &Vec<SH160>) -> Vec<u8> {
        let mut data = Vec::<u8>::new();
        let mut args_buf = [0_u8; 32];
        let array_len: U256 = items.len().into();

        // first 32byte value is the array length in big endian
        array_len.to_big_endian(&mut args_buf);
        data.extend_from_slice(&args_buf);

        // zero out the array
        let mut args_buf = [0_u8; 32];

        // all subsequent elements in big endian
        for item in items.iter() {
            args_buf[12..32].copy_from_slice(item.as_bytes());
            data.extend_from_slice(&args_buf);
        }
        data
    }

    pub fn encode_address_bytes32_vec(items: &Vec<(SH160, SH256)>) -> Vec<u8> {
        let mut data = Vec::<u8>::new();
        let mut args_buf = [0_u8; 32];
        let array_len: U256 = items.len().into();

        // first 32byte value is the array length in big endian
        array_len.to_big_endian(&mut args_buf);
        data.extend_from_slice(&args_buf);

        // zero out the array
        let mut address_data = [0_u8; 32];
        let mut bytes32_data = [0_u8; 32];

        // all subsequent elements in big endian
        for item in items {
            address_data[12..32].copy_from_slice(item.0.as_bytes());
            data.extend_from_slice(&address_data);
            bytes32_data.copy_from_slice(item.1.as_bytes());
            data.extend_from_slice(&bytes32_data);
        }
        data
    }
}

impl<'a> EncodeArg<SH160> for Encoder<'a> {
    fn add(&mut self, arg: &SH160) {
        let mut buf = [0_u8; 32];
        buf[12..32].copy_from_slice(arg.as_bytes());
        self.args.push(EncoderArgument::Word {
            bytes: buf,
            datatype: "address".to_owned(),
        });
    }
}

impl<'a> EncodeArg<bool> for Encoder<'a> {
    fn add(&mut self, arg: &bool) {
        let mut buf = [0_u8; 32];
        buf[31] = arg.clone().into();
        self.args.push(EncoderArgument::Word {
            bytes: buf,
            datatype: "bool".to_owned(),
        });
    }
}

impl<'a> EncodeArg<[u8]> for Encoder<'a> {
    fn add(&mut self, val: &[u8]) {
        self.static_flag = false;
        self.reloc.push(EncoderReloc {
            section: EncoderRelocSection::Args,
            index: self.args.len(),
        });

        let dynarg_data = Self::encode_bytes(val);
        let data_len: U256 = self.data.len().into();
        let mut data_len_buf = [0_u8; 32];
        data_len.to_big_endian(&mut data_len_buf[..]);
        self.args.push(EncoderArgument::Word {
            bytes: data_len_buf,
            datatype: "bytes".to_owned(),
        });
        self.data.extend(dynarg_data);
    }
}

impl<'a> EncodeArg<SH256> for Encoder<'a> {
    fn add(&mut self, arg: &SH256) {
        let mut buf = [0_u8; 32];
        buf.copy_from_slice(arg.as_bytes());
        self.args.push(EncoderArgument::Word {
            bytes: buf,
            datatype: "bytes32".to_owned(),
        });
    }
}

impl<'a> EncodeArg<SU256> for Encoder<'a> {
    fn add(&mut self, val: &SU256) {
        let mut buf = [0_u8; 32];
        val.to_big_endian(&mut buf[..]);
        self.args.push(EncoderArgument::Word {
            bytes: buf,
            datatype: "uint256".to_owned(),
        });
    }
}

impl<'a> EncodeArg<u8> for Encoder<'a> {
    fn add(&mut self, val: &u8) {
        let mut buf = [0_u8; 32];
        buf[31] = val.clone();
        self.args.push(EncoderArgument::Word {
            bytes: buf,
            datatype: "uint8".to_owned(),
        });
    }
}

impl<'a> EncodeArg<Vec<SH160>> for Encoder<'a> {
    fn add(&mut self, val: &Vec<SH160>) {
        self.static_flag = false;
        self.reloc.push(EncoderReloc {
            section: EncoderRelocSection::Args,
            index: self.args.len(),
        });

        let dynarg_data = Self::encode_address_array(val);
        let data_len: U256 = self.data.len().into();
        let mut data_len_buf = [0_u8; 32];
        data_len.to_big_endian(&mut data_len_buf[..]);
        self.args.push(EncoderArgument::Word {
            bytes: data_len_buf,
            datatype: "address[]".to_owned(),
        });
        self.data.extend(dynarg_data);
    }
}

impl<'a> EncodeArg<Vec<(SH160, SH256)>> for Encoder<'a> {
    fn add(&mut self, val: &Vec<(SH160, SH256)>) {
        self.static_flag = false;
        self.reloc.push(EncoderReloc {
            section: EncoderRelocSection::Args,
            index: self.args.len(),
        });

        let dynarg_data = Self::encode_address_bytes32_vec(val);
        let data_len: U256 = self.data.len().into();
        let mut data_len_buf = [0_u8; 32];
        data_len.to_big_endian(&mut data_len_buf[..]);
        self.args.push(EncoderArgument::Word {
            bytes: data_len_buf,
            datatype: "(address,bytes32)[]".to_owned(),
        });
        self.data.extend(dynarg_data);
    }
}

impl<'a> EncodeArg<Token> for Encoder<'a> {
    fn add(&mut self, val: &Token) {
        let encode_dyn = |self_: &mut Encoder<'_>, vs: &Vec<Token>, ty: &ParamType| {
            assert!(ty.is_array_like(), "array like dyn");
            self_.static_flag = false;
            self_.reloc.push(EncoderReloc {
                section: EncoderRelocSection::Args,
                index: self_.args.len(),
            });

            let dynarg_data = {
                let mut data = vec![];
                if !ty.is_fixed_length() {
                    let mut len_buf = [0_u8; 32];
                    let array_len: U256 = vs.len().into();
                    array_len.to_big_endian(&mut len_buf);
                    data.extend_from_slice(&len_buf);
                }
                let mut enc_inner = Encoder::new("");
                for v in vs.iter() {
                    enc_inner.add(v);
                }
                data.extend_from_slice(&enc_inner.encode());
                data
            };

            let data_len: U256 = self_.data.len().into();
            let mut data_len_buf = [0_u8; 32];
            data_len.to_big_endian(&mut data_len_buf[..]);
            self_.args.push(EncoderArgument::Word {
                bytes: data_len_buf,
                datatype: ty.to_string(),
            });
            self_.data.extend(dynarg_data);
        };

        match val {
            Token::Uint(v, sz) | Token::Int(v, sz) => {
                assert!(*sz % 8 == 0, "integer size align");
                self.add(v);
            }
            Token::Address(v) => self.add(v),
            Token::Bool(v) => self.add(v),
            tok @ Token::FixedBytes(vs) => {
                let len = vs.len();
                assert!(len <= 32, "bytes[M] M<=32");
                let mut buf = [0_u8; 32];
                buf[..len].copy_from_slice(vs);
                self.args.push(EncoderArgument::Word {
                    bytes: buf,
                    datatype: tok.type_info().to_string(),
                });
            }
            Token::Bytes(vs) => self.add(vs.as_slice()),
            Token::String(v) => self.add(v.as_bytes()),
            tok @ Token::FixedArray(vs, ty) => {
                let tok_ty = tok.type_info();
                if !ty.is_dynamic() {
                    let mut bytes = vec![];
                    for v in vs.iter() {
                        let mut enc_inner = Encoder::new("");
                        enc_inner.add(v);
                        bytes.extend_from_slice(&enc_inner.encode());
                    }
                    self.args.push(EncoderArgument::Tuple {
                        bytes,
                        datatype: tok_ty.to_string(),
                    });
                } else {
                    encode_dyn(self, vs, &tok_ty);
                }
            }
            tok @ Token::Array(vs, _) => encode_dyn(self, vs, &tok.type_info()),
            tok @ Token::Tuple(vs) => {
                let tok_ty = tok.type_info();
                if !tok.type_info().is_dynamic() {
                    let mut bytes = vec![];
                    for v in vs.iter() {
                        let mut enc_inner = Encoder::new("");
                        enc_inner.add(v);
                        bytes.extend_from_slice(&enc_inner.encode());
                    }
                    self.args.push(EncoderArgument::Tuple {
                        bytes,
                        datatype: tok_ty.to_string(),
                    });
                } else {
                    encode_dyn(self, vs, &tok_ty);
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
enum EncoderArgument {
    Word { bytes: [u8; 32], datatype: String },
    Tuple { bytes: Vec<u8>, datatype: String },
}

impl EncoderArgument {
    fn ty(&self) -> &str {
        match self {
            EncoderArgument::Word { bytes: _, datatype } => datatype,
            EncoderArgument::Tuple { bytes: _, datatype } => datatype,
        }
    }

    fn data(&self) -> &[u8] {
        match self {
            EncoderArgument::Word { bytes, datatype: _ } => &bytes[..],
            EncoderArgument::Tuple { bytes, datatype: _ } => bytes.as_slice(),
        }
    }
}

#[derive(Debug, Clone)]
struct EncoderReloc {
    section: EncoderRelocSection,
    index: usize,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
enum EncoderRelocSection {
    Args,
    Data,
}

#[cfg(test)]
mod test {
    use eth_types::{HexBytes, H160};

    use crate::Address;

    use super::*;

    fn debug_encoder(enc: Encoder<'_>) {
        let sig = enc.sig();
        let sig4b = Encoder::encode_fnsig(&sig);
        println!(
            "sig={}|{}, static={}",
            sig,
            HexBytes::from(&sig4b[..]),
            enc.static_flag
        );
        let encoded = enc.encode();
        println!("{}", HexBytes::from(encoded));
    }

    #[test]
    fn test_solidity_encode_st_tuple() {
        // static tuple
        // transfer(address,(uint256,bool))
        // call: "0xa12f64ca80bd24dbcc49f022e2cf06b94e5a50d3" "(8,true)"
        // 0x71a47eb2
        // 000000000000000000000000a12f64ca80bd24dbcc49f022e2cf06b94e5a50d3
        // 0000000000000000000000000000000000000000000000000000000000000008
        // 0000000000000000000000000000000000000000000000000000000000000001
        let mut enc = Encoder::new("transfer");
        let tok_addr = {
            let bytes = HexBytes::from_hex(b"0xa12f64ca80bd24dbcc49f022e2cf06b94e5a50d3").unwrap();
            let addr = H160::from_slice(&bytes);
            Token::Address(Address::from(addr))
        };
        enc.add(&tok_addr);
        let tok_st_tuple = {
            let u = Token::Uint(U256::from(8_u32).into(), 256);
            let b = Token::Bool(true);
            Token::Tuple(vec![u, b])
        };
        enc.add(&tok_st_tuple);
        assert!(enc.static_flag);
        let encoded = enc.encode();
        assert_eq!(
            HexBytes::from_hex(b"0x71a47eb2000000000000000000000000a12f64ca80bd24dbcc49f022e2cf06b94e5a50d300000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000001").unwrap(),
            encoded
        );
    }

    #[test]
    fn test_solidity_encode_dyn_tuple() {
        // dyn tuple
        // transfer(address,(uint32[],bool))
        // call: "0xa12f64ca80bd24dbcc49f022e2cf06b94e5a50d3" "([1,2,3],true)"
        // 0xa39cdbf6
        // 000000000000000000000000a12f64ca80bd24dbcc49f022e2cf06b94e5a50d3
        // 0000000000000000000000000000000000000000000000000000000000000040
        // 0000000000000000000000000000000000000000000000000000000000000040
        // 0000000000000000000000000000000000000000000000000000000000000001
        // 0000000000000000000000000000000000000000000000000000000000000003
        // 0000000000000000000000000000000000000000000000000000000000000001
        // 0000000000000000000000000000000000000000000000000000000000000002
        // 0000000000000000000000000000000000000000000000000000000000000003
        let mut enc = Encoder::new("transfer");
        let tok_addr = {
            let bytes = HexBytes::from_hex(b"0xa12f64ca80bd24dbcc49f022e2cf06b94e5a50d3").unwrap();
            let addr = H160::from_slice(&bytes);
            Token::Address(Address::from(addr))
        };
        enc.add(&tok_addr);
        let tok_dyn_tuple = {
            let ua = Token::Array(
                vec![
                    Token::Uint(U256::from(1_u32).into(), 32),
                    Token::Uint(U256::from(2_u32).into(), 32),
                    Token::Uint(U256::from(3_u32).into(), 32),
                ],
                ParamType::Uint(32),
            );
            let b = Token::Bool(true);
            Token::Tuple(vec![ua, b])
        };
        enc.add(&tok_dyn_tuple);
        debug_encoder(enc);
    }

    #[test]
    fn test_solidity_encode_fixed_st_array_in_tuple() {
        // dyn tuple
        // transfer(address,(uint32[3],bool))
        // call: "0xa12f64ca80bd24dbcc49f022e2cf06b94e5a50d3" "([1,2,3],true)"
        // 0x9d8dccb
        // 0000000000000000000000000a12f64ca80bd24dbcc49f022e2cf06b94e5a50d3
        // 0000000000000000000000000000000000000000000000000000000000000001
        // 0000000000000000000000000000000000000000000000000000000000000002
        // 0000000000000000000000000000000000000000000000000000000000000003
        // 0000000000000000000000000000000000000000000000000000000000000001
        let mut enc = Encoder::new("transfer");
        let tok_addr = {
            let bytes = HexBytes::from_hex(b"0xa12f64ca80bd24dbcc49f022e2cf06b94e5a50d3").unwrap();
            let addr = H160::from_slice(&bytes);
            Token::Address(Address::from(addr))
        };
        enc.add(&tok_addr);
        let tok_dyn_tuple = {
            let ua = Token::FixedArray(
                vec![
                    Token::Uint(1.into(), 32),
                    Token::Uint(2.into(), 32),
                    Token::Uint(3.into(), 32),
                ],
                ParamType::Uint(32),
            );
            let b = Token::Bool(true);
            Token::Tuple(vec![ua, b])
        };
        enc.add(&tok_dyn_tuple);
        debug_encoder(enc);
    }

    #[test]
    fn test_solidity_encode_fixed_dyn_array_in_tuple() {
        // dyn tuple
        // transfer(address,(bytes[3],bool))
        // call: "0xa12f64ca80bd24dbcc49f022e2cf06b94e5a50d3" "([0x01,0x02,0x03],true)"
        // 0x06d6505b
        // 000000000000000000000000a12f64ca80bd24dbcc49f022e2cf06b94e5a50d3
        // 0000000000000000000000000000000000000000000000000000000000000040
        // 0000000000000000000000000000000000000000000000000000000000000040
        // 0000000000000000000000000000000000000000000000000000000000000001
        // 0000000000000000000000000000000000000000000000000000000000000060
        // 00000000000000000000000000000000000000000000000000000000000000a0
        // 00000000000000000000000000000000000000000000000000000000000000e0
        // 0000000000000000000000000000000000000000000000000000000000000001
        // 0100000000000000000000000000000000000000000000000000000000000000
        // 0000000000000000000000000000000000000000000000000000000000000001
        // 0200000000000000000000000000000000000000000000000000000000000000
        // 0000000000000000000000000000000000000000000000000000000000000001
        // 0300000000000000000000000000000000000000000000000000000000000000
        let mut enc = Encoder::new("transfer");
        let tok_addr = {
            let bytes = HexBytes::from_hex(b"0xa12f64ca80bd24dbcc49f022e2cf06b94e5a50d3").unwrap();
            let addr = H160::from_slice(&bytes);
            Token::Address(Address::from(addr))
        };
        enc.add(&tok_addr);
        let tok_dyn_tuple = {
            let ua = Token::FixedArray(
                vec![
                    Token::Bytes(vec![1_u8]),
                    Token::Bytes(vec![2_u8]),
                    Token::Bytes(vec![3_u8]),
                ],
                ParamType::Bytes,
            );
            let b = Token::Bool(true);
            Token::Tuple(vec![ua, b])
        };
        enc.add(&tok_dyn_tuple);
        debug_encoder(enc);
    }

    #[test]
    fn test_solidity_encode_dyn_01() {
        // f(uint256,uint32[],bytes10,bytes) with values (0x123, [0x456, 0x789], "1234567890", "Hello, world!")
        // 0x8be65246
        //   0000000000000000000000000000000000000000000000000000000000000123
        //   0000000000000000000000000000000000000000000000000000000000000080
        //   3132333435363738393000000000000000000000000000000000000000000000
        //   00000000000000000000000000000000000000000000000000000000000000e0
        //   0000000000000000000000000000000000000000000000000000000000000002
        //   0000000000000000000000000000000000000000000000000000000000000456
        //   0000000000000000000000000000000000000000000000000000000000000789
        //   000000000000000000000000000000000000000000000000000000000000000d
        //   48656c6c6f2c20776f726c642100000000000000000000000000000000000000
        let mut enc = Encoder::new("f");
        enc.add(&Token::Uint(0x123.into(), 256));
        let tok_arr = Token::Array(
            vec![Token::Uint(0x456.into(), 32), Token::Uint(0x789.into(), 32)],
            ParamType::Uint(32),
        );
        enc.add(&tok_arr);
        enc.add(&Token::FixedBytes(b"1234567890".to_vec()));
        enc.add(&Token::String("Hello, world!".into()));
        debug_encoder(enc);
    }

    #[test]
    fn test_solidity_encode_dyn_02() {
        // g(uint256[][],string[]) with values ([[1, 2], [3]], ["one", "two", "three"])
        // 0x2289b18c                                                            - function signature
        //  0 - 0000000000000000000000000000000000000000000000000000000000000040 - offset of [[1, 2], [3]]
        //  1 - 0000000000000000000000000000000000000000000000000000000000000140 - offset of ["one", "two", "three"]
        //  2 - 0000000000000000000000000000000000000000000000000000000000000002 - count for [[1, 2], [3]]
        //  3 - 0000000000000000000000000000000000000000000000000000000000000040 - offset of [1, 2]
        //  4 - 00000000000000000000000000000000000000000000000000000000000000a0 - offset of [3]
        //  5 - 0000000000000000000000000000000000000000000000000000000000000002 - count for [1, 2]
        //  6 - 0000000000000000000000000000000000000000000000000000000000000001 - encoding of 1
        //  7 - 0000000000000000000000000000000000000000000000000000000000000002 - encoding of 2
        //  8 - 0000000000000000000000000000000000000000000000000000000000000001 - count for [3]
        //  9 - 0000000000000000000000000000000000000000000000000000000000000003 - encoding of 3
        // 10 - 0000000000000000000000000000000000000000000000000000000000000003 - count for ["one", "two", "three"]
        // 11 - 0000000000000000000000000000000000000000000000000000000000000060 - offset for "one"
        // 12 - 00000000000000000000000000000000000000000000000000000000000000a0 - offset for "two"
        // 13 - 00000000000000000000000000000000000000000000000000000000000000e0 - offset for "three"
        // 14 - 0000000000000000000000000000000000000000000000000000000000000003 - count for "one"
        // 15 - 6f6e650000000000000000000000000000000000000000000000000000000000 - encoding of "one"
        // 16 - 0000000000000000000000000000000000000000000000000000000000000003 - count for "two"
        // 17 - 74776f0000000000000000000000000000000000000000000000000000000000 - encoding of "two"
        // 18 - 0000000000000000000000000000000000000000000000000000000000000005 - count for "three"
        // 19 - 7468726565000000000000000000000000000000000000000000000000000000 - encoding of "three"
        let mut enc = Encoder::new("g");
        let tok_arr1 = {
            let a1 = Token::Array(
                vec![Token::Uint(1.into(), 256), Token::Uint(2.into(), 256)],
                ParamType::Uint(256),
            );
            let a2 = Token::Array(vec![Token::Uint(3.into(), 256)], ParamType::Uint(256));
            Token::Array(
                vec![a1, a2],
                ParamType::Array(Box::new(ParamType::Uint(256))),
            )
        };
        enc.add(&tok_arr1);
        let tok_arr2 = Token::Array(
            vec![
                Token::String("one".into()),
                Token::String("two".into()),
                Token::String("three".into()),
            ],
            ParamType::String,
        );
        enc.add(&tok_arr2);
        debug_encoder(enc);
    }
}
