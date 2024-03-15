use rand::RngCore;
use rand::rngs::OsRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self};
use std::path::Path;
use hex::encode;
use hex::FromHex;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use bdk::bitcoin::{Txid,TxIn,TxOut};
use bdk::bitcoin::blockdata::transaction::OutPoint;
use bdk::bitcoin::hashes::Hash;


#[derive(Debug, Serialize, Deserialize)]
pub struct SeedStore{
    pub mnemonic: String
}


pub fn convert_to_outpoint(utxo_str : &String) -> OutPoint{
    let parts : Vec<&str> = utxo_str.split(":").collect();
    let vout : u32 =  parts[1].parse().unwrap();
    let mut byte_arr = hex_string_to_u8_array(parts[0]).unwrap();
    byte_arr.reverse();
    let txid = Txid::from_slice(&byte_arr).expect("Invalid Txid");
    let outpoint = OutPoint{
        txid : txid,
        vout : vout
    };
    outpoint
}

pub fn hex_string_to_u8_array(hex_str: &str) -> Result<[u8; 32], hex::FromHexError> {
    let bytes = Vec::from_hex(hex_str)?;
    println!("Byte length: {}", bytes.len());
    if bytes.len() == 32 {
        let mut result = [0; 32];
        result.copy_from_slice(&bytes);
        Ok(result)
    } else {
        // If the length is not 32, return an error or handle the case accordingly
        Err(hex::FromHexError::InvalidStringLength)
    }
}