use std::{string::FromUtf8Error};
use binrw::{BinRead};
use aes::{Aes128, cipher::block_padding::NoPadding};
use cbc::{Decryptor, cipher::{BlockDecryptMut, KeyIvInit}};
type Aes128CbcDec = Decryptor<Aes128>;


// -- utils --
fn string_from_bytes(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).to_string()
}

// keys is stored in PEAKSBT.bin(0x300000 in nand afaik) 
// the actual keys are encrypted with this key and iv 
// key = c2 a4 21 f6 ad eb 44 be b0 fd a6 8c 23 4b b3 c5,
// iv  = e9 8e c6 8c 32 6f d3 95 07 c8 d7 5e f1 b1 b1 42)

// decrypted keys is as follows:
// key id 0
// key = 2e 2a 33 62 33 e5 5a ba f5 ff ec 54 f8 ab 71 25
// iv = 2c a4 b4 7a ff cb 1a e8 e1 ea 2d 9e f5 12 62 9a
//
// key id 1
// key = 24 5e 8d e8 f4 99 b0 f9 6e c1 55 b6 08 e2 42 f3
// iv  = 3e 8f 29 d4 ba e7 76 a5 18 a7 b6 3c 42 ca 1b 43
//
//

struct KeyEntry {
    key: [u8; 0x10],
    iv: [u8; 0x10],
}

const KEYS: [KeyEntry; 2] = [
    KeyEntry {
        key: [0x2e, 0x2a, 0x33, 0x62, 0x33, 0xe5, 0x5a, 0xba, 0xf5, 0xff, 0xec, 0x54, 0xf8, 0xab, 0x71, 0x25 ],
        iv: [0x2c, 0xa4, 0xb4, 0x7a, 0xff, 0xcb, 0x1a, 0xe8, 0xe1, 0xea, 0x2d, 0x9e, 0xf5, 0x12, 0x62, 0x9a]
    },
    KeyEntry {
        key: [0x24, 0x5e, 0x8d, 0xe8, 0xf4, 0x99, 0xb0, 0xf9, 0x6e, 0xc1, 0x55, 0xb6, 0x08, 0xe2, 0x42, 0xf3],
        iv: [0x3e, 0x8f, 0x29, 0xd4, 0xba, 0xe7, 0x76, 0xa5, 0x18, 0xa7, 0xb6, 0x3c, 0x42, 0xca, 0x1b, 0x43]
    }
];

pub fn decrypt(key_id: u16, encrypted_data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key_data = &KEYS[key_id as usize];

    let mut data = encrypted_data.to_vec();
    let decryptor = Aes128CbcDec::new(&key_data.key.into(), &key_data.iv.into());
    let decrypted = decryptor.decrypt_padded_mut::<NoPadding>(&mut data)
        .map_err(|e| format!("!!Decryption error!!: {:?}", e))?;
    
    Ok(decrypted.to_vec())
}


pub fn decipher(s: &[u8]) -> Vec<u8> {
    // deciphering algorithm seems same but diffrent for sdboot?
    
    let mut out = s.to_vec();
    let mut key: u16 = 0x0388;

    for i in 0..s.len(){
        out[i] = (key >> 8) as u8 ^ s[i];

        key = key.wrapping_add(0x96a3).wrapping_add(s[i] as u16);
    }
    
    out
}


#[derive(Debug, BinRead)]
pub struct SdbootSecHeader {
    num_files_str_bytes: [u8; 4],
    key_id_str_bytes: [u8; 4],
    _0x0008: [u8; 4],
    _0x000c: [u8; 4],
    _0x0010: [u8; 16],
}

impl SdbootSecHeader {
    pub const SIZE: usize = 0x20;

    pub fn num_files(&self) -> u32 {
        let string = string_from_bytes(&self.num_files_str_bytes);
        string.parse().unwrap()
    }
    pub fn key_id(&self) -> u16 {
        let string = string_from_bytes(&self.key_id_str_bytes);
        string.parse().unwrap()
    }
}

#[derive(Debug, BinRead)]
pub struct SdbootEntryHeader {
    pub file_name: [u8; 0x34],
    file_size_str_bytes: [u8; 0xc],
}

impl SdbootEntryHeader {
    pub const SIZE: usize = 0x40;

    pub fn name(&self) -> Result<String, FromUtf8Error> {
        let end = self.file_name.iter().position(|&b| b == 0).unwrap_or(self.file_name.len());
        String::from_utf8(self.file_name[..end].to_vec())
    }
    pub fn file_size(&self) -> usize {
        let string = string_from_bytes(&self.file_size_str_bytes);
        string.parse().unwrap()
    }
}
