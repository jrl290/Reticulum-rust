// Reticulum License
//
// Copyright (c) 2016-2025 Mark Qvist
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// - The Software shall not be used in any kind of system which includes amongst
//   its functions the ability to purposefully do harm to human beings.
//
// - The Software shall not be used, directly or indirectly, in the creation of
//   an artificial intelligence, machine learning or language model training
//   dataset, including but not limited to any use that contributes to the
//   training or development of such a model or algorithm.
//
// - The above copyright notice and this permission notice shall be included in
//   all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use sha2::{Digest, Sha256};
use hkdf::Hkdf;
use rand::RngCore;

/// LXMF-style proof-of-work stamp generator and validator
/// This implementation is byte-compatible with Python LXMF
pub struct LXStamper;

impl LXStamper {
    pub const STAMP_SIZE: usize = 32;
    
    /// Encodes a non-negative integer as MessagePack.
    /// Mirrors `umsgpack.packb` / `msgpack.packb` for unsigned ints
    /// to ensure the per-round salt counter matches Python LXMF exactly.
    fn msgpack_uint(n: u32) -> Vec<u8> {
        if n < 0x80 {
            vec![n as u8]
        } else if n <= 0xff {
            vec![0xcc, n as u8]
        } else if n <= 0xffff {
            vec![0xcd, (n >> 8) as u8, n as u8]
        } else {
            vec![
                0xce,
                (n >> 24) as u8,
                (n >> 16) as u8,
                (n >> 8) as u8,
                n as u8,
            ]
        }
    }
    
    /// Generate a memory-hard workblock from the given data
    pub fn stamp_workblock(data: &[u8], expand_rounds: u32) -> Vec<u8> {
        let mut workblock = Vec::with_capacity((expand_rounds as usize) * 256);
        
        for n in 0..expand_rounds {
            let counter = Self::msgpack_uint(n);
            let mut salt_input = Vec::with_capacity(data.len() + counter.len());
            salt_input.extend_from_slice(data);
            salt_input.extend_from_slice(&counter);
            
            let salt = Sha256::digest(&salt_input);
            
            // Extract and Expand using HKDF-SHA256
            let hk = Hkdf::<Sha256>::new(Some(&salt), data);
            let mut okm = [0u8; 256];
            hk.expand(&[], &mut okm).expect("HKDF expansion failed");
            
            workblock.extend_from_slice(&okm);
        }
        
        workblock
    }
    
    /// Generate a proof-of-work stamp
    /// Returns (stamp, value) where value indicates the computational cost
    pub fn generate_stamp(data: &[u8], stamp_cost: u32, expand_rounds: u32) -> (Vec<u8>, u32) {
        let workblock = Self::stamp_workblock(data, expand_rounds);
        let mut stamp = vec![0u8; Self::STAMP_SIZE];
        let mut rng = rand::thread_rng();
        
        loop {
            // Python LXMF searches for a valid 32-byte stamp by random trial
            rng.fill_bytes(&mut stamp);
            let value = Self::stamp_value(&workblock, &stamp);
            
            if value >= stamp_cost {
                return (stamp, value);
            }
        }
    }
    
    /// Calculate the value (difficulty) of a stamp
    pub fn stamp_value(workblock: &[u8], stamp: &[u8]) -> u32 {
        if stamp.len() < Self::STAMP_SIZE {
            return 0;
        }
        
        let mut hasher = Sha256::new();
        hasher.update(workblock);
        hasher.update(stamp);
        let result = hasher.finalize();
        
        // Count leading zero bits
        let mut value = 0u32;
        for byte in result.iter() {
            if *byte == 0 {
                value += 8;
            } else {
                value += byte.leading_zeros();
                break;
            }
        }
        
        value
    }
    
    /// Validate a stamp against required value and workblock
    pub fn stamp_valid(stamp: &[u8], required_value: u32, workblock: &[u8]) -> bool {
        if stamp.len() < Self::STAMP_SIZE {
            return false;
        }
        
        let value = Self::stamp_value(workblock, stamp);
        value >= required_value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_stamp_generation() {
        let data = b"test data";
        // Using a low cost and low rounds for fast tests
        let (stamp, value) = LXStamper::generate_stamp(data, 8, 2);
        
        assert_eq!(stamp.len(), LXStamper::STAMP_SIZE);
        assert!(value >= 8);
    }
    
    #[test]
    fn test_stamp_validation() {
        let data = b"test data";
        let (stamp, _value) = LXStamper::generate_stamp(data, 8, 2);
        let workblock = LXStamper::stamp_workblock(data, 2);
        
        assert!(LXStamper::stamp_valid(&stamp, 8, &workblock));
        assert!(!LXStamper::stamp_valid(&stamp, 100, &workblock)); // Too high requirement
    }
    
    #[test]
    fn test_stamp_value() {
        let data = b"test value data";
        let required = 8u32;
        let (stamp, _) = LXStamper::generate_stamp(data, required, 2);
        let workblock = LXStamper::stamp_workblock(data, 2);

        let value = LXStamper::stamp_value(&workblock, &stamp);
        assert!(value >= required, "stamp_value {} should be >= {}", value, required);
    }
}
