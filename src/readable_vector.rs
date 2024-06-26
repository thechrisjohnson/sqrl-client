use crate::{error::SqrlError, Result};
use std::collections::VecDeque;

pub(crate) trait ReadableVector {
    fn next_u16(&mut self) -> Result<u16>;
    fn next_u32(&mut self) -> Result<u32>;
    fn next_sub_array(&mut self, size: u32) -> Result<Vec<u8>>;
    fn skip(&mut self, count: u32);
}

impl ReadableVector for VecDeque<u8> {
    fn next_u16(&mut self) -> Result<u16> {
        let mut holder: [u8; 2] = [0; 2];
        for i in &mut holder {
            *i = self
                .pop_front()
                .ok_or(SqrlError::new("Invalid binary data".to_owned()))?;
        }
        Ok(u16::from_le_bytes(holder))
    }

    fn next_u32(&mut self) -> Result<u32> {
        let mut holder: [u8; 4] = [0; 4];
        for i in &mut holder {
            *i = self
                .pop_front()
                .ok_or(SqrlError::new("Invalid binary data".to_owned()))?;
        }
        Ok(u32::from_le_bytes(holder))
    }

    fn next_sub_array(&mut self, size: u32) -> Result<Vec<u8>> {
        let mut sub_array = Vec::new();
        for _ in 0..size {
            match self.pop_front() {
                Some(x) => sub_array.push(x),
                None => return Err(SqrlError::new("Invalid binary data".to_owned())),
            };
        }

        Ok(sub_array)
    }

    fn skip(&mut self, count: u32) {
        for _ in 0..count {
            self.pop_front();
        }
    }
}
