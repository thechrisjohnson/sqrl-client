use super::DataType;
use crate::error::SqrlError;
use byteorder::{LittleEndian, WriteBytesExt};
use std::collections::VecDeque;

pub(crate) trait WritableDataBlock {
    fn get_type(&self) -> DataType;
    fn len(&self) -> u16;
    fn from_binary(binary: &mut VecDeque<u8>) -> Result<Self, SqrlError>
    where
        Self: std::marker::Sized;
    fn to_binary_inner(&self, output: &mut Vec<u8>) -> Result<(), SqrlError>;

    fn to_binary(&self, output: &mut Vec<u8>) -> Result<(), SqrlError> {
        let length = self.len();
        if length > 0 {
            output.write_u16::<LittleEndian>(length)?;
            self.get_type().to_binary(output)?;
            self.to_binary_inner(output)?;
        }

        Ok(())
    }
}
