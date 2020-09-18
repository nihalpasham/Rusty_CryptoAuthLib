//! Module to craft command packets

use crate::constants;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
/// Security commands are sent (over i2c) to the device and responses received from the device 
/// This struct holds 'input commands'. It does not include the 'data payload' section
pub struct ATCAPacket<'a> {
    /// pkt_id: 1 byte value of 0x03 for normal operation
    pub pkt_id: u8, 
    /// 1 byte value that represents the number of bytes to be transferred to the device
    pub txsize: u8, 
    /// Command Opcode 
    pub opcode: u8,
    /// An additional 1 byte command parameter that must always be present. Value depends on the command being sent
    pub param1: u8,
    /// An additional 2 byte Command parameter that must always be present. Vlaue depends on the command being sent
    pub param2: [u8; 2],
    /// data bytes 
    pub req_data: &'a [u8],
    /// 2 byte CRC
    pub crc16: [u8; 2],
}

impl<'a> ATCAPacket<'_> {
    /// This methods constructs an input command packet. An input security command is sent
    /// after transmitting the 'i2c device address' and is broken down as follows
    /// - pkt_id: 1 byte value of 0x03 for normal operation
    /// - txsize: 1 byte value that represents the number of bytes to be transferred to the device, 
    ///           including count byte,
    ///           packet bytes, and checksum bytes. 
    ///           The count byte should therefore always have a value of
    ///           (N+1), where N is equal to the number of bytes in the packet plus the two checksum bytes.
    /// - Param1: An additional 1 byte command parameter that must always be present. Value depends on the command being sent
    /// - Param2: An additional 2 byte Command parameter that must always be present. Vlaue depends on the command being sent
    pub fn make_packet(
        &mut self,
        txsize: Option<u8>,
        opcode: Option<u8>,
        param1: Option<u8>,
        param2: Option<[u8; 2]>,
    ) -> &mut Self {
        match txsize {
            None => self.txsize = constants::ATCA_CMD_SIZE_MIN,
            Some(t) => self.txsize = t,
        }
        self.opcode = opcode.unwrap();
        self.param1 = param1.unwrap();
        match param2 {
            None => self.param2 = [0; 2],
            Some(t) => self.param2 = t,
        }

        let packet: [u8; 5] = [
            self.txsize,
            self.opcode,
            self.param1,
            self.param2[0],
            self.param2[1],
        ];

        let crc_bytes = self.crc(&packet[..], packet.len());
        self.crc16[0] = crc_bytes[0];
        self.crc16[1] = crc_bytes[1];
        // hprintln!("sending packet : {:?}", packet).unwrap();

        return self;
    }

    /// A method to calculate a 2 byte checksum value. The input to this method is a fully constructed input command 
    /// packet along with its length.
    pub fn crc(self, src: &[u8], length: usize) -> [u8; 2] {
        let polynom: u16 = 0x8005;
        let mut crc: u16 = 0x0000;
        let mut data_bit;
        let mut crc_bit;
        let mut d: u8;
        for i in 0..length {
            d = src[i];
            for b in 0..8 {
                if (d & 1 << b) == 0 {
                    data_bit = 0;
                } else {
                    data_bit = 1;
                }
                crc_bit = crc >> 15 & 0xff;
                crc = crc << (1 & 0xffff);
                // println!("crc is {:?}", crc);
                if data_bit != crc_bit {
                    crc = crc ^ (polynom & 0xffff);
                    // println!("crc is {:?}", crc);
                    // println!("end of loop =================");
                }
            }
        }
        let lsb = crc & 0x00ff;
        let msb = crc >> 8 & 0xff;
        return [lsb as u8, msb as u8];
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
/// Security commands are sent (over i2c) to the device and responses received from the device 
/// This struct holds 'input commands'. It includes the 'data payload' section
pub struct ATCAPacket_w_data<'a> {
 /// pkt_id: 1 byte value of 0x03 for normal operation
 pub pkt_id: u8, 
 /// 1 byte value that represents the number of bytes to be transferred to the device
 pub txsize: u8, 
 /// Command Opcode 
 pub opcode: u8,
 /// An additional 1 byte command parameter that must always be present. Value depends on the command being sent
 pub param1: u8,
 /// An additional 2 byte Command parameter that must always be present. Vlaue depends on the command being sent
 pub param2: [u8; 2],
 /// data bytes 
 pub req_data: &'a [u8],
 /// 2 byte CRC
 pub crc16: [u8; 2],
}

impl<'a> ATCAPacket_w_data<'_> {
    /// This methods constructs an input command packet. An input security command is sent
    /// after transmitting the 'i2c device address' and is broken down as follows
    /// - pkt_id: 1 byte value of 0x03 for normal operation
    /// - txsize: 1 byte value that represents the number of bytes to be transferred to the device, 
    ///           including count byte,
    ///           packet bytes, and checksum bytes. 
    ///           The count byte should therefore always have a value of
    ///           (N+1), where N is equal to the number of bytes in the packet plus the two checksum bytes.
    /// - Param1: An additional 1 byte command parameter that must always be present. Value depends on the command being sent
    /// - Param2: An additional 2 byte Command parameter that must always be present. Vlaue depends on the command being sent
    /// - Data: A data payload section.Value depends on the command being sent.
    pub fn make_packet(
        &mut self,
        txsize: Option<u8>,
        opcode: Option<u8>,
        param1: Option<u8>,
        param2: Option<[u8; 2]>,
    ) -> &mut Self {
        match txsize {
            None => self.txsize = constants::ATCA_CMD_SIZE_MIN,
            Some(t) => self.txsize = t,
        }
        self.opcode = opcode.unwrap();
        self.param1 = param1.unwrap();
        match param2 {
            None => self.param2 = [0; 2],
            Some(t) => self.param2 = t,
        }

        let packet: &[&[u8]] = &[
            &[self.txsize],
            &[0, self.opcode],
            &[0, 0, self.param1],
            &[0, 0, 0, self.param2[0]],
            &[0, 0, 0, 0, self.param2[1]],
            self.req_data,
        ];

        let crc_bytes = self.crc(packet, packet.len());
        self.crc16[0] = crc_bytes[0];
        self.crc16[1] = crc_bytes[1];
        // hprintln!("sending packet : {:?}", packet).unwrap();

        return self;
    }

    /// A method to calculate a 2 byte checksum value. The input to this method is fully constructed input command 
    /// packet along with its length. This method includes the data section in its crc computation.  
    pub fn crc(self, src: &[&[u8]], length: usize) -> [u8; 2] {
        let polynom: u16 = 0x8005;
        let mut crc: u16 = 0x0000;
        let mut data_bit;
        let mut crc_bit;
        let mut d: u8;
        for i in 0..length {
            // We're looping through an array of slices. The last slice is the req_data element
            // So, we handle the last index in the array separately.
            if i == length - 1 {
                for i in 0..self.req_data.len() {
                    d = src[length - 1][i];
                    // println!("d: 0x{:x}", d);
                    for b in 0..8 {
                        if (d & 1 << b) == 0 {
                            data_bit = 0;
                        } else {
                            data_bit = 1;
                        }
                        crc_bit = crc >> 15 & 0xff;
                        crc = crc << (1 & 0xffff);
                        // println!("crc is {:?}", crc);
                        if data_bit != crc_bit {
                            crc = crc ^ (polynom & 0xffff);
                            // println!("crc is {:?}", crc);
                            // println!("======end of loop =================");
                        }
                    }
                }
            } else {
                d = src[i][i];
                // println!("d: 0x{:x}", d);
                for b in 0..8 {
                    if (d & 1 << b) == 0 {
                        data_bit = 0;
                    } else {
                        data_bit = 1;
                    }
                    crc_bit = crc >> 15 & 0xff;
                    crc = crc << (1 & 0xffff);
                    // println!("crc is {:?}", crc);
                    if data_bit != crc_bit {
                        crc = crc ^ (polynom & 0xffff);
                        // println!("crc is {:?}", crc);
                        // println!("======end of loop =================");
                    }
                }
            }
        }
        let lsb = crc & 0x00ff;
        let msb = crc >> 8 & 0xff;
        return [lsb as u8, msb as u8];
    }
}


