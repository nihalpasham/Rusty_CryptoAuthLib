// #![deny(missing_docs)]
// #![deny(warnings)]
#![allow(warnings)]
#![no_std]

pub mod constants;
pub mod packet;

#[macro_use(block)]
extern crate nb;
extern crate embedded_hal;

use constants::{ATECC608A_EXECUTION_TIME, EXECUTION_TIME};
use core::ops::Deref;
use embedded_hal::blocking::delay::{DelayMs, DelayUs};
use embedded_hal::blocking::i2c::{Read, Write};
use embedded_hal::timer::CountDown;
use heapless::{consts::*, Vec};
use postcard::{from_bytes, to_vec};

// use core::marker::PhantomData;

pub const ADDRESS: u8 = 0xC0 >> 1;
pub const WAKE_DELAY: u32 = 1500;

/// ATECC680A driver
#[derive(Copy, Clone, Debug)]
pub struct ATECC608A<I2C, DELAY, TIMER> {
    pub i2c: I2C,
    pub delay: DELAY,
    pub timer: TIMER,
    pub dev_addr: u8,
}

impl<I2C, DELAY, TIMER, E> ATECC608A<I2C, DELAY, TIMER>
where
    I2C: Read<Error = E> + Write<Error = E>,
    DELAY: DelayMs<u32> + DelayUs<u32>,
    TIMER: CountDown<Time = u32>,
{
    /// Creates a new ATECC608a driver.
    pub fn new(i2c: I2C, delay: DELAY, timer: TIMER) -> Result<Self, E> {
        let mut atecc608a = ATECC608A {
            i2c,
            delay,
            timer,
            dev_addr: ADDRESS,
        };
        Ok(atecc608a)
    }

    /// This method just writes a zero byte to the bus without reading data back.
    /// Its required in the 'wake-up routine'.
    /// Note - the sendpacket method is used wake the device properly.
    pub fn wake(&mut self) -> Result<(), E> {
        let wake_bytes = [0; 1];
        self.i2c.write(self.dev_addr, &wake_bytes)
    }

    /// This method just writes a `byte 0x02` to the bus and puts the device
    /// into idle mode. In idle mode, all subsequent I/O transitions are ignored
    /// until the next wake flag. The contents of TempKey and RNG Seed registers are
    /// retained.
    pub fn idle(&mut self) -> Result<(), E> {
        let idle_byte = [2];
        self.i2c.write(self.dev_addr, &idle_byte)
    }

    /// This method just writes a `byte 0x01` to the bus which sends the device
    /// into the low power or sleep mode and ignores all subsequent I/O
    /// transitions until the next wake flag. The entire volatile state of the device is reset.
    pub fn sleep(&mut self) -> Result<(), E> {
        let sleep_byte = [1];
        self.i2c.write(self.dev_addr, &sleep_byte)
    }

    /// A method for sending i2c commands over to the ATECC608A and
    /// retrieving the associated response
    pub fn send_packet(
        &mut self,
        packet: &[u8],
        texec: ATECC608A_EXECUTION_TIME,
    ) -> Result<[u8; (constants::ATCA_CMD_SIZE_MAX) as usize], constants::StatusError> {
        // Part 1 of 'wake sequence'
        // tWLO - This write call is meant to wake the device.
        // The 'byte' is never
        // transmitted as the address always gets NACK'd.
        // This call holds SDA low for a period of at least 60 us.
        self.wake();
        // Part 2 of 'wake sequence'
        // Upon receiving a NACK, the master releases SDA i.e. it gets pushed back up
        // tWHI - ADD a delay of at least 1500 us to ensure SDA is held high.
        // This sequence wakes the device ans is now ready for data exchange.
        self.delay.delay_us(WAKE_DELAY);
        // After waking the device, we can send our actual data packet
        // if packet[(constants::ATCA_COUNT_IDX + 1) as usize] == constants::ATCA_CMD_SIZE_MIN {
        //     self.i2c.write(self.dev_addr, &packet[..packet.len()]);
        // } else
        let slice_1 = &packet[..6];
        // Variable length data in postcard (such as slices)
        // are prefixed by their length. Length is a VARINT
        let slice_2 = &packet[(constants::ATCA_CMD_SIZE_MIN) as usize..];

        let mut pkt = [0; constants::ATCA_CMD_SIZE_MAX as usize];
        for (idx, val) in slice_1.iter().chain(slice_2.iter()).enumerate() {
            pkt[idx] = *val;
        }

        self.i2c.write(self.dev_addr, &pkt[..(pkt[1] + 1) as usize]);

        let tExec: constants::Time = (EXECUTION_TIME::ATECC608A(texec.clone()))
            .get_value()
            .get_tExec();

        // wait tEXEC (max) after which the device will have completed execution, and the
        // result can be read from the device using a normal read sequence.
        self.timer.start(tExec.0 as u16 * 1000);
        block!(self.timer.wait());

        // The first byte holds the length of the response.
        let mut count_byte = [0; 1];
        self.i2c.read(self.dev_addr, &mut count_byte);
        // Perform a subsequent read for the remaining (response) bytes
        let mut resp = [0; (constants::ATCA_CMD_SIZE_MAX) as usize];
        self.i2c
            .read(self.dev_addr, &mut resp[..(count_byte[0] - 1) as usize]);

        // Check response for errors
        if count_byte[0] == constants::ATCA_RSP_SIZE_MIN
            && resp[(constants::ATCA_RSP_DATA_IDX - 1) as usize] == constants::CMD_STATUS_WAKEUP
        {
            self.send_packet(packet.deref(), texec);
        }
        // Return Status or Error
        let mut StatusError = constants::StatusError(0, constants::ATCA_ERRORS::NoError("NoError"));
        if StatusError.0 == constants::ATCA_SUCCESS {
            Ok(resp)
        } else if StatusError.0 == constants::ATCA_WAKE_SUCCESS {
            Ok(resp)
        } else if StatusError.0 == constants::ATCA_WATCHDOG_ABOUT_TO_EXPIRE {
            self.sleep();
            Err(StatusError)
        } else {
            //if count_byte[0] == constants::ATCA_RSP_SIZE_MIN
            StatusError = constants::DECODE_ERROR::get_error(
                resp[(constants::ATCA_RSP_DATA_IDX - 1) as usize],
            );
            Err(StatusError)
        }
    }

    #[doc = "###########################################################################"]
    #[doc = "#          Rusty CryptoAuthLib API/method for Info command                #"]
    #[doc = "###########################################################################"]

    /// This method crafts a 'INFO command' packet.
    pub fn atcab_info_base(&mut self, param1: u8) -> Vec<u8, U10> {
        let mut q = packet::ATCAPacket {
            pktID: 0x03,
            txsize: 0,
            opcode: 0,
            param1: 0,
            param2: [0; 2],
            req_data: &[],
            crc16: [0; 2],
        };

        let packet: &mut packet::ATCAPacket =
            q.make_packet(None, Some(constants::ATCA_INFO), Some(param1), None);
        //  Serialize packet structure to get a Heapless Vec.
        let output: Vec<u8, U10> = to_vec(packet).unwrap();
        assert_eq!(
            &[0x03, 0x07, 0x30, 0x00, 0x00, 0x00, 0x00, 0x03, 0x5D],
            output.deref()
        );
        return output;
    }
    /// Returns a single 4-byte word representing the revision number of the device. Software
    /// should not depend on this value as it may change from time to time.
    /// At the time of writing this, the Info command will return 0x00 0x00 0x60 0x02. For
    /// all versions of the ECC608A the 3rd byte will always be 0x60. The fourth byte will indicate the
    /// silicon revision.
    pub fn atcab_info(
        &mut self,
    ) -> Result<[u8; (constants::ATCA_CMD_SIZE_MAX) as usize], &'static str> {
        let packet = self.atcab_info_base(constants::INFO_MODE_REVISION);
        let response = match self.send_packet(
            packet.deref(),
            ATECC608A_EXECUTION_TIME::ATCA_INFO(constants::ATCA_INFO),
        ) {
            Ok(v) => v,
            Err(e) => return Err(e.1.get_string_error()),
        };
        Ok(response)
    }

    #[doc = "###########################################################################"]
    #[doc = "#           Rusty CryptoAuthLib API/method for SHA command                #"]
    #[doc = "###########################################################################"]

    /// This method crafts a 'SHA command' packet.
    pub fn atcab_sha_base(&mut self, mode: u8, data: &[u8]) -> Vec<u8, U74> {
        let cmd_mode = mode & constants::SHA_MODE_MASK;
        if cmd_mode == constants::SHA_MODE_SHA256_START
        // || cmd_mode == constants::SHA_MODE_HMAC_START
        // || cmd_mode == constants::SHA_MODE_SHA256_PUBLIC
        {
            let mut q = packet::ATCAPacket {
                pktID: 0x03,
                txsize: 0,
                opcode: 0,
                param1: 0,
                param2: [0; 2],
                req_data: data,
                crc16: [0; 2],
            };

            q.txsize = constants::ATCA_CMD_SIZE_MIN;
            let packet: &mut packet::ATCAPacket =
                q.make_packet(Some(q.txsize), Some(constants::ATCA_SHA), Some(mode), None);

            //  Serialize packet structure to get a Heapless Vec. The Vec's size still needs to
            // be known at compile time. So, we use a big enough Vec to fit all 3 types of command
            // packets. (i.e. INITIALIZE, UPDATE, END)
            let output: Vec<u8, U74> = to_vec(packet).unwrap();
            assert_eq!(
                &[0x03, 0x07, 0x47, 0x00, 0x00, 0x00, 0x00, 0x2E, 0x85],
                output.deref()
            );
            return output;
        } else
        // if cmd_mode == constants::SHA_MODE_SHA256_UPDATE
        // || cmd_mode == constants::SHA_MODE_SHA256_END
        // || cmd_mode == constants::SHA_MODE_HMAC_END
        {
            let mut q = packet::ATCAPacket_w_data {
                pktID: 0x03,
                txsize: 0,
                opcode: 0,
                param1: 0,
                param2: [0; 2],
                req_data: data,
                crc16: [0; 2],
            };

            q.txsize = constants::ATCA_CMD_SIZE_MIN + data.len() as u8;
            let packet: &mut packet::ATCAPacket_w_data = q.make_packet(
                Some(q.txsize),
                Some(constants::ATCA_SHA),
                Some(mode),
                Some((data.len() as u16).to_le_bytes()),
            );
            let output: Vec<u8, U74> = to_vec(packet).unwrap();
            return output;
        }
    }
    /// Computes a SHA-256 digest for general purpose use by the system.
    /// Calculation of a SHA-256 digest occurs in the following three steps:
    /// 1. Start: Initialization of the SHA-256 calculation engine and initialization of the SHA context in
    /// memory. This mode does not accept any message bytes.
    /// 2. Update: The command can be called a variable number of times with this mode to add bytes to the
    /// message. Each iteration of this mode must include a message of 64 bytes.
    /// 3. End: The SHA-256 calculation is completed, and the resulting digest is placed into the output
    /// buffer. From 0 bytes to 63 bytes may be passed to the device
    /// for this mode.
    /// * This method performs all three steps.
    pub fn atcab_sha(
        &mut self,
        data: &[u8],
    ) -> Result<[u8; (constants::ATCA_CMD_SIZE_MAX) as usize], &'static str> {
        let bs = constants::ATCA_SHA256_BLOCK_SIZE;
        // Initialize SHA 256 engine
        let packet = self.atcab_sha_base(constants::SHA_MODE_SHA256_START, &[]);
        let sha_init_resp = match self.send_packet(
            packet.deref(),
            ATECC608A_EXECUTION_TIME::ATCA_SHA(constants::ATCA_SHA),
        ) {
            Ok(v) => v,
            Err(e) => return Err(e.1.get_string_error()),
        };

        let mut remaining = data.len() as usize;
        let n: usize = bs as usize; //or 0x40 - sha256 takes a 512-bit block of data or 64 bytes at a time.
        let mut counter = 0;
        while remaining > 0 {
            if remaining < n {
                break;
            }
            let bytes = &data[counter..n];
            // Update SHA 256 state with consecutive blocks of 64 bytes.
            let packet_update = self.atcab_sha_base(constants::SHA_MODE_SHA256_UPDATE, bytes);
            let sha_update_resp = match self.send_packet(
                packet_update.deref(),
                ATECC608A_EXECUTION_TIME::ATCA_SHA(constants::ATCA_SHA),
            ) {
                Ok(v) => v,
                Err(e) => return Err(e.1.get_string_error()),
            };
            remaining -= n;
            counter += n;
        }
        // Finalize SHA256 calculation and get digest.
        let packet_final = self.atcab_sha_base(
            constants::SHA_MODE_SHA256_END,
            &data[counter..counter + remaining],
        );
        let sha_final_resp = match self.send_packet(
            packet_final.deref(),
            ATECC608A_EXECUTION_TIME::ATCA_SHA(constants::ATCA_SHA),
        ) {
            Ok(v) => v,
            Err(e) => return Err(e.1.get_string_error()),
        };
        Ok(sha_final_resp)
    }

    #[doc = "###########################################################################"]
    #[doc = "#           Rusty CryptoAuthLib API/method for Sign command               #"]
    #[doc = "###########################################################################"]

    pub fn atcab_sign_base() {}

    pub fn atcab_sign() {}

    #[doc = "###########################################################################"]
    #[doc = "#             Rusty CryptoAuthLib API/method for Lock command             #"]
    #[doc = "###########################################################################"]

    // This method crafts a 'LOCK command' packet.
    pub fn atcab_lock(&mut self, mode: u8, crc: [u8; 2]) -> Vec<u8, U10> {
        let mut q = packet::ATCAPacket {
            pktID: 0x03,
            txsize: 0,
            opcode: 0,
            param1: 0,
            param2: [0; 2],
            req_data: &[],
            crc16: [0; 2],
        };

        let packet: &mut packet::ATCAPacket = q.make_packet(
            Some(constants::LOCK_COUNT),
            Some(constants::ATCA_LOCK),
            Some(mode),
            Some(crc),
        );

        //  Serialize packet structure to get a Heapless Vec. The Vec's size still needs to
        // be known at compile time.
        let output: Vec<u8, U10> = to_vec(packet).unwrap();
        // assert_eq!(
        //     &[0x03, 0x07, 0x47, 0x00, 0x00, 0x00, 0x00, 0x2E, 0x85],
        //     output.deref()
        // );
        return output;
    }

    /// This method uses the Lock command to prevent future modification of the Configuration zone.
    /// CRC argument is [00, 00]
    /// The Lock command fails if the designated area is already locked.
    /// Upon successful execution, the device returns a value of zero.
    pub fn atcab_lock_config_zone(
        &mut self,
    ) -> Result<[u8; (constants::ATCA_CMD_SIZE_MAX) as usize], &'static str> {
        let packet = self.atcab_lock(
            constants::LOCK_ZONE_NO_CRC | constants::LOCK_ZONE_CONFIG,
            [0; 2],
        );
        let lock_resp = match self.send_packet(
            packet.deref(),
            ATECC608A_EXECUTION_TIME::ATCA_LOCK(constants::ATCA_LOCK),
        ) {
            Ok(v) => v,
            Err(e) => return Err(e.1.get_string_error()),
        };
        Ok(lock_resp)
    }

    /// Prior to locking the configuration zone, the device can optionally use the
    /// CRC-16 algorithm to verify the contents of the designated zone(s). The calculation uses the same
    /// algorithm as the CRC computed over the input and output groups.
    /// The value of the 7th bit of the 'mode parameter' (called summary check bit) is important.
    /// =>    0 = The summary value is verified before the zone is locked.
    /// =>    1 = Check of the zone summary is ignored and the zone is locked regardless of the contents of the zone.
    pub fn atcab_lock_config_zone_crc(
        &mut self,
        crc: [u8; 2],
    ) -> Result<[u8; (constants::ATCA_CMD_SIZE_MAX) as usize], &'static str> {
        let packet = self.atcab_lock(constants::LOCK_ZONE_CONFIG, crc);
        let lock_resp = match self.send_packet(
            packet.deref(),
            ATECC608A_EXECUTION_TIME::ATCA_LOCK(constants::ATCA_LOCK),
        ) {
            Ok(v) => v,
            Err(e) => return Err(e.1.get_string_error()),
        };
        Ok(lock_resp)
    }

    #[doc = "###########################################################################"]
    #[doc = "#             Rusty CryptoAuthLib API/method for Read command             #"]
    #[doc = "###########################################################################"]

    /// This method crafts a 'READ command' packet.
    /// Returns command packet as a heapless Vec.
    pub fn atcab_read_zone(
        &mut self,
        mut zone: u16,
        slot: u16,
        block: u16,
        offset: u16,
        length: u16,
    ) -> Vec<u8, U10> {
        if length == constants::ATCA_WORD_SIZE as u16 || length == constants::ATCA_BLOCK_SIZE as u16
        {
        } else {
            panic!("Error while reading zone - only 4 or 32 byte read are allowed");
        }

        let addr = self.atcab_get_addr(zone, slot, block, offset);

        if length == constants::ATCA_BLOCK_SIZE as u16 {
            zone = zone | constants::ATCA_ZONE_READWRITE_32 as u16; // mode parameter for the read command
        } // the 7th bit needs to be '1' for 32 byte reads.

        let mut q = packet::ATCAPacket {
            pktID: 0x03,
            txsize: 0,
            opcode: 0,
            param1: 0,
            param2: [0; 2],
            req_data: &[],
            crc16: [0; 2],
        };

        let packet: &mut packet::ATCAPacket = q.make_packet(
            None,
            Some(constants::ATCA_READ),
            Some(zone as u8),
            Some(addr.to_le_bytes()),
        );

        //  Serialize packet structure to get a Heapless Vec. The Vec's size still needs to
        // be known at compile time.
        let output: Vec<u8, U10> = to_vec(packet).unwrap();
        return output;
    }
    ///This method reads words (one four byte word or an 8-word block of 32 bytes) from one of the memory zones of the device.
    /// Returns an array of 4 byte arrays.
    pub fn atcab_read_bytes_zone(
        &mut self,
        zone: u16,
        slot: u16,
        block: u16,
        offset: u16, // If you want start reading from an offset within a given memory zone
        length: u16, // the number of bytes to be retrieved.
    ) -> Result<[[u8; 151]; 4], &'static str> {
        let zone_size = self.atcab_get_zone_size(zone, slot);

        if (offset + length) as u16 > zone_size {
            panic!("Length Error while reading zone bytes");
        }

        let BS = constants::ATCA_BLOCK_SIZE as u16;
        let WS = constants::ATCA_WORD_SIZE as u16;
        let mut config_zone = [[0; 151]; 4];

        let mut read_size = BS;
        let mut d_idx = 0;
        let mut i = 0;
        let mut read_index = 0;
        let mut read_offset = 0;
        let mut block_count = 0;
        let mut word_count = 0;
        block_count = offset / BS;
        while d_idx < length {
            // check to see if we're reading contents of the last block. If yes, reset read-size and word_count.
            if (read_size == BS) && (zone_size - (block_count * BS) as u16) < BS as u16 {
                read_size = WS;
                word_count = ((d_idx + offset) / WS) % (BS / WS);
            }
            // craft a 32 or 4 byte read command packet, send it and store the response from the device
            // in an array of arrays buffer.
            let packet = self.atcab_read_zone(zone, slot, block_count, word_count, read_size);
            let read_resp = match self.send_packet(
                packet.deref(),
                ATECC608A_EXECUTION_TIME::ATCA_READ(constants::ATCA_READ),
            ) {
                Ok(v) => v,
                Err(e) => return Err(e.1.get_string_error()),
            };

            config_zone[i] = read_resp;
            i += 1;

            // read_offset is an offset into the memory zone from which we wish to retrieve data.
            // Ex: say you supply an offset of 100 (into the config zone), read_offset evaluates to 96 (i.e. a multiple of 4 or 32)
            // read_index is the difference between user supplied offset and read_offset
            read_offset = block_count * BS + word_count * WS;
            if read_offset < offset {
                read_index = offset - read_offset;
            } else {
                read_index = 0;
            }
            if length - d_idx < read_size - read_index {
                d_idx += length - d_idx;
            } else {
                d_idx += read_size - read_index;
            }

            if read_size == BS {
                block_count += 1
            } else {
                word_count += 1
            }
        }
        return Ok(config_zone);
    }

    /// Dumps the contents of Config zone. Zone of 128 bytes (1,024-bit) EEPROM that contains the serial
    /// number and other ID information, as well as, access policy information for each slot of the data memory.
    /// The values programmed into the configuration zone will determine the access policy of how each data slot will respond.
    /// The configuration zone can be modified until it has been locked (LockConfig set to !=0x55).
    /// In order to enable the access policies, the LockValue byte must be set.
    pub fn atcab_read_config_zone(&mut self) -> Result<[u8; 128], &'static str> {
        let packet = match self.atcab_read_bytes_zone(
            constants::ATCA_ZONE_CONFIG as u16,
            0,
            0,
            0,
            constants::ATCA_ECC_CONFIG_SIZE as u16,
        ) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        // We have a 128 byte config zone. Iterate over the 4 element 'array of arrays'.
        // chain contents (bytes) into a single 128 byte array.
        let slice_1 = &packet[0][..32];
        let slice_2 = &packet[1][..32];
        let slice_3 = &packet[2][..32];
        let slice_4 = &packet[3][..32];

        let mut config_dump = [0; 0x80];
        for (idx, val) in slice_1
            .iter()
            .chain(slice_2.iter())
            .chain(slice_3.iter())
            .chain(slice_3.iter())
            .enumerate()
        {
            config_dump[idx] = *val;
        }
        return Ok(config_dump);
    }

    /// Address of first word to be read within the zone.
    /// The Read and Write commands include a single 16 bit address in Param2, which indicates the memory location to be accessed.
    /// In all cases, data is accessed on 4 byte word boundaries.
    /// Address Encoding for Config and OTP Zones (Param2). Byte 1 is unused and Byte 0 is used as follows
    /// ******************Byte 0 info ******************
    /// Unused - Bits 7-5 (drop the 3 most significant bits by left shifting)
    /// Block  - Bits 4-3 (the config zone has 4 blocks in total 0-3 and is 128 bytes in length)
    /// Offset - Bits 2-0 (offset into the block)
    pub fn atcab_get_addr(&mut self, zone: u16, slot: u16, block: u16, offset: u16) -> u16 {
        let mem_zone = zone & constants::ATCA_ZONE_MASK as u16;
        if mem_zone == constants::ATCA_ZONE_CONFIG as u16
            || mem_zone == constants::ATCA_ZONE_DATA as u16
            || mem_zone == constants::ATCA_ZONE_OTP as u16
        {
        } else {
            panic!("Error while getting address");
        }

        if slot < 0 || slot > 15 {
            panic!("Error slot ID out of range")
        }

        let mut addr = 0;
        let offset = offset & 0x07;
        if mem_zone == constants::ATCA_ZONE_CONFIG as u16
            || mem_zone == constants::ATCA_ZONE_OTP as u16
        {
            addr = block << 3;
            addr = addr | offset;
        } else if mem_zone == constants::ATCA_ZONE_DATA as u16 {
            addr = slot << 3;
            addr = addr | offset;
            addr = addr | block << 8;
        }

        return addr as u16;
    }

    /// Method to test for a valid memory zone, data slot and return zone size in bytes.
    pub fn atcab_get_zone_size(&mut self, zone: u16, slot: u16) -> u16 {
        if zone == constants::ATCA_ZONE_CONFIG as u16
            || zone == constants::ATCA_ZONE_DATA as u16
            || zone == constants::ATCA_ZONE_OTP as u16
        {
        } else {
            panic!("Error while getting zone size");
        }

        if slot < 0 || slot > 15 {
            panic!("Slot ID out of range")
        }

        if zone == constants::ATCA_ZONE_CONFIG as u16 {
            return 128;
        } else if zone == constants::ATCA_ZONE_OTP as u16 {
            return 64;
        } else if zone == constants::ATCA_ZONE_DATA as u16 && slot < 8 {
            return 36;
        } else if zone == constants::ATCA_ZONE_DATA as u16 && slot == 8 {
            return 412;
        } else if zone == constants::ATCA_ZONE_DATA as u16 && slot < 16 {
            return 72;
        } else {
            return 0;
        }
    }
}
