//! A platform agnostic I2C driver for Microchip's Crypto Authentication HW
//! (i.e. secure element `ATECC608A`), written in pure Rust.

#![deny(missing_docs)]
#![deny(arithmetic_overflow)]
#![deny(warnings)]
#![deny(unsafe_code)]
#![deny(unstable_features)]
#![deny(unused_import_braces)]
#![deny(unused_qualifications)]
// #![allow(warnings)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![no_std]

pub mod constants;
pub mod packet;

#[macro_use(block)]
extern crate nb;
extern crate embedded_hal;
// extern crate panic_halt;

use constants::{ATECC608A_EXECUTION_TIME, EXECUTION_TIME};
// use core::convert::TryFrom;
use core::fmt::Debug;
use core::ops::Deref;
use embedded_hal::blocking::delay::{DelayMs, DelayUs};
use embedded_hal::blocking::i2c::{Read, Write};
use embedded_hal::timer::CountDown;
use heapless::{consts::*, Vec};
use postcard::to_vec;

// For logging i.e. printf style debugging
use core::sync::atomic::{AtomicUsize, Ordering};

#[defmt::timestamp]
fn timestamp() -> u64 {
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    // NOTE(no-CAS) `timestamps` runs with interrupts disabled
    let n = COUNT.load(Ordering::Relaxed);
    COUNT.store(n + 1, Ordering::Relaxed);
    n as u64
}

// use cortex_m_semihosting::hprintln;

/// Device's i2c address
pub const ADDRESS: u8 = 0xC0 >> 1;
/// constant to ADD a delay of at least 1500 us to ensure SDA is held high during wake process.
pub const WAKE_DELAY: u32 = 1500;
const DEVICE_TYPE: Variant = Variant::ATECC608A;

#[allow(dead_code)]
#[derive(Copy, Clone, Debug, PartialEq)]
enum Variant {
    ATECC608A,
    ATECC508A,
}

/// Helper trait to convert ATCA_CMD_SIZE_MAX (151-byte) array to
/// -   a 3-byte (ATCA_RSP_SIZE_MIN-1) array
/// -   or a 64-byte array
///
/// This is just to optimize runtime space requirements. We use a ATCA_CMD_SIZE_MAX (151-byte) array
/// to store all responses from the ATECC device as Rust does not yet support code that is generic over
/// the size of an array type i.e. [Foo; 3] and [Bar; 3] are instances of same generic type [T; 3],
/// but [Foo; 3] and [Foo; 5]  are entirely different types.
pub trait ConvertTo {
    /// Trait to convert any array (of u8s) of size > 3 to a 3 byte array.
    fn convert_to_3(&self) -> [u8; 3];
    /// Trait to convert any array (of u8s) of size > 4 to a 4 byte array.
    fn convert_to_4(&self) -> [u8; 4];
    /// Trait to convert any array (of u8s) of size > 32 to a 32 byte array.
    fn convert_to_32(&self) -> [u8; 32];
    /// Trait to convert any array (of u8s) of size > 64 to a 64 byte array.
    fn convert_to_64(&self) -> [u8; 64];
}

impl ConvertTo for [u8; 151] {
    /// This method takes a reference to `self` (an array) and returns the first 3-bytes.
    /// Responses that do not contain data are 4 bytes in length. The method `send_packet` returns
    /// a [u8;151] which does not include the count (or first) byte. So, we only need to pick the first 3 bytes.  
    fn convert_to_3(&self) -> [u8; 3] {
        let mut rsp_bytes = [0; 3];
        for (idx, val) in self[..3].iter().enumerate() {
            rsp_bytes[idx] = *val
        }
        rsp_bytes
    }

    /// This method takes a reference to `self` (an array) and returns the first 4-bytes.
    fn convert_to_4(&self) -> [u8; 4] {
        let mut rsp_bytes = [0; 4];
        for (idx, val) in self[..4].iter().enumerate() {
            rsp_bytes[idx] = *val
        }
        rsp_bytes
    }
    /// This method takes a reference to `self` (an array) and returns the first 64-bytes.
    fn convert_to_64(&self) -> [u8; 64] {
        let mut rsp_bytes = [0; 64];
        for (idx, val) in self[..64].iter().enumerate() {
            rsp_bytes[idx] = *val
        }
        rsp_bytes
    }

    /// This method takes a reference to `self` (an array) and returns the first 32-bytes.
    fn convert_to_32(&self) -> [u8; 32] {
        let mut rsp_bytes = [0; 32];
        for (idx, val) in self[..32].iter().enumerate() {
            rsp_bytes[idx] = *val
        }
        rsp_bytes
    }
}

/// ATECC680A driver
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct ATECC608A<I2C, DELAY, TIMER> {
    /// i2c Instance
    pub i2c: I2C,
    /// delay timer instance
    pub delay: DELAY,
    /// time instance
    pub timer: TIMER,
    /// device address
    pub dev_addr: u8,
    device: Variant,
}

impl<I2C, DELAY, TIMER, E> ATECC608A<I2C, DELAY, TIMER>
where
    I2C: Read<Error = E> + Write<Error = E>,
    E: Debug,
    DELAY: DelayMs<u32> + DelayUs<u32>,
    TIMER: CountDown<Time = u32>,
{
    /// Creates a new ATECC608a driver.
    pub fn new(i2c: I2C, delay: DELAY, timer: TIMER) -> Result<Self, E> {
        let atecc608a = ATECC608A {
            i2c,
            delay,
            timer,
            dev_addr: ADDRESS,
            device: DEVICE_TYPE,
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

    /// A method for sending commands to the ATECC608A and
    /// retrieving the associated response.
    ///
    /// Method arguments:
    /// -   packet: data as slice of bytes.
    /// -   texec: An enum that holds the `max-execution time` for the command.
    ///
    /// Returns:
    /// -  Either an array of size [u8;151]
    ///     1.   If byte[0] is 0x00, it indicates the successful execution of a command
    ///     2.   If byte[0] is !=0x00, it includes the response associated with respective command
    /// -   If an error is encountered, it returns a struct containing the status error.
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
        match self.wake() {
            Ok(v) => v,
            Err(_e) => defmt::info!("DEVICE WAKE SEQUENCE: tWLO COMPLETE"),
        };
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
        // For Variable length data (such as slices) 'postcard'
        // prefixes the length byte. Length is a VARINT. So, we will need to remove the length byte before sending
        // the command packet over.
        let slice_2: &[u8];
        if &packet[6] > &127 {
            // packet lengths 128 or greater take up 2 bytes when using Varint encoding.
            slice_2 = &packet[(constants::ATCA_CMD_SIZE_MIN + 1) as usize..];
        } else {
            slice_2 = &packet[(constants::ATCA_CMD_SIZE_MIN) as usize..];
        }

        let mut pkt = [0; constants::ATCA_CMD_SIZE_MAX as usize];
        for (idx, val) in slice_1.iter().chain(slice_2.iter()).enumerate() {
            pkt[idx] = *val;
        }

        match self.i2c.write(self.dev_addr, &pkt[..(pkt[1] + 1) as usize]) {
            Ok(v) => v,
            Err(_e) => {
                defmt::error!("I2C WRITE ERROR: failed to write command-packet to the device ")
            }
        };

        let t_exec: constants::Time = (EXECUTION_TIME::ATECC608A(texec.clone()))
            .get_value()
            .get_t_exec();

        // wait tEXEC (max) after which the device will have completed execution, and the
        // result can be read from the device using a normal read sequence.
        self.timer.start(t_exec.0 as u32 * 1000);
        block!(self.timer.wait())
            .expect("ERROR: Something went wrong while waiting on the countdown timer to expire");

        // The first byte holds the length of the response.
        let mut count_byte = [0; 1];
        match self.i2c.read(self.dev_addr, &mut count_byte){
            Ok(v)   => v,
            Err(_e)  => defmt::error!("I2C READ ERROR: failed to read the first (or count) byte of the response from the device")
        };
        // Perform a subsequent read for the remaining (response) bytes
        let mut resp = [0; (constants::ATCA_CMD_SIZE_MAX) as usize];
        match self
            .i2c
            .read(self.dev_addr, &mut resp[..(count_byte[0] - 1) as usize])
        {
            Ok(v) => v,
            Err(_e) => defmt::error!(
                "I2C READ ERROR: failed to read the remainder of the response from the device"
            ),
        };

        // // Retry if its a CRC or Other Communications error. We could end up in a loop here
        // // Enable, if you'd like retry,
        // if count_byte[0] == constants::ATCA_RSP_SIZE_MIN
        //     && resp[(constants::ATCA_RSP_DATA_IDX - 1) as usize] == constants::CMD_STATUS_BYTE_COMM
        // {
        //     self.timer.start(tExec.0 as u32 * 1000);
        //     block!(self.timer.wait());
        //     self.send_packet(packet.deref(), texec);
        // }

        if count_byte[0] == constants::ATCA_RSP_SIZE_MIN {
            // Instantiate StatusError struct
            let status_error: constants::StatusError;
            // Check status byte of response to detemine if the command was executed successfully or returned an error.
            if resp[(constants::ATCA_RSP_DATA_IDX - 1) as usize] == constants::ATCA_SUCCESS {
                Ok(resp)
            } else if resp[(constants::ATCA_RSP_DATA_IDX - 1) as usize]
                == constants::CMD_STATUS_WAKEUP
            {
                Ok(resp)
            } else if resp[(constants::ATCA_RSP_DATA_IDX - 1) as usize]
                == constants::ATCA_WATCHDOG_ABOUT_TO_EXPIRE
            {
                match self.sleep() {
                    Ok(v) => v,
                    Err(_e) => defmt::error!("I2C WRITE ERROR: failed to put the device to sleep"),
                };

                status_error = constants::DECODE_ERROR::get_error(
                    resp[(constants::ATCA_RSP_DATA_IDX - 1) as usize],
                );
                Err(status_error)
            } else {
                //if count_byte[0] == constants::ATCA_RSP_SIZE_MIN
                status_error = constants::DECODE_ERROR::get_error(
                    resp[(constants::ATCA_RSP_DATA_IDX - 1) as usize],
                );
                Err(status_error)
            }
        } else {
            return Ok(resp);
        }
    }

    // *******************INFO COMMANDS***************************
    //
    /// This method crafts a 'INFO command' packet. The Info command is used to read the status and state of the device. This information is useful in determining errors
    /// or to operate various commands.
    ///
    /// Method arguments:
    /// -   param1: mode byte deteremines what kind of info will be returned. This implementation uses Revision mode
    ///     of the Info command to read back the silicon revision of the device. This information is hard coded into
    ///     the device. This information may or may not be the same as what is read back in the Revision bytes shown in the
    ///     Configuration zone.
    ///
    /// Returns:
    /// -   A heapless Vec containing the serialized command packet bytes.
    pub fn atcab_info_base(&mut self, param1: u8) -> Vec<u8, U10> {
        let mut q = packet::ATCAPacket {
            pkt_id: 0x03,
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
        // assert_eq!(
        //     &[0x03, 0x07, 0x30, 0x00, 0x00, 0x00, 0x00, 0x03, 0x5D],
        //     output.deref()
        // );
        return output;
    }

    /// Returns a single 4-byte word representing the revision number of the device. Software
    /// should not depend on this value as it may change from time to time.
    ///
    /// At the time of writing this, the Info command will return 0x00 0x00 0x60 0x02. For
    /// all versions of the ECC608A the 3rd byte will always be 0x60. The fourth byte will indicate the
    /// silicon revision.
    ///
    /// Method arguments:
    /// -   Takes none (but method can be extended if required)
    ///
    /// Returns:
    /// -   4-byte revision info [00 00 60 vv] indicated by ATECC608A. vv is the most recent silicon version.
    pub fn atcab_info(
        &mut self,
    ) -> Result<[u8; (constants::INFO_RSP_SIZE - 3) as usize], &'static str> {
        let packet = self.atcab_info_base(constants::INFO_MODE_REVISION);
        let response = match self.send_packet(
            packet.deref(),
            ATECC608A_EXECUTION_TIME::ATCA_INFO(constants::ATCA_INFO),
        ) {
            Ok(v) => v,
            Err(e) => return Err(e.1.get_string_error()),
        };
        Ok(response.convert_to_4())
    }

    // ******************************SHA COMMANDS**************************************
    //
    /// This method crafts a 'SHA command' packet.
    ///
    /// Method arguments:
    /// -   mode: a single byte to indicate whether SHA init, update or finalize states.
    ///     -   SHA_MODE_SHA256_END - 0x00
    ///     -   SHA_MODE_SHA256_START - 0x01
    ///     -   SHA_MODE_SHA256_UPDATE - 0x02
    /// -   data: data as a slice of bytes.
    ///
    /// Returns:
    /// -   A heapless Vec containing the serialized command packet bytes.
    pub fn atcab_sha_base(&mut self, mode: u8, data: &[u8]) -> Vec<u8, U74> {
        let cmd_mode = mode & constants::SHA_MODE_MASK;
        if cmd_mode == constants::SHA_MODE_SHA256_START
        // || cmd_mode == constants::SHA_MODE_HMAC_START
        // || cmd_mode == constants::SHA_MODE_SHA256_PUBLIC
        {
            let mut q = packet::ATCAPacket {
                pkt_id: 0x03,
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
                pkt_id: 0x03,
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
    ///
    /// Method arguments:
    /// -   data: data as a slice of bytes
    ///
    /// Returns:
    /// -   a 32 byte digest if successful
    /// -   an error string describing the error.  
    pub fn atcab_sha(
        &mut self,
        data: &[u8],
    ) -> Result<[u8; (constants::SHA_RSP_SIZE - 3) as usize], &'static str> {
        let bs = constants::ATCA_SHA256_BLOCK_SIZE;
        // Initialize SHA 256 engine
        let packet = self.atcab_sha_base(constants::SHA_MODE_SHA256_START, &[]);
        let _sha_init_resp = match self.send_packet(
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
            let _sha_update_resp = match self.send_packet(
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
        Ok(sha_final_resp.convert_to_32())
    }

    // **********************GENKEY COMMANDS*****************************
    //
    /// This methods crafts a `GENKEY command` packet
    ///
    /// Method arguments:
    /// -   mode: mode of operation, possible values 0x04, 0x0C.  Public key is generated and output on the bus (always).
    /// -   key_id: slot id in the data zone
    /// -   other_data: In the `private key- stored in TEMPKEY` mode, GenKey command can be used to generate an ephemeral ECC private key and place it in SRAM where
    ///     there is no limit on writing to a memory location. This key cannot be read out but may be used by the ECDH
    ///     command. In this mode, the private Key is stored in TempKey and requires other_data to be [0x00, 0x00, 0x00].
    ///     other_data is not included in all other modes.
    ///
    /// Returns:
    /// -   A heapless Vec containing the serialized command packet bytes.
    pub fn atcab_genkey_base(
        &mut self,
        mode: u16,
        key_id: u16,
        other_data: [u8; constants::GENKEY_OTHER_DATA_SIZE as usize],
    ) -> Vec<u8, U12> {
        let txsize;
        let data;
        if (mode & constants::GENKEY_MODE_PUBKEY_DIGEST as u16) != 0 {
            //Public Key Digest Generation Mode
            txsize = constants::GENKEY_COUNT_DATA;
            data = &other_data[..3];
        } else {
            txsize = constants::GENKEY_COUNT;
            data = &[];
        }

        // let data = &other_data[..3];

        let mut q = packet::ATCAPacket {
            pkt_id: 0x03,
            txsize: 0,
            opcode: 0,
            param1: 0,
            param2: [0; 2],
            req_data: data,
            crc16: [0; 2],
        };

        let packet: &mut packet::ATCAPacket = q.make_packet(
            Some(txsize),
            Some(constants::ATCA_GENKEY),
            Some(mode as u8),
            Some(key_id.to_le_bytes()),
        );

        // Serialize `packet struct` to get a Heapless Vec. The Vec's size still needs to
        // be known at compile time.
        let output: Vec<u8, U12> = to_vec(packet).unwrap();
        return output;
    }

    /// This method creates a new random private key and writes that key into the slot specified by the key_id
    /// parameter. Returns a 64 byte Public Key - X and Y coordinates (32 bytes each) or a failure error string.
    ///
    /// The private key stored in the designated slot can never be read (i.e. never leaves the device).
    ///
    /// Method arguments:
    /// -   key_id: slot id in the data zone
    ///
    /// Returns:
    /// -   a 64 byte array containing public keys X and Y coordinates, indicating the command’s success
    /// -   or an error string, describing the error.
    pub fn atcab_genkey(&mut self, key_id: u16) -> Result<[u8; 64], &'static str> {
        let packet = self.atcab_genkey_base(constants::GENKEY_MODE_PRIVATE as u16, key_id, [0; 3]);
        let genkey_resp = match self.send_packet(
            packet.deref(),
            ATECC608A_EXECUTION_TIME::ATCA_GENKEY(constants::ATCA_GENKEY),
        ) {
            Ok(v) => v,
            Err(e) => return Err(e.1.get_string_error()),
        };
        Ok(genkey_resp.convert_to_64())
    }

    /// Generates an ECC public key based upon the private key stored in the slot defined by the key_id
    /// parameter. This mode of the command may be used to avoid storing the public key on the device at
    /// the expense of the time required to regenerate it.
    ///
    /// Method arguments:
    /// -   key_id: slot id of data zone
    ///
    /// Returns:
    /// -   a 64 byte array containing public keys X and Y coordinates, indicating the command’s success
    /// -   or an error string, describing the error.
    pub fn atcab_get_pubkey(&mut self, key_id: u16) -> Result<[u8; 64], &'static str> {
        let packet = self.atcab_genkey_base(constants::GENKEY_MODE_PUBLIC as u16, key_id, [0; 3]);
        let genkey_resp = match self.send_packet(
            packet.deref(),
            ATECC608A_EXECUTION_TIME::ATCA_GENKEY(constants::ATCA_GENKEY),
        ) {
            Ok(v) => v,
            Err(e) => return Err(e.1.get_string_error()),
        };
        Ok(genkey_resp.convert_to_64())
    }

    // *****************************NONCE COMMANDS**********************************
    //
    /// This method crafts a `NONCE command` packet
    ///
    /// Method arguments:
    /// -   mode: random mode or fixed mode
    ///     -   for random, values can be 0x00 or 0x01
    ///     -   for fixed, values can be 0x3, 0x43, 0x83, 0x23, 0x63
    /// -   zero:
    ///     -   for random, values can be [0x00, 0x00] or [0x80, 0x00]
    ///     -   for fixed, value is always [0x00, 0x00]
    /// -   num_in:  
    ///     -   for random, input is always 20 random bytes
    ///     -   for fixed, input is either 32 or 64 bytes
    ///
    /// Returns:
    /// -   A heapless Vec containing the serialized command packet bytes.
    pub fn atcab_base_nonce(&mut self, mode: u16, zero: u16, num_in: &[u8]) -> Vec<u8, U74> {
        let nonce_mode = mode & constants::NONCE_MODE_MASK as u16;
        if nonce_mode == constants::NONCE_MODE_SEED_UPDATE as u16
            || nonce_mode == constants::NONCE_MODE_NO_SEED_UPDATE as u16
            || nonce_mode == constants::NONCE_MODE_PASSTHROUGH as u16
        {
        } else {
            defmt::error!("Not a valid NONCE command (or mode): ");
        }

        let mut txsize = 0;
        if nonce_mode == constants::NONCE_MODE_SEED_UPDATE as u16
            || nonce_mode == constants::NONCE_MODE_NO_SEED_UPDATE as u16
        {
            txsize = constants::NONCE_COUNT_SHORT as u16;
        } else if nonce_mode == constants::NONCE_MODE_PASSTHROUGH as u16 {
            let nonce_mode_input = mode & constants::NONCE_MODE_INPUT_LEN_MASK as u16;
            if nonce_mode_input == constants::NONCE_MODE_INPUT_LEN_64 as u16 {
                txsize = constants::NONCE_COUNT_LONG_64 as u16;
            } else {
                txsize = constants::NONCE_COUNT_LONG as u16;
            }
        }

        if num_in.len() < (txsize - constants::ATCA_CMD_SIZE_MIN as u16) as usize {
            defmt::error!("Nonce generation failed. Invalid number of input-bytes provided")
        }

        let mut q = packet::ATCAPacket_w_data {
            pkt_id: 0x03,
            txsize: 0,
            opcode: 0,
            param1: 0,
            param2: [0; 2],
            req_data: num_in,
            crc16: [0; 2],
        };

        let packet: &mut packet::ATCAPacket_w_data = q.make_packet(
            Some(txsize as u8),
            Some(constants::ATCA_NONCE),
            Some(mode as u8),
            Some(zero.to_le_bytes()),
        );

        //  Serialize packet structure to get a Heapless Vec. The Vec's size still needs to
        // be known at compile time.
        let output: Vec<u8, U74> = to_vec(packet).unwrap();
        return output;
    }

    /// This method passes a fixed nonce (num_in) to the device and stores it in the Message Digest Buffer.
    /// The size of the nonce may be either 32 or 64 bytes. This mode of the Nonce
    /// command does not run a SHA256 calculation or generate a random number.
    ///
    /// Method arguments -
    /// -   target: where to load the fixed nonce - TEMPKEY or Message Digest Buffer
    /// -   num_in: The size of the nonce may be either 32 or 64 bytes. This mode of the Nonce
    ///     command does not run a SHA256 calculation or generate a random number.
    ///
    /// Returns:
    /// -   a 1-byte response - 0x00 (along with 2 CRC bytes) if the command is completed successfully.
    /// -   Otherwise an error string is received.
    pub fn atcab_nonce_load(
        &mut self,
        target: u16,
        num_in: &[u8],
    ) -> Result<[u8; (constants::WRITE_RSP_SIZE - 1) as usize], &'static str> {
        let mut mode = constants::NONCE_MODE_PASSTHROUGH;
        // Target - where to load the fixed nonce - TEMPKEY or Message Digest Buffer
        mode = mode | (constants::NONCE_MODE_TARGET_MASK & target as u8);

        if num_in.len() == 32 {
            mode = mode | constants::NONCE_MODE_INPUT_LEN_32;
        } else if num_in.len() == 64 {
            mode = mode | constants::NONCE_MODE_INPUT_LEN_64;
        } else {
            defmt::error!("Nonce generation failed. Invalid number of input-bytes provided")
        }

        let packet = self.atcab_base_nonce(mode as u16, 0, num_in);
        let nonce_load_resp = match self.send_packet(
            packet.deref(),
            ATECC608A_EXECUTION_TIME::ATCA_NONCE(constants::ATCA_NONCE),
        ) {
            Ok(v) => v,
            Err(e) => return Err(e.1.get_string_error()),
        };
        Ok(nonce_load_resp.convert_to_3())
    }

    /// The Nonce command generates a nonce (Number used Once) for use by a subsequent command by combining a
    /// random number (which can be generated internally or externally) with an input value from the system. The resulting
    /// nonce is stored internally in three possible buffers: TempKey, Message Digest Buffer, and Alternate Key Buffer.
    /// Instead of generating a nonce, a value may be passed to the device if so desired.
    ///
    /// This method passes a fixed nonce (num_in) to the device and stores it in TempKey buffer.
    /// The size of the nonce should be 32 bytes. This mode of the Nonce
    /// command does not run a SHA256 calculation or generate a random number.
    ///
    /// Method arguments -
    /// -   num_in: The size of the nonce may be either 32 bytes. This mode of the Nonce
    ///     command does not run a SHA256 calculation or generate a random number.
    ///
    /// Returns:
    /// -   a 1-byte response - 0x00 (along with 2 CRC bytes) if the command is completed successfully.
    /// -   Otherwise an error string is received.
    pub fn atcab_nonce(
        &mut self,
        num_in: &[u8],
    ) -> Result<[u8; (constants::WRITE_RSP_SIZE - 1) as usize], &'static str> {
        let packet = self.atcab_base_nonce(constants::NONCE_MODE_PASSTHROUGH as u16, 0, num_in);
        let nonce_load_resp = match self.send_packet(
            packet.deref(),
            ATECC608A_EXECUTION_TIME::ATCA_NONCE(constants::ATCA_NONCE),
        ) {
            Ok(v) => v,
            Err(e) => return Err(e.1.get_string_error()),
        };
        Ok(nonce_load_resp.convert_to_3())
    }

    /// Same as atcab_nonce(..) i.e. fixed nonce.
    pub fn atcab_challenge(
        &mut self,
        num_in: &[u8],
    ) -> Result<[u8; (constants::WRITE_RSP_SIZE - 1) as usize], &'static str> {
        let packet = self.atcab_base_nonce(constants::NONCE_MODE_PASSTHROUGH as u16, 0, num_in);
        let nonce_load_resp = match self.send_packet(
            packet.deref(),
            ATECC608A_EXECUTION_TIME::ATCA_NONCE(constants::ATCA_NONCE),
        ) {
            Ok(v) => v,
            Err(e) => return Err(e.1.get_string_error()),
        };
        Ok(nonce_load_resp.convert_to_3())
    }

    /// When the Nonce command is run in Random mode, it generates a new nonce based on the input values. If
    /// out_type is 0x0000, then a `new random number` is generated based on the internal RNG. If
    /// out_type is 0x0080, a value stored in TempKey is used to generate a new nonce instead and the random number
    /// generator is not run. TempKey must be valid prior to running the Nonce command in this case.
    ///
    /// This method passes a random 20-byte (num_in) number to the ATECC device and 16-bit u8 which can only assume one of 2 values.
    /// (i.e. valid `out_type` can either be 0x0000 or 0x0080). The device combines it with an internally
    /// generated random number or the previous `TEMPKEY` (depending on the out_type) value. This combined value
    /// along with the following `NONCE command` parameters - OPCODE, MODE, LSB of out_type are hashed (SHA256) to produce
    /// the random nonce. This result is stored in TEMPKEY.
    ///
    /// Method arguments:
    /// -   out_type: If out_type is 0x0000, then a `new random number` is generated based on the internal RNG. If
    ///     out_type is 0x0080, a value stored in TempKey is used to generate a new nonce instead and the random number
    ///     generator is not run.
    /// -   num_in: a random 20-byte number is passed to the ATECC device
    ///
    /// Returns:
    /// -   if the out_type is 0x0000, it returns the 32-byte random number used to calculate the nonce.
    /// -   if the out_type is 0x0080, it returns the 32-byte Nonce (i.e. new TEMPKEY value)
    pub fn atcab_nonce_rand(
        &mut self,
        out_type: u16,
        num_in: &[u8],
    ) -> Result<[u8; (constants::NONCE_RSP_SIZE_LONG - 3) as usize], &'static str> {
        let packet =
            self.atcab_base_nonce(constants::NONCE_MODE_SEED_UPDATE as u16, out_type, num_in);
        let nonce_load_resp = match self.send_packet(
            packet.deref(),
            ATECC608A_EXECUTION_TIME::ATCA_NONCE(constants::ATCA_NONCE),
        ) {
            Ok(v) => v,
            Err(e) => return Err(e.1.get_string_error()),
        };
        Ok(nonce_load_resp.convert_to_32())
    }

    /// Same as atcab_nonce_rand(..), except for the response. This method does not take a `out_type` parameter. So,
    /// the response is  a 32 byte random number used to calculate the nonce (assuming the NONCE command executes
    /// successfully).
    pub fn atcab_challenge_seed_update(
        &mut self,
        num_in: &[u8],
    ) -> Result<[u8; (constants::NONCE_RSP_SIZE_LONG - 3) as usize], &'static str> {
        let packet = self.atcab_base_nonce(constants::NONCE_MODE_SEED_UPDATE as u16, 0, num_in);
        let nonce_load_resp = match self.send_packet(
            packet.deref(),
            ATECC608A_EXECUTION_TIME::ATCA_NONCE(constants::ATCA_NONCE),
        ) {
            Ok(v) => v,
            Err(e) => return Err(e.1.get_string_error()),
        };
        Ok(nonce_load_resp.convert_to_32())
    }

    // ****************************SIGN COMMANDS***********************************
    //
    /// This method crafts a `SIGN command` packet
    ///
    /// Method arguments:
    /// -   mode: byte to determine if the command will sign internally generated or externally generated messages.
    ///     -   External messages: values can be 0x80, 0xC0, 0xA0, or 0xD0
    ///     -   Internal messages: values can be 0x00, 0x20, 0x40, or 0x60
    /// -   key_id: slot id in the data zone
    ///
    /// Returns:
    /// -   A heapless Vec containing the serialized command packet bytes.
    pub fn atcab_sign_base(&mut self, mode: u16, key_id: u16) -> Vec<u8, U10> {
        let mut q = packet::ATCAPacket {
            pkt_id: 0x03,
            txsize: 0,
            opcode: 0,
            param1: 0,
            param2: [0; 2],
            req_data: &[],
            crc16: [0; 2],
        };

        let packet: &mut packet::ATCAPacket = q.make_packet(
            Some(constants::SIGN_COUNT),
            Some(constants::ATCA_SIGN),
            Some(mode as u8),
            Some(key_id.to_le_bytes()),
        );

        //  Serialize packet structure to get a Heapless Vec. The Vec's size still needs to
        // be known at compile time.
        let output: Vec<u8, U10> = to_vec(packet).unwrap();
        return output;
    }

    /// This method is used to sign the digest of an external message by an ECC private key. It takes
    ///
    /// Method arguments:
    /// -   The ECC private key in the slot specified by key_id is used to generate the signature.
    /// -   A digest of the message generated by the `host system`. The message can be loaded into either
    ///     the TempKey or Message Digest Buffer via the Nonce command run in fixed mode and is always 32 bytes
    ///     in length. The Sign command generates a signature using the ECDSA algorithm. Note- the digest can also
    ///     be generated via the `SHA command`.
    ///
    /// Returns:
    /// -   a 64-byte response containing the signature - composed of R and S values.
    /// -   or an error string descrbing the error.
    pub fn atcab_sign(
        &mut self,
        key_id: u16,
        digest: &[u8],
    ) -> Result<[u8; (constants::SIGN_RSP_SIZE) as usize], &'static str> {
        let mut nonce_target = constants::NONCE_MODE_TARGET_TEMPKEY;
        let mut sign_source = constants::SIGN_MODE_SOURCE_TEMPKEY;

        if self.device == Variant::ATECC608A {
            nonce_target = constants::NONCE_MODE_TARGET_MSGDIGBUF;
            sign_source = constants::SIGN_MODE_SOURCE_MSGDIGBUF;
        }
        // Load digest into device's Message Digest Buffer. nonce_target determines the buffer location for the location.
        self.atcab_nonce_load(nonce_target as u16, digest)
            .expect("ERROR: loading fixed nonce: ");

        let packet =
            self.atcab_sign_base((constants::SIGN_MODE_EXTERNAL | sign_source) as u16, key_id);
        let ext_sign_resp = match self.send_packet(
            packet.deref(),
            ATECC608A_EXECUTION_TIME::ATCA_SIGN(constants::ATCA_SIGN),
        ) {
            Ok(v) => v,
            Err(e) => return Err(e.1.get_string_error()),
        };
        Ok(ext_sign_resp.convert_to_64())
    }

    /// The Sign command in the `Internal Message` mode is used to sign a message that was internally generated. The
    /// command calculates the internal message digest and then signs the digest using the ECDSA sign algorithm with the
    /// private ECC key specified in key_id. Internally generated messages must always reside in TempKey. The value in
    /// TempKey must be generated using either the GenDig or the GenKey command. If TempKey is not valid an error will
    /// occur.
    ///
    /// Method arguments:
    /// -   key_id: The ECC private key in the slot specified by key_id is used to generate the signature.
    /// -   is_invalidate: if the resulting signature is intended to be used by Verify(Validate or Invalidate)
    ///     i.e. `mode-bit6` is zero if its verify(validate) and 1 if its verify(invalidate)
    /// -   is_full_sn: if the Serial number is to be included in the message digest calculation.
    ///
    /// Returns:
    /// -   a 64-byte response containing the signature - composed of R and S values.
    /// -   or an error string describing the error.    
    ///
    /// Typical uses include:
    /// -   Signing an internally generated random key. This is typically generated by the GenKey command.
    /// -   The output of a GenKey or GenDig commands, provided the output is located in TempKey.
    pub fn atcab_sign_internal(
        &mut self,
        key_id: u16,
        is_invalidate: bool,
        is_full_sn: bool,
    ) -> Result<[u8; (constants::SIGN_RSP_SIZE) as usize], &'static str> {
        let mut mode = constants::SIGN_MODE_INTERNAL;
        if is_invalidate {
            mode = mode | constants::SIGN_MODE_INVALIDATE;
        }
        if is_full_sn {
            // Serial number is included in the message digest calculation
            mode = mode | constants::SIGN_MODE_INCLUDE_SN;
        }

        let packet = self.atcab_sign_base(mode as u16, key_id);
        let int_sign_resp = match self.send_packet(
            packet.deref(),
            ATECC608A_EXECUTION_TIME::ATCA_SIGN(constants::ATCA_SIGN),
        ) {
            Ok(v) => v,
            Err(e) => return Err(e.1.get_string_error()),
        };
        Ok(int_sign_resp.convert_to_64())
    }

    // ***************VERIFY COMMANDS************************

    /// The Verify command takes an ECDSA [R,S] signature and verifies that it is correctly generated given an input
    /// message digest and public key. In all cases, the signature is an input to the command.
    ///
    /// This method crafts a `VERIFY command` packet. The Verify command can operate in four different modes:
    /// -   **External Mode:** The public key to be used is an input to the command. Prior to this command being run, the
    ///     message should be written to TempKey using the Nonce command. In this mode the device merely
    ///     accelerates the public key computation and returns a boolean result.
    ///     -   key_id is (always) 0x0004 for the `external mode`
    /// -   **Stored Mode:** The public key to be used is found in the key_id EEPROM slot. The message should have been
    ///     previously stored in TempKey. `All required configuration checks for the public key at key_id must
    ///     succeed`. Post which, the public key verification computation is performed and a boolean result is returned to
    ///     the system; otherwise, the command returns an execution error.
    ///     -   key_id is the slotID for the `stored mode`
    /// -   **Validate and Invalidate Modes:** The Verify command can be used to validate or invalidate a public key. Only those public keys whose access
    ///     policies require validation need to go through this process. Prior to a public key being used to verify a signature, it
    ///     must be validated. If a validated public key needs to be updated, then it needs to be invalidated prior to being written.
    ///     `Only internally stored public keys can be validated or invalidated`. The status of a public key is stored in the most
    ///     significant nibble of byte 0 of the public key slot.
    /// -   **ValidateExternal Mode:** The ValidateExternal mode is used to validate the public key stored in the EEPROM at key_id when
    ///     `X.509 format certificates` are to be used.
    ///
    /// An optional MAC can be returned from the Verify command to defeat any man-in-the-middle attacks.    
    ///
    /// Method arguments:
    /// -   mode: see above for the different modes.  
    /// -   key_id: slot id in data zone
    /// -   signature: 64 byte signature to be verified
    /// -   public_key: 64 byte signature to be used to verify the signature in external mode.
    /// -   other_data: 19 bytes of other data required when validating or invalidating a public key.
    /// -   mac: A 32-byte MAC, if specified by the mode (only required in stored mode)
    ///
    /// Returns:
    /// -   A heapless Vec containing the serialized command packet bytes.

    pub fn atcab_verify(
        &mut self,
        mode: u16,
        key_id: u16,
        signature: &[u8],
        public_key: &[u8],
        other_data: &[u8],
        _mac: &[u8],
    ) -> Vec<u8, U151> {
        let verify_mode = mode & constants::VERIFY_MODE_MASK as u16;

        let verify_mode_external = constants::VERIFY_MODE_EXTERNAL;
        if (verify_mode == verify_mode_external as u16) && (public_key == &[]) {
            defmt::error!("Invalid `public key` provided: ")
        }

        let verify_mode_validate = constants::VERIFY_MODE_VALIDATE;
        let verify_mode_invalidate = constants::VERIFY_MODE_INVALIDATE;
        if ((verify_mode == verify_mode_validate as u16)
            || (verify_mode == verify_mode_invalidate as u16))
            && (other_data == &[])
        {
            defmt::error!("Invalid number of bytes provided for `validate or invalidate command` on chosen `public key` slot: 
                     Please provide the same `19 bytes` that were used when calculating the original signature")
        }

        let mut txsize = 0;
        if verify_mode == constants::VERIFY_MODE_STORED as u16 {
            txsize = constants::VERIFY_256_STORED_COUNT;
        } else if verify_mode == constants::VERIFY_MODE_VALIDATE_EXTERNAL as u16
            || verify_mode == constants::VERIFY_MODE_EXTERNAL as u16
        {
            txsize = constants::VERIFY_256_EXTERNAL_COUNT;
        } else if verify_mode == constants::VERIFY_MODE_VALIDATE as u16
            || verify_mode == constants::VERIFY_MODE_INVALIDATE as u16
        {
            txsize = constants::VERIFY_256_VALIDATE_COUNT;
        }

        let mut max_cmd_size = [0; constants::ATCA_CMD_SIZE_MAX as usize];
        let data_payload: &[u8];

        if !(public_key == &[]) {
            for (idx, val) in signature.iter().chain(public_key.iter()).enumerate() {
                max_cmd_size[idx] = *val;
            }
            data_payload =
                &max_cmd_size[..(constants::ATCA_SIG_SIZE + constants::ATCA_PUB_KEY_SIZE) as usize]
        } else if !(other_data == &[]) {
            for (idx, val) in signature.iter().chain(other_data.iter()).enumerate() {
                max_cmd_size[idx] = *val;
            }
            data_payload = &max_cmd_size
                [..(constants::ATCA_SIG_SIZE + constants::VERIFY_OTHER_DATA_SIZE) as usize]
        } else {
            for (idx, val) in signature.iter().enumerate() {
                max_cmd_size[idx] = *val;
            }
            data_payload = &max_cmd_size[..constants::ATCA_SIG_SIZE as usize];
        }

        let mut q = packet::ATCAPacket_w_data {
            pkt_id: 0x03,
            txsize: 0,
            opcode: 0,
            param1: 0,
            param2: [0; 2],
            req_data: data_payload,
            crc16: [0; 2],
        };

        let packet: &mut packet::ATCAPacket_w_data = q.make_packet(
            Some(txsize),
            Some(constants::ATCA_VERIFY),
            Some(mode as u8),
            Some(key_id.to_le_bytes()),
        );

        //  Serialize packet structure to get a Heapless Vec. The Vec's size still needs to
        // be known at compile time.
        let output: Vec<u8, U151> = to_vec(packet).unwrap();
        return output;
    }

    /// The Verify command may be used to verify a message generated externally to the device with a
    /// public key that is passed to the command. The output of the command will either be a code indicating success, failure
    /// or error or a 32-byte MAC. Prior to this command being run, the message should be written using the Nonce
    /// command in Fixed mode to either TempKey or the Message Digest Buffer. In this mode, the device merely
    /// accelerates the public key computation and returns a boolean result.
    ///
    /// Method arguments:
    /// -   message: message to be signed. This is a sha256 digest of the message as a slice of bytes
    /// -   signature: the 64 byte signature to be verified as a slice of bytes
    /// -   pub_key: the 64 byte public key used to verify the signature as a slice of bytes.
    ///
    /// Returns:
    /// -   a 3 byte array if the signature is verified
    /// -   if the signature does not match or if there is a failure due to some other reason, an error string describing the
    ///     error.  
    pub fn atcab_verify_extern(
        &mut self,
        message: &[u8],
        signature: &[u8],
        pub_key: &[u8],
    ) -> Result<[u8; (constants::VERIFY_RSP_SIZE - 1) as usize], &'static str> {
        let mut nonce_target = constants::NONCE_MODE_TARGET_TEMPKEY;
        let mut verify_source = constants::VERIFY_MODE_SOURCE_TEMPKEY;

        if self.device == Variant::ATECC608A {
            nonce_target = constants::NONCE_MODE_TARGET_MSGDIGBUF; // target for nonce_load
            verify_source = constants::VERIFY_MODE_SOURCE_MSGDIGBUF; // source for verify
        }
        // Load digest into device's Message Digest Buffer. `nonce_target` setting determines the buffer location.
        self.atcab_nonce_load(nonce_target as u16, message)
            .expect("ERROR: loading fixed nonce: ");

        let packet = self.atcab_verify(
            (constants::VERIFY_MODE_EXTERNAL | verify_source) as u16,
            constants::VERIFY_KEY_P256 as u16,
            signature,
            pub_key,
            &[],
            &[],
        );

        let ext_verify_resp = match self.send_packet(
            packet.deref(),
            ATECC608A_EXECUTION_TIME::ATCA_VERIFY(constants::ATCA_VERIFY),
        ) {
            Ok(v) => v,
            Err(e) => return Err(e.1.get_string_error()),
        };
        Ok(ext_verify_resp.convert_to_3())
    }

    /// When using the Verify command in Stored mode, the public key to be used is stored in a data slot and does not
    /// need to be passed. Prior to this command being run, the message should be written to TempKey or the Message
    /// Digest Buffer using the Nonce command.
    ///
    /// Method arguments:
    /// -   message: message to be signed. This is a sha256 digest of the message as a slice of bytes
    /// -   signature: the 64 byte signature to be verified as a slice of bytes
    ///  
    /// Returns:
    /// -   a 3 byte array if the signature is verified
    /// -   if the signature does not match or if there is a failure due to some other reason, an error string describing the
    ///     error.  
    pub fn atcab_verify_stored(
        &mut self,
        message: &[u8],
        signature: &[u8],
        key_id: u16,
    ) -> Result<[u8; (constants::VERIFY_RSP_SIZE - 1) as usize], &'static str> {
        let mut nonce_target = constants::NONCE_MODE_TARGET_TEMPKEY;
        let mut verify_source = constants::VERIFY_MODE_SOURCE_TEMPKEY;

        if self.device == Variant::ATECC608A {
            nonce_target = constants::NONCE_MODE_TARGET_MSGDIGBUF;
            verify_source = constants::VERIFY_MODE_SOURCE_MSGDIGBUF;
        }
        // Load digest into device's Message Digest Buffer. `nonce_target` setting determines the buffer location.
        self.atcab_nonce_load(nonce_target as u16, message)
            .expect("ERROR: loading fixed nonce: ");

        let packet = self.atcab_verify(
            (constants::VERIFY_MODE_STORED | verify_source) as u16,
            key_id,
            signature,
            &[],
            &[],
            &[],
        );
        let ext_verify_resp = match self.send_packet(
            packet.deref(),
            ATECC608A_EXECUTION_TIME::ATCA_VERIFY(constants::ATCA_VERIFY),
        ) {
            Ok(v) => v,
            Err(e) => return Err(e.1.get_string_error()),
        };
        Ok(ext_verify_resp.convert_to_3())
    }

    // ***************LOCK COMMANDS**************************

    /// This method crafts a 'LOCK command' packet.
    ///
    /// Method arguments:
    /// -   mode: byte to indicate which zone is to be locked (0x00 - for config, 0x01 - for data and OTP )
    /// -   crc: a 2 byte checksum (optional)
    ///
    /// Returns:
    /// -   A heapless Vec containing the serialized command packet bytes.  
    pub fn atcab_lock(&mut self, mode: u8, crc: [u8; 2]) -> Vec<u8, U10> {
        let mut q = packet::ATCAPacket {
            pkt_id: 0x03,
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
        return output;
    }

    /// This method uses the Lock command to prevent future modification of the Configuration zone.
    ///
    /// The Lock command fails if the designated area is already locked.
    /// Upon successful execution, the device returns a value of zero.
    ///
    /// Method arguments:
    /// -   None
    ///
    /// Returns:
    /// -   a 3 byte array with byte[0] =0x00, indicating success
    /// -   or an error string, describing the error.
    pub fn atcab_lock_config_zone(
        &mut self,
    ) -> Result<[u8; (constants::LOCK_RSP_SIZE - 1) as usize], &'static str> {
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
        Ok(lock_resp.convert_to_3())
    }

    /// Prior to locking the configuration zone, the device can optionally use the
    /// CRC-16 algorithm to verify the contents of the designated zone(s).
    /// The CRC is calculated over all 128 bytes within the Configuration zone using the current value of
    /// LockConfig at address 87.
    /// If the compare succeeds, then LockConfig will be set to a value of 00.
    ///
    /// The calculation uses the same algorithm as the CRC computed over the input and output groups.
    /// The value of the 7th bit of the 'mode parameter' (called summary check bit) is important.
    ///
    /// - 0 = The summary value is verified before the zone is locked.
    /// - 1 = Check of the zone summary is ignored and the zone is locked regardless of the contents of the zone.
    ///
    /// Method argument:
    /// -   crc: a 2 byte checksum (see above for more info)
    ///
    /// Returns:
    /// -   a 3 byte array with byte[0] =0x00, indicating success
    /// -   or an error string, describing the error.   
    pub fn atcab_lock_config_zone_crc(
        &mut self,
        crc: [u8; 2],
    ) -> Result<[u8; (constants::LOCK_RSP_SIZE - 1) as usize], &'static str> {
        let packet = self.atcab_lock(constants::LOCK_ZONE_CONFIG, crc);
        let lock_resp = match self.send_packet(
            packet.deref(),
            ATECC608A_EXECUTION_TIME::ATCA_LOCK(constants::ATCA_LOCK),
        ) {
            Ok(v) => v,
            Err(e) => return Err(e.1.get_string_error()),
        };
        Ok(lock_resp.convert_to_3())
    }

    /// A method to calculate a 2 byte checksum value. The input to this method is a slice of u8s   
    /// along with its length.
    pub fn crc(&self, src: &[u8], length: usize) -> [u8; 2] {
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

    // ***********************READ COMMANDS**************************

    /// This method crafts and sends a 'READ command' packet to the device. Upon successful
    /// execution of the command, it returns 32 (or 4) bytes. If the command fails,
    /// it returns the error in a `StatusError` struct.
    ///
    /// Method arguments:
    /// -   zone: memory zone of EEPROM to read from
    /// -   slot: if data zone, ID of slot to read from
    /// -   block: each memory is divided in blocks of 32 bytes. This param indicate which block in a given zone
    /// -   offset: is a 4 byte or 1 word offset into a block.
    /// -   length: lenght of size of data to read
    ///
    /// Returns:
    /// -   an max size array of 151 bytes containing `read response`
    /// -   or an error string describing the error
    pub fn atcab_read_zone(
        &mut self,
        mut zone: u16,
        slot: u16,
        block: u16,
        offset: u16,
        length: u16,
    ) -> Result<[u8; (constants::ATCA_CMD_SIZE_MAX) as usize], constants::StatusError> {
        if length == constants::ATCA_WORD_SIZE as u16 || length == constants::ATCA_BLOCK_SIZE as u16
        {
        } else {
            defmt::error!("ERROR: reading memory zone, only 4 or 32 byte reads are allowed");
        }

        let addr = self.atcab_get_addr(zone, slot, block, offset);

        if length == constants::ATCA_BLOCK_SIZE as u16 {
            zone = zone | constants::ATCA_ZONE_READWRITE_32 as u16; // mode parameter for the read command
        } // the 7th bit needs to be '1' for 32 byte reads.

        let mut q = packet::ATCAPacket {
            pkt_id: 0x03,
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
        let read_resp = match self.send_packet(
            output.deref(),
            ATECC608A_EXECUTION_TIME::ATCA_READ(constants::ATCA_READ),
        ) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        return Ok(read_resp);
    }

    /// This method reads words (one four byte word or an 8-word block of 32 bytes) from one of the memory zones of the device.
    /// Returns an array of 4 max-cmd-bytes arrays.
    ///
    /// Method arguments:
    /// -   zone: memory zone of EEPROM to read from
    /// -   slot: if data zone, ID of slot to read from
    /// -   block: each memory is divided in blocks of 32 bytes. This param indicate which block in a given zone
    /// -   offset: is a 4 byte or 1 word offset into a block.
    /// -   length: lenght of size of data to read
    ///
    /// Returns:
    /// -   an array of 4 max-cmd-bytes arrays containing the full `read response`
    /// -   or an error string describing the error
    pub fn atcab_read_bytes_zone(
        &mut self,
        zone: u16,
        slot: u16,
        _block: u16,
        offset: u16, // If you want start reading from an offset within a given memory zone
        length: u16, // the number of bytes to be retrieved.
    ) -> Result<[[u8; 151]; 4], &'static str> {
        let zone_size = self.atcab_get_zone_size(zone, slot);

        if (offset + length) as u16 > zone_size {
            defmt::error!("ERROR: number of bytes to read from offset > zone size");
        }

        let bs = constants::ATCA_BLOCK_SIZE as u16;
        let ws = constants::ATCA_WORD_SIZE as u16;
        let mut config_zone = [[0; 151]; 4];

        let mut read_size = bs;
        let mut d_idx = 0;
        let mut i = 0;
        let mut read_index;
        let mut read_offset;
        let mut block_count;
        let mut word_count = 0;
        block_count = offset / bs;
        while d_idx < length {
            // check to see if we're reading contents of the last block. If yes, reset read-size and word_count.
            if (read_size == bs) && (zone_size - (block_count * bs) as u16) < bs as u16 {
                read_size = ws;
                word_count = ((d_idx + offset) / ws) % (bs / ws);
            }
            // craft a 32 or 4 byte read command packet, send it and store the response from the device
            // in an array of arrays buffer.
            let packet = self.atcab_read_zone(zone, slot, block_count, word_count, read_size);
            let read_resp = match packet {
                Ok(v) => v,
                Err(e) => return Err(e.1.get_string_error()),
            };

            config_zone[i] = read_resp;
            i += 1;

            // read_offset is an offset into the memory zone from which we wish to retrieve data.
            // Ex: say you supply an offset of 100 (into the config zone), read_offset evaluates to 96 (i.e. a multiple of 4 or 32)
            // read_index is the difference between user supplied offset and read_offset
            read_offset = block_count * bs + word_count * ws;
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

            if read_size == bs {
                block_count += 1
            } else {
                word_count += 1
            }
        }
        return Ok(config_zone);
    }

    /// Method arguments:
    /// -   Zone ID (0x00 - Config zone or 0x01 - Data Zone) (to check to see if the zone is locked.)
    ///
    /// Returns
    /// -   a bool indicating `True` if the zone is locked.
    pub fn atcab_is_locked(&mut self, zone: u16) -> bool {
        if zone == constants::LOCK_ZONE_CONFIG as u16 || zone == constants::LOCK_ZONE_DATA as u16 {
        } else {
            defmt::error!("'isLocked' check failed. Not a valid zone ID: ");
        }

        let resp = match self.atcab_read_zone(
            constants::ATCA_ZONE_CONFIG as u16,
            0x00, // Config zone ID
            0x02, // Block ID
            0x05, // word offset
            constants::ATCA_WORD_SIZE as u16,
        ) {
            Ok(v) => v,
            Err(e) => panic!("ERROR: reading lock bytes [84] or [85]: {:?}", e),
        };
        if zone == constants::LOCK_ZONE_CONFIG as u16 && resp[3] != 0x55 {
            return true;
        } else if zone == constants::LOCK_ZONE_DATA as u16 && resp[2] != 0x55 {
            return true;
        } else {
            return false;
        }
    }

    /// Dumps the contents of Config zone. Zone of 128 bytes (1,024-bit) EEPROM that contains the serial
    /// number and other ID information, as well as, access policy information for each slot of the data memory.
    ///
    /// The values programmed into the configuration zone will determine the access policy of how each data slot will respond.
    /// The configuration zone can be modified until it has been locked (LockConfig set to !=0x55).
    ///
    /// In order to enable the access policies, the LockValue byte must be set.
    ///
    /// Method arguments:
    /// -   None
    ///
    /// Returns
    /// -   An array containing 128 bytes i.e. contents of config zone
    /// -   or an error string describing the error.
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
            .chain(slice_4.iter())
            .enumerate()
        {
            config_dump[idx] = *val;
        }
        return Ok(config_dump);
    }

    /// Address of first word to be read/written within the zone.
    /// The Read and Write commands include a single 16 bit address in Param2,
    /// which indicates the memory location to be accessed.
    /// In all cases, data is accessed on 4 byte word boundaries.
    /// Address Encoding for Config and OTP Zones (Param2).
    ///
    /// Byte 1 is unused and Byte 0 is used as follows
    ///
    /// ===========Byte 0 info ===========
    ///
    /// - Unused - Bits 7-5 (drop the 3 most significant bits by left shifting)
    /// - Block  - Bits 4-3 (the config zone has 4 blocks in total 0-3 and is 128 bytes in length)
    /// - Offset - Bits 2-0 (offset into the block)
    ///
    /// Method arguments:
    /// -   zone: is the zone_id - config zone 0x00, data zone 0x02, OTP zone 0x01
    /// -   slot: is the slot_id - can be of 16 slots
    /// -   block: each zone's memory is divided in blocks of 32 bytes. `block` is the index of a block for a given zone
    /// -   offset: is the 4-byte (or word) offset into a block
    ///
    /// Returns:
    /// -   u16: Address of first word to be read/written within the zone  
    pub fn atcab_get_addr(&mut self, zone: u16, slot: u16, block: u16, offset: u16) -> u16 {
        let mem_zone = zone & constants::ATCA_ZONE_MASK as u16;
        if mem_zone == constants::ATCA_ZONE_CONFIG as u16
            || mem_zone == constants::ATCA_ZONE_DATA as u16
            || mem_zone == constants::ATCA_ZONE_OTP as u16
        {
        } else {
            defmt::error!("ERROR: retrieving memory address");
        }

        if slot > 15 {
            defmt::error!("ERROR: slot ID out of range")
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

    /// Method arguments:
    /// -   zone: is the zone_id - config zone 0x00, data zone 0x02, OTP zone 0x01   
    /// -   slot: is the slot_id - can be of 16 slots
    ///
    /// Returns:
    /// -   u16: Size of the zone
    pub fn atcab_get_zone_size(&mut self, zone: u16, slot: u16) -> u16 {
        if zone == constants::ATCA_ZONE_CONFIG as u16
            || zone == constants::ATCA_ZONE_DATA as u16
            || zone == constants::ATCA_ZONE_OTP as u16
        {
        } else {
            defmt::error!("ERROR: retrieving zone size");
        }

        if slot > 15 {
            defmt::error!("ERROR: Slot ID out of range")
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

    /// The Write command writes either one 4 byte word or an 8-word block of 32 bytes to one of the
    /// EEPROM zones on the device.
    /// -   **Configuration Zone:** If the configuration zone is locked or Zone<bit6> is set, then this command
    ///     returns an error; otherwise the bytes are written as requested
    /// -   **OTP Zone:** If the OTP zone is unlocked, then all bytes can be written with this command.
    /// -   **Data Zone:** If the data zone is unlocked, then all bytes in all zones can be written with either plain
    ///     text or encrypted data
    ///
    /// **Notes**
    /// -   Prior to EEPROM locking of config zone, all bytes (except the first 16 and bytes [84..87]) in the config zone are
    ///     writable. Data and OTP zones cannot be read or written to
    /// -   After locking the config zone, data and OTP zone are writable, depending on the configuration of slot access
    ///     policies. However, policies are not strictly enforced while in this state i.e. some commands like 'write or genkey'
    ///     will still work even though a slot is configured to be (permanently) not writable.  
    /// -   After locking the data zones byte [86]. All access policies for each slot are strictly enforced.
    ///
    /// `Locking is an irreversible operation.`
    ///
    /// Method arguments:
    /// -   addr: Address of first word to be written within the zone.
    /// -   data: Information to be written to the zone. May be encrypted.
    /// -   mac: Message authentication code to validate address and data.(only if data is encrypted)
    ///
    /// Returns:
    /// -   an 3-byte success array, where index [0] == 0x00 indicating a successful write or
    /// -   an error string describing the error.
    pub fn atcab_write(
        &mut self,
        zone: u16,
        address: u16,
        data: &[u8],
        mac: &[u8; 32],
    ) -> Result<[u8; (constants::WRITE_RSP_SIZE - 1) as usize], &'static str> {
        let mut txsize = constants::ATCA_CMD_SIZE_MIN;
        let mut data_buffer = [0; 64];
        let payload;

        // The device accepts either a 32 byte (+ mac if inlcuded) or a 4 byte write.
        if (zone & constants::ATCA_ZONE_READWRITE_32 as u16) != 0 {
            // and only 32 byte writes may use a valid MAC
            if mac != &[0; 32] {
                // chain data and mac slices to create a single 64 byte array.
                // idx is index and each `val` is a reference to data or mac values.
                for (idx, val) in data.iter().chain(mac.iter()).enumerate() {
                    data_buffer[idx] = *val;
                }
                payload = &data_buffer[..]; // Its a 64 byte write including the MAC
                txsize += constants::ATCA_BLOCK_SIZE;
                txsize += constants::WRITE_MAC_SIZE;
            } else {
                for (idx, val) in data.iter().enumerate() {
                    data_buffer[idx] = *val
                }
                payload = &data_buffer[..32]; // Its a 32 byte write
                txsize += constants::ATCA_BLOCK_SIZE;
            }
        } else {
            for (idx, val) in data.iter().enumerate() {
                data_buffer[idx] = *val
            }
            payload = &data_buffer[..4]; // Its a 4 byte write.
            txsize += constants::ATCA_WORD_SIZE;
        }

        let mut q = packet::ATCAPacket_w_data {
            pkt_id: 0x03,
            txsize: 0,
            opcode: 0,
            param1: 0,
            param2: [0; 2],
            req_data: payload,
            crc16: [0; 2],
        };

        q.txsize = txsize;
        let packet: &mut packet::ATCAPacket_w_data = q.make_packet(
            Some(q.txsize),
            Some(constants::ATCA_WRITE),
            Some(zone as u8),
            Some(address.to_le_bytes()),
        );
        let output: Vec<u8, U74> = to_vec(packet).unwrap();

        let write_resp = match self.send_packet(
            output.deref(),
            ATECC608A_EXECUTION_TIME::ATCA_WRITE(constants::ATCA_WRITE),
        ) {
            Ok(v) => v,
            Err(e) => return Err(e.1.get_string_error()),
        };
        Ok(write_resp.convert_to_3())
    }

    ///
    pub fn atcab_write_zone(
        &mut self,
        mut zone: u16,
        slot: u16,
        block: u16,
        offset: u16,
        data: &[u8],
    ) -> Result<[u8; (constants::WRITE_RSP_SIZE - 1) as usize], &'static str> {
        let length = data.len();
        if (length == constants::ATCA_WORD_SIZE as usize)
            || (length == constants::ATCA_BLOCK_SIZE as usize)
        {
        } else {
            defmt::error!("ERROR: Not 4 byte or a 32 byte write");
        }

        if length == constants::ATCA_BLOCK_SIZE as usize {
            zone = zone | constants::ATCA_ZONE_READWRITE_32 as u16; // mode parameter for the write command
        } // the 7th bit needs to be '1' for 32 byte reads.
        let mac = [0; 32];

        let addr = self.atcab_get_addr(zone, slot, block, offset);
        let resp = match self.atcab_write(zone, addr, data, &mac) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        Ok(resp)
    }

    /// This method takes the following arguments
    /// Method arguments:
    /// -   zone_id: Config zone - 0x00, Data zone - 0x02, OTP zone- 0x01.
    /// -   slotID: If zone is 0x02, then slot can be one of 16 slots.
    /// -   offset: is an integer offset into a zone.
    /// -   data: Information to be written to the zone. May be encrypted.
    ///
    /// Returns
    /// -   a heapless Vec of status_packets i.e. each element is a 3 byte array.
    pub fn atcab_write_bytes_zone(
        &mut self,
        zone: u16,
        slot: u16,
        offset: u16,
        data: &[u8],
    ) -> Vec<[u8; 3], U20> {
        let zone_size = self.atcab_get_zone_size(zone, slot);

        let length = data.len();
        if offset + length as u16 > zone_size {
            defmt::error!("ERROR: number of bytes to write from offset > zone size");
        }

        let bs = constants::ATCA_BLOCK_SIZE as u16;
        let ws = constants::ATCA_WORD_SIZE as u16;
        let zc = constants::ATCA_ZONE_CONFIG as u16;

        // A heapless Vec to hold responses received for each write.
        //
        // Note: Size of the heapless Vec `status_packets` may need to be incremented,
        // if you require more than 8 (32 or 4 byte) writes.
        let mut status_packets: Vec<[u8; 3], U20> = Vec::new();
        let mut d_idx = 0;
        // let mut i = 0;
        let mut block_count = offset / bs; // block count into a given zone
        let mut word_count = (offset % bs) / ws; // word count into a given block (i.e. 4 bytes == 1 offset)

        while d_idx < length {
            if word_count == 0
                && (length - d_idx >= bs as usize)
                && !(zone == zc && block_count == 2)
            {
                let resp = self
                    .atcab_write_zone(
                        zone,
                        slot,
                        block_count,
                        0x00,
                        &data[d_idx..d_idx + (bs as usize)],
                    )
                    .expect("32-byte write error: ");

                status_packets.push(resp).expect(
                    "too many writes: {heapless vec is full}, hint: increment len(heapless vec)",
                );
                d_idx += bs as usize;
                block_count += 1;
            } else {
                // UserExtra, UserExtraAdd, LockValue and LockConfig require the `UpdateExtra & Lock commands`
                // to be modified i.e. cannot be modified by write command. So, skip it.
                if !(zone == zc && block_count == 2 && word_count == 5) {
                    let resp = self
                        .atcab_write_zone(
                            zone,
                            slot,
                            block_count,
                            word_count,
                            &data[d_idx..d_idx + (ws as usize)],
                        )
                        .expect("4-byte write error: ");
                    status_packets.push(resp)
                                  .expect("too many writes: {heapless vec is full}, hint: increment len(heapless vec)");
                }

                d_idx += ws as usize;
                word_count += 1;
                if word_count == bs / ws {
                    // when we hit a new block
                    block_count += 1; // increment block_count
                    word_count = 0; // and reset word_count to zero.
                }
            }
        }
        // hprintln!("status_packets : {:?}", status_packets).unwrap();
        return status_packets;
    }

    /// Not implemented
    pub fn atcab_write_pubkey() {}

    /// This method takes a slice of 128 bytes, writes bytes[16-128] to the config zone
    /// and an returns array containing `15` 3-byte responses. Details of 15 writes are as follows
    ///
    /// -   `4` 4-byte writes followed
    /// -   `1` 1 32-byte write
    /// -   `7` 4-byte writes (i.e. skip block 2, word_count == 5)
    /// -   `1` 1 32-byte write
    /// -   `2` updateextra cmds for config bytes [84] and [85]
    ///
    ///  Details of 3-byte response are as follows
    ///
    /// -   Byte 1      => 00 means success, anything else is an error.
    /// -   Byte 2-3    => checksum of 4 bytes i.e. CRC((length byte == 4) + byte 1). For a successful
    ///                  write, this is always == [0x03, 0x40]
    pub fn atcab_write_config_zone(&mut self, config_data: &[u8]) -> [[u8; 3]; 15] {
        let config_size = self.atcab_get_zone_size(constants::ATCA_ZONE_CONFIG as u16, 0);
        let mut write_config_resp = [[0; 3]; 15];
        //Write config zone excluding UserExtra and UserExtraAdd
        let mut status_packets = self.atcab_write_bytes_zone(
            constants::ATCA_ZONE_CONFIG as u16,
            0x00,
            16,
            &config_data[16..config_size as usize],
        );

        // Write the UserExtra and UserExtraAdd. This may fail if either value is already non-zero.
        let user_extra_packet = self.atcab_updateextra(
            constants::UPDATE_MODE_USER_EXTRA as u16,
            config_data[84] as u16,
        );
        status_packets
            .push(user_extra_packet.expect("ERROR: failed to write to UserExtra field: "))
            .expect("too many writes: {heapless vec is full}, hint: increment len(heapless vec)");
        let user_extra_add_packet = self.atcab_updateextra(
            constants::UPDATE_MODE_USER_EXTRA as u16,
            config_data[85] as u16,
        );
        status_packets
            .push(user_extra_add_packet.expect("ERROR: failed to write to UserExtra field: "))
            .expect("too many writes: {heapless vec is full}, hint: increment len(heapless vec)");

        for (idx, val) in (status_packets.deref()).iter().enumerate() {
            write_config_resp[idx] = *val
        }
        // hprintln!("write_config_resp : {:?}", write_config_resp).unwrap();
        return write_config_resp;
    }

    /// Not implemented
    pub fn atcab_write_enc() {}

    /// Not implemented
    pub fn atcab_write_config_counter() {}

    /// The UpdateExtra command is used to update the UpdateExtra and UpdateExtraAdd bytes, bytes 84 and 85
    /// respectively in the Configuration zone. These bytes can only be updated by this command. These bytes are one-time
    /// updatable bytes and can only be updated if the current value is 0x00. Trying to update this byte if the value is not
    /// 0x00 will result in an error.
    ///
    /// Method arguments:   
    /// -   mode: 0x00 to update byte [84] or 0x01 to update byte [85]
    /// -   value: LSB of 2-byte value to write contains the byte to write  
    ///
    /// Returns
    /// -   a 3-byte response.
    ///     -   Byte 1      => 00 means success, anything else is an error.
    ///     -   Byte 2-3    => checksum of 4 bytes i.e. CRC((length byte == 4) + byte 1). For a successful
    ///                  write, this is always == [0x03, 0x40]
    /// -   or an error string describing the error.
    pub fn atcab_updateextra(
        &mut self,
        mode: u16,
        value: u16,
    ) -> Result<[u8; (constants::UPDATE_RSP_SIZE - 1) as usize], &'static str> {
        let mut q = packet::ATCAPacket {
            pkt_id: 0x03,
            txsize: 0,
            opcode: 0,
            param1: 0,
            param2: [0; 2],
            req_data: &[],
            crc16: [0; 2],
        };

        let packet: &mut packet::ATCAPacket = q.make_packet(
            None,
            Some(constants::ATCA_UPDATE_EXTRA),
            Some(mode as u8),
            Some(value.to_le_bytes()),
        );
        //  Serialize packet structure to get a Heapless Vec.
        let output: Vec<u8, U10> = to_vec(packet).unwrap();

        let update_extra_rsp = match self.send_packet(
            output.deref(),
            ATECC608A_EXECUTION_TIME::ATCA_UPDATE_EXTRA(constants::ATCA_UPDATE_EXTRA),
        ) {
            Ok(v) => v,
            Err(e) => return Err(e.1.get_string_error()),
        };
        Ok(update_extra_rsp.convert_to_3())
    }
}
