A platform agnostic I2C driver for Microchip's crypto-authentication device i.e. ATECC608a, written entirely in Rust. This library implements APIs required to communicate with Microchip Security device - ATECC608a.

![NRF52840 communicating with a ATECC608a](https://github.com/nihalpasham/Rusty_CryptoAuthLib/blob/master/i2c_logic_captures/atecc608a_w_nrf52840.jpg "Maker Diary's NRF52840-mdk communicating with a ATECC608a")

The ATECC608A device is a member of the Microchip CryptoAuthentication™ family of crypto engine
authentication devices with highly secure hardware-based key storage.

The ATECC608A device has a flexible command set that allows use in many applications, including the
following:
* **Network/IoT Node Protection** - Authenticates node IDs, ensures the integrity of messages, and
supports key agreement to create session keys for message encryption.
* **Anti-Counterfeiting** - Validates that a removable, replaceable, or consumable client is authentic.
Examples of clients could be system accessories, electronic daughter cards, or other spare parts. It
can also be used to validate a software/firmware module or memory storage element.
* **Protecting Firmware or Media** - Validates code stored in flash memory at boot to prevent
unauthorized modifications, encrypt downloaded program files as a common broadcast, or uniquely
encrypt code images to be usable on a single system only.
* **Storing Secure Data** - Stores secret keys for use by crypto accelerators in standard
microprocessors. Programmable protection is available using encrypted/authenticated reads and
writes.
* **Checking User Password** - Validates user-entered passwords without letting the expected value
become known, maps memorable passwords to a random number, and securely exchanges
password values with remote systems.

The device includes an EEPROM array which can be used for storage of up to 16 keys, certificates,
miscellaneous read/write, read-only or secret data, consumption logging, and security configurations.
Access to the various sections of memory can be restricted in a variety of ways and then the
configuration can be locked to prevent changes. Access to the device is made through a standard I2C 
Interface at speeds of up to 1 Mb/s(see Section I2C Interface). The interface is compatible with 
standard Serial EEPROM I2C interface specifications.

The ATECC608A is a command-based device which receives commands from the system, executes
those commands, and then returns a result or error code. Within this document, the following
nomenclature is used to describe the various commands:
* **Security Commands:**
Described in Section Security Commands. This group of commands generally access the EEPROM
space and/or perform cryptographic computation. These commands are indicated with a special
font in this document (e.g. GenDig) and are available from all interfaces.
* **Cryptographic Commands:**
This subset of the security commands includes all the ECC commands which access the hardware
ECC accelerator (GenKey, Sign, ECDH, and Verify) and the SHA commands which access the
hardware SHA accelerator (CheckMac, DeriveKey, GenDig, HMAC, MAC, SHA, and Nonce).

## Features:
1. 100% safe Rust code i.e. no memory-safety bugs in the driver (unless my logic is wrong).
2. Platform agnostic i.e. uses 'embedded-hal' for all HW dependencies.
3. No (heap) dynamic memory allocation required at all.
3. API compatibility with that of Microchip's CrypoAuthlib 'C library' i.e. uses the same names & arguments 
making it easier for to call from an existing C code-base.

## Notes:
1. This driver is a product of my interest in 'learning the language'. So, its not perfect (or production quality) and there may be better ways to do things. Feedback, comments, suggestions are welcome. 
2. Uses 'Postcard' to serizalize or de-serialize a Rust struct to 'heapless Vec' (i.e. stack-based vec for no_std environments)
2. This code has been tested on an nrf board using 'nrf-hal-common'. In theory, it should work with any HAL that implements 'embedded-hal' traits.
3. During development, I discovered a bug in the i2c/TWIM implementation for nrf52840 (in nrf52840_hal). 
4. A PR was raised and the fix was merged-in but just make sure you pull in the fix or edit cargo.toml accordingly to get this driver to work. https://github.com/nrf-rs/nrf-hal/pull/166
5. References used to build the rusty version of this driver. 
    * Libc version of CryptoAuthLib - Microchip's CryptoAuthentication Library (https://github.com/MicrochipTech/cryptoauthlib)
    * Micropython port of cryptoauthlib - https://github.com/dmazzella/ucryptoauthlib
    * ATECC508A Data Sheet - https://bit.ly/2YzqC00

## Usage: 

```Rust
#![no_main]
#![no_std]
// #![allow(warnings)]

extern crate nrf52840_hal as hal;
extern crate panic_halt;
use cortex_m_rt::{entry, exception};

use hal::gpio::{p0, p1, Floating, Input};
use hal::target::Peripherals;
use hal::timer::Timer;
use hal::twim::{self, Twim};
// use cortex_m_semihosting::hprintln;
use Rusty_CryptoAuthLib::ATECC608A;

/// Test Enum
#[derive(Copy, Clone, Debug)]
pub enum TestEnum {
    ShaTestData1,
    ShaTestData2,
}

impl<'a> TestEnum {
    pub fn get_value(self) -> &'a [u8] {
        match self {
            TestEnum::ShaTestData1 => &[0x01, 0x02, 0x03, 0x04, 0x05],
            TestEnum::ShaTestData2 => &[
                0x1f, 0xe6, 0x54, 0xc1, 0x80, 0x88, 0xe7, 0xfe, 0xf0, 0x84, 0xf9, 0x8a, 0x1a, 0x12,
                0xdb, 0x84, 0x69, 0x54, 0x34, 0x25, 0x06, 0xf5, 0x17, 0x69, 0x18, 0x9e, 0x3a, 0x90,
                0x79, 0x2f, 0xd3, 0x28, 0xcf, 0x51, 0x5d, 0x1e, 0x44, 0xbb, 0xa4, 0x9d, 0x34, 0xde,
                0x3b, 0x99, 0xca, 0x4c, 0x5e, 0x7e, 0xf4, 0x3a, 0xf6, 0xda, 0x41, 0x3c, 0x91, 0xc7,
                0x98, 0x70, 0xd4, 0x87, 0x68, 0xac, 0x74, 0x5b, 0x1f, 0xe6, 0x54, 0xc1, 0x80, 0x88,
                0xe7, 0xfe, 0xf0, 0x84, 0xf9, 0x8a, 0x1a, 0x12, 0xdb, 0x84, 0x69, 0x54, 0x34, 0x25,
                0x06, 0xf5, 0x17, 0x69, 0x18, 0x9e, 0x3a, 0x90, 0x79, 0x2f, 0xd3, 0x28,
            ],
        }
    }
}

#[entry]
fn main() -> ! {
    let p = Peripherals::take().unwrap();
    let pins = Pins::new(p0::Parts::new(p.P0), p1::Parts::new(p.P1));
    let scl = pins.p27.into_floating_input().degrade();
    let sda = pins.p26.into_floating_input().degrade();

    let i2c_pins = twim::Pins { scl, sda };

    let i2c = Twim::new(p.TWIM1, i2c_pins, twim::Frequency::K100);
    let delay = Timer::new(p.TIMER0);
    let timer = Timer::new(p.TIMER1);
    let mut atecc608a = ATECC608A::new(i2c, delay, timer).unwrap();

    // INFO COMMAND EXAMPLE
    let _info = match atecc608a.atcab_info() {
        Ok(v) => v,
        Err(e) => panic!("ERROR: {:?}", e),
    };
    // SHA COMMAND EXAMPLE
    let selection = TestEnum::ShaTestData1; // or TestEnum::ShaTestData2
    let sha = match atecc608a.atcab_sha(selection.get_value()) {
        Ok(v) => v,
        Err(e) => panic!("ERROR: {:?}", e),
    };
    match selection {
        TestEnum::ShaTestData1 => assert_eq!(
            [
                0x74, 0xf8, 0x1f, 0xe1, 0x67, 0xd9, 0x9b, 0x4c, 0xb4, 0x1d, 0x6d, 0x0c, 0xcd, 0xa8,
                0x22, 0x78, 0xca, 0xee, 0x9f, 0x3e, 0x2f, 0x25, 0xd5, 0xe5, 0xa3, 0x93, 0x6f, 0xf3,
                0xdc, 0xec, 0x60, 0xd0
            ],
            &sha[..32]
        ),
        TestEnum::ShaTestData2 => assert_eq!(
            [
                0x6e, 0x68, 0x88, 0x97, 0xd4, 0x70, 0xe7, 0x74, 0x27, 0x44, 0xcf, 0x2b, 0xcd, 0xe9,
                0x3c, 0x9b, 0xe6, 0x94, 0xf3, 0x36, 0x34, 0x54, 0x46, 0x48, 0x27, 0x04, 0x19, 0xe7,
                0xce, 0xe3, 0x40, 0xdd
            ],
            &sha[..32]
        ),
    }

    //READ COMMAND EXAMPLE
    let _dump_config_zone = atecc608a.atcab_read_config_zone();

    loop {}
}

#[exception]
fn HardFault(ef: &cortex_m_rt::ExceptionFrame) -> ! {
    panic!("HardFault at {:#?}", ef);
}

#[exception]
fn DefaultHandler(irqn: i16) {
    panic!("Unhandled exception (IRQn = {})", irqn);
}

.......
....... ///edited for brevity's sake. See atecc608a.rs examples for complete code. 

```

## Currently supported commands are:
- INFO
- LOCK
- READ (1)
- SHA (1)
    
## Support to be added for:
- WRITE (1) -
- VERIFY (1)
- GENKEY
- SIGN
- SELFTEST
- RANDOM
- NONCE

(1) Not all features are implemented, see follow list for details

## Currently implemented methods are:

- [ ] atcab_version()
- [x] atcab_get_addr(zone, slot=0, block=0, offset=0)
- [x] atcab_get_zone_size(zone, slot=0)
- [ ] atcab_checkmac(mode, key_id, challenge, response, other_data)
- [ ] atcab_counter(mode, counter_id)
- [ ] atcab_counter_increment(counter_id)
- [ ] atcab_counter_read(counter_id)
- [ ] atcab_derivekey(mode, key_id, mac)
- [ ] atcab_ecdh_base(mode, key_id, public_key)
- [ ] atcab_ecdh(key_id, public_key)
- [ ] atcab_ecdh_enc(key_id, public_key, read_key, read_key_id)
- [ ] atcab_ecdh_ioenc(key_id, public_key, io_key)
- [ ] atcab_ecdh_tempkey(public_key)
- [ ] atcab_ecdh_tempkey_ioenc(public_key, io_key)
- [ ] atcab_gendig(zone, key_id, other_data)
- [ ] atcab_genkey_base(mode, key_id, other_data=None)
- [ ] atcab_genkey(key_id)
- [ ] atcab_get_pubkey(key_id)
- [ ] atcab_hmac(mode, key_id)
- [x] atcab_info_base(mode=0)
- [x] atcab_info()
- [ ] atcab_kdf(mode, key_id, details, message)
- [ ] atcab_lock(mode, crc=0)
- [x] atcab_lock_config_zone()
- [x] atcab_lock_config_zone_crc(crc)
- [ ] atcab_lock_data_zone()
- [ ] atcab_lock_data_zone_crc(crc)
- [ ] atcab_lock_data_slot(slot)
- [ ] atcab_mac(mode, key_id, challenge)
- [ ] atcab_nonce_base(mode, zero=0, numbers=None)
- [ ] atcab_nonce(numbers=None)
- [ ] atcab_nonce_load(target, numbers=None)
- [ ] atcab_nonce_rand(numbers=None)
- [ ] atcab_challenge(numbers=None)
- [ ] atcab_challenge_seed_update(numbers=None)
- [ ] atcab_priv_write(key_id, priv_key, write_key_id, write_key)
- [ ] atcab_random()
- [x] atcab_read_zone(zone, slot=0, block=0, offset=0, length=0)
- [ ] atcab_read_serial_number()
- [x] atcab_read_bytes_zone(zone, slot=0, block=0, offset=0, length=0)
- [ ] atcab_is_slot_locked(slot)
- [ ] atcab_is_locked(zone)
- [x] atcab_read_config_zone()
- [ ] atcab_read_enc(key_id, block, data, enc_key, enc_key_id)
- [ ] atcab_cmp_config_zone(config_data)
- [ ] atcab_read_sig(slot)
- [ ] atcab_read_pubkey(slot)
- [ ] atcab_secureboot(mode, param2, digest, signature)
- [ ] atcab_secureboot_mac(mode, digest, signature, num_in, io_key)
- [ ] atcab_selftest(mode, param2=0)
- [x] atcab_sha_base(mode=0, data=b'', key_slot=None)
- [x] atcab_sha(data)
- [ ] atcab_sha_hmac(data, key_slot, target)
- [ ] atcab_sign_base(mode, key_id)
- [ ] atcab_sign(key_id, message)
- [ ] atcab_sign_internal(key_id, is_invalidate=False, is_full_sn=False)
- [ ] atcab_updateextra(mode, value)
- [ ] atcab_verify(mode, key_id, signature, public_key=None, other_data=None, mac=None)
- [ ] atcab_verify_extern(message, signature, public_key)
- [ ] atcab_verify_extern_mac(message, signature, public_key, num_in, io_key, is_verified)
- [ ] atcab_verify_stored(message, signature, key_id)
- [ ] atcab_verify_stored_mac(message, signature, key_id, num_in, io_key, is_verified)
- [ ] atcab_verify_validate( key_id, signature, other_data, is_verified)
- [ ] atcab_verify_invalidate( key_id, signature, other_data, is_verified)
- [ ] atcab_write(zone, address, value=None, mac=None)
- [ ] atcab_write_zone(zone, slot=0, block=0, offset=0, data=None)
- [ ] atcab_write_bytes_zone(zone, slot=0, offset=0, data=None)
- [ ] atcab_write_pubkey(slot, public_key)
- [ ] atcab_write_config_zone(config_data)
- [ ] atcab_write_enc(key_id, block, data, enc_key, enc_key_id)
- [ ] atcab_write_config_counter(counter_id, counter_value)

## Support:
For questions, issues, feature requests, and other changes, please file an issue in the github project.

## License:
Licensed under either of

* Apache License, Version 2.0 (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

at your option.

## Contributing:
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
