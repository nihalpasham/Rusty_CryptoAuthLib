A platform agnostic I2C driver for Microchip's crypto-authentication device i.e. ATECC608a, written entirely in Rust. This library implements APIs required to communicate with Microchip Security device - ATECC608a.

![NRF52840 communicating with a ATECC608a](https://user-images.githubusercontent.com/20253082/91416112-8ee97d00-e86c-11ea-884a-c2b24addd983.jpg "Maker Diary's NRF52840-mdk communicating with a ATECC608a")

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
those commands, and then returns a result or error code.
* **Security Commands:**
This group of commands generally access the EEPROM space and/or perform cryptographic computation. 
* **Cryptographic Commands:**
This subset of the security commands includes all the ECC commands which access the hardware
ECC accelerator (GenKey, Sign, ECDH, and Verify) and the SHA commands which access the
hardware SHA accelerator (CheckMac, DeriveKey, GenDig, HMAC, MAC, SHA, and Nonce).

## Features:
1. 100% safe Rust code i.e. no memory-safety bugs in the driver (unless my logic is wrong).
2. Platform agnostic i.e. uses 'embedded-hal' for all HW dependencies.
3. No (heap) dynamic memory allocation required at all. Uses `heapless` and `Postcard` for command packet construction.
3. API compatibility with that of Microchip's CrypoAuthlib 'C library' i.e. uses the same names & arguments,
making it easier to bind to an existing C code-base.

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
extern crate nrf52840_mdk;
// extern crate panic_halt;
use cortex_m_rt::{entry, exception};

use hal::gpio::{p0, p1};
use hal::target::Peripherals;
use hal::timer::Timer;
use hal::twim::{self, Twim};
// use cortex_m_semihosting::hprintln;
use defmt_rtt as _; // global logger
use nrf52840_mdk::Pins;
use panic_probe as _; // panic_handler
use Rusty_CryptoAuthLib::ATECC608A;

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

    // GENKEY COMMAND EXAMPLE
    // Note: TFLXTLSConfig has slot 2 configured to hold an ECC private key.
    // So, only GENKEY AND PRIVWRITE commands can be used to write (i.e. store or generate private keys) to this slot.
    // Check `Slot access policies` section in my GitHub readme for more info.
    let slot = 0x02;
    let gen_public_key = match atecc608a.atcab_genkey(slot) {
        // public key retreived upon
        Ok(v) => v, // generating and storing a new (random) ECC private key
        Err(e) => panic!("Error generating ECC private key: {:?}", e), // in slot 2.
    };
    defmt::info!("gen_public_key = {:[u8; 64]} ", gen_public_key);

    let comp_public_key = match atecc608a.atcab_get_pubkey(slot) {
        // public key computed from
        Ok(v) => v, // the previously generated and stored
        Err(e) => panic!("Error retrieving ECC public key: {:?}", e), // private key in slot 2.
    };
    defmt::info!("comp_public_key = {:[u8; 64]} ", comp_public_key);

    assert_eq!(&gen_public_key[..], &comp_public_key[..]);

    exit()
}

/// Terminates the application and makes `probe-run` exit with exit-code = 0
pub fn exit() -> ! {
    loop {
        cortex_m::asm::bkpt();
    }
}

#[exception]
fn HardFault(ef: &cortex_m_rt::ExceptionFrame) -> ! {
    panic!("HardFault at {:#?}", ef);
}

#[exception]
fn DefaultHandler(irqn: i16) {
    panic!("Unhandled exception (IRQn = {})", irqn);
}

```
### Output:

```sh
PS C:\Rusty_CryptoAuthLib> cargo run --release --example atcab_genkey
   Compiling Rusty_CryptoAuthLib v1.0.0 (C:\Rusty_CryptoAuthLib)
    Finished release [optimized + debuginfo] target(s) in 0.71s
     Running `probe-run --chip nRF52840_xxAA --defmt target\thumbv7em-none-eabihf\release\examples\atcab_genkey`
  (HOST) INFO  flashing program
  (HOST) INFO  success!
────────────────────────────────────────────────────────────────────────────────
0.000000 INFO  DEVICE WAKE SEQUENCE: tWLO COMPLETE
└─ Rusty_CryptoAuthLib::{{impl}}::send_packet @ src\lib.rs:201
0.000001 INFO  gen_public_key = [6, 172, 45, 12, 15, 225, 99, 241, 134, 200, 188, 148, 205, 58, 176, 5, 92, 241, 196, 60, 128, 226, 212, 164, 109, 85, 245, 42, 115, 97, 23, 32, 188, 237, 99, 46, 48, 122, 93, 103, 158, 33, 149, 122, 234, 19, 208, 19, 88, 224, 224, 61, 195, 192, 173, 0, 214, 83, 30, 37, 219, 172, 39, 149]
└─ atcab_genkey::__cortex_m_rt_main @ examples\atcab_genkey.rs:44
0.000002 INFO  comp_public_key = [6, 172, 45, 12, 15, 225, 99, 241, 134, 200, 188, 148, 205, 58, 176, 5, 92, 241, 196, 60, 128, 226, 212, 164, 109, 85, 245, 42, 115, 97, 23, 32, 188, 237, 99, 46, 48, 122, 93, 103, 158, 33, 149, 122, 234, 19, 208, 19, 88, 224, 224, 61, 195, 192, 173, 0, 214, 83, 30, 37, 219, 172, 39, 149]
└─ atcab_genkey::__cortex_m_rt_main @ examples\atcab_genkey.rs:51
stack backtrace:
   0: __bkpt
   1: atcab_genkey::exit
        at examples/atcab_genkey.rs:60
   2: atcab_genkey::__cortex_m_rt_main
        at examples/atcab_genkey.rs:55
   3: main
        at examples/atcab_genkey.rs:20
   4: ResetTrampoline
        at C:\Users\Nil\.cargo\registry\src\github.com-1ecc6299db9ec823\cortex-m-rt-0.6.13/C:\Users\Nil\.cargo\registry\src\github.com-1ecc6299db9ec823\cortex-m-rt-0.6.13\src/lib.rs:547
   5: Reset
        at C:\Users\Nil\.cargo\registry\src\github.com-1ecc6299db9ec823\cortex-m-rt-0.6.13/C:\Users\Nil\.cargo\registry\src\github.com-1ecc6299db9ec823\cortex-m-rt-0.6.13\src/lib.rs:550

```
Please see the examples folder for more.

## Device personalisation (i.e. configuration) steps:

The ATECC608A is a command-based device which receives commands from the system, executes those commands, and then returns a result or error code. It contains an integrated EEPROM storage memory and SRAM buffer. The EEPROM memory contains a total of 1400 bytes and is divided into the following zones:

1. Configuration zone: 128 bytes contains device configuration info such as access policies for each slot, serial number, lock information etc.
2. Data zone: 1208 bytes (split into 16 general purpose read-only or read/write memory slots.)
3. OTP zone: 64 bytes

Before we begin, we'll need to program the Config zone with values that will determine the access policy for how each data slot will respond. The configuration zone can
be modified until it has been locked (LockConfig set to !=0x55). In order to enable the access policies, the LockValue byte must be set. Here's a comparison between an out-of-the-box config Vs sample (ATECC-TFLXTLS) config. (Sample config taken from Microchip. It's used in some of its pre-provisioned variants.) 

![atecc608a_configs_graphical_view](https://user-images.githubusercontent.com/20253082/93613422-78a78a80-f9ee-11ea-8e32-2d7a15770091.png "Out of the box Config Vs ATECC-TFLXTLS Config")

Writing the ATECC-TFLXTLS configuration to the device will yield a personalised device i.e. you can now generate/store keys, certificates and other content in the device's EEPROM slots as shown in the table below. For a more detailed view of slot access policies and commands that can be used on each slot - [Detailed slot access policies](https://user-images.githubusercontent.com/20253082/93618137-83651e00-f9f4-11ea-8ee4-8b98373ac0be.png)

| Slot  | Use-case                          |
|-------|-----------------------------------|
| 0     | Primary private key               |
| 1     | Internal sign private key         |
| 2     | Secondary private key 1           |
| 3     | Secondary private key 2           |
| 4     | Secondary private key 3           |
| 5     | Secret key                        |
| 6     | IO protection key                 |
| 7     | Secure boot digest                |
| 8     | General data                      |
| 9     | AES key                           |
| 10    | Device compressed certificate     |
| 11    | Signer public key                 |
| 12    | Signer compressed certificate     |
| 13    | Parent public key or general data |
| 14    | Validated public key              |
| 15    | Secure boot public key            |

**Important: Please do not proceed before reading this section**
1. To write the ATECC-TFLXTLS configuration bytes to the device, use the example `atcab_write_config_zone.rs` included in the examples folder. 
2. Use the read command example - `atcab_read_config_zone.rs` to read contents (i.e. all 128 bytes) of config zone. This is just a double check to see if the correct set of bytes (i.e. ATECC-TFLXTLS config bytes) were written to the device.
3. Before we can begin populating (i.e. read from or write to) data or OTP zones, we have to lock the config zone. Use the `atcab_lock_config_zone_crc.rs` example to lock the config zone. Note: locking the config zone is an **irreversible operation**. So, please make sure you get everything right before you do.
3. Once that's done, you can start populating the device's data zone with private ECC keys or externally generated public keys of your choice as per the above table. 
    -   The example `atcab_sign_and_verify.rs` does just that. It generates and loads a new (random) ECC private key into slot 3 of the device. The private key is generated 'within-the-device' and never leaves it. The example contains a test message, which is signed by the private key and verified by the corresponding 'computed' public key. 
    -   Note: In step 3, you can do this for all private keys slots (0-4) as not all access policies are strictly enforced. For example, private keys in sot 0-1 are permanent and slot2-4 are updateable as per policy. But because the data zone is unlocked, commands like `WRITE or GENKEY` will still work without restrictions, even though a slot is configured to be (permanently) not writable. 
    -   In other words, this is step where you actually populate all slots on the device with the keys, certificates and other data and when you're happy with the contents in the data zone, move to step 4.
4. Only after locking the data zone (i.e. byte [86] or `LockValue` of the config zone) are access policies for slots strictly enforced. For example: you can no longer issue the GENKEY command to generate a new random private for slots 0 and 1 but you can issue GENKEY to compute the public key of the corresponding *permanent* private keys in slots 0 and 1.
    -   Note: I'm yet to implement a method to lock the data zone. I will be adding more commands that will need testing. If you need it, drop a note.

## Update:
-   Switched to `probe-run and defmt` for logging and printf style debugging. 

## Currently supported commands are:
- INFO
- LOCK
- READ (1)
- SHA (1)
- WRITE (1) -
- VERIFY (1)
- GENKEY
- SIGN
- NONCE
    
## Support to be added for:
- SELFTEST
- RANDOM
- SECUREBOOT
- AES
- KDF

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
- [x] atcab_genkey_base(mode, key_id, other_data=None)
- [x] atcab_genkey(key_id)
- [x] atcab_get_pubkey(key_id)
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
- [x] atcab_nonce_base(mode, zero=0, numbers=None)
- [x] atcab_nonce(numbers=None)
- [x] atcab_nonce_load(target, numbers=None)
- [x] atcab_nonce_rand(numbers=None)
- [x] atcab_challenge(numbers=None)
- [x] atcab_challenge_seed_update(numbers=None)
- [ ] atcab_priv_write(key_id, priv_key, write_key_id, write_key)
- [ ] atcab_random()
- [x] atcab_read_zone(zone, slot=0, block=0, offset=0, length=0)
- [ ] atcab_read_serial_number()
- [x] atcab_read_bytes_zone(zone, slot=0, block=0, offset=0, length=0)
- [ ] atcab_is_slot_locked(slot)
- [x] atcab_is_locked(zone)
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
- [x] atcab_sign_base(mode, key_id)
- [x] atcab_sign(key_id, message)
- [x] atcab_sign_internal(key_id, is_invalidate=False, is_full_sn=False)
- [x] atcab_updateextra(mode, value)
- [x] atcab_verify(mode, key_id, signature, public_key=None, other_data=None, mac=None)
- [x] atcab_verify_extern(message, signature, public_key)
- [ ] atcab_verify_extern_mac(message, signature, public_key, num_in, io_key, is_verified)
- [x] atcab_verify_stored(message, signature, key_id)
- [ ] atcab_verify_stored_mac(message, signature, key_id, num_in, io_key, is_verified)
- [ ] atcab_verify_validate( key_id, signature, other_data, is_verified)
- [ ] atcab_verify_invalidate( key_id, signature, other_data, is_verified)
- [x] atcab_write(zone, address, value=None, mac=None)
- [x] atcab_write_zone(zone, slot=0, block=0, offset=0, data=None)
- [x] atcab_write_bytes_zone(zone, slot=0, offset=0, data=None)
- [ ] atcab_write_pubkey(slot, public_key)
- [x] atcab_write_config_zone(config_data)
- [ ] atcab_write_enc(key_id, block, data, enc_key, enc_key_id)
- [ ] atcab_write_config_counter(counter_id, counter_value)

## Support:
For questions, issues, feature requests, and other changes, please file an issue in the github project.

## License:
Rusty_CryptoAuthLib was ported from the C implementaion of `Microchip CryptoAuthentication Library CryptoAuthLib  v3.2.3`

*  (c) 2015-2020 Microchip Technology Inc. and its subsidiaries.
*  License terms (https://github.com/MicrochipTech/cryptoauthlib/blob/main/license.txt)

Rusty_CryptoAuthLib is licensed under Microchip CryptoAuthentication Library CryptoAuthLib v3.2.3 license terms and either of

* Apache License, Version 2.0 (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

at your option.

## Contributing:
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
