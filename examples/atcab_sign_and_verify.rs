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

    let test_message = "Sign test message using ECDSA";
    let sha256_digest_test_message = &[
        0xc3, 0x0f, 0x64, 0x48, 0x2b, 0x53, 0x08, 0xac, 0x71, 0xde, 0xa6, 0x5a, 0x1b, 0x11, 0x03,
        0xfa, 0x2e, 0x3b, 0x01, 0xe7, 0x8f, 0x88, 0xa0, 0x5b, 0x6f, 0x67, 0x2e, 0x57, 0xc2, 0x95,
        0x1c, 0x1a,
    ];

    // SIGN and VERIFY COMMAND EXAMPLE
    // Note: TFLXTLSConfig has slot 3 configured to hold an ECC private key.
    let slot = 0x03;
    let gen_public_key = match atecc608a.atcab_genkey(slot) {
        // public key retreived upon
        Ok(v) => v, // generating and storing a new (random) ECC private key
        Err(e) => panic!("Error generating ECC private key: {:?}", e), // in slot 2.
    };
    let comp_public_key = match atecc608a.atcab_get_pubkey(slot) {
        // public key computed from
        Ok(v) => v, // the previously generated and stored
        Err(e) => panic!("Error retrieving ECC public key: {:?}", e), // private key in slot 2.
    };
    assert_eq!(&gen_public_key[..], &comp_public_key[..]); // check to see if both public keys are equal

    // Compute a digest of the message and have the ATECC608a sign it
    let digest = atecc608a
        .atcab_sha(&test_message[..].as_bytes())
        .expect("Error computing SHA256 digest");
    assert_eq!(&digest[..32], sha256_digest_test_message); // check to see if the computed sha256 matches the one you have.
    let signature = match atecc608a.atcab_sign(slot, &digest[..32]) {
        Ok(v) => v,
        Err(e) => panic!("Error generating ECC signature: {:?}", e),
    };

    // Verify if the signature generated in the previous step is correct.
    // If signature does not match (or if you get any other error), `e` will contain an approriate `error-string`
    // verified[0] == 0x00, means the signature was successfully verified by the device.
    let verified =
        match atecc608a.atcab_verify_extern(&digest[..32], &signature[..], &comp_public_key[..]) {
            Ok(v) => v,
            Err(e) => panic!("Error verifying ECC signature: {:?}", e),
        };

    defmt::info!("verified[0]: 0x{:u8} ", verified[0]); // verified[0] must be equal to 0x00
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
