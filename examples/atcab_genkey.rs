#![no_main]
#![no_std]
// #![allow(warnings)]

extern crate nrf52840_hal as hal;
extern crate panic_halt;
extern crate nrf52840_mdk;
use cortex_m_rt::{entry, exception};

use hal::gpio::{p0, p1};
use hal::target::Peripherals;
use hal::timer::Timer;
use hal::twim::{self, Twim};
// use cortex_m_semihosting::hprintln;
use Rusty_CryptoAuthLib::ATECC608A;
use nrf52840_mdk::Pins;


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
    let gen_public_key = match atecc608a.atcab_genkey(slot) { // public key retreived upon 
        Ok(v) => v,                                           // generating and storing a new (random) ECC private key
        Err(e) => panic!("Error generating ECC private key: {:?}", e), // in slot 2.
    };

    let comp_public_key = match atecc608a.atcab_get_pubkey(slot) { // public key computed from
        Ok(v) => v,                                                // the previously generated and stored
        Err(e) => panic!("Error retrieving ECC public key: {:?}", e), // private key in slot 2.
    };

    assert_eq!(&gen_public_key[..], &comp_public_key[..]);

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