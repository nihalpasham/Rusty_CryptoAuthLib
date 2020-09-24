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

    // INFO COMMAND EXAMPLE
    let revision_id = &[0x00, 0x00, 0x60, 0x02];
    let info = match atecc608a.atcab_info() {
        Ok(v) => v,
        Err(e) => panic!("ERROR: {:?}", e),
    };

    assert_eq!(&info[..], revision_id);
    defmt::info!("REVISION INFO: {:[u8; 4]} ", info);

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
