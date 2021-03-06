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

    // SHA COMMAND EXAMPLE
    let selection = TestEnum::ShaTestData1; // or TestEnum::ShaTestData2
    let sha = match atecc608a.atcab_sha(selection.get_value()) {
        Ok(v) => v,
        Err(e) => {
            defmt::error!("{:str}", e);
            panic!("ERROR: {:?}", e)
        }
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
    defmt::info!("SHA TEST SUCCESS");

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
