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

    // // INFO COMMAND EXAMPLE
    // let _info = match atecc608a.atcab_info() {
    //     Ok(v) => v,
    //     Err(e) => panic!("ERROR: {:?}", e),
    // };
    // // SHA COMMAND EXAMPLE
    // let selection = TestEnum::ShaTestData1; // or TestEnum::ShaTestData2
    // let sha = match atecc608a.atcab_sha(selection.get_value()) {
    //     Ok(v) => v,
    //     Err(e) => panic!("ERROR: {:?}", e),
    // };
    // match selection {
    //     TestEnum::ShaTestData1 => assert_eq!(
    //         [
    //             0x74, 0xf8, 0x1f, 0xe1, 0x67, 0xd9, 0x9b, 0x4c, 0xb4, 0x1d, 0x6d, 0x0c, 0xcd, 0xa8,
    //             0x22, 0x78, 0xca, 0xee, 0x9f, 0x3e, 0x2f, 0x25, 0xd5, 0xe5, 0xa3, 0x93, 0x6f, 0xf3,
    //             0xdc, 0xec, 0x60, 0xd0
    //         ],
    //         &sha[..32]
    //     ),
    //     TestEnum::ShaTestData2 => assert_eq!(
    //         [
    //             0x6e, 0x68, 0x88, 0x97, 0xd4, 0x70, 0xe7, 0x74, 0x27, 0x44, 0xcf, 0x2b, 0xcd, 0xe9,
    //             0x3c, 0x9b, 0xe6, 0x94, 0xf3, 0x36, 0x34, 0x54, 0x46, 0x48, 0x27, 0x04, 0x19, 0xe7,
    //             0xce, 0xe3, 0x40, 0xdd
    //         ],
    //         &sha[..32]
    //     ),
    // }

    // READ COMMAND EXAMPLE
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

// Macro that re-defines nrf-mdk pins.
macro_rules! define_pins {
    ($(#[$topattr:meta])* struct $Type:ident,
    p0: {
     $( $(#[$attr:meta])* pin $name:ident = $pin_ident:ident : $pin_type:ident),+ ,
    },
    p1: {
     $( $(#[$attr1:meta])* pin $name1:ident = $pin_ident1:ident: $pin_type1:ident),+ ,
    }) => {

$(#[$topattr])*
pub struct $Type {
    $($(#[$attr])* pub $name: p0:: $pin_type <Input<Floating>>,)+
    $($(#[$attr1])* pub $name1: p1:: $pin_type1 <Input<Floating>>,)+
}

impl $Type {
    /// Returns the pins for the device
    pub fn new(pins0: p0::Parts, pins1: p1::Parts) -> Self {
        $Type {
            $($name: pins0.$pin_ident, )+
            $($name1: pins1.$pin_ident1, )+
        }
    }
}
}}

define_pins!(
    /// Maps the pins to the names printed on the device
    struct Pins,
    p0: {
        /// Uart RXD
        pin rxd = p0_19: P0_19,
        /// Uart TXD
        pin txd = p0_20: P0_20,

        pin p6 = p0_06: P0_06,
        pin p7 = p0_07: P0_07,
        pin p8 = p0_08: P0_08,
        pin p11 = p0_11: P0_11,
        pin p12 = p0_12: P0_12,
        pin p13 = p0_13: P0_13,
        pin p14 = p0_14: P0_14,
        pin p15 = p0_15: P0_15,
        pin p16 = p0_16: P0_16,
        pin p17 = p0_17: P0_17,
        pin p21 = p0_21: P0_21,
        pin p25 = p0_25: P0_25,
        pin p26 = p0_26: P0_26,
        pin p27 = p0_27: P0_27,


        pin ain0 = p0_02: P0_02,
        pin ain1 = p0_03: P0_03,
        pin ain2 = p0_04: P0_04,
        pin ain3 = p0_05: P0_05,
        pin ain4 = p0_28: P0_28,
        pin ain5 = p0_29: P0_29,
        pin ain6 = p0_30: P0_30,
        pin ain7 = p0_31: P0_31,

        pin nfc1 = p0_09: P0_09,
        pin nfc2 = p0_10: P0_10,

        pin red_led = p0_23: P0_23,
        pin green_led = p0_22: P0_22,
        pin blue_led = p0_24: P0_24,
    },
    p1: {
        pin button = p1_00: P1_00,

        /// ~RESET line to the QSPI flash
        pin qspi_reset = p1_01: P1_01,
        /// ~WP Write protect pin on the QSPI flash.
        pin qspi_wp = p1_02: P1_02,
        /// SPI SCLK for QSPI flash
        pin qspi_sclk = p1_03: P1_03,
        /// SPI MISO for QSPI flash
        pin qspi_miso = p1_04: P1_04,
        /// SPI MOSI for QSPI flash
        pin qspi_mosi = p1_05: P1_05,
        /// ~CS for the QSPI flash
        pin qspi_cs = p1_06: P1_06,
    }
);
