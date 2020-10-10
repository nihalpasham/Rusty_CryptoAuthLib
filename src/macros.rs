//! Macro to define 'ConvertTo' trait and implement it for [u8;151]

/// Macro to define 'ConvertTo' trait and implement it for [u8;151]
///
/// The method `send_packet` returns a [u8;151]. We use this trait to transform the 151-byte array.
/// - Responses that contain a payload are either 4, 32, or 64 bytes in length
/// - Responses that do not contain a payload (or additional data) are 4 bytes in length but we exclude the count (or first) byte.
/// So, we only need to pick the first 3 bytes.
macro_rules! ConvertTo {
    ($($(#[$attr:meta])* $j:ident($i:literal)),+) => {
        /// Trait to extract the first 'x' bytes. In this instance its either
        /// -   3, 4, 32 or 64 bytes
        ///
        /// Purpose: This is just to optimize runtime space requirements. We use a ATCA_CMD_SIZE_MAX (151-byte) array
        /// to store all responses from the ATECC device as Rust does not yet support code that is generic over
        /// the size of an array type i.e. [Foo; 3] and [Bar; 3] are instances of same generic type [T; 3],
        /// but [Foo; 3] and [Foo; 5]  are entirely different types.
        pub trait ConvertTo {
            $($(#[$attr])* fn $j(&self) -> [u8; $i];)+
        }

        impl ConvertTo for [u8; 151] {
            $(fn $j(&self) -> [u8; $i] {
                let mut rsp_bytes = [0; $i];
                for (idx, val) in self[..$i].iter().enumerate() {
                    rsp_bytes[idx] = *val
                }
                rsp_bytes
            })+
    }
}}

ConvertTo!(
    /// This method takes a reference to `self` (an array of 151 bytes) and returns the first 3-bytes.
    convert_to_3(3),
    /// This method takes a reference to `self` (an array of 151 bytes) and returns the first 4-bytes.
    convert_to_4(4),
    /// This method takes a reference to `self` (an array of 151 bytes) and returns the first 32-bytes.
    convert_to_32(32),
    /// This method takes a reference to `self` (an array of 151 bytes) and returns the first 64-bytes.
    convert_to_64(64)
);

// The above macro expands into the following-

// /// Trait to extract the first 'x' bytes. In this instance its either
// /// -   3, 4, 32 or 64 bytes
// ///
// /// Purpose: This is just to optimize runtime space requirements. We use a ATCA_CMD_SIZE_MAX (151-byte) array
// /// to store all responses from the ATECC device as Rust does not yet support code that is generic over
// /// the size of an array type i.e. [Foo; 3] and [Bar; 3] are instances of same generic type [T; 3],
// /// but [Foo; 3] and [Foo; 5]  are entirely different types.
// pub trait ConvertTo {
//     #[doc =
//       r" This method takes a reference to `self` (an array of 151 bytes) and returns the first 3-bytes."]
//     fn convert_to_3(&self)
//     -> [u8; 3];
//     #[doc =
//       r" This method takes a reference to `self` (an array of 151 bytes) and returns the first 4-bytes."]
//     fn convert_to_4(&self)
//     -> [u8; 4];
//     #[doc =
//       r" This method takes a reference to `self` (an array of 151 bytes) and returns the first 32-bytes."]
//     fn convert_to_32(&self)
//     -> [u8; 32];
//     #[doc =
//       r" This method takes a reference to `self` (an array of 151 bytes) and returns the first 64-bytes."]
//     fn convert_to_64(&self)
//     -> [u8; 64];
// }
// impl ConvertTo for [u8; 151] {
//     fn convert_to_3(&self) -> [u8; 3] {
//         let mut rsp_bytes = [0; 3];
//         for (idx, val) in self[..3].iter().enumerate() {
//             rsp_bytes[idx] = *val
//         }
//         rsp_bytes
//     }
//     fn convert_to_4(&self) -> [u8; 4] {
//         let mut rsp_bytes = [0; 4];
//         for (idx, val) in self[..4].iter().enumerate() {
//             rsp_bytes[idx] = *val
//         }
//         rsp_bytes
//     }
//     fn convert_to_32(&self) -> [u8; 32] {
//         let mut rsp_bytes = [0; 32];
//         for (idx, val) in self[..32].iter().enumerate() {
//             rsp_bytes[idx] = *val
//         }
//         rsp_bytes
//     }
//     fn convert_to_64(&self) -> [u8; 64] {
//         let mut rsp_bytes = [0; 64];
//         for (idx, val) in self[..64].iter().enumerate() {
//             rsp_bytes[idx] = *val
//         }
//         rsp_bytes
//     }
// }
