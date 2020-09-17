pub(crate) const ATCA_CMD_SIZE_MIN: u8 = 7;
pub(crate) const ATCA_CMD_SIZE_MAX: u8 = 4 * 36 + 7;
pub(crate) const CMD_STATUS_SUCCESS: u8 = 0x00;
pub(crate) const CMD_STATUS_WAKEUP: u8 = 0x11;
pub(crate) const CMD_STATUS_BYTE_PARSE: u8 = 0x03;
pub(crate) const CMD_STATUS_BYTE_ECC: u8 = 0x05;
pub(crate) const CMD_STATUS_BYTE_EXEC: u8 = 0x0F;
pub(crate) const CMD_STATUS_BYTE_COMM: u8 = 0xFF;
pub(crate) const ATCA_CHECKMAC: u8 = 0x28;
pub(crate) const ATCA_DERIVE_KEY: u8 = 0x1C;
pub(crate) const ATCA_INFO: u8 = 0x30;
pub(crate) const ATCA_GENDIG: u8 = 0x15;
pub(crate) const ATCA_GENKEY: u8 = 0x40;
pub(crate) const ATCA_HMAC: u8 = 0x11;
pub(crate) const ATCA_LOCK: u8 = 0x17;
pub(crate) const ATCA_MAC: u8 = 0x08;
pub(crate) const ATCA_NONCE: u8 = 0x16;
pub(crate) const ATCA_PAUSE: u8 = 0x01;
pub(crate) const ATCA_PRIVWRITE: u8 = 0x46;
pub(crate) const ATCA_RANDOM: u8 = 0x1B;
pub(crate) const ATCA_READ: u8 = 0x02;
pub(crate) const ATCA_SIGN: u8 = 0x41;
pub(crate) const ATCA_UPDATE_EXTRA: u8 = 0x20;
pub(crate) const ATCA_VERIFY: u8 = 0x45;
pub(crate) const ATCA_WRITE: u8 = 0x12;
pub(crate) const ATCA_ECDH: u8 = 0x43;
pub(crate) const ATCA_COUNTER: u8 = 0x24;
pub(crate) const ATCA_SHA: u8 = 0x47;
pub(crate) const ATCA_AES: u8 = 0x51;
pub(crate) const ATCA_KDF: u8 = 0x56;
pub(crate) const ATCA_SECUREBOOT: u8 = 0x80;
pub(crate) const ATCA_SELFTEST: u8 = 0x77;
pub(crate) const ATCA_KEY_SIZE: u8 = 32;
pub(crate) const ATCA_BLOCK_SIZE: u8 = 32;
pub(crate) const ATCA_WORD_SIZE: u8 = 4;
pub(crate) const ATCA_PUB_KEY_PAD: u8 = 4;
pub(crate) const ATCA_SERIAL_NUM_SIZE: u8 = 9;
pub(crate) const ATCA_RSP_SIZE_VAL: u8 = 7;
pub(crate) const ATCA_KEY_COUNT: u8 = 16;
pub(crate) const ATCA_ECC_CONFIG_SIZE: u8 = 128;
pub(crate) const ATCA_SHA_CONFIG_SIZE: u8 = 88;
pub(crate) const ATCA_OTP_SIZE: u8 = 64;
pub(crate) const ATCA_DATA_SIZE: u16 = 16 * 32;
pub(crate) const ATCA_AES_GFM_SIZE: u8 = 32;
pub(crate) const ATCA_CHIPMODE_OFFSET: u8 = 19;
pub(crate) const ATCA_CHIPMODE_I2C_ADDRESS_FLAG: u8 = 0x01;
pub(crate) const ATCA_CHIPMODE_TTL_ENABLE_FLAG: u8 = 0x02;
pub(crate) const ATCA_CHIPMODE_WATCHDOG_MASK: u8 = 0x04;
pub(crate) const ATCA_CHIPMODE_WATCHDOG_SHORT: u8 = 0x00;
pub(crate) const ATCA_CHIPMODE_WATCHDOG_LONG: u8 = 0x04;
pub(crate) const ATCA_CHIPMODE_CLOCK_DIV_MASK: u8 = 0xF8;
pub(crate) const ATCA_CHIPMODE_CLOCK_DIV_M0: u8 = 0x00;
pub(crate) const ATCA_CHIPMODE_CLOCK_DIV_M1: u8 = 0x28;
pub(crate) const ATCA_CHIPMODE_CLOCK_DIV_M2: u8 = 0x68;
pub(crate) const ATCA_COUNT_SIZE: u8 = 1;
pub(crate) const ATCA_CRC_SIZE: u8 = 2;
pub(crate) const ATCA_PACKET_OVERHEAD: u8 = 3;
pub(crate) const ATCA_PUB_KEY_SIZE: u8 = 64;
pub(crate) const ATCA_PRIV_KEY_SIZE: u8 = 32;
pub(crate) const ATCA_SIG_SIZE: u8 = 64;
pub(crate) const RSA2048_KEY_SIZE: u16 = 256;
pub(crate) const ATCA_RSP_SIZE_MIN: u8 = 4;
pub(crate) const ATCA_RSP_SIZE_4: u8 = 7;
pub(crate) const ATCA_RSP_SIZE_72: u8 = 75;
pub(crate) const ATCA_RSP_SIZE_64: u8 = 67;
pub(crate) const ATCA_RSP_SIZE_32: u8 = 35;
pub(crate) const ATCA_RSP_SIZE_16: u8 = 19;
pub(crate) const ATCA_RSP_SIZE_MAX: u8 = 75;
pub(crate) const OUTNONCE_SIZE: u8 = 32;
pub(crate) const ATCA_KEY_ID_MAX: u8 = 15;
pub(crate) const ATCA_OTP_BLOCK_MAX: u8 = 1;
pub(crate) const ATCA_COUNT_IDX: u8 = 0;
pub(crate) const ATCA_OPCODE_IDX: u8 = 1;
pub(crate) const ATCA_PARAM1_IDX: u8 = 2;
pub(crate) const ATCA_PARAM2_IDX: u8 = 3;
pub(crate) const ATCA_DATA_IDX: u8 = 5;
pub(crate) const ATCA_RSP_DATA_IDX: u8 = 1;
pub(crate) const ATCA_ZONE_CONFIG: u8 = 0x00;
pub(crate) const ATCA_ZONE_OTP: u8 = 0x01;
pub(crate) const ATCA_ZONE_DATA: u8 = 0x02;
pub(crate) const ATCA_ZONE_MASK: u8 = 0x03;
pub(crate) const ATCA_ZONE_ENCRYPTED: u8 = 0x40;
pub(crate) const ATCA_ZONE_READWRITE_32: u8 = 0x80;
pub(crate) const ATCA_ADDRESS_MASK_CONFIG: u16 = 0x001F;
pub(crate) const ATCA_ADDRESS_MASK_OTP: u16 = 0x000F;
pub(crate) const ATCA_ADDRESS_MASK: u16 = 0x007F;
pub(crate) const ATCA_TEMPKEY_KEYID: u16 = 0xFFFF;
pub(crate) const ATCA_B283_KEY_TYPE: u8 = 0;
pub(crate) const ATCA_K283_KEY_TYPE: u8 = 1;
pub(crate) const ATCA_P256_KEY_TYPE: u8 = 4;
pub(crate) const ATCA_AES_KEY_TYPE: u8 = 6;
pub(crate) const ATCA_SHA_KEY_TYPE: u8 = 7;
pub(crate) const AES_MODE_IDX: u8 = 2;
pub(crate) const AES_KEYID_IDX: u8 = 3;
pub(crate) const AES_INPUT_IDX: u8 = 5;
pub(crate) const AES_COUNT: u8 = 23;
pub(crate) const AES_MODE_MASK: u8 = 0xC7;
pub(crate) const AES_MODE_KEY_BLOCK_MASK: u8 = 0xC0;
pub(crate) const AES_MODE_OP_MASK: u8 = 0x07;
pub(crate) const AES_MODE_ENCRYPT: u8 = 0x00;
pub(crate) const AES_MODE_DECRYPT: u8 = 0x01;
pub(crate) const AES_MODE_GFM: u8 = 0x03;
pub(crate) const AES_MODE_KEY_BLOCK_POS: u8 = 6;
pub(crate) const AES_DATA_SIZE: u8 = 16;
pub(crate) const AES_RSP_SIZE: u8 = 19;
pub(crate) const CHECKMAC_MODE_IDX: u8 = 2;
pub(crate) const CHECKMAC_KEYID_IDX: u8 = 3;
pub(crate) const CHECKMAC_CLIENT_CHALLENGE_IDX: u8 = 5;
pub(crate) const CHECKMAC_CLIENT_RESPONSE_IDX: u8 = 37;
pub(crate) const CHECKMAC_DATA_IDX: u8 = 69;
pub(crate) const CHECKMAC_COUNT: u8 = 84;
pub(crate) const CHECKMAC_MODE_CHALLENGE: u8 = 0x00;
pub(crate) const CHECKMAC_MODE_BLOCK2_TEMPKEY: u8 = 0x01;
pub(crate) const CHECKMAC_MODE_BLOCK1_TEMPKEY: u8 = 0x02;
pub(crate) const CHECKMAC_MODE_SOURCE_FLAG_MATCH: u8 = 0x04;
pub(crate) const CHECKMAC_MODE_INCLUDE_OTP_64: u8 = 0x20;
pub(crate) const CHECKMAC_MODE_MASK: u8 = 0x27;
pub(crate) const CHECKMAC_CLIENT_CHALLENGE_SIZE: u8 = 32;
pub(crate) const CHECKMAC_CLIENT_RESPONSE_SIZE: u8 = 32;
pub(crate) const CHECKMAC_OTHER_DATA_SIZE: u8 = 13;
pub(crate) const CHECKMAC_CLIENT_COMMAND_SIZE: u8 = 4;
pub(crate) const CHECKMAC_CMD_MATCH: u8 = 0;
pub(crate) const CHECKMAC_CMD_MISMATCH: u8 = 1;
pub(crate) const CHECKMAC_RSP_SIZE: u8 = 4;
pub(crate) const COUNTER_COUNT: u8 = 7;
pub(crate) const COUNTER_MODE_IDX: u8 = 2;
pub(crate) const COUNTER_KEYID_IDX: u8 = 3;
pub(crate) const COUNTER_MODE_MASK: u8 = 0x01;
pub(crate) const COUNTER_MAX_VALUE: u32 = 2097151;
pub(crate) const COUNTER_MODE_READ: u8 = 0x00;
pub(crate) const COUNTER_MODE_INCREMENT: u8 = 0x01;
pub(crate) const COUNTER_RSP_SIZE: u8 = 7;
pub(crate) const DERIVE_KEY_RANDOM_IDX: u8 = 2;
pub(crate) const DERIVE_KEY_TARGETKEY_IDX: u8 = 3;
pub(crate) const DERIVE_KEY_MAC_IDX: u8 = 5;
pub(crate) const DERIVE_KEY_COUNT_SMALL: u8 = 7;
pub(crate) const DERIVE_KEY_MODE: u8 = 0x04;
pub(crate) const DERIVE_KEY_COUNT_LARGE: u8 = 39;
pub(crate) const DERIVE_KEY_RANDOM_FLAG: u8 = 4;
pub(crate) const DERIVE_KEY_MAC_SIZE: u8 = 32;
pub(crate) const DERIVE_KEY_RSP_SIZE: u8 = 4;
pub(crate) const ECDH_PREFIX_MODE: u8 = 0x00;
pub(crate) const ECDH_COUNT: u8 = 7 + 64;
pub(crate) const ECDH_MODE_SOURCE_MASK: u8 = 0x01;
pub(crate) const ECDH_MODE_SOURCE_EEPROM_SLOT: u8 = 0x00;
pub(crate) const ECDH_MODE_SOURCE_TEMPKEY: u8 = 0x01;
pub(crate) const ECDH_MODE_OUTPUT_MASK: u8 = 0x02;
pub(crate) const ECDH_MODE_OUTPUT_CLEAR: u8 = 0x00;
pub(crate) const ECDH_MODE_OUTPUT_ENC: u8 = 0x02;
pub(crate) const ECDH_MODE_COPY_MASK: u8 = 0x0C;
pub(crate) const ECDH_MODE_COPY_COMPATIBLE: u8 = 0x00;
pub(crate) const ECDH_MODE_COPY_EEPROM_SLOT: u8 = 0x04;
pub(crate) const ECDH_MODE_COPY_TEMP_KEY: u8 = 0x08;
pub(crate) const ECDH_MODE_COPY_OUTPUT_BUFFER: u8 = 0x0C;
pub(crate) const ECDH_KEY_SIZE: u8 = 32;
pub(crate) const ECDH_RSP_SIZE: u8 = 67;
pub(crate) const GENDIG_ZONE_IDX: u8 = 2;
pub(crate) const GENDIG_KEYID_IDX: u8 = 3;
pub(crate) const GENDIG_DATA_IDX: u8 = 5;
pub(crate) const GENDIG_COUNT: u8 = 7;
pub(crate) const GENDIG_ZONE_CONFIG: u8 = 0;
pub(crate) const GENDIG_ZONE_OTP: u8 = 1;
pub(crate) const GENDIG_ZONE_DATA: u8 = 2;
pub(crate) const GENDIG_ZONE_SHARED_NONCE: u8 = 3;
pub(crate) const GENDIG_ZONE_COUNTER: u8 = 4;
pub(crate) const GENDIG_ZONE_KEY_CONFIG: u8 = 5;
pub(crate) const GENDIG_RSP_SIZE: u8 = 4;
pub(crate) const GENKEY_MODE_IDX: u8 = 2;
pub(crate) const GENKEY_KEYID_IDX: u8 = 3;
pub(crate) const GENKEY_DATA_IDX: u8 = 5;
pub(crate) const GENKEY_COUNT: u8 = 7;
pub(crate) const GENKEY_COUNT_DATA: u8 = 10;
pub(crate) const GENKEY_OTHER_DATA_SIZE: u8 = 3;
pub(crate) const GENKEY_MODE_MASK: u8 = 0x1C;
pub(crate) const GENKEY_MODE_PRIVATE: u8 = 0x04;
pub(crate) const GENKEY_MODE_PUBLIC: u8 = 0x00;
pub(crate) const GENKEY_MODE_DIGEST: u8 = 0x08;
pub(crate) const GENKEY_MODE_PUBKEY_DIGEST: u8 = 0x10;
pub(crate) const GENKEY_PRIVATE_TO_TEMPKEY: u16 = 0xFFFF;
pub(crate) const GENKEY_RSP_SIZE_SHORT: u8 = 4;
pub(crate) const GENKEY_RSP_SIZE_LONG: u8 = 75;
pub(crate) const HMAC_MODE_IDX: u8 = 2;
pub(crate) const HMAC_KEYID_IDX: u8 = 3;
pub(crate) const HMAC_COUNT: u8 = 7;
pub(crate) const HMAC_MODE_FLAG_TK_RAND: u8 = 0x00;
pub(crate) const HMAC_MODE_FLAG_TK_NORAND: u8 = 0x04;
pub(crate) const HMAC_MODE_FLAG_OTP88: u8 = 0x10;
pub(crate) const HMAC_MODE_FLAG_OTP64: u8 = 0x20;
pub(crate) const HMAC_MODE_FLAG_FULLSN: u8 = 0x40;
pub(crate) const HMAC_MODE_MASK: u8 = 0x74;
pub(crate) const HMAC_DIGEST_SIZE: u8 = 32;
pub(crate) const HMAC_RSP_SIZE: u8 = 35;
pub(crate) const INFO_PARAM1_IDX: u8 = 2;
pub(crate) const INFO_PARAM2_IDX: u8 = 3;
pub(crate) const INFO_COUNT: u8 = 7;
pub(crate) const INFO_MODE_REVISION: u8 = 0x00;
pub(crate) const INFO_MODE_KEY_VALID: u8 = 0x01;
pub(crate) const INFO_MODE_STATE: u8 = 0x02;
pub(crate) const INFO_MODE_GPIO: u8 = 0x03;
pub(crate) const INFO_MODE_VOL_KEY_PERMIT: u8 = 0x04;
pub(crate) const INFO_MODE_MAX: u8 = 0x03;
pub(crate) const INFO_NO_STATE: u8 = 0x00;
pub(crate) const INFO_OUTPUT_STATE_MASK: u8 = 0x01;
pub(crate) const INFO_DRIVER_STATE_MASK: u8 = 0x02;
pub(crate) const INFO_PARAM2_SET_LATCH_STATE: u16 = 0x0002;
pub(crate) const INFO_PARAM2_LATCH_SET: u16 = 0x0001;
pub(crate) const INFO_PARAM2_LATCH_CLEAR: u16 = 0x0000;
pub(crate) const INFO_SIZE: u8 = 0x04;
pub(crate) const INFO_RSP_SIZE: u8 = 7;
pub(crate) const KDF_MODE_IDX: u8 = 2;
pub(crate) const KDF_KEYID_IDX: u8 = 3;
pub(crate) const KDF_DETAILS_IDX: u8 = 5;
pub(crate) const KDF_DETAILS_SIZE: u8 = 4;
pub(crate) const KDF_MESSAGE_IDX: u8 = 5 + 4;
pub(crate) const KDF_MODE_SOURCE_MASK: u8 = 0x03;
pub(crate) const KDF_MODE_SOURCE_TEMPKEY: u8 = 0x00;
pub(crate) const KDF_MODE_SOURCE_TEMPKEY_UP: u8 = 0x01;
pub(crate) const KDF_MODE_SOURCE_SLOT: u8 = 0x02;
pub(crate) const KDF_MODE_SOURCE_ALTKEYBUF: u8 = 0x03;
pub(crate) const KDF_MODE_TARGET_MASK: u8 = 0x1C;
pub(crate) const KDF_MODE_TARGET_TEMPKEY: u8 = 0x00;
pub(crate) const KDF_MODE_TARGET_TEMPKEY_UP: u8 = 0x04;
pub(crate) const KDF_MODE_TARGET_SLOT: u8 = 0x08;
pub(crate) const KDF_MODE_TARGET_ALTKEYBUF: u8 = 0x0C;
pub(crate) const KDF_MODE_TARGET_OUTPUT: u8 = 0x10;
pub(crate) const KDF_MODE_TARGET_OUTPUT_ENC: u8 = 0x14;
pub(crate) const KDF_MODE_ALG_MASK: u8 = 0x60;
pub(crate) const KDF_MODE_ALG_PRF: u8 = 0x00;
pub(crate) const KDF_MODE_ALG_AES: u8 = 0x20;
pub(crate) const KDF_MODE_ALG_HKDF: u8 = 0x40;
pub(crate) const KDF_DETAILS_PRF_KEY_LEN_MASK: u32 = 0x00000003;
pub(crate) const KDF_DETAILS_PRF_KEY_LEN_16: u32 = 0x00000000;
pub(crate) const KDF_DETAILS_PRF_KEY_LEN_32: u32 = 0x00000001;
pub(crate) const KDF_DETAILS_PRF_KEY_LEN_48: u32 = 0x00000002;
pub(crate) const KDF_DETAILS_PRF_KEY_LEN_64: u32 = 0x00000003;
pub(crate) const KDF_DETAILS_PRF_TARGET_LEN_MASK: u32 = 0x00000100;
pub(crate) const KDF_DETAILS_PRF_TARGET_LEN_32: u32 = 0x00000000;
pub(crate) const KDF_DETAILS_PRF_TARGET_LEN_64: u32 = 0x00000100;
pub(crate) const KDF_DETAILS_PRF_AEAD_MASK: u32 = 0x00000600;
pub(crate) const KDF_DETAILS_PRF_AEAD_MODE0: u32 = 0x00000000;
pub(crate) const KDF_DETAILS_PRF_AEAD_MODE1: u32 = 0x00000200;
pub(crate) const KDF_DETAILS_AES_KEY_LOC_MASK: u32 = 0x00000003;
pub(crate) const KDF_DETAILS_HKDF_MSG_LOC_MASK: u32 = 0x00000003;
pub(crate) const KDF_DETAILS_HKDF_MSG_LOC_SLOT: u32 = 0x00000000;
pub(crate) const KDF_DETAILS_HKDF_MSG_LOC_TEMPKEY: u32 = 0x00000001;
pub(crate) const KDF_DETAILS_HKDF_MSG_LOC_INPUT: u32 = 0x00000002;
pub(crate) const KDF_DETAILS_HKDF_MSG_LOC_IV: u32 = 0x00000003;
pub(crate) const KDF_DETAILS_HKDF_ZERO_KEY: u32 = 0x00000004;
pub(crate) const LOCK_ZONE_IDX: u8 = 2;
pub(crate) const LOCK_SUMMARY_IDX: u8 = 3;
pub(crate) const LOCK_COUNT: u8 = 7;
pub(crate) const LOCK_ZONE_CONFIG: u8 = 0x00;
pub(crate) const LOCK_ZONE_DATA: u8 = 0x01;
pub(crate) const LOCK_ZONE_DATA_SLOT: u8 = 0x02;
pub(crate) const LOCK_ZONE_NO_CRC: u8 = 0x80;
pub(crate) const LOCK_ZONE_MASK: u8 = 0xBF;
pub(crate) const ATCA_UNLOCKED: u8 = 0x55;
pub(crate) const ATCA_LOCKED: u8 = 0x00;
pub(crate) const LOCK_RSP_SIZE: u8 = 4;
pub(crate) const MAC_MODE_IDX: u8 = 2;
pub(crate) const MAC_KEYID_IDX: u8 = 3;
pub(crate) const MAC_CHALLENGE_IDX: u8 = 5;
pub(crate) const MAC_COUNT_SHORT: u8 = 7;
pub(crate) const MAC_COUNT_LONG: u8 = 39;
pub(crate) const MAC_MODE_CHALLENGE: u8 = 0x00;
pub(crate) const MAC_MODE_BLOCK2_TEMPKEY: u8 = 0x01;
pub(crate) const MAC_MODE_BLOCK1_TEMPKEY: u8 = 0x02;
pub(crate) const MAC_MODE_SOURCE_FLAG_MATCH: u8 = 0x04;
pub(crate) const MAC_MODE_PTNONCE_TEMPKEY: u8 = 0x06;
pub(crate) const MAC_MODE_PASSTHROUGH: u8 = 0x07;
pub(crate) const MAC_MODE_INCLUDE_OTP_88: u8 = 0x10;
pub(crate) const MAC_MODE_INCLUDE_OTP_64: u8 = 0x20;
pub(crate) const MAC_MODE_INCLUDE_SN: u8 = 0x40;
pub(crate) const MAC_CHALLENGE_SIZE: u8 = 32;
pub(crate) const MAC_SIZE: u8 = 32;
pub(crate) const MAC_MODE_MASK: u8 = 0x77;
pub(crate) const MAC_RSP_SIZE: u8 = 35;
pub(crate) const NONCE_MODE_IDX: u8 = 2;
pub(crate) const NONCE_PARAM2_IDX: u8 = 3;
pub(crate) const NONCE_INPUT_IDX: u8 = 5;
pub(crate) const NONCE_COUNT_SHORT: u8 = 7 + 20;
pub(crate) const NONCE_COUNT_LONG: u8 = 7 + 32;
pub(crate) const NONCE_COUNT_LONG_64: u8 = 7 + 64;
pub(crate) const NONCE_MODE_MASK: u8 = 0x03;
pub(crate) const NONCE_MODE_SEED_UPDATE: u8 = 0x00;
pub(crate) const NONCE_MODE_NO_SEED_UPDATE: u8 = 0x01;
pub(crate) const NONCE_MODE_INVALID: u8 = 0x02;
pub(crate) const NONCE_MODE_PASSTHROUGH: u8 = 0x03;
pub(crate) const NONCE_MODE_INPUT_LEN_MASK: u8 = 0x20;
pub(crate) const NONCE_MODE_INPUT_LEN_32: u8 = 0x00;
pub(crate) const NONCE_MODE_INPUT_LEN_64: u8 = 0x20;
pub(crate) const NONCE_MODE_TARGET_MASK: u8 = 0xC0;
pub(crate) const NONCE_MODE_TARGET_TEMPKEY: u8 = 0x00;
pub(crate) const NONCE_MODE_TARGET_MSGDIGBUF: u8 = 0x40;
pub(crate) const NONCE_MODE_TARGET_ALTKEYBUF: u8 = 0x80;
pub(crate) const NONCE_ZERO_CALC_MASK: u16 = 0x8000;
pub(crate) const NONCE_ZERO_CALC_RANDOM: u16 = 0x0000;
pub(crate) const NONCE_ZERO_CALC_TEMPKEY: u16 = 0x8000;
pub(crate) const NONCE_NUMIN_SIZE: u8 = 20;
pub(crate) const NONCE_NUMIN_SIZE_PASSTHROUGH: u8 = 32;
pub(crate) const NONCE_RSP_SIZE_SHORT: u8 = 4;
pub(crate) const NONCE_RSP_SIZE_LONG: u8 = 35;
pub(crate) const PAUSE_SELECT_IDX: u8 = 2;
pub(crate) const PAUSE_PARAM2_IDX: u8 = 3;
pub(crate) const PAUSE_COUNT: u8 = 7;
pub(crate) const PAUSE_RSP_SIZE: u8 = 4;
pub(crate) const PRIVWRITE_ZONE_IDX: u8 = 2;
pub(crate) const PRIVWRITE_KEYID_IDX: u8 = 3;
pub(crate) const PRIVWRITE_VALUE_IDX: u8 = 5;
pub(crate) const PRIVWRITE_MAC_IDX: u8 = 41;
pub(crate) const PRIVWRITE_COUNT: u8 = 75;
pub(crate) const PRIVWRITE_ZONE_MASK: u8 = 0x40;
pub(crate) const PRIVWRITE_MODE_ENCRYPT: u8 = 0x40;
pub(crate) const PRIVWRITE_RSP_SIZE: u8 = 4;
pub(crate) const RANDOM_MODE_IDX: u8 = 2;
pub(crate) const RANDOM_PARAM2_IDX: u8 = 3;
pub(crate) const RANDOM_COUNT: u8 = 7;
pub(crate) const RANDOM_SEED_UPDATE: u8 = 0x00;
pub(crate) const RANDOM_NO_SEED_UPDATE: u8 = 0x01;
pub(crate) const RANDOM_NUM_SIZE: u8 = 32;
pub(crate) const RANDOM_RSP_SIZE: u8 = 35;
pub(crate) const READ_ZONE_IDX: u8 = 2;
pub(crate) const READ_ADDR_IDX: u8 = 3;
pub(crate) const READ_COUNT: u8 = 7;
pub(crate) const READ_ZONE_MASK: u8 = 0x83;
pub(crate) const READ_4_RSP_SIZE: u8 = 7;
pub(crate) const READ_32_RSP_SIZE: u8 = 35;
pub(crate) const SECUREBOOT_MODE_IDX: u8 = 2;
pub(crate) const SECUREBOOT_DIGEST_SIZE: u8 = 32;
pub(crate) const SECUREBOOT_SIGNATURE_SIZE: u8 = 64;
pub(crate) const SECUREBOOT_COUNT_DIG: u8 = 7 + 32;
pub(crate) const SECUREBOOT_COUNT_DIG_SIG: u8 = 7 + 32 + 64;
pub(crate) const SECUREBOOT_MAC_SIZE: u8 = 32;
pub(crate) const SECUREBOOT_RSP_SIZE_NO_MAC: u8 = 4;
pub(crate) const SECUREBOOT_RSP_SIZE_MAC: u8 = 3 + 32;
pub(crate) const SECUREBOOT_MODE_MASK: u8 = 0x07;
pub(crate) const SECUREBOOT_MODE_FULL: u8 = 0x05;
pub(crate) const SECUREBOOT_MODE_FULL_STORE: u8 = 0x06;
pub(crate) const SECUREBOOT_MODE_FULL_COPY: u8 = 0x07;
pub(crate) const SECUREBOOT_MODE_PROHIBIT_FLAG: u8 = 0x40;
pub(crate) const SECUREBOOT_MODE_ENC_MAC_FLAG: u8 = 0x80;
pub(crate) const SECUREBOOTCONFIG_OFFSET: u8 = 70;
pub(crate) const SECUREBOOTCONFIG_MODE_MASK: u16 = 0x0003;
pub(crate) const SECUREBOOTCONFIG_MODE_DISABLED: u16 = 0x0000;
pub(crate) const SECUREBOOTCONFIG_MODE_FULL_BOTH: u16 = 0x0001;
pub(crate) const SECUREBOOTCONFIG_MODE_FULL_SIG: u16 = 0x0002;
pub(crate) const SECUREBOOTCONFIG_MODE_FULL_DIG: u16 = 0x0003;
pub(crate) const SELFTEST_MODE_IDX: u8 = 2;
pub(crate) const SELFTEST_COUNT: u8 = 7;
pub(crate) const SELFTEST_MODE_RNG: u8 = 0x01;
pub(crate) const SELFTEST_MODE_ECDSA_SIGN_VERIFY: u8 = 0x02;
pub(crate) const SELFTEST_MODE_ECDH: u8 = 0x08;
pub(crate) const SELFTEST_MODE_AES: u8 = 0x10;
pub(crate) const SELFTEST_MODE_SHA: u8 = 0x20;
pub(crate) const SELFTEST_MODE_ALL: u8 = 0x3B;
pub(crate) const SELFTEST_RSP_SIZE: u8 = 4;
pub(crate) const SHA_COUNT_SHORT: u8 = 7;
pub(crate) const SHA_COUNT_LONG: u8 = 7;
pub(crate) const ATCA_SHA_DIGEST_SIZE: u8 = 32;
pub(crate) const SHA_DATA_MAX: u8 = 64;
pub(crate) const ATCA_SHA256_BLOCK_SIZE: u8 = 64;
pub(crate) const SHA_CONTEXT_MAX_SIZE: u8 = 99;
pub(crate) const SHA_MODE_MASK: u8 = 0x07;
pub(crate) const SHA_MODE_SHA256_START: u8 = 0x00;
pub(crate) const SHA_MODE_SHA256_UPDATE: u8 = 0x01;
pub(crate) const SHA_MODE_SHA256_END: u8 = 0x02;
pub(crate) const SHA_MODE_SHA256_PUBLIC: u8 = 0x03;
pub(crate) const SHA_MODE_HMAC_START: u8 = 0x04;
pub(crate) const SHA_MODE_HMAC_UPDATE: u8 = 0x01;
pub(crate) const SHA_MODE_HMAC_END: u8 = 0x05;
pub(crate) const SHA_MODE_608_HMAC_END: u8 = 0x02;
pub(crate) const SHA_MODE_READ_CONTEXT: u8 = 0x06;
pub(crate) const SHA_MODE_WRITE_CONTEXT: u8 = 0x07;
pub(crate) const SHA_MODE_TARGET_MASK: u8 = 0xC0;
pub(crate) const SHA_MODE_TARGET_TEMPKEY: u8 = 0x00;
pub(crate) const SHA_MODE_TARGET_MSGDIGBUF: u8 = 0x40;
pub(crate) const SHA_MODE_TARGET_OUT_ONLY: u8 = 0xC0;
pub(crate) const SHA_RSP_SIZE: u8 = 35;
pub(crate) const SHA_RSP_SIZE_SHORT: u8 = 4;
pub(crate) const SHA_RSP_SIZE_LONG: u8 = 35;
pub(crate) const SIGN_MODE_IDX: u8 = 2;
pub(crate) const SIGN_KEYID_IDX: u8 = 3;
pub(crate) const SIGN_COUNT: u8 = 7;
pub(crate) const SIGN_MODE_MASK: u8 = 0xE1;
pub(crate) const SIGN_MODE_INTERNAL: u8 = 0x00;
pub(crate) const SIGN_MODE_INVALIDATE: u8 = 0x01;
pub(crate) const SIGN_MODE_INCLUDE_SN: u8 = 0x40;
pub(crate) const SIGN_MODE_EXTERNAL: u8 = 0x80;
pub(crate) const SIGN_MODE_SOURCE_MASK: u8 = 0x20;
pub(crate) const SIGN_MODE_SOURCE_TEMPKEY: u8 = 0x00;
pub(crate) const SIGN_MODE_SOURCE_MSGDIGBUF: u8 = 0x20;
pub(crate) const SIGN_RSP_SIZE: u8 = 64;
pub(crate) const UPDATE_MODE_IDX: u8 = 2;
pub(crate) const UPDATE_VALUE_IDX: u8 = 3;
pub(crate) const UPDATE_COUNT: u8 = 7;
pub(crate) const UPDATE_MODE_USER_EXTRA: u8 = 0x00;
pub(crate) const UPDATE_MODE_SELECTOR: u8 = 0x01;
pub(crate) const UPDATE_MODE_USER_EXTRA_ADD: u8 = 0x01;
pub(crate) const UPDATE_MODE_DEC_COUNTER: u8 = 0x02;
pub(crate) const UPDATE_RSP_SIZE: u8 = 4;
pub(crate) const VERIFY_MODE_IDX: u8 = 2;
pub(crate) const VERIFY_KEYID_IDX: u8 = 3;
pub(crate) const VERIFY_DATA_IDX: u8 = 5;
pub(crate) const VERIFY_256_STORED_COUNT: u8 = 71;
pub(crate) const VERIFY_283_STORED_COUNT: u8 = 79;
pub(crate) const VERIFY_256_VALIDATE_COUNT: u8 = 90;
pub(crate) const VERIFY_283_VALIDATE_COUNT: u8 = 98;
pub(crate) const VERIFY_256_EXTERNAL_COUNT: u8 = 135;
pub(crate) const VERIFY_283_EXTERNAL_COUNT: u8 = 151;
pub(crate) const VERIFY_256_KEY_SIZE: u8 = 64;
pub(crate) const VERIFY_283_KEY_SIZE: u8 = 72;
pub(crate) const VERIFY_256_SIGNATURE_SIZE: u8 = 64;
pub(crate) const VERIFY_283_SIGNATURE_SIZE: u8 = 72;
pub(crate) const VERIFY_OTHER_DATA_SIZE: u8 = 19;
pub(crate) const VERIFY_MODE_MASK: u8 = 0x03;
pub(crate) const VERIFY_MODE_STORED: u8 = 0x00;
pub(crate) const VERIFY_MODE_VALIDATE_EXTERNAL: u8 = 0x01;
pub(crate) const VERIFY_MODE_EXTERNAL: u8 = 0x02;
pub(crate) const VERIFY_MODE_VALIDATE: u8 = 0x03;
pub(crate) const VERIFY_MODE_INVALIDATE: u8 = 0x07;
pub(crate) const VERIFY_MODE_SOURCE_MASK: u8 = 0x20;
pub(crate) const VERIFY_MODE_SOURCE_TEMPKEY: u8 = 0x00;
pub(crate) const VERIFY_MODE_SOURCE_MSGDIGBUF: u8 = 0x20;
pub(crate) const VERIFY_MODE_MAC_FLAG: u8 = 0x80;
pub(crate) const VERIFY_KEY_B283: u8 = 0;
pub(crate) const VERIFY_KEY_K283: u16 = 0x0001;
pub(crate) const VERIFY_KEY_P256: u16 = 0x0004;
pub(crate) const VERIFY_RSP_SIZE: u8 = 4;
pub(crate) const VERIFY_RSP_SIZE_MAC: u8 = 35;
pub(crate) const WRITE_ZONE_IDX: u8 = 2;
pub(crate) const WRITE_ADDR_IDX: u8 = 3;
pub(crate) const WRITE_VALUE_IDX: u8 = 5;
pub(crate) const WRITE_MAC_VS_IDX: u8 = 9;
pub(crate) const WRITE_MAC_VL_IDX: u8 = 37;
pub(crate) const WRITE_MAC_SIZE: u8 = 32;
pub(crate) const WRITE_ZONE_MASK: u8 = 0xC3;
pub(crate) const WRITE_ZONE_WITH_MAC: u8 = 0x40;
pub(crate) const WRITE_ZONE_OTP: u8 = 1;
pub(crate) const WRITE_ZONE_DATA: u8 = 2;
pub(crate) const WRITE_RSP_SIZE: u8 = 4;

#[derive(Copy, Clone, Debug)]
pub struct Time(pub u8);

#[derive(Copy, Clone, Debug)]
pub(crate) enum EXECUTION_TIME {
    ATECC608A(ATECC608A_EXECUTION_TIME),
}

impl EXECUTION_TIME {
    pub fn get_value(self) -> ATECC608A_EXECUTION_TIME {
        match self {
            EXECUTION_TIME::ATECC608A(value) => value,
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum ATECC608A_EXECUTION_TIME {
    ATCA_AES(u8),
    ATCA_CHECKMAC(u8),
    ATCA_COUNTER(u8),
    ATCA_DERIVE_KEY(u8),
    ATCA_ECDH(u8),
    ATCA_GENDIG(u8),
    ATCA_GENKEY(u8),
    ATCA_INFO(u8),
    ATCA_KDF(u8),
    ATCA_LOCK(u8),
    ATCA_MAC(u8),
    ATCA_NONCE(u8),
    ATCA_PRIVWRITE(u8),
    ATCA_RANDOM(u8),
    ATCA_READ(u8),
    ATCA_SECUREBOOT(u8),
    ATCA_SELFTEST(u8),
    ATCA_SHA(u8),
    ATCA_SIGN(u8),
    ATCA_UPDATE_EXTRA(u8),
    ATCA_VERIFY(u8),
    ATCA_WRITE(u8),
}

impl ATECC608A_EXECUTION_TIME {
    pub fn get_tExec(self) -> Time {
        match self {
            ATECC608A_EXECUTION_TIME::ATCA_AES(ATCA_AES) => Time(27),
            ATECC608A_EXECUTION_TIME::ATCA_CHECKMAC(ATCA_CHECKMAC) => Time(40),
            ATECC608A_EXECUTION_TIME::ATCA_COUNTER(ATCA_COUNTER) => Time(25),
            ATECC608A_EXECUTION_TIME::ATCA_DERIVE_KEY(ATCA_DERIVE_KEY) => Time(50),
            ATECC608A_EXECUTION_TIME::ATCA_ECDH(ATCA_ECDH) => Time(60),
            ATECC608A_EXECUTION_TIME::ATCA_GENDIG(ATCA_GENDIG) => Time(25),
            ATECC608A_EXECUTION_TIME::ATCA_GENKEY(ATCA_GENKEY) => Time(115),
            ATECC608A_EXECUTION_TIME::ATCA_INFO(ATCA_INFO) => Time(5),
            ATECC608A_EXECUTION_TIME::ATCA_KDF(ATCA_KDF) => Time(165),
            ATECC608A_EXECUTION_TIME::ATCA_LOCK(ATCA_LOCK) => Time(35),
            ATECC608A_EXECUTION_TIME::ATCA_MAC(ATCA_MAC) => Time(55),
            ATECC608A_EXECUTION_TIME::ATCA_NONCE(ATCA_NONCE) => Time(20),
            ATECC608A_EXECUTION_TIME::ATCA_PRIVWRITE(ATCA_PRIVWRITE) => Time(50),
            ATECC608A_EXECUTION_TIME::ATCA_RANDOM(ATCA_RANDOM) => Time(23),
            ATECC608A_EXECUTION_TIME::ATCA_READ(ATCA_READ) => Time(5),
            ATECC608A_EXECUTION_TIME::ATCA_SECUREBOOT(ATCA_SECUREBOOT) => Time(80),
            ATECC608A_EXECUTION_TIME::ATCA_SELFTEST(ATCA_SELFTEST) => Time(250),
            ATECC608A_EXECUTION_TIME::ATCA_SHA(ATCA_SHA) => Time(36),
            ATECC608A_EXECUTION_TIME::ATCA_SIGN(ATCA_SIGN) => Time(115),
            ATECC608A_EXECUTION_TIME::ATCA_UPDATE_EXTRA(ATCA_UPDATE_EXTRA) => Time(10),
            ATECC608A_EXECUTION_TIME::ATCA_VERIFY(ATCA_VERIFY) => Time(105),
            ATECC608A_EXECUTION_TIME::ATCA_WRITE(ATCA_WRITE) => Time(45),
            _ => Time(0),
        }
    }
}

/// Status Constants
pub(crate) const ATCA_SUCCESS: u8 = 0x00;
pub(crate) const ATCA_CONFIG_ZONE_LOCKED: u8 = 0x01;
pub(crate) const ATCA_DATA_ZONE_LOCKED: u8 = 0x02;
pub(crate) const ATCA_WAKE_FAILED: u8 = 0xD0;
pub(crate) const ATCA_CHECKMAC_VERIFY_FAILED: u8 = 0xD1;
pub(crate) const ATCA_PARSE_ERROR: u8 = 0xD2;
pub(crate) const ATCA_STATUS_CRC: u8 = 0xD4;
pub(crate) const ATCA_STATUS_UNKNOWN: u8 = 0xD5;
pub(crate) const ATCA_STATUS_ECC: u8 = 0xD6;
pub(crate) const ATCA_STATUS_SELFTEST_ERROR: u8 = 0xD7;
pub(crate) const ATCA_FUNC_FAIL: u8 = 0xE0;
pub(crate) const ATCA_GEN_FAIL: u8 = 0xE1;
pub(crate) const ATCA_BAD_PARAM: u8 = 0xE2;
pub(crate) const ATCA_INVALID_ID: u8 = 0xE3;
pub(crate) const ATCA_INVALID_SIZE: u8 = 0xE4;
pub(crate) const ATCA_RX_CRC_ERROR: u8 = 0xE5;
pub(crate) const ATCA_RX_FAIL: u8 = 0xE6;
pub(crate) const ATCA_RX_NO_RESPONSE: u8 = 0xE7;
pub(crate) const ATCA_RESYNC_WITH_WAKEUP: u8 = 0xE8;
pub(crate) const ATCA_PARITY_ERROR: u8 = 0xE9;
pub(crate) const ATCA_TX_TIMEOUT: u8 = 0xEA;
pub(crate) const ATCA_RX_TIMEOUT: u8 = 0xEB;
pub(crate) const ATCA_TOO_MANY_COMM_RETRIES: u8 = 0xEC;
pub(crate) const ATCA_SMALL_BUFFER: u8 = 0xED;
pub(crate) const ATCA_COMM_FAIL: u8 = 0xF0;
pub(crate) const ATCA_TIMEOUT: u8 = 0xF1;
pub(crate) const ATCA_BAD_OPCODE: u8 = 0xF2;
pub(crate) const ATCA_WAKE_SUCCESS: u8 = 0xF3;
pub(crate) const ATCA_EXECUTION_ERROR: u8 = 0xF4;
pub(crate) const ATCA_UNIMPLEMENTED: u8 = 0xF5;
pub(crate) const ATCA_ASSERT_FAILURE: u8 = 0xF6;
pub(crate) const ATCA_TX_FAIL: u8 = 0xF7;
pub(crate) const ATCA_NOT_LOCKED: u8 = 0xF8;
pub(crate) const ATCA_NO_DEVICES: u8 = 0xF9;
pub(crate) const ATCA_HEALTH_TEST_ERROR: u8 = 0xFA;
pub(crate) const ATCA_ALLOC_FAILURE: u8 = 0xFB;
pub(crate) const ATCA_WATCHDOG_ABOUT_TO_EXPIRE: u8 = 0xEE;

pub struct StatusError(pub u8, pub ATCA_ERRORS);
pub(crate) enum DECODE_ERROR {}

impl DECODE_ERROR {
    pub fn get_error(value: u8) -> StatusError {
        match value {
            0x00 => StatusError (ATCA_SUCCESS, ATCA_ERRORS::NoError("StatusSuccess")),
            0x01 => StatusError (ATCA_CHECKMAC_VERIFY_FAILED, ATCA_ERRORS::CheckmacVerifyFailedError("response status byte indicates CheckMac/Verify failure, (status byte = 0x01)")),
            0x03 => StatusError (ATCA_PARSE_ERROR, ATCA_ERRORS::ParseError("response status byte indicates parsing, error(status byte = 0x03)")),
            0x05 => StatusError (ATCA_STATUS_ECC, ATCA_ERRORS::EccFaultError("response status byte is ECC fault (status byte = 0x05)")),
            0x07 => StatusError (ATCA_STATUS_SELFTEST_ERROR, ATCA_ERRORS::SelfTestError("response status byte is Self Test Error, chip in failure mode (status byte = 0x07)")),
            0x08 => StatusError (ATCA_HEALTH_TEST_ERROR, ATCA_ERRORS::HealthTestError("random number generator health test error")),
            0x0F => StatusError (ATCA_EXECUTION_ERROR, ATCA_ERRORS::ExecutionError("chip was in a state where it could not execute the command, response, status byte indicates command execution error (status byte = 0x0F)")),
            0x11 => StatusError (ATCA_WAKE_SUCCESS, ATCA_ERRORS::NoError("WakeSuccess")),
            0xEE => StatusError (ATCA_WATCHDOG_ABOUT_TO_EXPIRE, ATCA_ERRORS::WatchDogAboutToExpireError("response status indicates insufficient time to execute the given commmand before watchdog timer expires (status byte = 0xEE)")),
            0xFF => StatusError (ATCA_STATUS_CRC, ATCA_ERRORS::CrcError("incorrect CRC received")),
            _    => StatusError (ATCA_UNIMPLEMENTED, ATCA_ERRORS::UnimplementedError),
        }
    }
}
pub enum ATCA_ERRORS {
    ConfigZoneLockedError(&'static str),
    DataZoneLockedError(&'static str),
    WakeFailedError(&'static str),
    CheckmacVerifyFailedError(&'static str),
    ParseError(&'static str),
    WatchDogAboutToExpireError(&'static str),
    CrcError(&'static str),
    StatusUnknownError(&'static str),
    EccFaultError(&'static str),
    SelfTestError(&'static str),
    HealthTestError(&'static str),
    FunctionError(&'static str),
    GenericError(&'static str),
    BadArgumentError(&'static str),
    InvalidIdentifierError(&'static str),
    InvalidSizeError(&'static str),
    BadCrcError(&'static str),
    ReceiveError(&'static str),
    NoResponseError(&'static str),
    ResyncWithWakeupError(&'static str),
    ParityError(&'static str),
    TransmissionTimeoutError(&'static str),
    ReceiveTimeoutError(&'static str),
    CommunicationError(&'static str),
    TimeOutError(&'static str),
    BadOpcodeError(&'static str),
    ExecutionError(&'static str),
    UnimplementedError,
    AssertionFailure(&'static str),
    TransmissionError(&'static str),
    ZoneNotLockedError(&'static str),
    NoDevicesFoundError(&'static str),
    NoError(&'static str),
}

impl ATCA_ERRORS {
    pub fn get_string_error(self) -> &'static str {
        match self {
            ATCA_ERRORS::ConfigZoneLockedError(val) => val,
            ATCA_ERRORS::CheckmacVerifyFailedError(val) => val,
            ATCA_ERRORS::ParseError(val) => val,
            ATCA_ERRORS::EccFaultError(val) => val,
            ATCA_ERRORS::SelfTestError(val) => val,
            ATCA_ERRORS::HealthTestError(val) => val,
            ATCA_ERRORS::ExecutionError(val) => val,
            ATCA_ERRORS::NoError(val) => val,
            ATCA_ERRORS::WatchDogAboutToExpireError(val) => val,
            ATCA_ERRORS::CrcError(val) => val,
            _ => "Unimplemented Error",
        }
    }
}

/// Packet COUNTS
pub enum PKT_COUNT {
    ATCA_KEY_COUNT,
    AES_COUNT,
    CHECKMAC_COUNT,
    COUNTER_COUNT,
    DERIVE_KEY_COUNT_SMALL,
    DERIVE_KEY_COUNT_LARGE,
    ECDH_COUNT,
    GENDIG_COUNT,
    GENKEY_COUNT,
    HMAC_COUNT,
    INFO_COUNT,
    LOCK_COUNT,
    MAC_COUNT_SHORT,
    MAC_COUNT_LONG,
    NONCE_COUNT_SHORT,
    NONCE_COUNT_LONG,
    NONCE_COUNT_LONG_64,
    PAUSE_COUNT,
    PRIVWRITE_COUNT,
    RANDOM_COUNT,
    READ_COUNT,
    SECUREBOOT_COUNT_DIG,
    SECUREBOOT_COUNT_DIG_SIG,
    SELFTEST_COUNT,
    SHA_COUNT_SHORT,
    SHA_COUNT_LONG,
    SIGN_COUNT,
    UPDATE_COUNT,
    VERIFY_256_STORED_COUNT,
    VERIFY_283_STORED_COUNT,
    VERIFY_256_VALIDATE_COUNT,
    VERIFY_283_VALIDATE_COUNT,
    VERIFY_256_EXTERNAL_COUNT,
    VERIFY_283_EXTERNAL_COUNT,
}

impl PKT_COUNT {
    pub fn get_pkt_count(self) -> u8 {
        match self {
            PKT_COUNT::ATCA_KEY_COUNT => 16,
            PKT_COUNT::AES_COUNT => 23,
            PKT_COUNT::CHECKMAC_COUNT => 84,
            PKT_COUNT::COUNTER_COUNT => 7,
            PKT_COUNT::DERIVE_KEY_COUNT_SMALL => 7,
            PKT_COUNT::DERIVE_KEY_COUNT_LARGE => 39,
            PKT_COUNT::ECDH_COUNT => 7 + 64,
            PKT_COUNT::GENDIG_COUNT => 7,
            PKT_COUNT::GENKEY_COUNT => 7,
            PKT_COUNT::HMAC_COUNT => 7,
            PKT_COUNT::INFO_COUNT => 7,
            PKT_COUNT::LOCK_COUNT => 7,
            PKT_COUNT::MAC_COUNT_SHORT => 7,
            PKT_COUNT::MAC_COUNT_LONG => 39,
            PKT_COUNT::NONCE_COUNT_SHORT => 7 + 20,
            PKT_COUNT::NONCE_COUNT_LONG => 7 + 32,
            PKT_COUNT::NONCE_COUNT_LONG_64 => 7 + 64,
            PKT_COUNT::PAUSE_COUNT => 7,
            PKT_COUNT::PRIVWRITE_COUNT => 75,
            PKT_COUNT::RANDOM_COUNT => 7,
            PKT_COUNT::READ_COUNT => 7,
            PKT_COUNT::SECUREBOOT_COUNT_DIG => 7 + 32,
            PKT_COUNT::SECUREBOOT_COUNT_DIG_SIG => 7 + 32 + 64,
            PKT_COUNT::SELFTEST_COUNT => 7,
            PKT_COUNT::SHA_COUNT_SHORT => 7,
            PKT_COUNT::SHA_COUNT_LONG => 7,
            PKT_COUNT::SIGN_COUNT => 7,
            PKT_COUNT::UPDATE_COUNT => 7,
            PKT_COUNT::VERIFY_256_STORED_COUNT => 71,
            PKT_COUNT::VERIFY_283_STORED_COUNT => 79,
            PKT_COUNT::VERIFY_256_VALIDATE_COUNT => 90,
            PKT_COUNT::VERIFY_283_VALIDATE_COUNT => 98,
            PKT_COUNT::VERIFY_256_EXTERNAL_COUNT => 135,
            PKT_COUNT::VERIFY_283_EXTERNAL_COUNT => 151,
            _ => 0,
        }
    }
}

/// Test Enum
#[derive(Copy, Clone, Debug)]
pub(crate) enum TEST_ENUM {
    SHA_TEST_DATA_1,
    SHA_TEST_DATA_2,
}

impl<'a> TEST_ENUM {
    pub fn get_value(self) -> &'a [u8] {
        match self {
            TEST_ENUM::SHA_TEST_DATA_1 => &[0x01, 0x02, 0x03, 0x04, 0x05],
            TEST_ENUM::SHA_TEST_DATA_2 => &[0x1f, 0xe6, 0x54, 0xc1, 0x80, 0x88, 0xe7, 0xfe, 0xf0, 0x84, 0xf9, 0x8a, 0x1a, 0x12,
                                            0xdb, 0x84, 0x69, 0x54, 0x34, 0x25, 0x06, 0xf5, 0x17, 0x69, 0x18, 0x9e, 0x3a, 0x90,
                                            0x79, 0x2f, 0xd3, 0x28, 0xcf, 0x51, 0x5d, 0x1e, 0x44, 0xbb, 0xa4, 0x9d, 0x34, 0xde,
                                            0x3b, 0x99, 0xca, 0x4c, 0x5e, 0x7e, 0xf4, 0x3a, 0xf6, 0xda, 0x41, 0x3c, 0x91, 0xc7,
                                            0x98, 0x70, 0xd4, 0x87, 0x68, 0xac, 0x74, 0x5b, 0x1f, 0xe6, 0x54, 0xc1, 0x80, 0x88,
                                            0xe7, 0xfe, 0xf0, 0x84, 0xf9, 0x8a, 0x1a, 0x12, 0xdb, 0x84, 0x69, 0x54, 0x34, 0x25,
                                            0x06, 0xf5, 0x17, 0x69, 0x18, 0x9e, 0x3a, 0x90, 0x79, 0x2f, 0xd3, 0x28],
        }
    }
}

// ConfigZoneLockedError(&'static str),
//     DataZoneLockedError("Configuration Enabled"),
//     WakeFailedError("Device Wake failed"),
//     CheckmacVerifyFailedError("response status byte indicates CheckMac/Verify failure, (status byte = 0x01)"),
//     ParseError("response status byte indicates parsing, error(status byte = 0x03)"),
//     // WatchDogAboutToExpireError( "response status indicates insufficient time to execute the given commmand before watchdog timer expires (status byte = 0xEE)"),
// CrcError("response status byte indicates CRC error (status byte = 0xFF)"),
// StatusUnknownError("Response status byte is unknown"),
// EccFaultError("response status byte is ECC fault (status byte = 0x05)"),
// SelfTestError("response status byte is Self Test Error, chip in failure mode (status byte = 0x07)"),
// HealthTestError("random number generator health test error"),
// FunctionError("Function could not execute due to incorrect condition / state."),
// GenericError("unspecified error"),
// BadArgumentError("bad argument (out of range, null pointer, etc.)"),
// InvalidIdentifierError("invalid device id, id not set"),
// InvalidSizeError("Count value is out of range or greater than buffer size."),
// BadCrcError("incorrect CRC received"),
// ReceiveError("Timed out while waiting for response. Number of bytes received is > 0."),
// NoResponseError("error while the Command layer is polling for a command response."),
// ResyncWithWakeupError("Re-synchronization succeeded, but only after generating a Wake-up"),
// ParityError("for protocols needing parity"),
// TransmissionTimeoutError("for Microchip PHY protocol,timeout on transmission waiting for master"),
// ReceiveTimeoutError("for Microchip PHY protocol, timeout on receipt waiting for master"),
// CommunicationError("Communication with device failed.Same as in hardware dependent modules."),
// TimeOutError("Timed out while waiting for response. Number of bytes received is 0."),
// BadOpcodeError("Opcode is not supported by the device"),
// ExecutionError("chip was in a state where it could not execute the command, response, status byte indicates command execution error (status byte = 0x0F)"),
// UnimplementedError("Function or some element of it hasn't been implemented yet"),
// AssertionFailure("Code failed run-time consistency check"),
// TransmissionError("Failed to write"),
// ZoneNotLockedError("required zone was not locked"),
// NoDevicesFoundError("For protocols that support device discovery (kit protocol), no devices were found"),
// NoError("NoError"),
