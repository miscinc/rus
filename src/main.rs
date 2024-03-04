//*  1  /////////////////////////////////////////////////////////////////////////////////////////////////////////


// Import necessary modules and crates
// use aes::Aes128; // Adjust based on the AES variant you are using

// Constants for AES configuration
const NB: u32 = 4; // Number of columns (32-bit words) in the state, constant for AES

//if mode is 258
#[cfg(feature = "aes256")]
const NK: u32 = 8;
#[cfg(feature = "aes256")]
const NR: u32 = 14;

// if mode is 192
#[cfg(feature = "aes192")]
const NK: u32 = 6; 
#[cfg(feature = "aes192")]
const NR: u32 = 12;

// default
#[cfg(not(any(feature = "aes256", feature = "aes192")))]
const NK: u32 = 4; // Default to AES-128
#[cfg(not(any(feature = "aes256", feature = "aes192")))]
const NR: u32 = 10; // Default to AES-128



//? both type u32, NB always set to 4, 
// NK -> u32 value
// NR -> u32 value
// NB -> u32 value

//  2  /////////////////////////////////////////////////////////////////////////////////////////////////////////

// sets State var w/ tuple of u8, 4, by 4 
type State = [[u8; 4]; 4];


//* */ 16 rows, 16 columns, 16x16=256; what are these values?
// default values 
const SBOX: [u8; 256] = [
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 ];

// if CBC is enabled then use this, maybe some sort of config for differing versions?
const RSBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d ];


const RCON: [u8; 11] = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 ];


//  3  /////////////////////////////////////////////////////////////////////////////////////////////////////////

fn get_sbox_value(num: u8) -> u8 {
    SBOX[num as usize]
}

fn key_expansion(round_key: &mut [u8], key: &[u8]) {
    //? // the ofiginal, i think nk/nb are defined already?o    // unsigned i, j, k;k nk/nb are defined already?
    // unsigned i, j, k;
    // uint8_t tempa[4]; // Used for the column/row operations 
    

    let nk = 4; // Nk value, depends on AES version (AES-128, AES-192, AES-256)
    let nb = 4; // Nb is always 4 for AES
    let nr = 10; // Nr value, depends on AES version (AES-128 -> 10, AES-192 -> 12, AES-256 -> 14)

    for i in 0..nk {
        round_key[(i * 4)..(i * 4 + 4)].copy_from_slice(&key[(i * 4)..(i * 4 + 4)]);
        // 4 lines
    }

    for i in nk..(nb * (nr + 1)) {
        let mut tempa = [0u8; 4];
        tempa.copy_from_slice(&round_key[((i - 1) * 4)..(i * 4)]);
        // 4 lines

        //? only if i % Nk == 0 
        if i % nk == 0 {
            
            // Function RotWord()
            tempa.rotate_left(1);
            //? 4 lines

            // Function Subword()
            for j in 0..4 {
                tempa[j] = get_sbox_value(tempa[j]);
                // 4 lines
            }

            tempa[0] ^= RCON[i / nk];
        }

        #[cfg(feature = "aes256")]
        if i % nk == 4 {
            for j in 0..4 {
                tempa[j] = get_sbox_value(tempa[j]);
                // 4 lines
            }
        }

        let j = i * 4;
        let k = (i - nk) * 4;

        // Function Subword()
        for l in 0..4 {
            round_key[j + l] = round_key[k + l] ^ tempa[l];
            // 4 lines
        }
    }
}


//  4  /////////////////////////////////////////////////////////////////////////////////////////////////////////

struct AesCtx {
    round_key: [u8; 240], // Adjust size based on AES variant (AES-128, AES-192, AES-256)
    #[cfg(any(feature = "CBC", feature = "CTR"))]
    iv: [u8; 16], // AES block size is 16 bytes
}

impl AesCtx {
    // Initialize AES context with a key
    pub fn new(key: &[u8]) -> Self {
        let mut ctx = Self {
            round_key: [0; 240], // Adjust size based on the key length
            #[cfg(any(feature = "CBC", feature = "CTR"))]
            iv: [0; 16],
        };
        key_expansion(&mut ctx.round_key, key);
        ctx
    }

    // Initialize AES context with a key and IV (for CBC or CTR mode)
    #[cfg(any(feature = "CBC", feature = "CTR"))]
    pub fn new_with_iv(key: &[u8], iv: &[u8]) -> Self {
        let mut ctx = Self::new(key);
        ctx.set_iv(iv);
        ctx
    }

    // Set or update the IV in the AES context (for CBC or CTR mode)
    #[cfg(any(feature = "CBC", feature = "CTR"))]
    pub fn set_iv(&mut self, iv: &[u8]) {
        self.iv.copy_from_slice(iv);
    }
}

// AddRoundKey step in Rust
fn add_round_key(round: u8, state: &mut State, round_key: &[u8]) {
    for i in 0..4 {
        for j in 0..4 {
            state[i][j] ^= round_key[(round as usize * NB * 4) + (i * NB) + j];
        }
    }
}

// SubBytes step in Rust
fn sub_bytes(state: &mut State) {
    for i in 0..4 {
        for j in 0..4 {
            state[j][i] = SBOX[state[j][i] as usize];
        }
    }
}


//*  5  /////////////////////////////////////////////////////////////////////////////////////////////////////////

fn shift_rows(state: &mut State) {
    let mut temp;

    // Rotate first row 1 column to the left
    temp = state[0][1];
    state[0][1] = state[1][1];
    state[1][1] = state[2][1];
    state[2][1] = state[3][1];
    state[3][1] = temp;

    // Rotate second row 2 columns to the left
    temp = state[0][2];
    state[0][2] = state[2][2];
    state[2][2] = temp;

    temp = state[1][2];
    state[1][2] = state[3][2];
    state[3][2] = temp;

    // Rotate third row 3 columns to the left
    temp = state[0][3];
    state[0][3] = state[3][3];
    state[3][3] = state[2][3];
    state[2][3] = state[1][3];
    state[1][3] = temp;
}


//*  6  /////////////////////////////////////////////////////////////////////////////////////////////////////////

fn mix_columns(state: &mut State) {
    for i in 0..4 {
        let t = state[i][0];
        let tmp = state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3];
        let tm = state[i][0] ^ state[i][1];
        let tm = xtime(tm);
        state[i][0] ^= tm ^ tmp;
        let tm = state[i][1] ^ state[i][2];
        let tm = xtime(tm);
        state[i][1] ^= tm ^ tmp;
        let tm = state[i][2] ^ state[i][3];
        let tm = xtime(tm);
        state[i][2] ^= tm ^ tmp;
        let tm = state[i][3] ^ t;
        let tm = xtime(tm);
        state[i][3] ^= tm ^ tmp;
    }
}

// Polynomial multiplication in GF(2^8)
fn multiply(x: u8, y: u8) -> u8 {
    ((y & 1) * x) ^
    ((y >> 1 & 1) * xtime(x)) ^
    ((y >> 2 & 1) * xtime(xtime(x))) ^
    ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
    ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x)))))
}
// was another version in original. i think this is if you run with MULTIPLY func or what ever as true

//*  7  /////////////////////////////////////////////////////////////////////////////////////////////////////////
//? switched to chatgpt 3.5

// InvMixColumns
// InvSubBytes
// InvShiftRows

fn inv_mix_columns(state: &mut [[u8; 4]; 4]) {
    for i in 0..4 {
        let a = state[i][0];
        let b = state[i][1];
        let c = state[i][2];
        let d = state[i][3];

        state[i][0] = multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(c, 0x0d) ^ multiply(d, 0x09);
        state[i][1] = multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(c, 0x0b) ^ multiply(d, 0x0d);
        state[i][2] = multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(c, 0x0e) ^ multiply(d, 0x0b);
        state[i][3] = multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(c, 0x09) ^ multiply(d, 0x0e);
    }
}

fn inv_sub_bytes(state: &mut [[u8; 4]; 4]) {
    for i in 0..4 {
        for j in 0..4 {
            state[j][i] =  get_sbox_value((*state)[j][i]) // RSBOX[state[j][i] as usize];
        }
    }
}
// get_sbox_invert -> (rsbox[(num)])


fn inv_shift_rows(state: &mut [[u8; 4]; 4]) {
    let mut temp: u8;

    // Rotate first row 1 column to the right
    temp = state[3][1];
    state[3][1] = state[2][1];
    state[2][1] = state[1][1];
    state[1][1] = state[0][1];
    state[0][1] = temp;

    // Rotate second row 2 columns to the right
    temp = state[0][2];
    state[0][2] = state[2][2];
    state[2][2] = temp;

    temp = state[1][2];
    state[1][2] = state[3][2];
    state[3][2] = temp;

    // Rotate third row 3 columns to the right
    temp = state[0][3];
    state[0][3] = state[1][3];
    state[1][3] = state[2][3];
    state[2][3] = temp;
}



//*  8  /////////////////////////////////////////////////////////////////////////////////////////////////////////

// Cipher
// InvCipher

fn cipher(state: &mut [[u8; 4]; 4], round_key: &[u8]) {
    let mut round: u8 = 0;

    // Add the First round key to the state before starting the rounds.
    add_round_key(0, state, round_key);

    // There will be NR rounds.
    // The first NR-1 rounds are identical.
    // These NR rounds are executed in the loop below.
    // Last one without MixColumns()
    for round in 1..=NR {
        sub_bytes(state);
        shift_rows(state);
        if round == NR {
            break;
        }
        mix_columns(state);
        add_round_key(round, state, round_key);
    }
    // Add round key to last round
    add_round_key(NR, state, round_key);
}

#[cfg(any(feature = "cbc", feature = "ecb"))]
fn inv_cipher(state: &mut [[u8; 4]; 4], round_key: &[u8]) {
    let mut round: u8 = 0;

    // Add the First round key to the state before starting the rounds.
    add_round_key(NR, state, round_key);

    // There will be NR rounds.
    // The first NR-1 rounds are identical.
    // These NR rounds are executed in the loop below.
    // Last one without InvMixColumn()
    for round in (0..NR).rev() {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(round, state, round_key);
        if round == 0 {
            break;
        }
        inv_mix_columns(state);
    }
}


//*  9  /////////////////////////////////////////////////////////////////////////////////////////////////////////

#[cfg(feature = "ecb")]
fn aes_ecb_encrypt(ctx: &AES_ctx, buf: &mut [u8]) {
    // The next function call encrypts the PlainText with the Key using AES algorithm.
    cipher(unsafe { &mut *(buf as *mut [u8; 16]) }, &ctx.RoundKey);
}

#[cfg(feature = "ecb")]
fn aes_ecb_decrypt(ctx: &AES_ctx, buf: &mut [u8]) {
    // The next function call decrypts the PlainText with the Key using AES algorithm.
    inv_cipher(unsafe { &mut *(buf as *mut [u8; 16]) }, &ctx.RoundKey);
}

#[cfg(feature = "cbc")]
fn xor_with_iv(buf: &mut [u8], iv: &[u8]) {
    for i in 0..AES_BLOCKLEN {
        buf[i] ^= iv[i];
    }
}


//*  10  /////////////////////////////////////////////////////////////////////////////////////////////////////////

#[cfg(feature = "cbc")]
fn aes_cbc_encrypt_buffer(ctx: &mut AES_ctx, buf: &mut [u8], length: usize) {
    let mut iv = &mut ctx.Iv;
    for i in (0..length).step_by(AES_BLOCKLEN) {
        xor_with_iv(&mut buf[i..i + AES_BLOCKLEN], iv);
        cipher(unsafe { &mut *(buf[i..i + AES_BLOCKLEN].as_mut_ptr() as *mut [u8; 16]) }, &ctx.RoundKey);
        iv = &mut buf[i..i + AES_BLOCKLEN];
    }
    // store Iv in ctx for next call
    ctx.Iv.copy_from_slice(iv);
}

#[cfg(feature = "cbc")]
fn aes_cbc_decrypt_buffer(ctx: &mut AES_ctx, buf: &mut [u8], length: usize) {
    let mut store_next_iv = [0u8; AES_BLOCKLEN];
    for i in (0..length).step_by(AES_BLOCKLEN) {
        store_next_iv.copy_from_slice(&buf[i..i + AES_BLOCKLEN]);
        inv_cipher(unsafe { &mut *(buf[i..i + AES_BLOCKLEN].as_mut_ptr() as *mut [u8; 16]) }, &ctx.RoundKey);
        xor_with_iv(&mut buf[i..i + AES_BLOCKLEN], &ctx.Iv);
        ctx.Iv.copy_from_slice(&store_next_iv);
    }
}



//*  11  /////////////////////////////////////////////////////////////////////////////////////////////////////////

#[cfg(feature = "ctr")]
fn aes_ctr_xcrypt_buffer(ctx: &mut AES_ctx, buf: &mut [u8], length: usize) {
    let mut buffer = [0u8; AES_BLOCKLEN];
  
    let mut bi = AES_BLOCKLEN;
    for (i, byte) in buf.iter_mut().enumerate() {
        if bi == AES_BLOCKLEN {
            // Regenerate xor complement in buffer
            buffer.copy_from_slice(&ctx.Iv);
            cipher(unsafe { &mut *(buffer.as_mut_ptr() as *mut [u8; 16]) }, &ctx.RoundKey);

            // Increment Iv and handle overflow
            for bi in (0..AES_BLOCKLEN).rev() {
                // Increment will overflow
                if ctx.Iv[bi] == 255 {
                    ctx.Iv[bi] = 0;
                } else {
                    ctx.Iv[bi] += 1;
                    break;
                }
            }
            bi = 0;
        }

        *byte ^= buffer[bi];
        bi += 1;
    }
}


/*
@misc{
    and contributors_2004, 
    title={Tiny AES in C}, 
    url={
        https://github.com/kokke/tiny-AES-c}, 
        journal={Github.com}, 
        author={
            and contributors, 
            kokke}, 
            year={2004}, 
            month={Jan}
        }
    }
)
*/