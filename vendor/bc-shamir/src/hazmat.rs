use bc_crypto::memzero;

pub fn bitslice(r: &mut [u32; 8], x: &[u8]) {
    assert!(x.len() >= 32);
    memzero(r);
    for (arr_idx, cur) in x.iter().enumerate().take(32) {
        let cur = *cur as u32;
        for (bit_idx, r) in r.iter_mut().enumerate() {
            *r |= ((cur & (1u32.wrapping_shl(bit_idx as u32)))
                .wrapping_shr(bit_idx as u32))
            .wrapping_shl(arr_idx as u32);
        }
    }
}

pub fn unbitslice(r: &mut [u8], x: &[u32; 8]) {
    assert!(r.len() >= 32);
    memzero(r);
    for (bit_idx, cur) in x.iter().enumerate() {
        for (arr_idx, r) in r.iter_mut().take(32).enumerate() {
            *r |= (((cur & (1u32.wrapping_shl(arr_idx as u32)))
                .wrapping_shr(arr_idx as u32))
            .wrapping_shl(bit_idx as u32)) as u8;
        }
    }
}

pub fn bitslice_setall(r: &mut [u32; 8], x: u8) {
    r.iter_mut().enumerate().for_each(|(idx, r)| {
        *r = (((((x as u32) & (1u32.wrapping_shl(idx as u32)))
            .wrapping_shl(31 - idx as u32)) as i32)
            .wrapping_shr(31)) as u32;
    });
}

/// Add (XOR) `r` with `x` and store the result in `r`.
pub fn gf256_add(r: &mut [u32; 8], x: &[u32; 8]) {
    r.iter_mut().zip(x.iter()).for_each(|(r, x)| *r ^= x);
}

/// Safely multiply two bitsliced polynomials in GF(2^8) reduced by
/// x^8 + x^4 + x^3 + x + 1. `r` and `a` may overlap, but overlapping of `r`
/// and `b` will produce an incorrect result! If you need to square a polynomial
/// use `gf256_square` instead.
pub fn gf256_mul(r: &mut [u32; 8], a: &[u32; 8], b: &[u32; 8]) {
    // This function implements Russian Peasant multiplication on two
    // bitsliced polynomials.
    //
    // I personally think that these kinds of long lists of operations
    // are often a bit ugly. A double for loop would be nicer and would
    // take up a lot less lines of code.
    // However, some compilers seem to fail in optimizing these kinds of
    // loops. So we will just have to do this by hand.
    let mut a2 = *a;

    r[0] = a2[0] & b[0];
    r[1] = a2[1] & b[0];
    r[2] = a2[2] & b[0];
    r[3] = a2[3] & b[0];
    r[4] = a2[4] & b[0];
    r[5] = a2[5] & b[0];
    r[6] = a2[6] & b[0];
    r[7] = a2[7] & b[0];
    a2[0] ^= a2[7]; // reduce
    a2[2] ^= a2[7];
    a2[3] ^= a2[7];

    r[0] ^= a2[7] & b[1]; // add
    r[1] ^= a2[0] & b[1];
    r[2] ^= a2[1] & b[1];
    r[3] ^= a2[2] & b[1];
    r[4] ^= a2[3] & b[1];
    r[5] ^= a2[4] & b[1];
    r[6] ^= a2[5] & b[1];
    r[7] ^= a2[6] & b[1];
    a2[7] ^= a2[6]; // reduce
    a2[1] ^= a2[6];
    a2[2] ^= a2[6];

    r[0] ^= a2[6] & b[2]; // add
    r[1] ^= a2[7] & b[2];
    r[2] ^= a2[0] & b[2];
    r[3] ^= a2[1] & b[2];
    r[4] ^= a2[2] & b[2];
    r[5] ^= a2[3] & b[2];
    r[6] ^= a2[4] & b[2];
    r[7] ^= a2[5] & b[2];
    a2[6] ^= a2[5]; // reduce
    a2[0] ^= a2[5];
    a2[1] ^= a2[5];

    r[0] ^= a2[5] & b[3]; // add
    r[1] ^= a2[6] & b[3];
    r[2] ^= a2[7] & b[3];
    r[3] ^= a2[0] & b[3];
    r[4] ^= a2[1] & b[3];
    r[5] ^= a2[2] & b[3];
    r[6] ^= a2[3] & b[3];
    r[7] ^= a2[4] & b[3];
    a2[5] ^= a2[4]; // reduce
    a2[7] ^= a2[4];
    a2[0] ^= a2[4];

    r[0] ^= a2[4] & b[4]; // add
    r[1] ^= a2[5] & b[4];
    r[2] ^= a2[6] & b[4];
    r[3] ^= a2[7] & b[4];
    r[4] ^= a2[0] & b[4];
    r[5] ^= a2[1] & b[4];
    r[6] ^= a2[2] & b[4];
    r[7] ^= a2[3] & b[4];
    a2[4] ^= a2[3]; // reduce
    a2[6] ^= a2[3];
    a2[7] ^= a2[3];

    r[0] ^= a2[3] & b[5]; // add
    r[1] ^= a2[4] & b[5];
    r[2] ^= a2[5] & b[5];
    r[3] ^= a2[6] & b[5];
    r[4] ^= a2[7] & b[5];
    r[5] ^= a2[0] & b[5];
    r[6] ^= a2[1] & b[5];
    r[7] ^= a2[2] & b[5];
    a2[3] ^= a2[2]; // reduce
    a2[5] ^= a2[2];
    a2[6] ^= a2[2];

    r[0] ^= a2[2] & b[6]; // add
    r[1] ^= a2[3] & b[6];
    r[2] ^= a2[4] & b[6];
    r[3] ^= a2[5] & b[6];
    r[4] ^= a2[6] & b[6];
    r[5] ^= a2[7] & b[6];
    r[6] ^= a2[0] & b[6];
    r[7] ^= a2[1] & b[6];
    a2[2] ^= a2[1]; // reduce
    a2[4] ^= a2[1];
    a2[5] ^= a2[1];

    r[0] ^= a2[1] & b[7]; // add
    r[1] ^= a2[2] & b[7];
    r[2] ^= a2[3] & b[7];
    r[3] ^= a2[4] & b[7];
    r[4] ^= a2[5] & b[7];
    r[5] ^= a2[6] & b[7];
    r[6] ^= a2[7] & b[7];
    r[7] ^= a2[0] & b[7];
}

/// Square `x` in GF(2^8) and write the result to `r`. `r` and `x` may overlap.
pub fn gf256_square(r: &mut [u32; 8], x: &[u32; 8]) {
    let mut r8: u32;
    let mut r10: u32;
    // Use the Freshman's Dream rule to square the polynomial
    // Assignments are done from 7 downto 0, because this allows the user
    // to execute this function in-place (e.g. `gf256_square(r, r);`).
    let r14 = x[7];
    let r12 = x[6];
    r10 = x[5];
    r8 = x[4];
    r[6] = x[3];
    r[4] = x[2];
    r[2] = x[1];
    r[0] = x[0];

    // Reduce with  x^8 + x^4 + x^3 + x + 1 until order is less than 8
    r[7] = r14; // r[7] was 0
    r[6] ^= r14;
    r10 ^= r14;
    // Skip, because r13 is always 0
    r[4] ^= r12;
    r[5] = r12; // r[5] was 0
    r[7] ^= r12;
    r8 ^= r12;
    // Skip, because r11 is always 0
    r[2] ^= r10;
    r[3] = r10; // r[3] was 0
    r[5] ^= r10;
    r[6] ^= r10;
    r[1] = r14; // r[1] was 0
    r[2] ^= r14; // Substitute r9 by r14 because they will always be equal
    r[4] ^= r14;
    r[5] ^= r14;
    r[0] ^= r8;
    r[1] ^= r8;
    r[3] ^= r8;
    r[4] ^= r8;
}

/// Invert `x` in GF(2^8) and write the result to `r`
pub fn gf256_inv(r: &mut [u32; 8], x: &mut [u32; 8]) {
    let mut y = [0u32; 8];
    let mut z = [0u32; 8];

    gf256_square(&mut y, x); // y = x^2
    let y2 = y;
    gf256_square(&mut y, &y2); // y = x^4
    gf256_square(r, &y); // r = x^8
    gf256_mul(&mut z, r, x); // z = x^9
    let r2 = *r;
    gf256_square(r, &r2); // r = x^16
    let r2 = *r;
    gf256_mul(r, &r2, &z); // r = x^25
    let r2 = *r;
    gf256_square(r, &r2); // r = x^50
    gf256_square(&mut z, r); // z = x^100
    let z2 = z;
    gf256_square(&mut z, &z2); // z = x^200
    let r2 = *r;
    gf256_mul(r, &r2, &z); // r = x^250
    let r2 = *r;
    gf256_mul(r, &r2, &y); // r = x^254
}
