use bc_crypto::{memzero, memzero_vec_vec_u8};

use crate::{
    MAX_SECRET_LEN, Result,
    hazmat::{
        bitslice, bitslice_setall, gf256_add, gf256_inv, gf256_mul, unbitslice,
    },
};

/// Calculate the lagrange basis coefficients for the lagrange polynomial
/// defined byt the x coordinates xc at the value x.
/// inputs: values: pointer to an array to write the values
///         n: number of points - length of the xc array, 0 < n <= 32
///         xc: array of x components to use as interpolating points
///         x: x coordinate to evaluate lagrange polynomials at
/// After the function runs, the values array should hold data satisfying
/// the following:
///                ---     (x-xc[j])
///   values[i] =  | |   -------------
///              j != i  (xc[i]-xc[j])
fn hazmat_lagrange_basis(values: &mut [u8], n: usize, xc: &[u8], x: u8) {
    // call the contents of xc [ x0 x1 x2 ... xn-1 ]
    let mut xx = [0u8; 32 + 16];
    let mut x_slice = [0u32; 8];
    let mut lxi = vec![[0u32; 8]; n];
    let mut numerator = [0u32; 8];
    let mut denominator = [0u32; 8];
    let mut temp = [0u32; 8];
    xx[..n].copy_from_slice(&xc[..n]);

    // xx now contains bitsliced [ x0 x1 x2 ... xn-1 0 0 0 ... ]
    for i in 0..n {
        // lxi = bitsliced [ xi xi+1 xi+2 ... xi-1 0 0 0 ]
        bitslice(&mut lxi[i], &xx[i..]);
        xx[i + n] = xx[i];
    }

    bitslice_setall(&mut x_slice, x);
    bitslice_setall(&mut numerator, 1);
    bitslice_setall(&mut denominator, 1);

    for i in 1..n {
        temp = x_slice;
        gf256_add(&mut temp, &lxi[i]);
        // temp = [ x-xi+i x-xi+2 x-xi+3 ... x-xi x x x]
        let numerator2 = numerator;
        gf256_mul(&mut numerator, &numerator2, &temp);

        temp = lxi[0];
        gf256_add(&mut temp, &lxi[i]);
        // temp = [x0-xi+1 x1-xi+1 x2-xi+2 ... xn-x0 0 0 0]
        let denominator2 = denominator;
        gf256_mul(&mut denominator, &denominator2, &temp);
    }

    // At this stage the numerator contains
    // [ num0 num1 num2 ... numn 0 0 0]
    //
    // where numi = prod(j, j!=i, x-xj )
    //
    // and the denomintor contains
    // [ d0 d1 d2 ... dn 0 0 0]
    //
    // where di = prod(j, j!=i, xi-xj)

    gf256_inv(&mut temp, &mut denominator);

    // gf256_inv uses exponentiaton to calculate inverse, so the zeros end up
    // remaining zeros.

    // tmp = [ 1/d0 1/d1 1/d2 ... 1/dn 0 0 0]

    let numerator2 = numerator;
    gf256_mul(&mut numerator, &numerator2, &temp);

    // numerator now contains [ l_n_0(x) l_n_1(x) ... l_n_n-1(x) 0 0 0]
    // use the xx array to unpack it

    unbitslice(&mut xx, &numerator);

    // copy results to ouptut array
    values[..n].copy_from_slice(&xx[..n]);
}

/// safely interpolate the polynomial going through
/// the points (x0 [y0_0 y0_1 y0_2 ... y0_31]) , (x1 [y1_0 ...]), ...
///
/// where
///   xi points to [x0 x1 ... xn-1 ]
///   y contains an array of pointers to 32-bit arrays of y values
///   y contains [y0 y1 y2 ... yn-1]
///   and each of the yi arrays contain [yi_0 yi_i ... yi_31].
///
/// returns: on success, the number of bytes written to result
///          on failure, a negative error code
///
/// inputs: n: number of points to interpolate
///         xi: x coordinates for points (array of length n)
///         yl: length of y coordinate arrays
///         yij: array of n pointers to arrays of length yl
///         x: coordinate to interpolate at
///         result: space for yl bytes of interpolate data
pub fn interpolate<T>(
    n: usize,
    xi: &[u8],
    yl: usize,
    yij: &[T],
    x: u8,
) -> Result<Vec<u8>>
where
    T: AsRef<[u8]>,
{
    // The hazmat gf256 implementation needs the y-coordinate data
    // to be in 32-byte blocks
    let mut y = vec![vec![0u8; MAX_SECRET_LEN]; n];
    // let mut yv = vec![0u8; SHAMIR_MAX_SECRET_SIZE * n];
    let mut values = vec![0u8; MAX_SECRET_LEN];

    // yv[..yl].copy_from_slice(&yij[0]);
    for i in 0..n {
        y[i][..yl].copy_from_slice(yij[i].as_ref());
    }

    let mut lagrange = vec![0u8; n];
    let mut y_slice = [0u32; 8];
    let mut result_slice = [0u32; 8];
    let mut temp = [0u32; 8];

    hazmat_lagrange_basis(&mut lagrange, n, xi, x);

    bitslice_setall(&mut result_slice, 0);

    for i in 0..n {
        bitslice(&mut y_slice, &y[i]);
        bitslice_setall(&mut temp, lagrange[i]);
        let temp2 = temp;
        gf256_mul(&mut temp, &temp2, &y_slice);
        gf256_add(&mut result_slice, &temp);
    }

    unbitslice(&mut values, &result_slice);
    // the calling code is only expecting yl bytes back
    let mut result = vec![0u8; yl];
    result[..yl].copy_from_slice(&values[..yl]);

    // clean up stack
    memzero(&mut lagrange);
    memzero(&mut y_slice);
    memzero(&mut result_slice);
    memzero(&mut temp);
    memzero_vec_vec_u8(&mut y);
    // memzero(&mut yv);
    memzero(&mut values);

    Ok(result)
}
