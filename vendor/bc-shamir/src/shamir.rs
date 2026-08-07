use bc_crypto::{hash::hmac_sha256, memzero, memzero_vec_vec_u8};
use bc_rand::RandomNumberGenerator;

use crate::{
    Error, MAX_SECRET_LEN, MAX_SHARE_COUNT, MIN_SECRET_LEN, Result,
    interpolate::interpolate,
};

const SECRET_INDEX: u8 = 255;
const DIGEST_INDEX: u8 = 254;

fn create_digest(random_data: &[u8], shared_secret: &[u8]) -> [u8; 32] {
    hmac_sha256(random_data, shared_secret)
}

fn validate_parameters(
    threshold: usize,
    share_count: usize,
    secret_length: usize,
) -> Result<()> {
    if share_count > MAX_SHARE_COUNT {
        return Err(Error::TooManyShares);
    } else if threshold < 1 || threshold > share_count {
        return Err(Error::InvalidThreshold);
    } else if secret_length > MAX_SECRET_LEN {
        return Err(Error::SecretTooLong);
    } else if secret_length < MIN_SECRET_LEN {
        return Err(Error::SecretTooShort);
    } else if secret_length & 1 != 0 {
        return Err(Error::SecretNotEvenLen);
    }
    Ok(())
}

/// Splits a secret into shares using the Shamir secret sharing algorithm.
///
/// # Arguments
///
/// * `threshold` - The minimum number of shares required to reconstruct the
///   secret. Must be greater than or equal to 1 and less than or equal to
///   `share_count`.
/// * `share_count` - The total number of shares to generate. Must be at least
///   `threshold` and less than or equal to `MAX_SHARE_COUNT`.
/// * `secret` - A byte slice containing the secret to be split. Must be at
///   least `MIN_SECRET_LEN` bytes long and at most `MAX_SECRET_LEN` bytes long.
///   The length must be an even number.
/// * `random_generator` - An implementation of the `RandomNumberGenerator`
///   trait, used to generate random data.
///
/// # Returns
///
/// A `Result` containing a vector of vectors of bytes (`Vec<Vec<u8>>`)
/// representing the shares of the secret. If the function succeeds, the
/// `Result` contains `Ok(result)`, where `result` is the vector of shares. If
/// the function fails, the `Result` contains `Err(error)`, where `error` is an
/// `Error` object describing the failure.
///
/// # Example
///
/// ```
/// use bc_shamir::split_secret;
///
/// let threshold = 2;
/// let share_count = 3;
/// let secret = b"my secret belongs to me.";
/// let mut random_generator = bc_rand::SecureRandomNumberGenerator;
///
/// let shares =
///     split_secret(threshold, share_count, secret, &mut random_generator)
///         .unwrap();
///
/// assert_eq!(shares.len(), share_count);
/// ```
pub fn split_secret(
    threshold: usize,
    share_count: usize,
    secret: &[u8],
    random_generator: &mut impl RandomNumberGenerator,
) -> Result<Vec<Vec<u8>>> {
    validate_parameters(threshold, share_count, secret.len())?;

    if threshold == 1 {
        // just return share_count copies of the secret
        let mut result = vec![vec![0u8; secret.len()]; share_count];
        for share in &mut result {
            share.copy_from_slice(secret);
        }
        Ok(result)
    } else {
        let mut x = vec![0u8; share_count];
        let mut y = vec![vec![0u8; secret.len()]; share_count];
        let mut n = 0;
        let mut result = vec![vec![0u8; secret.len()]; share_count];

        result.iter_mut().enumerate().take(threshold - 2).for_each(
            |(index, result_item)| {
                random_generator.fill_random_data(result_item);
                x[n] = index as u8;
                y[n].copy_from_slice(result_item);
                n += 1;
            },
        );

        // generate secret_length - 4 bytes worth of random data
        let mut digest = vec![0u8; secret.len()];
        random_generator.fill_random_data(&mut digest[4..]);
        // put 4 bytes of digest at the top of the digest array
        let d = create_digest(&digest[4..], secret);
        digest[..4].copy_from_slice(&d[..4]);
        x[n] = DIGEST_INDEX;
        y[n].copy_from_slice(&digest);
        n += 1;

        x[n] = SECRET_INDEX;
        y[n].copy_from_slice(secret);
        n += 1;

        result
            .iter_mut()
            .enumerate()
            .take(share_count)
            .skip(threshold - 2)
            .try_for_each(|(index, result_item)| {
                let v = interpolate(n, &x, secret.len(), &y, index as u8)?;
                result_item.copy_from_slice(&v);
                Ok(())
            })?;

        // clean up stack
        memzero(&mut digest);
        memzero(&mut x);
        memzero_vec_vec_u8(&mut y);

        Ok(result)
    }
}

/// Recovers the secret from the given shares using the Shamir secret sharing
/// algorithm.
///
/// # Arguments
///
/// * `indexes` - A slice of indexes of the shares to be used for recovering the
///   secret. These are the indexes of the shares returned by `split_secret`.
/// * `shares` - A slice of shares of the secret matching the indexes in
///   `indexes`. These are the shares returned by `split_secret`.
///
/// # Returns
///
/// A `Result` containing a vector of bytes (`Vec<u8>`) representing the secret.
/// If the function succeeds, the `Result` contains `Ok(result)`, where `result`
/// is the vector of bytes representing the secret. If the function fails, the
/// `Result` contains `Err(error)`, where `error` is an `Error` object
/// describing the failure.
///
/// # Example
///
/// ```
/// use bc_shamir::recover_secret;
///
/// let indexes = vec![0, 2];
/// let shares = vec![
///     vec![
///         47, 165, 102, 232, 218, 99, 6, 94, 39, 6, 253, 215, 12, 88, 64, 32,
///         105, 40, 222, 146, 93, 197, 48, 129,
///     ],
///     vec![
///         221, 174, 116, 201, 90, 99, 136, 33, 64, 215, 60, 84, 207, 28, 74,
///         10, 111, 243, 43, 224, 48, 64, 199, 172,
///     ],
/// ];
///
/// let secret = recover_secret(&indexes, &shares).unwrap();
///
/// assert_eq!(secret, b"my secret belongs to me.");
/// ```
pub fn recover_secret<T>(indexes: &[usize], shares: &[T]) -> Result<Vec<u8>>
where
    T: AsRef<[u8]>,
{
    let threshold = shares.len();
    if threshold == 0 || indexes.len() != threshold {
        return Err(Error::InvalidThreshold);
    }
    let share_length = shares[0].as_ref().len();
    validate_parameters(threshold, threshold, share_length)?;

    shares
        .iter()
        .all(|share| share.as_ref().len() == share_length)
        .then_some(())
        .ok_or(Error::SharesUnequalLength)?;

    if threshold == 1 {
        Ok(shares[0].as_ref().to_vec())
    } else {
        let indexes = indexes.iter().map(|x| *x as u8).collect::<Vec<_>>();
        let mut digest = interpolate(
            threshold,
            &indexes,
            share_length,
            shares,
            DIGEST_INDEX,
        )?;
        let secret = interpolate(
            threshold,
            &indexes,
            share_length,
            shares,
            SECRET_INDEX,
        )?;
        let mut verify = create_digest(&digest[4..], &secret);

        let mut valid = true;
        for i in 0..4 {
            valid &= digest[i] == verify[i];
        }
        memzero(&mut digest);
        memzero(&mut verify);

        if !valid {
            return Err(Error::ChecksumFailure);
        }

        Ok(secret)
    }
}

#[cfg(test)]
mod tests {
    use bc_rand::SecureRandomNumberGenerator;

    use super::split_secret;
    use crate::recover_secret;

    #[test]
    fn example_split() {
        let threshold = 2;
        let share_count = 3;
        let secret = b"my secret belongs to me.";
        let mut random_generator = SecureRandomNumberGenerator;
        let shares =
            split_secret(threshold, share_count, secret, &mut random_generator)
                .unwrap();
        assert_eq!(shares.len(), share_count);

        // Print out the shares, one per line.
        // for share in shares {
        //     println!("{:?}", share);
        // }
    }

    #[test]
    fn example_recover() {
        let indexes = vec![0, 2];
        let shares = vec![
            vec![
                47, 165, 102, 232, 218, 99, 6, 94, 39, 6, 253, 215, 12, 88, 64,
                32, 105, 40, 222, 146, 93, 197, 48, 129,
            ],
            vec![
                221, 174, 116, 201, 90, 99, 136, 33, 64, 215, 60, 84, 207, 28,
                74, 10, 111, 243, 43, 224, 48, 64, 199, 172,
            ],
        ];

        let secret = recover_secret(&indexes, &shares).unwrap();

        assert_eq!(secret, b"my secret belongs to me.");
    }
}
