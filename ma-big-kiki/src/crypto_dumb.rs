// This file is part of GNU KeyMaker.
// (C) 2022 Theodore Huang <msa42@ctemplar.com>
//
// GNU KeyMaker is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// GNU KeyMaker is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: GPL-3.0-or-later

use dumb_crypto::scrypt::{Scrypt, ScryptError};

use {KMError, ScryptParams};

pub fn scrypt_derive(
    params: &ScryptParams,
    input: &[u8],
    salt: &[u8],
    out: &mut [u8],
) -> Result<(), KMError> {
    match Scrypt::new(params.r, params.n, params.p).derive(input, salt, out) {
        Ok(_) => Ok(()),
        Err(e) => {
            println!("{:?}", e);
            Err(KMError::InvalidParams())
        }
    }
}
