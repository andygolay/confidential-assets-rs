// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

use bcs;

/// Serialize a byte slice as BCS `vector<u8>`.
/// BCS encodes `vector<u8>` as: uleb128(length) || data.
pub fn serialize_vector_u8(data: &[u8]) -> Vec<u8> {
    bcs::to_bytes(data).expect("BCS serialization of &[u8] is infallible")
}
