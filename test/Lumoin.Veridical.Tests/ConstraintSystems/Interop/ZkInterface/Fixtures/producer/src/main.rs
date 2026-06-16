//Owned ZkInterface fixture producer for Lumoin.Veridical's W.4 end-to-end tests.
//
//Emits a `multiplier2` R1CS circuit (a*b = c, plus a 1*1 = 1 padding row so the
//shape is a power of two for Spartan) as a size-prefixed ZkInterface `.zkif`
//stream, once per wired curve, using the canonical `zkinterface` crate's own
//FlatBuffers serializer. Because the bytes come from the reference producer, the
//Veridical reader parsing them is a genuine interop check, not a self-test.
//
//Circuit variables: z = (one=0, c=1, a=2, b=3), free_variable_id = 4.
//  - instance_variables (public): c (id 1)
//  - witness assigned_variables (private): a (id 2), b (id 3)
//  - satisfied by a = 3, b = 11, c = 33.

use std::fs;
use std::path::Path;

use zkinterface::{CircuitHeader, ConstraintSystem, Variables, Witness};

/// Decode a big-endian hex modulus into the little-endian byte vector the
/// ZkInterface `field_maximum` field expects.
fn be_hex_to_le(hex: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect();
    bytes.reverse();
    bytes
}

/// A small unsigned value as a full 32-byte little-endian field element.
fn field_le(value: u64) -> Vec<u8> {
    let mut v = vec![0u8; 32];
    v[..8].copy_from_slice(&value.to_le_bytes());
    v
}

fn multiplier2_header(field_maximum_le: Vec<u8>) -> CircuitHeader {
    CircuitHeader {
        instance_variables: Variables {
            variable_ids: vec![1],      //c (public output)
            values: Some(field_le(33)), //c = 33, as a full 32-byte element
        },
        free_variable_id: 4,
        field_maximum: Some(field_maximum_le),
        configuration: None,
    }
}

fn multiplier2_constraints() -> ConstraintSystem {
    //Coefficients are the single byte 1 (truncated representation; the reader
    //zero-pads to the field width) to exercise the truncation path alongside
    //the full-width instance/witness values.
    let rows: &[((Vec<u64>, Vec<u8>), (Vec<u64>, Vec<u8>), (Vec<u64>, Vec<u8>))] = &[
        ((vec![2], vec![1]), (vec![3], vec![1]), (vec![1], vec![1])), //a * b = c
        ((vec![0], vec![1]), (vec![0], vec![1]), (vec![0], vec![1])), //1 * 1 = 1 padding
    ];
    ConstraintSystem::from(rows)
}

fn multiplier2_witness() -> Witness {
    Witness {
        assigned_variables: Variables {
            variable_ids: vec![2, 3],                            //a, b (private)
            values: Some([field_le(3), field_le(11)].concat()), //a = 3, b = 11
        },
    }
}

fn write_fixture(path: &str, field_maximum_le: Vec<u8>) {
    let mut buf = Vec::<u8>::new();
    multiplier2_header(field_maximum_le).write_into(&mut buf).unwrap();
    multiplier2_constraints().write_into(&mut buf).unwrap();
    multiplier2_witness().write_into(&mut buf).unwrap();

    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, &buf).unwrap();
    println!("wrote {} ({} bytes)", path, buf.len());
}

fn main() {
    //BLS12-381 scalar field order minus one.
    let bls = be_hex_to_le("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    //BN254 (alt_bn128) scalar field order minus one.
    let bn254 = be_hex_to_le("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000");

    let out = std::env::args().nth(1).unwrap_or_else(|| ".".to_string());
    write_fixture(&format!("{}/bls12_381/multiplier2.zkif", out), bls);
    write_fixture(&format!("{}/bn254/multiplier2.zkif", out), bn254);
}
