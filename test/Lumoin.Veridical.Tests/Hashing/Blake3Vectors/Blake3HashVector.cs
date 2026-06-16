namespace Lumoin.Veridical.Tests.Hashing.Blake3Vectors;

/// <summary>
/// A single canonical BLAKE3 test vector. Tests decode the hex strings
/// at consumption time via <see cref="System.Convert.FromHexString(string)"/>
/// so the expected-byte buffers land in caller-controlled memory rather
/// than living as long-lived byte arrays.
/// </summary>
/// <param name="InputLength">The byte length of the canonical 251-byte cycling input.</param>
/// <param name="ExpectedHashHex">Expected XOF output for the hash mode, hex-encoded.</param>
/// <param name="ExpectedKeyedHashHex">Expected XOF output for the keyed_hash mode under <see cref="Blake3CanonicalVectors.Key"/>, hex-encoded.</param>
/// <param name="ExpectedDeriveKeyHex">Expected XOF output for the derive_key mode under <see cref="Blake3CanonicalVectors.DeriveKeyContext"/>, hex-encoded.</param>
internal sealed record Blake3HashVector(
    int InputLength,
    string ExpectedHashHex,
    string ExpectedKeyedHashHex,
    string ExpectedDeriveKeyHex);