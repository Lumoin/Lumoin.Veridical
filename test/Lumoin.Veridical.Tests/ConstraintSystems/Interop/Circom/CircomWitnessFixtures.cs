namespace Lumoin.Veridical.Tests.ConstraintSystems.Interop.Circom;

/// <summary>
/// Hand-constructed Circom <c>.wtns</c> witness fixtures. The .wtns format
/// has no separate specification document, so byte-for-byte fidelity to
/// the real file shape below — magic, version, section types, field size,
/// and witness count, in this order — is itself the interop contract these
/// fixtures exist to exercise.
/// </summary>
internal static class CircomWitnessFixtures
{
    /// <summary>
    /// Witness for the multiplier2 circuit with <c>a = 3</c>,
    /// <c>b = 11</c>, <c>c = 33</c>:
    /// <c>z = (1, c, a, b) = (1, 33, 3, 11)</c>.
    ///
    /// File layout:
    ///   Magic "wtns"     77 74 6e 73
    ///   Version          02 00 00 00
    ///   Section count    02 00 00 00
    ///
    ///   Section 1 (header, type 1, payload 40 bytes)
    ///     field_size      20 00 00 00          (32)
    ///     prime           BLS12-381 scalar r little-endian
    ///     nWitness        04 00 00 00
    ///
    ///   Section 2 (witness data, type 2, payload 128 bytes)
    ///     z[0] = 1   (32 bytes LE)
    ///     z[1] = 33  (32 bytes LE)
    ///     z[2] = 3   (32 bytes LE)
    ///     z[3] = 11  (32 bytes LE)
    ///
    /// Total file: 204 bytes.
    /// </summary>
    public static byte[] Multiplier2Bytes => Convert.FromHexString(
        "77746e7302000000020000000100000028000000000000002000000001000000" +
        "fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7ed7304000000" +
        "0200000080000000000000000100000000000000000000000000000000000000" +
        "0000000000000000000000002100000000000000000000000000000000000000" +
        "0000000000000000000000000300000000000000000000000000000000000000" +
        "0000000000000000000000000b00000000000000000000000000000000000000" +
        "000000000000000000000000");
}