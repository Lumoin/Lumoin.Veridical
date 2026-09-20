namespace Lumoin.Veridical.Tests.ConstraintSystems.Interop.Circom;

/// <summary>
/// Hand-constructed Circom <c>.r1cs</c> binary fixtures for the
/// CircomR1csReader tests. The fixtures are bytes the iden3 binary
/// specification at
/// <c>https://github.com/iden3/r1csfile/blob/master/doc/r1cs_bin_format.md</c>
/// emits or accepts; they reproduce what <c>circom -p bls12381 --r1cs</c>
/// would write for the named circuit, with the deliberate adjustment
/// that the trivial padding constraint <c>z[0] · z[0] = z[0]</c> is
/// added so the Spartan prover's power-of-two row-count requirement
/// is satisfied without a separate padding step in the parser.
/// </summary>
internal static class CircomR1csFixtures
{
    /// <summary>
    /// Multiplier2 (<c>c &lt;== a * b</c>) plus a trivial padding
    /// constraint <c>z[0] · z[0] = z[0]</c> so the parsed instance has
    /// row count 2 (the smallest power of two the Spartan prover
    /// accepts).
    ///
    /// Shape:
    ///   nWires = 4 (constant, c, a, b)
    ///   nPubOut = 1, nPubIn = 0, nPrvIn = 2
    ///   nConstraints = 2
    ///   C0: A={2:1}, B={3:1}, C={1:1}  (a * b = c)
    ///   C1: A={0:1}, B={0:1}, C={0:1}  (1 * 1 = 1, padding)
    ///   Total file: 384 bytes
    /// </summary>
    public static byte[] Multiplier2Bytes => Convert.FromHexString(Multiplier2HexBls12Curve381);


    /// <summary>
    /// The BN254 counterpart of <see cref="Multiplier2Bytes"/>: byte-identical
    /// except the header's 32-byte little-endian scalar prime is BN254's
    /// <c>r = 0x30644e72…f0000001</c> instead of BLS12-381's. The circuit's
    /// coefficients are all <c>1</c>, so they are prime-independent and need no
    /// other change; the field byte size stays 32 (both scalar fields are 254
    /// bits). Exercises the CircomR1csReader's BN254 prime dispatch and
    /// the curve-generic construction path when requested with
    /// <see cref="Lumoin.Veridical.Core.CurveParameterSet.Bn254"/>.
    /// </summary>
    public static byte[] Bn254Multiplier2Bytes => Convert.FromHexString(
        Multiplier2HexBls12Curve381.Replace(
            Bls12Curve381ScalarPrimeLittleEndianHex,
            Bn254ScalarPrimeLittleEndianHex,
            StringComparison.Ordinal));


    /// <summary>The raw hex bytes of the BLS12-381 Multiplier2-plus-padding fixture described above.</summary>
    private const string Multiplier2HexBls12Curve381 =
        "7231637301000000030000000100000040000000000000002000000001000000" +
        "fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7ed7304000000" +
        "01000000000000000200000004000000000000000200000002000000f0000000" +
        "0000000001000000020000000100000000000000000000000000000000000000" +
        "0000000000000000000000000100000003000000010000000000000000000000" +
        "0000000000000000000000000000000000000000010000000100000001000000" +
        "0000000000000000000000000000000000000000000000000000000001000000" +
        "0000000001000000000000000000000000000000000000000000000000000000" +
        "0000000001000000000000000100000000000000000000000000000000000000" +
        "0000000000000000000000000100000000000000010000000000000000000000" +
        "0000000000000000000000000000000000000000030000002000000000000000" +
        "0000000000000000010000000000000002000000000000000300000000000000";

    /// <summary>The BLS12-381 scalar field prime as 32 little-endian bytes, the way the iden3 .r1cs format stores it in the header (big-endian hex reversed byte-wise).</summary>
    private const string Bls12Curve381ScalarPrimeLittleEndianHex =
        "01000000fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7ed73";
    /// <summary>The BN254 scalar field prime as 32 little-endian bytes, the way the iden3 .r1cs format stores it in the header.</summary>
    private const string Bn254ScalarPrimeLittleEndianHex =
        "010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430";
}