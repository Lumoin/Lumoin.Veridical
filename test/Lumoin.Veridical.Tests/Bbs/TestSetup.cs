using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Bbs;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;

namespace Lumoin.Veridical.Tests.Bbs;

/// <summary>
/// Wires the BigInteger reference backends from
/// <c>Lumoin.Veridical.Tests</c> into delegate-bundle properties the
/// BBS+ test classes consume. The ciphersuite-agnostic delegates
/// (scalar arithmetic, G1/G2 group operations, pairing) live at the
/// root; the ciphersuite-keyed delegates (<c>hash_to_scalar</c>,
/// <c>g1_hash_to_curve</c>) live under the per-ciphersuite nested
/// classes so test wiring is explicit about which ciphersuite the
/// caller intends.
/// </summary>
internal static class TestSetup
{
    //Secret keys request the native (locked) tier; with no native backing wired on the test host the pool must
    //allow degradation to the pinned tier (BaseMemoryPool.Shared is strict and would reject a Native rent).
    private static readonly BaseMemoryPool DegradingPool = new(allowNativeDegradation: true);

    public static BaseMemoryPool Pool => DegradingPool;


    public static ScalarAddDelegate ScalarAdd { get; } =
        Bls12Curve381BigIntegerScalarReference.GetAdd();

    public static ScalarSubtractDelegate ScalarSubtract { get; } =
        Bls12Curve381BigIntegerScalarReference.GetSubtract();

    public static ScalarMultiplyDelegate ScalarMultiply { get; } =
        Bls12Curve381BigIntegerScalarReference.GetMultiply();

    public static ScalarNegateDelegate ScalarNegate { get; } =
        Bls12Curve381BigIntegerScalarReference.GetNegate();

    public static ScalarInvertDelegate ScalarInvert { get; } =
        Bls12Curve381BigIntegerScalarReference.GetInvert();

    public static ScalarReduceDelegate ScalarReduce { get; } =
        Bls12Curve381BigIntegerScalarReference.GetReduce();

    public static ScalarRandomDelegate ScalarRandom { get; } =
        Bls12Curve381BigIntegerScalarReference.GetRandom();

    public static G1AddDelegate G1Add { get; } =
        Bls12Curve381BigIntegerG1Reference.GetAdd();

    public static G1ScalarMultiplyDelegate G1ScalarMultiply { get; } =
        Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();

    public static G1MultiScalarMultiplyDelegate G1MultiScalarMultiply { get; } =
        TestG1Backends.Bls12Curve381Msm;

    public static G2AddDelegate G2Add { get; } =
        Bls12Curve381BigIntegerG2Reference.GetAdd();

    public static G2ScalarMultiplyDelegate G2ScalarMultiply { get; } =
        Bls12Curve381BigIntegerG2Reference.GetScalarMultiply();

    public static PairingDelegate Pairing { get; } =
        Bls12Curve381BigIntegerPairingReference.GetPairing();


    /// <summary>Delegates wired for the BLS12-381-SHA-256 BBS+ ciphersuite.</summary>
    internal static class Sha256
    {
        public static ExpandMessageDelegate ExpandMessage { get; } =
            Rfc9380ExpandMessage.ExpandMessageXmdSha256;

        public static ScalarHashToScalarDelegate HashToScalar { get; } =
            Bls12Curve381BigIntegerScalarReference.GetHashToScalar();

        public static G1HashToCurveDelegate G1HashToCurve { get; } =
            Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
    }


    /// <summary>Delegates wired for the BLS12-381-SHAKE-256 BBS+ ciphersuite.</summary>
    internal static class Shake256
    {
        public static ExpandMessageDelegate ExpandMessage { get; } =
            Rfc9380ExpandMessage.ExpandMessageXofShake256;

        public static ScalarHashToScalarDelegate HashToScalar { get; } =
            Bls12Curve381BigIntegerScalarReference.GetHashToScalarShake256();

        public static G1HashToCurveDelegate G1HashToCurve { get; } =
            Bls12Curve381BigIntegerG1Reference.GetHashToCurveShake256();
    }
}