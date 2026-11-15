using Lumoin.Base;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Bbs;
using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Cli;

/// <summary>
/// The BBS delegates the tool composes for one ciphersuite: the managed BLS12-381 scalar, G1, G2 and pairing
/// backends, with the ciphersuite-keyed expand-message, hash-to-scalar and hash-to-curve for SHA-256 or
/// SHAKE-256. The library selects none of these; this type is the one place the tool, as composition root,
/// chooses them. The backends are disposed with the composition.
/// </summary>
internal sealed class BbsPlatformComposition: IDisposable
{
    /// <summary>The ciphersuite name that selects BLS12-381-SHA-256.</summary>
    public const string Sha256Name = "sha256";

    /// <summary>The ciphersuite name that selects BLS12-381-SHAKE-256.</summary>
    public const string Shake256Name = "shake256";

    private readonly ScalarArithmeticBackend scalar;
    private readonly G1ArithmeticBackend g1;
    private readonly G2ArithmeticBackend g2;
    private readonly PairingBackend pairingBackend;


    private BbsPlatformComposition(
        BbsCiphersuite ciphersuite,
        ExpandMessageDelegate expandMessage,
        ScalarHashToScalarDelegate hashToScalar,
        G1HashToCurveDelegate g1HashToCurve)
    {
        Ciphersuite = ciphersuite;
        ExpandMessage = expandMessage;
        HashToScalar = hashToScalar;
        G1HashToCurve = g1HashToCurve;
        scalar = Bls12Curve381ManagedScalarBackend.Create();
        g1 = Bls12Curve381ManagedG1Backend.Create();
        g2 = Bls12Curve381ManagedG2Backend.Create();
        pairingBackend = Bls12Curve381ManagedPairingBackend.Create();
    }


    /// <summary>
    /// The pool the BBS operations rent from. Secret keys request the hardened memory tier, which degrades to
    /// the pinned tier where no native backing is wired, so the pool permits that degradation.
    /// </summary>
    public static BaseMemoryPool Pool { get; } = new(allowNativeDegradation: true);

    /// <summary>The BBS ciphersuite.</summary>
    public BbsCiphersuite Ciphersuite { get; }

    /// <summary>The ciphersuite's expand-message function.</summary>
    public ExpandMessageDelegate ExpandMessage { get; }

    /// <summary>The ciphersuite's hash-to-scalar.</summary>
    public ScalarHashToScalarDelegate HashToScalar { get; }

    /// <summary>The ciphersuite's G1 hash-to-curve.</summary>
    public G1HashToCurveDelegate G1HashToCurve { get; }

    /// <summary>Scalar addition.</summary>
    public ScalarAddDelegate ScalarAdd => scalar.Add;

    /// <summary>Scalar subtraction.</summary>
    public ScalarSubtractDelegate ScalarSubtract => scalar.Subtract;

    /// <summary>Scalar multiplication.</summary>
    public ScalarMultiplyDelegate ScalarMultiply => scalar.Multiply;

    /// <summary>Scalar negation.</summary>
    public ScalarNegateDelegate ScalarNegate => scalar.Negate;

    /// <summary>Scalar inversion.</summary>
    public ScalarInvertDelegate ScalarInvert => scalar.Invert;

    /// <summary>The operating system random scalar source.</summary>
    public ScalarRandomDelegate ScalarRandom => scalar.Random;

    /// <summary>G1 addition.</summary>
    public G1AddDelegate G1Add => g1.Add;

    /// <summary>G1 scalar multiplication, constant-time.</summary>
    public G1ScalarMultiplyDelegate G1ScalarMultiply => g1.ScalarMultiply;

    /// <summary>G1 multi-scalar multiplication.</summary>
    public G1MultiScalarMultiplyDelegate G1MultiScalarMultiply => g1.MultiScalarMultiply;

    /// <summary>G1 on-curve predicate.</summary>
    public G1IsOnCurveDelegate G1IsOnCurve => g1.IsOnCurve ?? throw new InvalidOperationException("The G1 backend provides no on-curve predicate.");

    /// <summary>G1 prime-order-subgroup predicate.</summary>
    public G1IsInPrimeOrderSubgroupDelegate G1IsInPrimeOrderSubgroup => g1.IsInPrimeOrderSubgroup ?? throw new InvalidOperationException("The G1 backend provides no subgroup predicate.");

    /// <summary>G2 addition.</summary>
    public G2AddDelegate G2Add => g2.Add;

    /// <summary>G2 scalar multiplication.</summary>
    public G2ScalarMultiplyDelegate G2ScalarMultiply => g2.ScalarMultiply;

    /// <summary>G2 on-curve predicate.</summary>
    public G2IsOnCurveDelegate G2IsOnCurve => g2.IsOnCurve;

    /// <summary>G2 prime-order-subgroup predicate.</summary>
    public G2IsInPrimeOrderSubgroupDelegate G2IsInPrimeOrderSubgroup => g2.IsInPrimeOrderSubgroup;

    /// <summary>The pairing.</summary>
    public PairingDelegate Pairing => pairingBackend.Pairing;


    /// <summary>Composes the delegates for the named ciphersuite.</summary>
    /// <param name="name"><see cref="Sha256Name"/> or <see cref="Shake256Name"/>.</param>
    /// <returns>The composition; the caller disposes it.</returns>
    /// <exception cref="ArgumentException">The name is neither ciphersuite.</exception>
    public static BbsPlatformComposition Create(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        return name switch
        {
            Sha256Name => new BbsPlatformComposition(
                BbsCiphersuite.Bls12Curve381Sha256,
                Rfc9380ExpandMessage.ExpandMessageXmdSha256,
                Bls12Curve381ManagedScalarBackend.GetHashToScalarSha256(),
                Bls12Curve381ManagedG1Backend.GetHashToCurveSha256()),
            Shake256Name => new BbsPlatformComposition(
                BbsCiphersuite.Bls12Curve381Shake256,
                Rfc9380ExpandMessage.ExpandMessageXofShake256,
                Bls12Curve381ManagedScalarBackend.GetHashToScalarShake256(),
                Bls12Curve381ManagedG1Backend.GetHashToCurveShake256()),
            _ => throw new ArgumentException($"The ciphersuite is '{Sha256Name}' or '{Shake256Name}'; received '{name}'.", nameof(name))
        };
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        scalar.Dispose();
        g1.Dispose();
        g2.Dispose();
        pairingBackend.Dispose();
    }
}
