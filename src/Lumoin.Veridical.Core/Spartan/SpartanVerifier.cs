using System;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Verifies Spartan2 proofs of R1CS satisfaction with random-oracle
/// zero-knowledge. Returns <c>true</c> when the proof attests to the
/// existence of a witness satisfying the verifying key's R1CS instance;
/// returns <c>false</c> for any tampered proof, mismatched instance, or
/// malformed proof bytes.
/// </summary>
/// <remarks>
/// <para>
/// The verifier wraps a <see cref="SpartanVerifyingKey"/> and is
/// constructed once per (instance, commitment key) pair. <c>Verify</c>
/// is called once per proof; the verifying key may be reused across
/// many proofs against the same instance.
/// </para>
/// <para>
/// See <c>SPARTAN2.md</c> in this folder for the protocol flow,
/// transcript schedule, proof byte layout, and the verifier's check
/// sequence.
/// </para>
/// </remarks>
public sealed class SpartanVerifier: IDisposable
{
    private SpartanVerifyingKey? verifyingKey;


    /// <summary>The verifying key this verifier wraps.</summary>
    public SpartanVerifyingKey VerifyingKey => verifyingKey ?? throw new ObjectDisposedException(nameof(SpartanVerifier));

    /// <summary>The curve identifying the scalar field and group operations.</summary>
    public CurveParameterSet Curve { get; }

    /// <summary>The runtime tag.</summary>
    public Tag Tag { get; }


    /// <summary>
    /// Wraps a verifying key in a verifier. The verifier takes ownership
    /// of the key and disposes it when disposed itself.
    /// </summary>
    /// <exception cref="ArgumentNullException">When <paramref name="verifyingKey"/> is <see langword="null"/>.</exception>
    public SpartanVerifier(SpartanVerifyingKey verifyingKey)
    {
        ArgumentNullException.ThrowIfNull(verifyingKey);

        this.verifyingKey = verifyingKey;
        Curve = verifyingKey.Curve;

        Tag = Tag.Create(AlgebraicRole.VerificationKey)
            .With(verifyingKey.Curve);
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        verifyingKey?.Dispose();
        verifyingKey = null;
    }
}