using System;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Verifies a <see cref="MaskedSpartanProof"/> against its
/// <see cref="SpartanVerifyingKey"/>. Decodes the mask commitments and
/// weighted openings, re-derives the blending scalars <c>ρ_outer</c>
/// and <c>ρ_inner</c> from the Fiat-Shamir transcript, derives each
/// mask's terminal value from the masked chain, and checks one
/// weighted opening per mask against <c>v = g(r) + σ_F</c> (design v3).
/// </summary>
/// <remarks>
/// <para>
/// The masked verifier is exception-safe against malformed proof
/// bytes — both <c>ArgumentException</c> and
/// <c>InvalidOperationException</c> raised during decode or
/// downstream algebraic operations are caught at the operation
/// boundary and translated to a <c>false</c> return, matching the
/// base verifier's contract.
/// </para>
/// </remarks>
public sealed class MaskedSpartanVerifier: IDisposable
{
    private SpartanVerifyingKey? verifyingKey;


    /// <summary>The verifying key this verifier wraps.</summary>
    public SpartanVerifyingKey VerifyingKey => verifyingKey ?? throw new ObjectDisposedException(nameof(MaskedSpartanVerifier));

    /// <summary>The curve identifying the scalar field and group operations.</summary>
    public CurveParameterSet Curve { get; }

    /// <summary>The runtime tag.</summary>
    public Tag Tag { get; }


    /// <summary>
    /// Wraps a verifying key in a masked verifier. The verifier
    /// takes ownership of the key and disposes it when disposed
    /// itself.
    /// </summary>
    /// <param name="verifyingKey">The verifying key. Ownership transfers to this verifier.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="verifyingKey"/> is <see langword="null"/>.</exception>
    public MaskedSpartanVerifier(SpartanVerifyingKey verifyingKey)
    {
        ArgumentNullException.ThrowIfNull(verifyingKey);

        this.verifyingKey = verifyingKey;
        Curve = verifyingKey.Curve;

        Tag = Tag.Create(AlgebraicRole.VerificationKey)
            .With(verifyingKey.Curve)
            .With(SpartanProofVariant.MaskedStatistical);
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        verifyingKey?.Dispose();
        verifyingKey = null;
    }
}