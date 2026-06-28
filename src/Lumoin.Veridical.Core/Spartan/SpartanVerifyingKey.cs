using Lumoin.Veridical.Core.Commitments;
using System;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// The Spartan2 verifying key: the polynomial-commitment provider the
/// verifier needs to check the witness opening and the error-commitment
/// opening. The verifier-side parallel to <see cref="SpartanProvingKey"/>.
/// </summary>
/// <remarks>
/// <para>
/// As on the proving side, the verifying key names no scheme-specific
/// type; it holds a provider whose verify operation the verifier drives.
/// The R1CS instance is <em>not</em> part of the verifying key — it is
/// supplied per call to <see cref="SpartanVerifierExtensions"/>'s
/// <c>Verify</c>. Multiple <see cref="SpartanVerifier"/> instances over
/// different instances share a single verifying key.
/// </para>
/// </remarks>
public sealed class SpartanVerifyingKey: IDisposable
{
    private PolynomialCommitmentProvider? provider;


    /// <summary>The commitment provider used to verify the witness MLE opening and the error-commitment opening.</summary>
    public PolynomialCommitmentProvider Pcs => provider ?? throw new ObjectDisposedException(nameof(SpartanVerifyingKey));

    /// <summary>The curve identifying the scalar field and group operations.</summary>
    public CurveParameterSet Curve { get; }

    /// <summary>The runtime tag identifying this key's role.</summary>
    public Tag Tag { get; }


    /// <summary>
    /// Wraps a commitment provider as a verifying key. The verifying key
    /// takes ownership of the provider and disposes it (and the commitment
    /// material it owns) when disposed itself.
    /// </summary>
    /// <exception cref="ArgumentNullException">When <paramref name="provider"/> is <see langword="null"/>.</exception>
    public SpartanVerifyingKey(PolynomialCommitmentProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);

        this.provider = provider;
        Curve = provider.Curve;

        Tag = Tag.Create(AlgebraicRole.VerificationKey)
            .With(provider.Curve);
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        provider?.Dispose();
        provider = null;
    }
}