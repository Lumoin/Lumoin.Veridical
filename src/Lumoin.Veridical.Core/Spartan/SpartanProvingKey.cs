using Lumoin.Veridical.Core.Commitments;
using System;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// The Spartan2 proving key: the polynomial-commitment provider the
/// prover commits the witness (and opens the error commitment) against.
/// Held across multiple <see cref="SpartanProver"/> instances so the same
/// commitment material can be reused across many proofs and many R1CS
/// instances.
/// </summary>
/// <remarks>
/// <para>
/// The provider bundles the scheme's commit/open/verify operations with
/// its commitment key and algebraic backends captured, so the proving key
/// names no scheme-specific type — a future commitment scheme drops in by
/// supplying a different provider at construction.
/// </para>
/// <para>
/// The R1CS instance is <em>not</em> part of the proving key — it is
/// supplied per call to <see cref="SpartanProverExtensions"/>'s
/// <c>Prove</c>. This is what lets a folding scheme pass a different
/// folded relaxed instance to each <c>Prove</c> call without rebuilding
/// the key: the key holds only the reusable commitment material; the
/// per-proof state (the instance, the witness commitment, blinding
/// factors, sumcheck transcripts) lives on the prover's call frame.
/// </para>
/// <para>
/// Size compatibility (commitment-key vector length vs witness MLE
/// shape) is validated at proof time, where the witness dimensions are
/// concretely known.
/// </para>
/// </remarks>
public sealed class SpartanProvingKey: IDisposable
{
    private PolynomialCommitmentProvider? provider;


    /// <summary>The commitment provider used to commit and open the witness MLE and to open the error commitment.</summary>
    public PolynomialCommitmentProvider Pcs => provider ?? throw new ObjectDisposedException(nameof(SpartanProvingKey));

    /// <summary>The curve identifying the scalar field and group operations.</summary>
    public CurveParameterSet Curve { get; }

    /// <summary>The runtime tag identifying this key's role.</summary>
    public Tag Tag { get; }


    /// <summary>
    /// Wraps a commitment provider as a proving key. The proving key
    /// takes ownership of the provider and disposes it (and the commitment
    /// material it owns) when disposed itself.
    /// </summary>
    /// <param name="provider">The polynomial-commitment provider.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="provider"/> is <see langword="null"/>.</exception>
    public SpartanProvingKey(PolynomialCommitmentProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);

        this.provider = provider;
        Curve = provider.Curve;

        Tag = Tag.Create(
            (typeof(AlgebraicRole), (object)AlgebraicRole.ProvingKey),
            (typeof(CurveParameterSet), (object)provider.Curve));
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        provider?.Dispose();
        provider = null;
    }
}