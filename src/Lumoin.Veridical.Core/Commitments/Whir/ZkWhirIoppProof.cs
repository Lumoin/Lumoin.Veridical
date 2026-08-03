using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Sumcheck;
using System;
using System.Buffers;
using System.Collections.Generic;

namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// An HVZK-WHIR proof (eprint 2026/391 Construction 9.7), compiled
/// non-interactive: per masked-sumcheck batch the interleaved mask oracle
/// root, the mask total <c>μ̃</c> and the <c>c_1</c>-elided wire polynomials;
/// per code-switch round the folded oracle's root, the fresh code-switch mask
/// root, the private out-of-domain reply and the shift-query openings; and
/// the masked base case replacing the cleartext final polynomial — the fresh
/// main and blind commitments, the masked claim <c>μ_g</c>, the blinded
/// one-time-pad reveals and the spot-check openings. The input oracle's root
/// is the public commitment the verifier is given separately. Every dimension
/// is a pure function of the <see cref="WhirZkParameters"/> both endpoints
/// derive independently, so no dimension travels.
/// </summary>
public sealed class ZkWhirIoppProof: IDisposable
{
    private readonly CompressedRoundPolynomial[] batchWirePolynomials;
    private readonly MerkleRoot[] sumcheckMaskRoots;
    private readonly Scalar[] maskTotals;
    private readonly MerkleRoot[] oracleRoots;
    private readonly MerkleRoot[] codeSwitchMaskRoots;
    private readonly Scalar[] privateOutOfDomainReplies;
    private readonly WhirQueryOpening[][] openings;
    private readonly MerkleRoot baseCaseFreshRoot;
    private readonly MerkleRoot[] baseCaseMaskRoots;
    private readonly Scalar baseCaseMaskedClaim;
    private readonly WhirQueryOpening[] baseCaseFreshOpenings;
    private readonly WhirQueryOpening[][] baseCaseCarriedMaskOpenings;
    private readonly WhirQueryOpening[][] baseCaseFreshMaskOpenings;
    private IMemoryOwner<byte>? blindedRevealsOwner;
    private readonly int blindedSourceMessageLength;
    private readonly int blindedSourceRandomnessLength;
    private readonly int blindedMaskRevealsLength;


    /// <summary>The zero-knowledge parameter extension the proof was produced under; the verifier re-derives its own from the same public figures.</summary>
    public WhirZkParameters Parameters { get; }

    /// <summary>The compressed masked wire polynomials, <c>k</c> per batch in protocol order, batch-major.</summary>
    public IReadOnlyList<CompressedRoundPolynomial> BatchWirePolynomials => batchWirePolynomials;

    /// <summary>The interleaved sumcheck mask oracle roots, one per batch.</summary>
    public IReadOnlyList<MerkleRoot> SumcheckMaskRoots => sumcheckMaskRoots;

    /// <summary>The mask totals <c>μ̃</c>, one per batch.</summary>
    public IReadOnlyList<Scalar> MaskTotals => maskTotals;

    /// <summary>The Merkle roots of the folded oracles <c>f_1 .. f_(M-1)</c>, in send order.</summary>
    public IReadOnlyList<MerkleRoot> OracleRoots => oracleRoots;

    /// <summary>The code-switch mask roots, one per folded oracle, in send order.</summary>
    public IReadOnlyList<MerkleRoot> CodeSwitchMaskRoots => codeSwitchMaskRoots;

    /// <summary>The private out-of-domain replies, one per code-switch round, in send order.</summary>
    public IReadOnlyList<Scalar> PrivateOutOfDomainReplies => privateOutOfDomainReplies;

    /// <summary>The base case's fresh main-oracle commitment.</summary>
    public MerkleRoot BaseCaseFreshRoot => baseCaseFreshRoot;

    /// <summary>The base case's fresh blind commitments, one per carried mask group in chronological group order.</summary>
    public IReadOnlyList<MerkleRoot> BaseCaseMaskRoots => baseCaseMaskRoots;

    /// <summary>The masked base-case claim <c>μ_g</c>.</summary>
    public Scalar BaseCaseMaskedClaim => baseCaseMaskedClaim;

    /// <summary>The base case's fresh main-oracle openings at the source spot-check positions, in squeeze order.</summary>
    public IReadOnlyList<WhirQueryOpening> BaseCaseFreshOpenings => baseCaseFreshOpenings;

    /// <summary>
    /// The blinded source message reveal
    /// <c>f* = g̃ + γ·(final message)</c>, <c>2^(m_M)</c> elements.
    /// </summary>
    /// <exception cref="ObjectDisposedException">When the proof has been disposed.</exception>
    public ReadOnlySpan<byte> BlindedSourceMessage =>
        BlindedReveals[..blindedSourceMessageLength];

    /// <summary>
    /// The blinded source randomness reveal
    /// <c>r* = r_g + γ·(folded oracle randomness)</c>.
    /// </summary>
    /// <exception cref="ObjectDisposedException">When the proof has been disposed.</exception>
    public ReadOnlySpan<byte> BlindedSourceRandomness =>
        BlindedReveals.Slice(blindedSourceMessageLength, blindedSourceRandomnessLength);

    /// <summary>
    /// The blinded mask reveals, flat in chronological group order: per group
    /// member, the blinded message followed by the blinded encoding
    /// randomness.
    /// </summary>
    /// <exception cref="ObjectDisposedException">When the proof has been disposed.</exception>
    public ReadOnlySpan<byte> BlindedMaskReveals =>
        BlindedReveals.Slice(blindedSourceMessageLength + blindedSourceRandomnessLength, blindedMaskRevealsLength);


    /// <summary>The single pooled buffer behind every blinded reveal.</summary>
    private ReadOnlySpan<byte> BlindedReveals =>
        (blindedRevealsOwner ?? throw new ObjectDisposedException(nameof(ZkWhirIoppProof))).Memory.Span;


    /// <summary>
    /// Assembles a proof from prover-owned parts; the proof takes ownership
    /// of every part.
    /// </summary>
    internal ZkWhirIoppProof(
        WhirZkParameters parameters,
        CompressedRoundPolynomial[] batchWirePolynomials,
        MerkleRoot[] sumcheckMaskRoots,
        Scalar[] maskTotals,
        MerkleRoot[] oracleRoots,
        MerkleRoot[] codeSwitchMaskRoots,
        Scalar[] privateOutOfDomainReplies,
        WhirQueryOpening[][] openings,
        MerkleRoot baseCaseFreshRoot,
        MerkleRoot[] baseCaseMaskRoots,
        Scalar baseCaseMaskedClaim,
        WhirQueryOpening[] baseCaseFreshOpenings,
        WhirQueryOpening[][] baseCaseCarriedMaskOpenings,
        WhirQueryOpening[][] baseCaseFreshMaskOpenings,
        IMemoryOwner<byte> blindedRevealsOwner,
        int blindedSourceMessageLength,
        int blindedSourceRandomnessLength,
        int blindedMaskRevealsLength)
    {
        Parameters = parameters;
        this.batchWirePolynomials = batchWirePolynomials;
        this.sumcheckMaskRoots = sumcheckMaskRoots;
        this.maskTotals = maskTotals;
        this.oracleRoots = oracleRoots;
        this.codeSwitchMaskRoots = codeSwitchMaskRoots;
        this.privateOutOfDomainReplies = privateOutOfDomainReplies;
        this.openings = openings;
        this.baseCaseFreshRoot = baseCaseFreshRoot;
        this.baseCaseMaskRoots = baseCaseMaskRoots;
        this.baseCaseMaskedClaim = baseCaseMaskedClaim;
        this.baseCaseFreshOpenings = baseCaseFreshOpenings;
        this.baseCaseCarriedMaskOpenings = baseCaseCarriedMaskOpenings;
        this.baseCaseFreshMaskOpenings = baseCaseFreshMaskOpenings;
        this.blindedRevealsOwner = blindedRevealsOwner;
        this.blindedSourceMessageLength = blindedSourceMessageLength;
        this.blindedSourceRandomnessLength = blindedSourceRandomnessLength;
        this.blindedMaskRevealsLength = blindedMaskRevealsLength;
    }


    /// <summary>
    /// The query openings read from the committed oracle at
    /// <paramref name="oracleIndex"/>: the shift queries of the following
    /// code-switch round, or the base case's source spot checks for the last
    /// oracle. One opening per scheduled query.
    /// </summary>
    /// <param name="oracleIndex">The oracle index in <c>[0, IterationCount)</c>.</param>
    /// <returns>The openings in squeeze order.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="oracleIndex"/> is out of range.</exception>
    public IReadOnlyList<WhirQueryOpening> OpeningsForOracle(int oracleIndex)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(oracleIndex);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(oracleIndex, openings.Length);

        return openings[oracleIndex];
    }


    /// <summary>
    /// The base case's spot-check openings of one carried mask group and its
    /// fresh blind, at shared positions in squeeze order.
    /// </summary>
    /// <param name="groupIndex">The group index in chronological group order.</param>
    /// <returns>The carried group's openings and the fresh blind's openings.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="groupIndex"/> is out of range.</exception>
    public (IReadOnlyList<WhirQueryOpening> Carried, IReadOnlyList<WhirQueryOpening> Fresh) OpeningsForMaskGroup(int groupIndex)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(groupIndex);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(groupIndex, baseCaseCarriedMaskOpenings.Length);

        return (baseCaseCarriedMaskOpenings[groupIndex], baseCaseFreshMaskOpenings[groupIndex]);
    }


    /// <summary>The carried mask group count of the base case.</summary>
    public int MaskGroupCount => baseCaseCarriedMaskOpenings.Length;


    /// <inheritdoc/>
    public void Dispose()
    {
        foreach(CompressedRoundPolynomial polynomial in batchWirePolynomials)
        {
            polynomial.Dispose();
        }

        DisposeAll(sumcheckMaskRoots);
        DisposeAll(maskTotals);
        DisposeAll(oracleRoots);
        DisposeAll(codeSwitchMaskRoots);
        DisposeAll(privateOutOfDomainReplies);
        foreach(WhirQueryOpening[] oracleOpenings in openings)
        {
            DisposeAll(oracleOpenings);
        }

        baseCaseFreshRoot.Dispose();
        DisposeAll(baseCaseMaskRoots);
        baseCaseMaskedClaim.Dispose();
        DisposeAll(baseCaseFreshOpenings);
        foreach(WhirQueryOpening[] groupOpenings in baseCaseCarriedMaskOpenings)
        {
            DisposeAll(groupOpenings);
        }

        foreach(WhirQueryOpening[] groupOpenings in baseCaseFreshMaskOpenings)
        {
            DisposeAll(groupOpenings);
        }

        //The pool zeroes rented buffers on return, so no explicit scrub is
        //needed for the blinded reveals.
        IMemoryOwner<byte>? local = blindedRevealsOwner;
        if(local is not null)
        {
            blindedRevealsOwner = null;
            local.Dispose();
        }
    }


    /// <summary>
    /// Disposes every entry of a part array.
    /// </summary>
    private static void DisposeAll<T>(T[] parts) where T: IDisposable
    {
        foreach(T part in parts)
        {
            part.Dispose();
        }
    }
}
