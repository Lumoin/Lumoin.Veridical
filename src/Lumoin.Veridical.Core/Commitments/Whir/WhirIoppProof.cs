using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Sumcheck;
using System;
using System.Buffers;
using System.Collections.Generic;

namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// A WHIR IOPP proof (WHIR Construction 5.1), compiled non-interactive: the
/// Merkle roots of the folded oracles the main loop sends, the sumcheck round
/// polynomials of every iteration in protocol order, the out-of-domain
/// replies, the cleartext final polynomial, and the query openings each phase
/// reads from the oracles. The input oracle's root is the public commitment
/// the verifier is given separately; it is not carried in the proof. Every
/// dimension is a pure function of the <see cref="WhirParameterSchedule"/>
/// both endpoints derive independently, so no dimension travels.
/// </summary>
public sealed class WhirIoppProof: IDisposable
{
    private readonly MerkleRoot[] oracleRoots;
    private readonly CompressedRoundPolynomial[] roundPolynomials;
    private readonly Scalar[] outOfDomainReplies;
    private readonly WhirQueryOpening[][] openings;
    private IMemoryOwner<byte>? finalPolynomialOwner;
    private readonly int finalPolynomialLength;


    /// <summary>The schedule the proof was produced under; the verifier re-derives its own from the same public figures.</summary>
    public WhirParameterSchedule Schedule { get; }

    /// <summary>The Merkle roots of oracles <c>f_1 .. f_(M-1)</c>, in send order.</summary>
    public IReadOnlyList<MerkleRoot> OracleRoots => oracleRoots;

    /// <summary>The compressed sumcheck round polynomials, <c>k</c> per iteration in protocol order.</summary>
    public IReadOnlyList<CompressedRoundPolynomial> RoundPolynomials => roundPolynomials;

    /// <summary>The out-of-domain replies <c>y_(1,0) .. y_(M-1,0)</c>, in send order.</summary>
    public IReadOnlyList<Scalar> OutOfDomainReplies => outOfDomainReplies;

    /// <summary>The final polynomial's cleartext coefficients, <c>2^(m_M)</c> elements.</summary>
    /// <exception cref="ObjectDisposedException">When the proof has been disposed.</exception>
    public ReadOnlySpan<byte> FinalPolynomial =>
        (finalPolynomialOwner ?? throw new ObjectDisposedException(nameof(WhirIoppProof))).Memory.Span[..finalPolynomialLength];


    /// <summary>
    /// Assembles a proof from prover-owned parts; the proof takes ownership of
    /// every part.
    /// </summary>
    internal WhirIoppProof(
        WhirParameterSchedule schedule,
        MerkleRoot[] oracleRoots,
        CompressedRoundPolynomial[] roundPolynomials,
        Scalar[] outOfDomainReplies,
        IMemoryOwner<byte> finalPolynomialOwner,
        int finalPolynomialLength,
        WhirQueryOpening[][] openings)
    {
        Schedule = schedule;
        this.oracleRoots = oracleRoots;
        this.roundPolynomials = roundPolynomials;
        this.outOfDomainReplies = outOfDomainReplies;
        this.finalPolynomialOwner = finalPolynomialOwner;
        this.finalPolynomialLength = finalPolynomialLength;
        this.openings = openings;
    }


    /// <summary>
    /// The query openings read from the oracle at <paramref name="oracleIndex"/>:
    /// the shift queries of iteration <c>oracleIndex + 1</c>, or the final
    /// queries for the last oracle. One opening per scheduled query.
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


    /// <inheritdoc/>
    public void Dispose()
    {
        foreach(MerkleRoot root in oracleRoots)
        {
            root.Dispose();
        }

        foreach(CompressedRoundPolynomial polynomial in roundPolynomials)
        {
            polynomial.Dispose();
        }

        foreach(Scalar reply in outOfDomainReplies)
        {
            reply.Dispose();
        }

        foreach(WhirQueryOpening[] oracleOpenings in openings)
        {
            foreach(WhirQueryOpening opening in oracleOpenings)
            {
                opening.Dispose();
            }
        }

        //The pool zeroes rented buffers on return, so no explicit scrub is
        //needed for the final polynomial.
        IMemoryOwner<byte>? local = finalPolynomialOwner;
        if(local is not null)
        {
            finalPolynomialOwner = null;
            local.Dispose();
        }
    }
}
