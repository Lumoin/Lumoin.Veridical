using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Analysis.BaseFoldLeakage;

/// <summary>
/// The wired dependencies a BaseFold leakage experiment needs, bundled so the
/// experiment functions take one context rather than a long delegate list. The
/// application supplies a commitment provider (a BaseFold provider for the
/// demonstration), an entropy-sourced scalar sampler, a fresh-transcript factory,
/// the curve, and the pool. The harness owns no disposable state; it only holds
/// these references and offers the sample/commit/open helpers the experiments
/// share.
/// </summary>
/// <remarks>
/// The leakage being demonstrated is a property of a <em>non-hiding</em>
/// commitment: with BaseFold the commitment is a deterministic Merkle root over
/// the codeword, so <see cref="CommitRoot"/> on the same polynomial reproduces
/// the same bytes and <see cref="ProofBytes"/> is a deterministic function of the
/// witness. A hiding provider (Hyrax) would randomise these and the structural
/// experiments would correctly fail to recover.
/// </remarks>
[DebuggerDisplay("BaseFoldLeakageHarness ({Provider.Scheme} over {Curve})")]
public sealed class BaseFoldLeakageHarness
{
    private readonly ScalarRandomDelegate random;
    private readonly Func<FiatShamirTranscript> transcriptFactory;
    private readonly SensitiveMemoryPool<byte> pool;


    /// <summary>The commitment provider under investigation.</summary>
    public PolynomialCommitmentProvider Provider { get; }

    /// <summary>The curve the polynomials and points live over.</summary>
    public CurveParameterSet Curve { get; }


    /// <summary>Bundles the wired dependencies.</summary>
    /// <param name="provider">The commitment provider (a BaseFold provider for the demonstration).</param>
    /// <param name="curve">The curve.</param>
    /// <param name="random">The entropy-sourced scalar sampler used to draw polynomials and points.</param>
    /// <param name="transcriptFactory">Produces a fresh, identically-initialised transcript for each open.</param>
    /// <param name="pool">The pool every buffer is rented from.</param>
    /// <exception cref="ArgumentNullException">When any argument is <see langword="null"/>.</exception>
    public BaseFoldLeakageHarness(
        PolynomialCommitmentProvider provider,
        CurveParameterSet curve,
        ScalarRandomDelegate random,
        Func<FiatShamirTranscript> transcriptFactory,
        SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(random);
        ArgumentNullException.ThrowIfNull(transcriptFactory);
        ArgumentNullException.ThrowIfNull(pool);

        Provider = provider;
        Curve = curve;
        this.random = random;
        this.transcriptFactory = transcriptFactory;
        this.pool = pool;
    }


    /// <summary>Draws a uniformly random multilinear polynomial in <paramref name="variableCount"/> variables. The caller owns its disposal.</summary>
    public MultilinearExtension SamplePolynomial(int variableCount)
    {
        return MultilinearExtension.Random(variableCount, Curve, random, pool);
    }


    /// <summary>Draws a uniformly random evaluation point of <paramref name="variableCount"/> coordinates. The caller disposes each scalar.</summary>
    public Scalar[] SamplePoint(int variableCount)
    {
        var point = new Scalar[variableCount];
        for(int i = 0; i < variableCount; i++)
        {
            point[i] = Scalar.FromRandom(random, Curve, pool);
        }

        return point;
    }


    /// <summary>
    /// Returns the commitment (Merkle root) bytes for <paramref name="polynomial"/>.
    /// For a non-hiding provider this is a deterministic function of the
    /// polynomial — committing the same polynomial twice yields the same bytes.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The commitment and blind are disposed in the using block once their bytes are copied into the returned array.")]
    public byte[] CommitRoot(MultilinearExtension polynomial)
    {
        ArgumentNullException.ThrowIfNull(polynomial);

        (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = Provider.Commit(polynomial, pool);
        using(commitment)
        using(blind)
        {
            return commitment.AsReadOnlySpan().ToArray();
        }
    }


    /// <summary>
    /// Produces the public proof bytes for opening <paramref name="polynomial"/>
    /// at <paramref name="point"/>: the commitment bytes followed by the opening
    /// bytes. For a non-hiding provider this is a deterministic function of the
    /// witness — the leakage the experiments measure.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "All intermediate disposables are released in the using blocks once their bytes are copied into the returned array.")]
    public byte[] ProofBytes(MultilinearExtension polynomial, ReadOnlySpan<Scalar> point)
    {
        ArgumentNullException.ThrowIfNull(polynomial);

        (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = Provider.Commit(polynomial, pool);
        using(commitment)
        using(blind)
        using(FiatShamirTranscript transcript = transcriptFactory())
        {
            (PolynomialOpening opening, Scalar claimedValue) = Provider.Open(commitment, blind, polynomial, point, transcript, pool);
            using(opening)
            using(claimedValue)
            {
                ReadOnlySpan<byte> commitmentBytes = commitment.AsReadOnlySpan();
                ReadOnlySpan<byte> openingBytes = opening.AsReadOnlySpan();
                byte[] proof = new byte[commitmentBytes.Length + openingBytes.Length];
                commitmentBytes.CopyTo(proof);
                openingBytes.CopyTo(proof.AsSpan(commitmentBytes.Length));

                return proof;
            }
        }
    }
}
