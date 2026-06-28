using System;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// The polynomial-commitment surface Spartan operates against: a bundle of
/// the scheme's operations (<see cref="Commit"/>, <see cref="Open"/>,
/// <see cref="VerifyEvaluation"/>) plus the scheme and curve identity.
/// Spartan's prover and verifier take one of these rather than
/// scheme-specific types, so a future scheme (BaseFold, WHIR, …) drops in
/// behind the same surface.
/// </summary>
/// <remarks>
/// <para>
/// A concrete scheme produces a provider with its commitment key and the
/// curve's scalar/group backends captured (the "non-moving parts"), so the
/// operation delegates carry slim signatures. Today the only producer is
/// the Hyrax scheme.
/// </para>
/// <para>
/// This is the delegate-bundle equivalent of Microsoft Research's Spartan2
/// <c>PCSEngineTrait</c>; structural inspiration only, no code dependency.
/// See microsoft/Spartan2 on GitHub. The homomorphic commitment/blind
/// combination operations the trait also defines are added to this surface
/// alongside the folding migration that needs them.
/// </para>
/// </remarks>
public sealed class PolynomialCommitmentProvider: IDisposable
{
    private IDisposable? ownedResource;


    /// <summary>The commitment scheme this provider implements. Stamped onto every artifact it produces.</summary>
    public CommitmentScheme Scheme { get; }

    /// <summary>The curve the provider commits over.</summary>
    public CurveParameterSet Curve { get; }

    /// <summary>Commits to a multilinear polynomial.</summary>
    public PolynomialCommitDelegate Commit { get; }

    /// <summary>Produces an evaluation argument for a committed polynomial at a point.</summary>
    public PolynomialOpenDelegate Open { get; }

    /// <summary>Verifies an evaluation argument.</summary>
    public PolynomialVerifyEvaluationDelegate VerifyEvaluation { get; }

    /// <summary>
    /// The scheme's query-repetition count, when the scheme has one and a
    /// consumer needs it to size variable-length artifacts (BaseFold). Hyrax and
    /// other schemes whose artifact sizes follow from the curve alone leave this
    /// <see langword="null"/>.
    /// </summary>
    public int? QueryCount { get; }

    /// <summary>
    /// The scheme's Merkle/digest size in bytes, when the scheme commits via a
    /// hash tree (BaseFold) and a consumer needs it to size artifacts.
    /// <see langword="null"/> for schemes without a hash-tree digest (Hyrax).
    /// </summary>
    public int? DigestSizeBytes { get; }

    /// <summary>
    /// Whether the scheme's commitment is additively homomorphic — whether two
    /// commitments (and a blind) can be combined into a commitment to the linear
    /// combination of the committed vectors. Pedersen-family schemes (Hyrax) are;
    /// hash-based schemes (BaseFold, FRI) are not. Nova-style folding requires
    /// this (it combines error and cross-term commitments homomorphically), so
    /// <see cref="FoldChain"/> rejects a provider for which this is
    /// <see langword="false"/>. Defaults to <see langword="false"/> — a scheme
    /// must opt in.
    /// </summary>
    public bool IsAdditivelyHomomorphic { get; }

    /// <summary>
    /// Whether the scheme's commitment and evaluation argument are hiding —
    /// whether they reveal nothing about the committed polynomial beyond the single
    /// opened evaluation. Pedersen-family schemes (Hyrax) are hiding; the plain
    /// hash-based BaseFold is binding-but-not-hiding (its commitment is a
    /// deterministic Merkle root over the codeword and its opening reveals queried
    /// codeword positions), while a salted/masked ZK BaseFold variant is. Masked
    /// Spartan only achieves true zero-knowledge over a hiding provider, so a
    /// consumer can check this to know whether the privacy its name implies holds.
    /// Defaults to <see langword="false"/> — a scheme must opt in.
    /// </summary>
    public bool IsHiding { get; }

    /// <summary>
    /// The number of extra (mask) variables <c>t</c> a dimension-lifting hiding
    /// scheme commits each polynomial by (the ZK BaseFold lift: a <c>d</c>-variable
    /// polynomial is committed at <c>d + t</c> layers), when a consumer needs it to
    /// size the lifted variable-length openings. <see langword="null"/> for schemes
    /// that do not lift (plain BaseFold, Hyrax, and the salted-only hiding BaseFold).
    /// </summary>
    public int? ExtraVariableCount { get; }

    /// <summary>
    /// Commits a vector for a later weighted opening (the statistical sumcheck
    /// mask's coefficient vector <c>C*</c>; design doc §2 v3). Distinct from
    /// <see cref="Commit"/> because the commitment shape differs where the
    /// evaluation commitment is structured: Hyrax commits the whole vector as
    /// one Pedersen row (an arbitrary weight vector does not factor through
    /// its matrix split), while the BaseFold flavors commit the vector's MLE
    /// under their usual (plain / salted-and-lifted) Merkle path.
    /// <see langword="null"/> for providers without a weighted-opening path.
    /// </summary>
    public PolynomialCommitDelegate? CommitVector { get; }

    /// <summary>
    /// Produces a weighted-opening argument for a commitment made via
    /// <see cref="CommitVector"/>: the inner product of the committed vector
    /// with a public weight vector. <see langword="null"/> for providers
    /// without a weighted-opening path.
    /// </summary>
    public PolynomialOpenWeightedSumDelegate? OpenWeightedSum { get; }

    /// <summary>
    /// Verifies a weighted-opening argument produced by
    /// <see cref="OpenWeightedSum"/>. <see langword="null"/> for providers
    /// without a weighted-opening path.
    /// </summary>
    public PolynomialVerifyWeightedSumDelegate? VerifyWeightedSum { get; }

    /// <summary>
    /// Resolves the statistical sumcheck mask's commitment shape under this
    /// scheme's ledger, so the masked-Spartan prover and verifier agree on the
    /// mask vector's layout without wire data. <see langword="null"/> for
    /// providers without a weighted-opening path.
    /// </summary>
    public StatisticalMaskShapeDelegate? ResolveStatisticalMaskShape { get; }

    /// <summary>
    /// Whether the scheme supplies the complete weighted-opening path
    /// (<see cref="CommitVector"/>, <see cref="OpenWeightedSum"/>, <see cref="VerifyWeightedSum"/>,
    /// <see cref="ResolveStatisticalMaskShape"/>) that the masked-Spartan statistical mask binding needs. A
    /// consumer can check this upfront rather than discovering the gap mid-proof; masked Spartan refuses a
    /// provider for which it is <see langword="false"/> (the binding-only Ligero PCS). Hyrax and the BaseFold
    /// flavors supply it.
    /// </summary>
    public bool SupportsWeightedOpening =>
        CommitVector is not null && OpenWeightedSum is not null && VerifyWeightedSum is not null && ResolveStatisticalMaskShape is not null;


    /// <summary>Bundles a scheme's operations and identity into the surface Spartan consumes.</summary>
    /// <param name="scheme">The commitment scheme identity.</param>
    /// <param name="curve">The curve the provider commits over.</param>
    /// <param name="commit">The commit operation.</param>
    /// <param name="open">The open operation.</param>
    /// <param name="verifyEvaluation">The verify operation.</param>
    /// <param name="ownedResource">
    /// An optional resource the provider's operations close over (typically the
    /// scheme's commitment key) and that the provider disposes when disposed. Pass
    /// <see langword="null"/> when the caller retains ownership of that resource.
    /// </param>
    /// <param name="queryCount">The scheme's query-repetition count, when a consumer needs it to size variable-length artifacts; <see langword="null"/> when not applicable.</param>
    /// <param name="digestSizeBytes">The scheme's Merkle digest size in bytes, when it commits via a hash tree; <see langword="null"/> when not applicable.</param>
    /// <param name="isAdditivelyHomomorphic">Whether the scheme's commitment is additively homomorphic (required for folding). Defaults to <see langword="false"/>.</param>
    /// <param name="isHiding">Whether the scheme's commitment and opening are hiding (required for true zero-knowledge under masked Spartan). Defaults to <see langword="false"/>.</param>
    /// <param name="extraVariableCount">The dimension-lift <c>t</c> a lifting hiding scheme commits each polynomial by, when a consumer needs it to size lifted openings; <see langword="null"/> when not applicable.</param>
    /// <param name="commitVector">The vector commit for weighted openings; <see langword="null"/> when the scheme has no weighted-opening path.</param>
    /// <param name="openWeightedSum">The weighted opening; <see langword="null"/> when the scheme has no weighted-opening path.</param>
    /// <param name="verifyWeightedSum">The weighted-opening verification; <see langword="null"/> when the scheme has no weighted-opening path.</param>
    /// <param name="resolveStatisticalMaskShape">The scheme's statistical-mask shape resolution; <see langword="null"/> when the scheme has no weighted-opening path.</param>
    /// <exception cref="ArgumentNullException">When any operation delegate is null.</exception>
    public PolynomialCommitmentProvider(
        CommitmentScheme scheme,
        CurveParameterSet curve,
        PolynomialCommitDelegate commit,
        PolynomialOpenDelegate open,
        PolynomialVerifyEvaluationDelegate verifyEvaluation,
        IDisposable? ownedResource = null,
        int? queryCount = null,
        int? digestSizeBytes = null,
        bool isAdditivelyHomomorphic = false,
        bool isHiding = false,
        int? extraVariableCount = null,
        PolynomialCommitDelegate? commitVector = null,
        PolynomialOpenWeightedSumDelegate? openWeightedSum = null,
        PolynomialVerifyWeightedSumDelegate? verifyWeightedSum = null,
        StatisticalMaskShapeDelegate? resolveStatisticalMaskShape = null)
    {
        ArgumentNullException.ThrowIfNull(commit);
        ArgumentNullException.ThrowIfNull(open);
        ArgumentNullException.ThrowIfNull(verifyEvaluation);

        Scheme = scheme;
        Curve = curve;
        Commit = commit;
        Open = open;
        VerifyEvaluation = verifyEvaluation;
        this.ownedResource = ownedResource;
        QueryCount = queryCount;
        DigestSizeBytes = digestSizeBytes;
        IsAdditivelyHomomorphic = isAdditivelyHomomorphic;
        IsHiding = isHiding;
        ExtraVariableCount = extraVariableCount;
        CommitVector = commitVector;
        OpenWeightedSum = openWeightedSum;
        VerifyWeightedSum = verifyWeightedSum;
        ResolveStatisticalMaskShape = resolveStatisticalMaskShape;
    }


    /// <summary>Disposes the resource the provider owns (if any). Idempotent.</summary>
    public void Dispose()
    {
        ownedResource?.Dispose();
        ownedResource = null;
    }
}
