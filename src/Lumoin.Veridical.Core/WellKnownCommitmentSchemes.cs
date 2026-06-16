using System;

namespace Lumoin.Veridical.Core;

/// <summary>
/// Well-known polynomial commitment scheme identifiers and predicates.
/// </summary>
/// <remarks>
/// <para>
/// The polynomial commitment scheme is the interchangeable layer beneath the
/// proof system. The same proof-system construction can run over different
/// commitment schemes; the choice is governed by trust assumptions, performance
/// requirements, and post-quantum trajectory.
/// </para>
/// <para>
/// Three classes of scheme are commonly used together: pairing-based (KZG and
/// its variants) require a structured reference string from a trusted setup
/// but produce the smallest commitments and openings; discrete-log-based (IPA,
/// Hyrax, Pedersen-Bulletproofs) need no trusted setup but have larger proofs;
/// hash-based (FRI) need no trusted setup, are post-quantum candidates, and
/// have larger proofs again but with the simplest assumptions.
/// </para>
/// </remarks>
public static class WellKnownCommitmentSchemes
{
    /// <summary>
    /// KZG polynomial commitment (Kate, Zaverucha, Goldberg, 2010). Pairing-based,
    /// constant-size commitments and openings, requires a trusted setup.
    /// </summary>
    public const string Kzg = "KZG";

    /// <summary>
    /// HyperKZG. Multilinear-polynomial variant of KZG used by Nova-family
    /// folding schemes; reuses the universal KZG SRS.
    /// </summary>
    public const string HyperKzg = "HyperKZG";

    /// <summary>
    /// Mercury. Multilinear KZG-style commitment optimised for the prover
    /// hot path; reuses the universal KZG SRS.
    /// </summary>
    public const string Mercury = "Mercury";

    /// <summary>
    /// Inner Product Argument (Bünz et al., 2018). Discrete-log-based,
    /// logarithmic-size proofs, no trusted setup.
    /// </summary>
    public const string Ipa = "IPA";

    /// <summary>
    /// FRI (Ben-Sasson et al., 2018). Hash-based, transparent (no trusted
    /// setup), post-quantum candidate. The commitment scheme used by STARK
    /// proof systems.
    /// </summary>
    public const string Fri = "FRI";

    /// <summary>
    /// Hyrax (Wahby et al., 2018). Discrete-log-based commitment for
    /// multilinear polynomials, no trusted setup.
    /// </summary>
    public const string Hyrax = "Hyrax";

    /// <summary>
    /// Pedersen vector commitment. Discrete-log-based, additively
    /// homomorphic, the foundation under Bulletproofs and many older
    /// schemes; no trusted setup.
    /// </summary>
    public const string Pedersen = "Pedersen";


    /// <summary>Determines whether the specified value identifies KZG.</summary>
    public static bool IsKzg(string? value) =>
        !string.IsNullOrEmpty(value)
            && string.Equals(value, Kzg, StringComparison.OrdinalIgnoreCase);

    /// <summary>Determines whether the specified value identifies HyperKZG.</summary>
    public static bool IsHyperKzg(string? value) =>
        !string.IsNullOrEmpty(value)
            && string.Equals(value, HyperKzg, StringComparison.OrdinalIgnoreCase);

    /// <summary>Determines whether the specified value identifies Mercury.</summary>
    public static bool IsMercury(string? value) =>
        !string.IsNullOrEmpty(value)
            && string.Equals(value, Mercury, StringComparison.OrdinalIgnoreCase);

    /// <summary>Determines whether the specified value identifies the Inner Product Argument (IPA).</summary>
    public static bool IsIpa(string? value) =>
        !string.IsNullOrEmpty(value)
            && string.Equals(value, Ipa, StringComparison.OrdinalIgnoreCase);

    /// <summary>Determines whether the specified value identifies FRI.</summary>
    public static bool IsFri(string? value) =>
        !string.IsNullOrEmpty(value)
            && string.Equals(value, Fri, StringComparison.OrdinalIgnoreCase);

    /// <summary>Determines whether the specified value identifies Hyrax.</summary>
    public static bool IsHyrax(string? value) =>
        !string.IsNullOrEmpty(value)
            && string.Equals(value, Hyrax, StringComparison.OrdinalIgnoreCase);

    /// <summary>Determines whether the specified value identifies the Pedersen commitment.</summary>
    public static bool IsPedersen(string? value) =>
        !string.IsNullOrEmpty(value)
            && string.Equals(value, Pedersen, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Determines whether the specified commitment scheme is a KZG-family
    /// pairing-based scheme (KZG, HyperKZG, Mercury), all of which share the
    /// universal structured reference string and require pairing arithmetic.
    /// </summary>
    public static bool IsKzgFamily(string? value) =>
        IsKzg(value) || IsHyperKzg(value) || IsMercury(value);

    /// <summary>
    /// Determines whether the specified commitment scheme requires a trusted
    /// setup (a structured reference string produced by a multi-party
    /// ceremony). KZG-family schemes require it; IPA, FRI, Hyrax, and Pedersen
    /// do not.
    /// </summary>
    public static bool IsTrustedSetupRequired(string? value) =>
        IsKzgFamily(value);

    /// <summary>
    /// Determines whether the specified commitment scheme is a candidate for
    /// post-quantum security. FRI rests only on collision-resistant hashing
    /// and is the standard post-quantum choice; all other schemes here rely
    /// on a discrete-logarithm or pairing assumption that Shor's algorithm
    /// breaks.
    /// </summary>
    public static bool IsPostQuantumCandidate(string? value) =>
        IsFri(value);
}