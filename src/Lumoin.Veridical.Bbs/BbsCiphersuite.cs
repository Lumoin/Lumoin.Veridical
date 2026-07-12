using System;
using System.Diagnostics;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// Identifies a BBS+ ciphersuite by its IETF-spec api_id string.
/// </summary>
/// <param name="Identifier">The api_id string as defined by the IETF draft (e.g. <see cref="WellKnownBbsCiphersuites.Bls12Curve381Sha256"/>).</param>
/// <remarks>
/// The ciphersuite is the discriminator that BBS+ leaf types carry in
/// their tag alongside the algebraic role and curve parameter set. Two
/// ciphersuites can share a curve (BLS12-381-SHA-256 and
/// BLS12-381-SHAKE-256 both use BLS12-381) but differ in their hashing
/// primitive, generator-derivation seed, and per-operation DSTs.
/// </remarks>
[DebuggerDisplay("{Identifier,nq}")]
public readonly record struct BbsCiphersuite(string Identifier)
{
    /// <summary>The BLS12-381-SHA-256 ciphersuite per IETF draft Section 7.2.2.</summary>
    public static BbsCiphersuite Bls12Curve381Sha256 { get; } = new(WellKnownBbsCiphersuites.Bls12Curve381Sha256);

    /// <summary>The BLS12-381-SHAKE-256 ciphersuite per IETF draft Section 7.2.1.</summary>
    public static BbsCiphersuite Bls12Curve381Shake256 { get; } = new(WellKnownBbsCiphersuites.Bls12Curve381Shake256);


    /// <summary>
    /// The BLS12-381-SHA-256 Blind BBS Interface per
    /// <c>draft-irtf-cfrg-bbs-blind-signatures-03</c> Section 4.2.1. A
    /// distinct Interface from <see cref="Bls12Curve381Sha256"/>: shares
    /// the curve and hash-to-curve suite but derives every generator and
    /// DST under the <c>BLIND_H2G_HM2S_</c> suffix instead of
    /// <c>H2G_HM2S_</c>, so a value produced under one Interface never
    /// verifies under the other.
    /// </summary>
    public static BbsCiphersuite Bls12Curve381Sha256Blind { get; } = new(WellKnownBbsCiphersuites.Bls12Curve381Sha256Blind);

    /// <summary>
    /// The BLS12-381-SHAKE-256 Blind BBS Interface per
    /// <c>draft-irtf-cfrg-bbs-blind-signatures-03</c> Section 4.2.1. See
    /// <see cref="Bls12Curve381Sha256Blind"/> for the Interface-separation
    /// rationale.
    /// </summary>
    public static BbsCiphersuite Bls12Curve381Shake256Blind { get; } = new(WellKnownBbsCiphersuites.Bls12Curve381Shake256Blind);

    /// <summary>
    /// The BLS12-381-SHA-256 per-verifier-pseudonym Interface per
    /// <c>draft-irtf-cfrg-bbs-per-verifier-linkability-03</c> Section 6. A
    /// distinct Interface from <see cref="Bls12Curve381Sha256"/> and
    /// <see cref="Bls12Curve381Sha256Blind"/>: pseudonyms and nym proofs
    /// are Interface- and ciphersuite-specific by design (linking across
    /// Interfaces is explicitly out of scope for the draft), so this value
    /// must never be conflated with either of the other two.
    /// </summary>
    public static BbsCiphersuite Bls12Curve381Sha256Pseudonym { get; } = new(WellKnownBbsCiphersuites.Bls12Curve381Sha256Pseudonym);

    /// <summary>
    /// The BLS12-381-SHAKE-256 per-verifier-pseudonym Interface per
    /// <c>draft-irtf-cfrg-bbs-per-verifier-linkability-03</c> Section 6.
    /// See <see cref="Bls12Curve381Sha256Pseudonym"/> for the
    /// Interface-separation rationale.
    /// </summary>
    public static BbsCiphersuite Bls12Curve381Shake256Pseudonym { get; } = new(WellKnownBbsCiphersuites.Bls12Curve381Shake256Pseudonym);


    /// <summary>
    /// The base hash-to-curve ciphersuite this value builds on:
    /// <see cref="Bls12Curve381Sha256"/> for the SHA-256 family and
    /// <see cref="Bls12Curve381Shake256"/> for the SHAKE-256 family. The
    /// core ciphersuites map to themselves.
    /// </summary>
    /// <remarks>
    /// The extension Interfaces (blind, pseudonym) reuse the core suites'
    /// hash primitives, generator-derivation machinery, and <c>P1</c>
    /// constant — only the Interface suffix in the api_id differs. Keys
    /// are always tagged with a core ciphersuite, so any guard comparing
    /// a key's ciphersuite against an extension container's must compare
    /// through this property; a naive equality between a core and an
    /// interface-scoped value is always <see langword="false"/>.
    /// </remarks>
    /// <exception cref="InvalidOperationException">When the identifier is not one of the six well-known values.</exception>
    public BbsCiphersuite BaseHashSuite
    {
        get
        {
            if(this == Bls12Curve381Sha256 || this == Bls12Curve381Sha256Blind || this == Bls12Curve381Sha256Pseudonym)
            {
                return Bls12Curve381Sha256;
            }
            if(this == Bls12Curve381Shake256 || this == Bls12Curve381Shake256Blind || this == Bls12Curve381Shake256Pseudonym)
            {
                return Bls12Curve381Shake256;
            }

            throw new InvalidOperationException($"Unknown BBS ciphersuite '{Identifier}'.");
        }
    }
}