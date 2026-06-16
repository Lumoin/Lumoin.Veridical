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
}