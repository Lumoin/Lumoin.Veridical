using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// The fixed BBS+ <c>P1</c> generator (a G1 point) per IETF
/// <c>draft-irtf-cfrg-bbs-signatures-10</c> Section 7.2. Each
/// ciphersuite pins a different <c>P1</c> derived via
/// <c>create_generators(1, …)</c> with that ciphersuite's
/// <c>hash_to_curve_suite</c>; the values are frozen as constants
/// in the spec.
/// </summary>
/// <remarks>
/// <para>
/// We hold the canonical compressed 48-byte encoding of each
/// ciphersuite's <c>P1</c> as a hex literal lifted from the spec /
/// the corresponding canonical fixture. <see cref="GetForCiphersuite"/>
/// dispatches to the right one so the operation extensions can stay
/// generic over ciphersuite.
/// </para>
/// </remarks>
internal static class BbsP1Generator
{
    /// <summary>The canonical compressed hex encoding of <c>P1</c> for BLS12-381-SHA-256.</summary>
    public const string Bls12Curve381Sha256Hex =
        "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9";

    /// <summary>The canonical compressed hex encoding of <c>P1</c> for BLS12-381-SHAKE-256.</summary>
    public const string Bls12Curve381Shake256Hex =
        "8929dfbc7e6642c4ed9cba0856e493f8b9d7d5fcb0c31ef8fdcd34d50648a56c795e106e9eada6e0bda386b414150755";


    private static readonly byte[] Bls12Curve381Sha256Bytes = Convert.FromHexString(Bls12Curve381Sha256Hex);
    private static readonly byte[] Bls12Curve381Shake256Bytes = Convert.FromHexString(Bls12Curve381Shake256Hex);


    /// <summary>
    /// Returns a freshly pool-rented G1 point holding the
    /// <paramref name="ciphersuite"/>-specific <c>P1</c>.
    /// </summary>
    /// <exception cref="ArgumentException">When <paramref name="ciphersuite"/> is not a known well-known ciphersuite.</exception>
    public static G1Point GetForCiphersuite(BbsCiphersuite ciphersuite, SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(ciphersuite == BbsCiphersuite.Bls12Curve381Sha256)
        {
            return G1Point.FromCanonical(Bls12Curve381Sha256Bytes, CurveParameterSet.Bls12Curve381, pool);
        }
        if(ciphersuite == BbsCiphersuite.Bls12Curve381Shake256)
        {
            return G1Point.FromCanonical(Bls12Curve381Shake256Bytes, CurveParameterSet.Bls12Curve381, pool);
        }
        throw new ArgumentException($"Unknown BBS+ ciphersuite '{ciphersuite.Identifier}'.", nameof(ciphersuite));
    }
}