using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Provenance;
using System;
using System.Text;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// A deterministic <see cref="ScalarRandomDelegate"/> source implementing the IETF
/// <c>mocked_calculate_random_scalars</c> (draft-irtf-cfrg-bbs-signatures-10, Section 7.4): the
/// reproducibility stand-in for the production random-scalar source. Feeding it to
/// <c>BbsSignature.GenerateProof</c> in place of an OS-RNG-backed source regenerates a BBS+ proof
/// bit-for-bit — the mechanism by which the draft's (and downstream cryptosuites') proof test vectors
/// are reproduced.
/// </summary>
/// <remarks>
/// <para>
/// Despite the spec's role-based name (<c>mocked_calculate_random_scalars</c>), this is not a mock that
/// returns canned values — it is a precise key-derivation, which is why the identifier reflects the
/// mechanics (deterministic) rather than the spec's role label. The algorithm: expand <c>SEED</c>
/// through RFC 9380 <c>expand_message</c> over the DST <c>api_id ‖ "MOCK_RANDOM_SCALARS_DST_"</c> to
/// <c>count · 48</c> uniform bytes, chunk into 48-byte slices, and reduce each modulo the scalar-field
/// order.
/// </para>
/// <para>
/// In keeping with the rest of the BBS+ surface, the <c>expand_message</c> primitive and the modular
/// reduction enter as injected delegates. The supplied <paramref name="expandMessage"/> MUST be the
/// variant the <paramref name="ciphersuite"/> mandates — RFC 9380 XMD-SHA-256 for BLS12-381-SHA-256,
/// XOF-SHAKE-256 for BLS12-381-SHAKE-256 — exactly the same delegate wired into
/// <c>GenerateProof</c>; the ciphersuite is used here only to form the DST.
/// </para>
/// <para>
/// ProofGen draws <c>5 + U</c> scalars (U = the number of undisclosed messages), so pass
/// <c>count = 5 + U</c>. The returned delegate hands out the precomputed scalars in order; a call past
/// the preset <paramref name="count"/> throws <see cref="InvalidOperationException"/>.
/// </para>
/// </remarks>
public static class BbsDeterministicScalars
{
    //The canonical IETF proof-vector seed for BLS12-381 (identical bytes for both ciphersuites): the
    //ASCII of the first 30 digits of pi, "3.141592653589793238462643383279". Held as the locked hex so
    //the source-of-truth matches the draft verbatim.
    private static readonly byte[] CanonicalSeedValue =
        Convert.FromHexString("332e313431353932363533353839373933323338343632363433333833323739");

    /// <summary>
    /// The canonical IETF proof-vector seed for BLS12-381 (the ASCII of the first 30 digits of π); the
    /// draft uses the same seed bytes for both the SHA-256 and SHAKE-256 ciphersuites.
    /// </summary>
    public static ReadOnlySpan<byte> CanonicalSeedBls12Curve381 => CanonicalSeedValue;

    /// <summary>
    /// The DST suffix the IETF draft appends to <c>api_id</c> for the deterministic scalar derivation;
    /// the spec names this wire constant <c>"MOCK_RANDOM_SCALARS_DST_"</c>. The byte content is locked
    /// by Section 7.4 — changing it breaks vector reproduction; only the C# identifier is ours.
    /// </summary>
    public const string IetfMockRandomScalarsDstSuffix = "MOCK_RANDOM_SCALARS_DST_";

    private const int ExpandLengthBytes = 48;

    private static readonly ProviderOperation DeterministicScalarsOperation = new("BbsDeterministicScalars");


    /// <summary>
    /// Builds a <see cref="ScalarRandomDelegate"/> that yields the first <paramref name="count"/> scalars
    /// of the IETF deterministic sequence (<c>mocked_calculate_random_scalars</c>) for
    /// <paramref name="ciphersuite"/>, seeded by <paramref name="seed"/>. Successive invocations return
    /// the precomputed scalars in order.
    /// </summary>
    /// <param name="seed">The derivation seed; the IETF canonical value is <see cref="CanonicalSeedBls12Curve381"/>, but a downstream cryptosuite's worked example may pin its own.</param>
    /// <param name="ciphersuite">The BBS+ ciphersuite the scalars belong to; used to form the DST (<c>api_id ‖ "MOCK_RANDOM_SCALARS_DST_"</c>).</param>
    /// <param name="count">Total number of scalars to be drawn (<c>5 + U</c> for a U-undisclosed proof).</param>
    /// <param name="expandMessage">RFC 9380 <c>expand_message</c> for the ciphersuite's hash (XMD-SHA-256 or XOF-SHAKE-256) — the same delegate wired into <c>GenerateProof</c>.</param>
    /// <param name="reduce">Scalar reduction, mapping each 48-byte chunk to a canonical scalar mod the BLS12-381 order.</param>
    /// <returns>A delegate that yields the i-th precomputed scalar on the i-th call.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="expandMessage"/> or <paramref name="reduce"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="count"/> is negative.</exception>
    public static ScalarRandomDelegate FromSeed(
        ReadOnlySpan<byte> seed,
        BbsCiphersuite ciphersuite,
        int count,
        ExpandMessageDelegate expandMessage,
        ScalarReduceDelegate reduce)
    {
        ArgumentNullException.ThrowIfNull(expandMessage);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentOutOfRangeException.ThrowIfNegative(count);

        byte[] dst = Encoding.UTF8.GetBytes(ciphersuite.Identifier + IetfMockRandomScalarsDstSuffix);

        byte[] uniformBytes = new byte[ExpandLengthBytes * count];
        if(count > 0)
        {
            expandMessage(seed, dst, uniformBytes);
        }

        //Precompute the reduced 32-byte scalars so the returned delegate is a thin lookup.
        byte[][] scalars = new byte[count][];
        for(int i = 0; i < count; i++)
        {
            scalars[i] = new byte[Scalar.SizeBytes];
            reduce(
                uniformBytes.AsSpan(i * ExpandLengthBytes, ExpandLengthBytes),
                scalars[i],
                CurveParameterSet.Bls12Curve381);
        }

        Counter counter = new();
        return (Span<byte> destination, CurveParameterSet curve, Tag inboundTag) =>
        {
            int callIndex = counter.Next();
            if(callIndex >= count)
            {
                throw new InvalidOperationException(
                    $"BbsDeterministicScalars: requested scalar #{callIndex + 1} but only {count} were precomputed.");
            }
            scalars[callIndex].CopyTo(destination);
            return ProviderInstrumentation.StampTag(
                inboundTag,
                WellKnownBbsProviderIdentities.Library,
                WellKnownBbsProviderIdentities.Crypto,
                WellKnownBbsProviderIdentities.Class,
                DeterministicScalarsOperation);
        };
    }


    private sealed class Counter
    {
        private int value;

        public int Next()
        {
            int current = value;
            value = current + 1;
            return current;
        }
    }
}
