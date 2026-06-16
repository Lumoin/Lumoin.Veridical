using Lumoin.Veridical.Bbs;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Provenance;
using System;
using System.Text;

namespace Lumoin.Veridical.Tests.Bbs;

/// <summary>
/// Test-only deterministic <see cref="ScalarRandomDelegate"/> source that
/// reproduces the IETF draft's <c>mocked_calculate_random_scalars</c>
/// (Section 7.4 of <c>draft-irtf-cfrg-bbs-signatures-10</c>) for
/// byte-faithful proof-vector reproduction.
/// </summary>
/// <remarks>
/// <para>
/// The IETF draft defines a deterministic stand-in for the production
/// random-scalar source so that proof test vectors can be reproduced
/// bit-for-bit by any conformant implementation. Despite the spec's
/// role-based name (<c>mocked_calculate_random_scalars</c>), this is not a
/// mock that returns canned values — it is a precise key-derivation, which
/// is why the identifier here reflects the mechanics (deterministic) rather
/// than the spec's role label. The algorithm: expand <c>SEED</c> through
/// <c>expand_message_xmd(DST, expand_len * count)</c> to <c>count * 48</c>
/// uniform bytes, then chunk those bytes into 48-byte slices and reduce
/// each modulo the scalar field order.
/// </para>
/// <para>
/// For the <c>BLS12-381-SHA-256</c> ciphersuite (the only one
/// exercised by sub-batch BBS+.2 vectors):
/// </para>
/// <list type="bullet">
///   <item><c>SEED = h'332e313431353932363533353839373933323338343632363433333833323739'</c> — the hex encoding of the ASCII string of the first 30 digits of π (<c>"3.141592653589793238462643383279"</c>).</item>
///   <item><c>DST = api_id || "MOCK_RANDOM_SCALARS_DST_"</c> where <c>api_id = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_"</c>.</item>
///   <item><c>expand_len = 48</c>.</item>
/// </list>
/// <para>
/// The returned <see cref="ScalarRandomDelegate"/> hands out the
/// precomputed scalars in order across successive calls; once the
/// preset <c>count</c> is exhausted, subsequent calls throw
/// <see cref="InvalidOperationException"/>.
/// </para>
/// </remarks>
internal static class BbsDeterministicScalars
{
    /// <summary>The canonical IETF proof-vector seed for BLS12-381-SHA-256: ASCII of the first 30 digits of π.</summary>
    public static byte[] CanonicalSeedBls12Curve381Sha256 { get; } =
        Convert.FromHexString("332e313431353932363533353839373933323338343632363433333833323739");

    /// <summary>
    /// The DST suffix the IETF draft appends to api_id for the deterministic
    /// scalar derivation; the spec names this wire constant
    /// <c>"MOCK_RANDOM_SCALARS_DST_"</c>. The byte content is a locked
    /// wire-format string — it is hashed into the DST per Section 7.4, so
    /// changing it would break vector reproduction. Only the C# identifier is
    /// ours.
    /// </summary>
    public const string IetfMockRandomScalarsDstSuffix = "MOCK_RANDOM_SCALARS_DST_";

    private const int ExpandLengthBytes = 48;

    private static readonly ProviderLibrary DeterministicLibrary = new(
        Name: "Lumoin.Veridical.Tests.Bbs",
        Version: typeof(BbsDeterministicScalars).Assembly.GetName().Version?.ToString() ?? "unknown");

    private static readonly CryptoLibrary DeterministicCrypto = new(
        Name: "IETF-mocked-calculate-random-scalars",
        Version: "draft-irtf-cfrg-bbs-signatures-10");

    private static readonly ProviderClass DeterministicClass = new(nameof(BbsDeterministicScalars));

    private static readonly ProviderOperation DeterministicOperation = new("BbsDeterministicScalar");


    /// <summary>
    /// Builds a <see cref="ScalarRandomDelegate"/> that returns the
    /// first <paramref name="count"/> scalars of the IETF deterministic
    /// sequence (<c>mocked_calculate_random_scalars</c>) for the supplied
    /// <paramref name="ciphersuite"/>, seeded by <paramref name="seed"/>.
    /// Successive invocations of the returned delegate yield the precomputed
    /// scalars in order.
    /// </summary>
    /// <param name="seed">The derivation seed (the IETF canonical value is <see cref="CanonicalSeedBls12Curve381Sha256"/> for both ciphersuites — the seed bytes are identical; the DST and the underlying <c>expand_message</c> variant differ).</param>
    /// <param name="ciphersuite">The BBS+ ciphersuite the scalars belong to. Determines both the DST (<c>api_id || "MOCK_RANDOM_SCALARS_DST_"</c>) and the <c>expand_message</c> variant used to derive the uniform bytes.</param>
    /// <param name="count">Total number of scalars to be drawn from the returned delegate (5 + U for a U-undisclosed proof).</param>
    /// <param name="reduce">Backend scalar-reduce delegate, used to map each 48-byte chunk to a 32-byte canonical scalar.</param>
    /// <returns>A delegate that yields the i-th precomputed scalar on the i-th call.</returns>
    /// <exception cref="ArgumentException">When <paramref name="ciphersuite"/> is not a known well-known ciphersuite.</exception>
    public static ScalarRandomDelegate FromSeed(
        ReadOnlySpan<byte> seed,
        BbsCiphersuite ciphersuite,
        int count,
        ScalarReduceDelegate reduce)
    {
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentOutOfRangeException.ThrowIfNegative(count);

        byte[] dst = Encoding.UTF8.GetBytes(ciphersuite.Identifier + IetfMockRandomScalarsDstSuffix);

        byte[] uniformBytes = new byte[ExpandLengthBytes * count];
        if(count > 0)
        {
            if(ciphersuite == BbsCiphersuite.Bls12Curve381Sha256)
            {
                Rfc9380ExpandMessage.ExpandMessageXmdSha256(seed, dst, uniformBytes);
            }
            else if(ciphersuite == BbsCiphersuite.Bls12Curve381Shake256)
            {
                Rfc9380ExpandMessage.ExpandMessageXofShake256(seed, dst, uniformBytes);
            }
            else
            {
                throw new ArgumentException($"Unknown BBS+ ciphersuite '{ciphersuite.Identifier}'.", nameof(ciphersuite));
            }
        }

        //Precompute the reduced 32-byte scalars so the delegate is a thin lookup.
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
                DeterministicLibrary,
                DeterministicCrypto,
                DeterministicClass,
                DeterministicOperation);
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
