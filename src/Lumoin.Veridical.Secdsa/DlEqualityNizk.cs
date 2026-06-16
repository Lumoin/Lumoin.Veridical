using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Numerics;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// Schnorr / Chaum–Pedersen non-interactive zero-knowledge proof of equality of discrete logarithms over NIST
/// P-256 — Verheul's Algorithm 19 (prove) and Algorithm 20 (verify). The proof attests statement (9):
/// <c>∃ d ∈ [1, n−1] : D_i = d·G_i for every i</c>, i.e. a set of public keys <c>D_i</c> share one private key
/// <c>d</c> across their (possibly distinct) generators <c>G_i</c>, in zero knowledge. SECDSA uses the two-pair
/// case (<c>n = 1</c>) to prove the blinding relations in blind signing and transaction-transparency evidence.
/// </summary>
/// <remarks>
/// <para>
/// <b>Fiat–Shamir, full-width <c>r</c>.</b> The challenge <c>r = H(Ḡ ‖ Ḡ' ‖ D̄ ‖ N)</c> is the raw hash digest
/// treated as an integer — stored and compared <em>full-width</em>, never reduced mod <c>n</c> (see
/// <see cref="DlEqualityProof"/>). The response is <c>s = k + (r mod n)·d mod n</c>; verification recomputes the
/// commitments <c>G'_i = s·G_i − (r mod n)·D_i</c> and accepts iff <c>H(Ḡ ‖ Ḡ' ‖ D̄ ‖ N) == r</c>. The reduction
/// <c>r mod n</c> is applied <em>only</em> where <c>r</c> is a scalar coefficient.
/// </para>
/// <para>
/// <b>Delegate-injected.</b> The hash is supplied as a <see cref="FiatShamirHashDelegate"/> so the caller chooses
/// the hasher implementation; the algorithm fixes SHA-256 (its 32-byte digest matches the P-256 scalar width).
/// All scalar and group arithmetic enters as named Core delegates — the package carries no concrete backend.
/// </para>
/// <para>
/// <b>Deterministic, domain-separated nonce.</b> The commitment nonce <c>k</c> is drawn through a <see cref="SecdsaNonceSource"/>
/// keyed on the witness and a digest of the static statement <c>Ḡ ‖ D̄ ‖ N</c>, so it is unpredictable without
/// the witness and never repeats across distinct statements. A degenerate result (<c>r = 0</c>, <c>s = 0</c>, or
/// a commitment at infinity) throws — it is a ~<c>1/n</c> event, handled exactly as <see cref="SecdsaAlgorithm"/>
/// handles a degenerate raw signature.
/// </para>
/// <para>
/// <b>Point-validation contract.</b> <see cref="Verify"/> takes no explicit on-curve or subgroup delegate: it
/// relies on the injected group delegates to decode and thereby validate each compressed point, throwing on a
/// malformed or off-curve encoding (which the verifier turns into a rejection), plus an explicit check that no
/// input is the identity (the <c>0x00</c>-prefixed 33-byte point). On P-256 (prime order, cofactor 1) on-curve
/// and non-identity already implies prime-order membership. The seam therefore requires that group delegates
/// throw on an invalid encoding; a backend that clamps or sentinels instead would weaken this.
/// </para>
/// <para>
/// <b>Not constant-time yet.</b> As with <see cref="SecdsaAlgorithm"/>, the wired arithmetic and range checks are
/// variable-time in their secret inputs; witness-derived scratch (<c>k</c>, <c>r·d</c>) is nonetheless cleared
/// before return. Constant-time hardening is a separate, later step.
/// </para>
/// </remarks>
public static class DlEqualityNizk
{
    /// <summary>The P-256 scalar octet length (also the SHA-256 digest width carried by <c>r</c>).</summary>
    public const int ScalarSizeBytes = WellKnownCurves.P256ScalarSizeBytes;

    /// <summary>The P-256 SEC1 compressed point length, the form every generator, public key, and commitment takes.</summary>
    public const int CompressedPointSizeBytes = WellKnownCurves.P256CompressedSizeBytes;

    //A generous upper bound on the assembled Fiat-Shamir transcript so a runtime-sized stackalloc cannot be
    //driven to overflow by a large pair count or challenge. SECDSA uses two pairs and a <=32-byte challenge
    //(~198-230 bytes); this cap covers far more while staying a safe stack allocation.
    private const int MaxTranscriptSizeBytes = 4096;

    private static readonly CurveParameterSet Curve = CurveParameterSet.P256;


    //The order n as a 32-byte big-endian scalar, used only for the public-order range checks. These range
    //helpers mirror the private ones in SecdsaAlgorithm; they are duplicated rather than shared so this
    //security-sensitive new code does not churn the already-verified SecdsaAlgorithm. A later refactor may
    //promote both onto one internal helper.
    private static byte[] OrderBytes { get; } = BuildOrderBytes();


    //Domain-separation label for the deterministic commitment-nonce pre-image. It (a) disjoins this NIZK's nonce
    //domain from the ECDSA signing nonce so the two can never collide, and (b) together with the length prefixes
    //makes the pre-image injective in the statement. It is prover-local and never transmitted, so it does NOT
    //enter the Fiat-Shamir challenge r (which stays paper-conformant for interoperability).
    private static readonly byte[] NonceDomainLabel = "SECDSA-DLEQ-NIZK-nonce-v1"u8.ToArray();


    /// <summary>
    /// Proves statement (9) — that every <c>(G_i, D_i)</c> pair shares the private key <paramref name="witness"/>
    /// (<c>D_i = d·G_i</c>) — writing the proof <c>(r, s)</c> into the supplied spans (Verheul Algorithm 19).
    /// </summary>
    /// <param name="witness">The shared private key <c>d</c>, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="generatorsConcat">The generators <c>G_0 ‖ … ‖ G_n</c>, each 33-byte SEC1 compressed.</param>
    /// <param name="publicKeysConcat">The public keys <c>D_0 ‖ … ‖ D_n</c>, each 33-byte; <c>D_i = d·G_i</c>.</param>
    /// <param name="challengeN">An optional context binding <c>N</c> appended last to the transcript (may be empty).</param>
    /// <param name="nonceSource">The nonce source for the commitment nonce <c>k</c>; production binds RFC 6979.</param>
    /// <param name="hash">The Fiat–Shamir hash; invoked with <see cref="WellKnownHashAlgorithms.Sha256"/>.</param>
    /// <param name="scalarMultiply">Scalar multiplication mod <c>n</c>.</param>
    /// <param name="scalarAdd">Scalar addition mod <c>n</c>.</param>
    /// <param name="scalarReduce">Reduction mod <c>n</c> (used only to reduce <c>r</c> for the scalar coefficient).</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication (for the commitments <c>k·G_i</c>).</param>
    /// <param name="rOut">Receives the 32-byte full-width Fiat–Shamir value <c>r</c>.</param>
    /// <param name="sOut">Receives the 32-byte response scalar <c>s</c>.</param>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span has the wrong length, the concatenations disagree, the transcript exceeds the cap, or <c>d</c> is outside <c>[1, n−1]</c>.</exception>
    /// <exception cref="InvalidOperationException">When the nonce yields a degenerate proof (retry; probability ~<c>1/n</c>).</exception>
    public static void Prove(
        ReadOnlySpan<byte> witness,
        ReadOnlySpan<byte> generatorsConcat,
        ReadOnlySpan<byte> publicKeysConcat,
        ReadOnlySpan<byte> challengeN,
        SecdsaNonceSource nonceSource,
        FiatShamirHashDelegate hash,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarAddDelegate scalarAdd,
        ScalarReduceDelegate scalarReduce,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        Span<byte> rOut,
        Span<byte> sOut)
    {
        ArgumentNullException.ThrowIfNull(nonceSource);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(scalarMultiply);
        ArgumentNullException.ThrowIfNull(scalarAdd);
        ArgumentNullException.ThrowIfNull(scalarReduce);
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        RequireLength(witness, ScalarSizeBytes, nameof(witness));
        RequireLength(rOut, ScalarSizeBytes, nameof(rOut));
        RequireLength(sOut, ScalarSizeBytes, nameof(sOut));
        int pairCount = RequirePairs(generatorsConcat, publicKeysConcat);
        RequireScalarInRange(witness, nameof(witness));

        int pointsLen = pairCount * CompressedPointSizeBytes;
        int fsLen = (pointsLen * 3) + challengeN.Length;
        if(fsLen > MaxTranscriptSizeBytes)
        {
            throw new ArgumentException(
                $"The assembled transcript ({fsLen} bytes) exceeds the {MaxTranscriptSizeBytes}-byte cap; reduce the pair count or the challenge length.",
                nameof(challengeN));
        }

        Span<byte> k = stackalloc byte[ScalarSizeBytes];
        Span<byte> rModN = stackalloc byte[ScalarSizeBytes];
        Span<byte> rd = stackalloc byte[ScalarSizeBytes];
        try
        {
            //k binds to (witness, statement) through an INJECTIVE, domain-separated pre-image. Without the label
            //and the pairCount / |N| length prefixes the bare concatenation Gbar || Dbar || N is ambiguous: two
            //DIFFERENT statements (e.g. one pair with N = D0||D1 versus two pairs with N empty) collapse to the
            //same bytes, hence the same k, and two responses over one k leak the witness. The commitments G'_i
            //depend on k, so they cannot enter its derivation (circular); the Fiat-Shamir challenge below binds
            //them. This pre-image is prover-local — it does NOT affect the wire-visible, paper-conformant r.
            int noncePreimageLen = NonceDomainLabel.Length + sizeof(int) + (pointsLen * 2) + sizeof(int) + challengeN.Length;
            if(noncePreimageLen > MaxTranscriptSizeBytes)
            {
                throw new ArgumentException(
                    $"The nonce pre-image ({noncePreimageLen} bytes) exceeds the {MaxTranscriptSizeBytes}-byte cap; reduce the pair count or the challenge length.",
                    nameof(challengeN));
            }

            Span<byte> noncePreimage = stackalloc byte[noncePreimageLen];
            int offset = 0;
            NonceDomainLabel.CopyTo(noncePreimage);
            offset += NonceDomainLabel.Length;
            BinaryPrimitives.WriteInt32BigEndian(noncePreimage[offset..], pairCount);
            offset += sizeof(int);
            generatorsConcat.CopyTo(noncePreimage[offset..]);
            offset += pointsLen;
            publicKeysConcat.CopyTo(noncePreimage[offset..]);
            offset += pointsLen;
            BinaryPrimitives.WriteInt32BigEndian(noncePreimage[offset..], challengeN.Length);
            offset += sizeof(int);
            challengeN.CopyTo(noncePreimage[offset..]);

            Span<byte> staticDigest = stackalloc byte[ScalarSizeBytes];
            hash(noncePreimage, staticDigest, WellKnownHashAlgorithms.Sha256);
            nonceSource(Curve, witness, staticDigest, k);

            //Fiat-Shamir transcript: Gbar || G'bar || Dbar || N, every point 33-byte SEC1 compressed.
            Span<byte> fsTranscript = stackalloc byte[fsLen];
            generatorsConcat.CopyTo(fsTranscript);
            Span<byte> commitments = fsTranscript.Slice(pointsLen, pointsLen);
            for(int i = 0; i < pairCount; i++)
            {
                int at = i * CompressedPointSizeBytes;
                //G'_i = k·G_i — the SAME k for every pair is what ties them to one witness.
                g1ScalarMultiply(generatorsConcat.Slice(at, CompressedPointSizeBytes), k, commitments.Slice(at, CompressedPointSizeBytes), Curve);
                if(commitments[at] == 0x00)
                {
                    throw new InvalidOperationException("The nonce yielded a commitment at infinity; retry with a fresh nonce.");
                }
            }

            publicKeysConcat.CopyTo(fsTranscript[(pointsLen * 2)..]);
            challengeN.CopyTo(fsTranscript[(pointsLen * 3)..]);

            //r = H(transcript), stored FULL-WIDTH (the raw digest, never reduced mod n).
            hash(fsTranscript, rOut, WellKnownHashAlgorithms.Sha256);
            if(IsZero(rOut))
            {
                throw new InvalidOperationException("The Fiat-Shamir challenge r = 0; retry with a fresh nonce.");
            }

            //s = k + (r mod n)·d mod n. r is reduced mod n ONLY here, as the scalar coefficient.
            scalarReduce(rOut, rModN, Curve);
            scalarMultiply(rModN, witness, rd, Curve);
            scalarAdd(k, rd, sOut, Curve);
            if(IsZero(sOut))
            {
                throw new InvalidOperationException("The response s = 0; retry with a fresh nonce.");
            }
        }
        finally
        {
            k.Clear();
            rModN.Clear();
            rd.Clear();
        }
    }


    /// <summary>
    /// Proves statement (9) and returns the proof as a pool-backed <see cref="DlEqualityProof"/>.
    /// </summary>
    /// <param name="witness">The shared private key <c>d</c>, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="generatorsConcat">The generators <c>G_0 ‖ … ‖ G_n</c>, each 33-byte SEC1 compressed.</param>
    /// <param name="publicKeysConcat">The public keys <c>D_0 ‖ … ‖ D_n</c>, each 33-byte; <c>D_i = d·G_i</c>.</param>
    /// <param name="challengeN">An optional context binding <c>N</c> (may be empty).</param>
    /// <param name="nonceSource">The nonce source for the commitment nonce <c>k</c>.</param>
    /// <param name="hash">The Fiat–Shamir hash.</param>
    /// <param name="scalarMultiply">Scalar multiplication mod <c>n</c>.</param>
    /// <param name="scalarAdd">Scalar addition mod <c>n</c>.</param>
    /// <param name="scalarReduce">Reduction mod <c>n</c>.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication.</param>
    /// <param name="pool">The pool to rent the 64-byte proof buffer from.</param>
    /// <returns>A proof wrapping a pool-rented <c>r || s</c> buffer.</returns>
    /// <exception cref="ArgumentNullException">When a delegate or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span has the wrong length, the concatenations disagree, the transcript exceeds the cap, or <c>d</c> is outside <c>[1, n−1]</c>.</exception>
    /// <exception cref="InvalidOperationException">When the nonce yields a degenerate proof (retry; probability ~<c>1/n</c>).</exception>
    public static DlEqualityProof Prove(
        ReadOnlySpan<byte> witness,
        ReadOnlySpan<byte> generatorsConcat,
        ReadOnlySpan<byte> publicKeysConcat,
        ReadOnlySpan<byte> challengeN,
        SecdsaNonceSource nonceSource,
        FiatShamirHashDelegate hash,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarAddDelegate scalarAdd,
        ScalarReduceDelegate scalarReduce,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(DlEqualityProof.SizeBytes);
        try
        {
            Span<byte> proof = owner.Memory.Span[..DlEqualityProof.SizeBytes];
            Prove(
                witness, generatorsConcat, publicKeysConcat, challengeN, nonceSource, hash,
                scalarMultiply, scalarAdd, scalarReduce, g1ScalarMultiply,
                proof.Slice(DlEqualityProof.ROffset, DlEqualityProof.RSizeBytes),
                proof.Slice(DlEqualityProof.SOffset, DlEqualityProof.SSizeBytes));
        }
        catch
        {
            owner.Dispose();
            throw;
        }

        return new DlEqualityProof(owner, DlEqualityProof.AlgebraicTag);
    }


    /// <summary>
    /// Verifies a DL-equality proof <c>(r, s)</c> for statement (9) over the given <c>(G_i, D_i)</c> pairs
    /// (Verheul Algorithm 20). Adversarial inputs reject rather than throw.
    /// </summary>
    /// <param name="generatorsConcat">The generators <c>G_0 ‖ … ‖ G_n</c>, each 33-byte SEC1 compressed.</param>
    /// <param name="publicKeysConcat">The public keys <c>D_0 ‖ … ‖ D_n</c>, each 33-byte.</param>
    /// <param name="challengeN">The context binding <c>N</c> the proof was bound to (may be empty).</param>
    /// <param name="r">The full-width Fiat–Shamir value <c>r</c>, 32-byte big-endian (raw digest, not a scalar).</param>
    /// <param name="s">The response scalar <c>s</c>, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="hash">The Fiat–Shamir hash; invoked with <see cref="WellKnownHashAlgorithms.Sha256"/>.</param>
    /// <param name="scalarReduce">Reduction mod <c>n</c> (for the scalar coefficient <c>r mod n</c>).</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication.</param>
    /// <param name="g1Add">G1 addition.</param>
    /// <param name="g1Negate">G1 negation (for the subtraction <c>s·G_i − (r mod n)·D_i</c>).</param>
    /// <returns><see langword="true"/> iff the proof is valid.</returns>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="r"/>/<paramref name="s"/> has the wrong length or the concatenations disagree.</exception>
    public static bool Verify(
        ReadOnlySpan<byte> generatorsConcat,
        ReadOnlySpan<byte> publicKeysConcat,
        ReadOnlySpan<byte> challengeN,
        ReadOnlySpan<byte> r,
        ReadOnlySpan<byte> s,
        FiatShamirHashDelegate hash,
        ScalarReduceDelegate scalarReduce,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1AddDelegate g1Add,
        G1NegateDelegate g1Negate)
    {
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(scalarReduce);
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        ArgumentNullException.ThrowIfNull(g1Add);
        ArgumentNullException.ThrowIfNull(g1Negate);

        //A proof and its statement arrive from the wire: structural defects REJECT, they do not throw. (Null
        //delegates remain a programmer error and still throw above.) Wrong-width r/s, an empty or non-33-multiple
        //generator concatenation, and a mismatched public-key concatenation are all rejected here.
        if(r.Length != ScalarSizeBytes || s.Length != ScalarSizeBytes)
        {
            return false;
        }
        if(generatorsConcat.Length == 0
            || generatorsConcat.Length % CompressedPointSizeBytes != 0
            || publicKeysConcat.Length != generatorsConcat.Length)
        {
            return false;
        }

        int pairCount = generatorsConcat.Length / CompressedPointSizeBytes;
        int pointsLen = pairCount * CompressedPointSizeBytes;
        int fsLen = (pointsLen * 3) + challengeN.Length;
        if(fsLen > MaxTranscriptSizeBytes)
        {
            //Adversarial oversized input: reject rather than throw.
            return false;
        }

        //Adversarial inputs (out-of-range r/s, a malformed or infinity point) must reject, not throw: each point
        //is decoded — and thereby validated on-curve — by the group delegate, which throws on a malformed point;
        //the catch turns that into a rejection. For P-256 (prime order, cofactor 1) on-curve and non-infinity
        //already implies prime-order membership, so no separate subgroup check is needed.
        try
        {
            //r is full-width: reject only the zero value (range [1, 2^256-1]). s is a scalar: reject outside [1, n-1].
            if(IsZero(r) || IsZero(s) || !IsLess(s, OrderBytes))
            {
                return false;
            }

            //Every G_i and D_i must be a finite point, and each G_i a generator, i.e. not the identity.
            for(int i = 0; i < pairCount; i++)
            {
                int at = i * CompressedPointSizeBytes;
                if(generatorsConcat[at] == 0x00 || publicKeysConcat[at] == 0x00)
                {
                    return false;
                }
            }

            Span<byte> rModN = stackalloc byte[ScalarSizeBytes];
            scalarReduce(r, rModN, Curve);

            Span<byte> fsTranscript = stackalloc byte[fsLen];
            generatorsConcat.CopyTo(fsTranscript);
            Span<byte> commitments = fsTranscript.Slice(pointsLen, pointsLen);

            Span<byte> sG = stackalloc byte[CompressedPointSizeBytes];
            Span<byte> rD = stackalloc byte[CompressedPointSizeBytes];
            Span<byte> negRD = stackalloc byte[CompressedPointSizeBytes];
            for(int i = 0; i < pairCount; i++)
            {
                int at = i * CompressedPointSizeBytes;
                //G'_i = s·G_i − (r mod n)·D_i — subtraction via negate + add (there is no G1 subtract delegate).
                g1ScalarMultiply(generatorsConcat.Slice(at, CompressedPointSizeBytes), s, sG, Curve);
                g1ScalarMultiply(publicKeysConcat.Slice(at, CompressedPointSizeBytes), rModN, rD, Curve);
                g1Negate(rD, negRD, Curve);
                Span<byte> commitment = commitments.Slice(at, CompressedPointSizeBytes);
                g1Add(sG, negRD, commitment, Curve);
                if(commitment[0] == 0x00)
                {
                    return false;
                }
            }

            publicKeysConcat.CopyTo(fsTranscript[(pointsLen * 2)..]);
            challengeN.CopyTo(fsTranscript[(pointsLen * 3)..]);

            //v = H(transcript), full-width; accept iff it matches the carried r byte-for-byte (NOT reduced).
            Span<byte> v = stackalloc byte[ScalarSizeBytes];
            hash(fsTranscript, v, WellKnownHashAlgorithms.Sha256);

            return v.SequenceEqual(r);
        }
        catch(InvalidOperationException)
        {
            return false;
        }
        catch(ArgumentException)
        {
            return false;
        }
    }


    private static byte[] BuildOrderBytes()
    {
        BigInteger n = WellKnownCurves.GetScalarFieldOrder(Curve);
        byte[] big = n.ToByteArray(isUnsigned: true, isBigEndian: true);
        byte[] order = new byte[ScalarSizeBytes];
        big.CopyTo(order.AsSpan(ScalarSizeBytes - big.Length));

        return order;
    }


    private static int RequirePairs(ReadOnlySpan<byte> generatorsConcat, ReadOnlySpan<byte> publicKeysConcat)
    {
        if(generatorsConcat.Length == 0 || generatorsConcat.Length % CompressedPointSizeBytes != 0)
        {
            throw new ArgumentException(
                $"generatorsConcat must be a non-empty multiple of {CompressedPointSizeBytes} bytes; received {generatorsConcat.Length}.",
                nameof(generatorsConcat));
        }

        if(publicKeysConcat.Length != generatorsConcat.Length)
        {
            throw new ArgumentException(
                $"publicKeysConcat ({publicKeysConcat.Length}) must match generatorsConcat ({generatorsConcat.Length}); each pair is one generator and one public key.",
                nameof(publicKeysConcat));
        }

        return generatorsConcat.Length / CompressedPointSizeBytes;
    }


    private static void RequireScalarInRange(ReadOnlySpan<byte> scalar, string name)
    {
        if(IsZero(scalar) || !IsLess(scalar, OrderBytes))
        {
            throw new ArgumentException("The scalar must be in [1, n-1] for the P-256 group order.", name);
        }
    }


    private static void RequireLength(ReadOnlySpan<byte> span, int expected, string name)
    {
        if(span.Length != expected)
        {
            throw new ArgumentException($"Expected {expected} bytes; received {span.Length}.", name);
        }
    }


    private static bool IsZero(ReadOnlySpan<byte> value) => value.IndexOfAnyExcept((byte)0) < 0;


    //Unsigned big-endian comparison of two equal-length scalars: returns a < b.
    private static bool IsLess(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        for(int i = 0; i < a.Length; i++)
        {
            if(a[i] != b[i])
            {
                return a[i] < b[i];
            }
        }

        return false;
    }
}
