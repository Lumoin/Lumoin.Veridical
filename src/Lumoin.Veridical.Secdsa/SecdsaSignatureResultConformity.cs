using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Buffers;
using System.Security.Cryptography;
using static Lumoin.Veridical.Core.Cryptography.ConstantTimeComparison;
using static Lumoin.Veridical.Secdsa.P256PointValidation;
using static Lumoin.Veridical.Secdsa.P256ScalarValidation;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The zero-knowledge signature-result conformity check for ECDSA signatures (Verheul Annex F, Algorithm 41):
/// a monitoring service verifies that a transaction record contains a valid signature on the message the
/// instruction fixes, without being given the signature and therefore without being able to present it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Prover.</b> <see cref="Prove"/> takes the signature <c>(r, s)</c>, forms its full representation
/// <c>(R, s)</c>, the blinded pair <c>G'' = s⁻¹·G</c> and <c>Q_U'' = s⁻¹·Q_U</c>, and the proof <c>π</c> that the pair
/// shares the scalar <c>s⁻¹</c> across the generators <c>G</c> and <c>Q_U</c>. That is the blind-signing relation
/// of <see cref="SecdsaEvidence"/> with the user key <c>Q_U</c> in the place of the certificate point <c>Y'</c>
/// (the blinded verification of Algorithm 36 with the blinding key set to one), so the proof is produced and
/// verified by <see cref="SecdsaEvidence.ProveBlindingRelation"/> and <see cref="SecdsaEvidence.VerifyBlindingRelation"/>
/// (Algorithms 20 and 21). The prover refuses a signature that does not verify, because a record built from one
/// could only raise an alarm.
/// </para>
/// <para>
/// <b>Verifier.</b> <see cref="Check"/> performs Algorithm 41 steps 1 to 4. It needs no secret key and no
/// privileged access. Its inputs come from a possibly compromised component, so every malformed or failing input
/// is an alarm returned as a <see cref="SignatureResultConformity"/> value; the method does not throw for the
/// alarm case.
/// </para>
/// <para>
/// <b>Soundness reading.</b> Since <c>R = e·G'' + r·Q_U'' = s⁻¹·(e·G + r·Q_U)</c> and the proof ties both
/// blinded points to one scalar <c>t</c>, the equation holds exactly when <c>(R, t⁻¹)</c> is a valid signature
/// on <c>e</c> under <c>Q_U</c>. Verification is therefore an equality of points, and <c>r</c> is the
/// x-coordinate of <c>R</c> reduced modulo the group order, as in ECDSA.
/// </para>
/// </remarks>
public static class SecdsaSignatureResultConformity
{
    /// <summary>The P-256 scalar octet length.</summary>
    public const int ScalarSizeBytes = WellKnownCurves.P256ScalarSizeBytes;

    /// <summary>The P-256 SEC1 compressed point length.</summary>
    public const int CompressedPointSizeBytes = WellKnownCurves.P256CompressedSizeBytes;

    private static CurveParameterSet Curve { get; } = CurveParameterSet.P256;


    /// <summary>
    /// Builds the signature-result record <c>(R, G'', Q_U'', π)</c> for an ECDSA signature (Annex F, the paragraph
    /// before Algorithm 41, which refers to Algorithms 20 and 21 for the proof).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <paramref name="signature"/> is the user's signature and stays with the caller; the record does not contain
    /// <c>s</c>. The intermediate <c>s⁻¹</c> is the proof witness and is cleared before return.
    /// </para>
    /// <para>
    /// The caller authenticates <paramref name="userPublicKey"/> and <paramref name="messageHash"/>: the record
    /// proves a signature under exactly that key on exactly that message representative.
    /// </para>
    /// </remarks>
    /// <param name="signature">The ECDSA signature <c>(r, s)</c> on <paramref name="messageHash"/> under <paramref name="userPublicKey"/>.</param>
    /// <param name="messageHash">The message representative <c>e</c>, 32-byte big-endian.</param>
    /// <param name="userPublicKey">The user public key <c>Q_U</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="nonceSource">The commitment-nonce source of the proof; production binds RFC 6979.</param>
    /// <param name="hash">The Fiat–Shamir hash.</param>
    /// <param name="scalarMultiply">Scalar multiplication mod <c>n</c>.</param>
    /// <param name="scalarAdd">Scalar addition mod <c>n</c>.</param>
    /// <param name="scalarInvert">Scalar inversion mod <c>n</c>.</param>
    /// <param name="scalarReduce">Reduction mod <c>n</c>.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication.</param>
    /// <param name="g1Add">G1 addition.</param>
    /// <param name="pool">The pool to rent the record buffer from.</param>
    /// <returns>The record, owned by the caller.</returns>
    /// <exception cref="ArgumentNullException">When a delegate, <paramref name="signature"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a span has the wrong length, <paramref name="userPublicKey"/> is not a canonical finite on-curve point, or the signature does not verify under the key on the message.</exception>
    /// <exception cref="InvalidOperationException">When the proof nonce yields a degenerate proof (retry; probability about <c>1/n</c>).</exception>
    public static SignatureResultRecord Prove(
        SecdsaSignature signature,
        ReadOnlySpan<byte> messageHash,
        ReadOnlySpan<byte> userPublicKey,
        SecdsaNonceSource nonceSource,
        FiatShamirHashDelegate hash,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarAddDelegate scalarAdd,
        ScalarInvertDelegate scalarInvert,
        ScalarReduceDelegate scalarReduce,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1AddDelegate g1Add,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(nonceSource);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(scalarMultiply);
        ArgumentNullException.ThrowIfNull(scalarAdd);
        ArgumentNullException.ThrowIfNull(scalarInvert);
        ArgumentNullException.ThrowIfNull(scalarReduce);
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        ArgumentNullException.ThrowIfNull(g1Add);
        ArgumentNullException.ThrowIfNull(pool);
        RequireLength(messageHash, ScalarSizeBytes, nameof(messageHash));

        Span<byte> canonicalKey = stackalloc byte[CompressedPointSizeBytes];
        ValidateCanonical(userPublicKey, g1ScalarMultiply, canonicalKey, nameof(userPublicKey));

        if(!SecdsaAlgorithm.Verify(canonicalKey, messageHash, signature.GetRBytes(), signature.GetSBytes(), scalarMultiply, scalarInvert, scalarReduce, g1ScalarMultiply, g1Add))
        {
            throw new ArgumentException("The signature does not verify under the user public key on the message.", nameof(signature));
        }

        //The full representation (R, s) of Annex A.2: R is recovered from the verified signature.
        Span<byte> noncePoint = stackalloc byte[CompressedPointSizeBytes];
        if(!SecdsaAlgorithm.RecoverNoncePoint(canonicalKey, messageHash, signature.GetRBytes(), signature.GetSBytes(), scalarMultiply, scalarInvert, scalarReduce, g1ScalarMultiply, g1Add, noncePoint))
        {
            throw new ArgumentException("The nonce point of the signature cannot be recovered.", nameof(signature));
        }

        //The proof witness is t = s^-1; G'' = t·G and Q_U'' = t·Q_U. The witness is cleared in the finally.
        Span<byte> witness = stackalloc byte[ScalarSizeBytes];
        Span<byte> generator = stackalloc byte[CompressedPointSizeBytes];
        Span<byte> blindedGenerator = stackalloc byte[CompressedPointSizeBytes];
        Span<byte> blindedKey = stackalloc byte[CompressedPointSizeBytes];
        IMemoryOwner<byte> owner = pool.Rent(SignatureResultRecord.SizeBytes);
        bool completed = false;
        try
        {
            scalarInvert(signature.GetSBytes(), witness, Curve);
            WellKnownCurves.GetG1GeneratorCompressed(Curve).CopyTo(generator);
            g1ScalarMultiply(generator, witness, blindedGenerator, Curve);
            g1ScalarMultiply(canonicalKey, witness, blindedKey, Curve);

            using DlEqualityProof proof = SecdsaEvidence.ProveBlindingRelationSpan(
                generator, blindedGenerator, canonicalKey, blindedKey, witness,
                nonceSource, hash, scalarMultiply, scalarAdd, scalarReduce, g1ScalarMultiply, pool);

            Span<byte> record = owner.Memory.Span[..SignatureResultRecord.SizeBytes];
            noncePoint.CopyTo(record[SignatureResultRecord.NoncePointOffset..]);
            blindedGenerator.CopyTo(record[SignatureResultRecord.BlindedGeneratorOffset..]);
            blindedKey.CopyTo(record[SignatureResultRecord.BlindedPublicKeyOffset..]);
            proof.AsReadOnlySpan().CopyTo(record[SignatureResultRecord.ProofOffset..]);
            completed = true;
        }
        finally
        {
            witness.Clear();
            if(!completed)
            {
                owner.Dispose();
            }
        }

        return new SignatureResultRecord(owner, SignatureResultRecord.AlgebraicTag);
    }


    /// <summary>
    /// The conformity check of Algorithm 41, steps 1 to 4: verifies the proof <c>π</c> that <c>G''</c> and <c>Q_U''</c>
    /// share one scalar across <c>G</c> and <c>Q_U</c>, then validates <c>R = e·G'' + r·Q_U''</c> with <c>r</c> the
    /// x-coordinate of <c>R</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Step 1 of the paper obtains the message representative <c>e</c> and the user key <c>Q_U</c> from the
    /// instruction; here the caller supplies them, and authenticating that they are those the instruction fixes
    /// is the caller's. Nothing is secret.
    /// </para>
    /// <para>
    /// Step 3 of the paper writes <c>r</c> as the x-coordinate of <c>R</c> converted to an integer; the equation
    /// is a scalar multiple of the group, whose scalars are modulo the group order, so <c>r</c> is that integer
    /// reduced modulo <c>n</c>, the reduction ECDSA itself applies. A zero <c>r</c> is an alarm, as no valid
    /// ECDSA signature has one.
    /// </para>
    /// </remarks>
    /// <param name="record">The record <c>(R, G'', Q_U'', π)</c> from the transaction record.</param>
    /// <param name="messageHash">The message representative <c>e</c>, 32-byte big-endian; reduced mod <c>n</c> as in ECDSA.</param>
    /// <param name="userPublicKey">The user public key <c>Q_U</c>, SEC1 compressed (33 bytes).</param>
    /// <param name="hash">The Fiat–Shamir hash.</param>
    /// <param name="scalarReduce">Reduction mod <c>n</c>.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication.</param>
    /// <param name="g1Add">G1 addition.</param>
    /// <param name="g1Negate">G1 negation.</param>
    /// <returns><see cref="SignatureResultConformity.NoAlarm"/> or the alarm that was raised.</returns>
    /// <exception cref="ArgumentNullException">When a delegate or <paramref name="record"/> is <see langword="null"/>.</exception>
    public static SignatureResultConformity Check(
        SignatureResultRecord record,
        ReadOnlySpan<byte> messageHash,
        ReadOnlySpan<byte> userPublicKey,
        FiatShamirHashDelegate hash,
        ScalarReduceDelegate scalarReduce,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1AddDelegate g1Add,
        G1NegateDelegate g1Negate)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(scalarReduce);
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        ArgumentNullException.ThrowIfNull(g1Add);
        ArgumentNullException.ThrowIfNull(g1Negate);

        //Every input is wire data: a structural defect is an alarm, never an exception.
        if(messageHash.Length != ScalarSizeBytes
            || !IsValidCanonical(userPublicKey, g1ScalarMultiply)
            || !IsValidCanonical(record.GetNoncePointBytes(), g1ScalarMultiply)
            || !IsValidCanonical(record.GetBlindedGeneratorBytes(), g1ScalarMultiply)
            || !IsValidCanonical(record.GetBlindedPublicKeyBytes(), g1ScalarMultiply))
        {
            return SignatureResultConformity.AlarmMalformedRecord;
        }

        //Step 2: Algorithm 21 on (G, Q_U) against (G'', Q_U'').
        Span<byte> generator = stackalloc byte[CompressedPointSizeBytes];
        WellKnownCurves.GetG1GeneratorCompressed(Curve).CopyTo(generator);
        if(!SecdsaEvidence.VerifyBlindingRelationSpan(
            generator, record.GetBlindedGeneratorBytes(), userPublicKey, record.GetBlindedPublicKeyBytes(),
            record.GetProofRBytes(), record.GetProofSBytes(),
            hash, scalarReduce, g1ScalarMultiply, g1Add, g1Negate))
        {
            return SignatureResultConformity.AlarmProofRejected;
        }

        //Step 3: r = x(R) mod n and the check R = e·G'' + r·Q_U''.
        try
        {
            Span<byte> e = stackalloc byte[ScalarSizeBytes];
            Span<byte> r = stackalloc byte[ScalarSizeBytes];
            scalarReduce(messageHash, e, Curve);
            scalarReduce(record.GetNoncePointBytes()[1..], r, Curve);
            if(IsZero(r))
            {
                return SignatureResultConformity.AlarmResultMismatch;
            }

            Span<byte> rQ = stackalloc byte[CompressedPointSizeBytes];
            g1ScalarMultiply(record.GetBlindedPublicKeyBytes(), r, rQ, Curve);

            //A zero e makes e·G'' the identity, which the scalar multiplication need not represent; the sum is then r·Q_U'' alone.
            Span<byte> expected = stackalloc byte[CompressedPointSizeBytes];
            if(IsZero(e))
            {
                rQ.CopyTo(expected);
            }
            else
            {
                Span<byte> eG = stackalloc byte[CompressedPointSizeBytes];
                g1ScalarMultiply(record.GetBlindedGeneratorBytes(), e, eG, Curve);
                g1Add(eG, rQ, expected, Curve);
            }

            return CryptographicOperations.FixedTimeEquals(expected, record.GetNoncePointBytes())
                ? SignatureResultConformity.NoAlarm
                : SignatureResultConformity.AlarmResultMismatch;
        }
        catch(InvalidOperationException)
        {
            return SignatureResultConformity.AlarmResultMismatch;
        }
        catch(ArgumentException)
        {
            return SignatureResultConformity.AlarmResultMismatch;
        }
    }
}
