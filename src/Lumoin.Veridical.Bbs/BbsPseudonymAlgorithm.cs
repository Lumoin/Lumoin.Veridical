using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Text;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// Shared algorithmic primitives for the per-verifier-pseudonym BBS
/// Interface operations (CommitWithNym, BlindSignWithNym,
/// VerifyFinalizeWithNym, ProofGenWithNym, ProofVerifyWithNym) per IETF
/// <c>draft-irtf-cfrg-bbs-per-verifier-linkability-03</c>. All
/// operations dispatch to backend delegates; this class implements the
/// pseudonym-specific composition of those delegates — the pseudonym
/// polynomial construction (Section 4), the sigma-protocol init pair
/// (Sections 7.3.1/7.3.2), the pseudonym-aware challenge (Section 8.1),
/// and the <c>combined_header</c> length binding — reusing the core and
/// blind primitives in <see cref="BbsAlgorithm"/>,
/// <see cref="BbsBlindAlgorithm"/>, and <see cref="BbsProofAlgorithm"/>
/// under the pseudonym api_id.
/// </summary>
internal static class BbsPseudonymAlgorithm
{
    /// <summary>
    /// Maps a ciphersuite to its per-verifier-pseudonym Interface value:
    /// the interface a key tagged with a core suite signs and verifies
    /// pseudonym-bound material under.
    /// </summary>
    /// <exception cref="InvalidOperationException">When <paramref name="ciphersuite"/> is not one of the six well-known values.</exception>
    public static BbsCiphersuite GetPseudonymInterface(BbsCiphersuite ciphersuite)
    {
        BbsCiphersuite baseSuite = ciphersuite.BaseHashSuite;

        return baseSuite == BbsCiphersuite.Bls12Curve381Sha256
            ? BbsCiphersuite.Bls12Curve381Sha256Pseudonym
            : BbsCiphersuite.Bls12Curve381Shake256Pseudonym;
    }


    /// <summary>
    /// Builds <c>combined_header = header || I2OSP(length_nym_vector, 8)</c>
    /// per Sections 6.1.2 step 9, 6.1.3 step 5, 7.1 step 2, and 7.2 step
    /// 1: the declared nym-vector length is cryptographically bound into
    /// the signature and proof domains at sign, verify, prove, and
    /// proof-verify time, so a prover claiming a different vector length
    /// than the one the signer certified fails every downstream check
    /// (the draft's Sybil-resistance binding, Section 10.2).
    /// </summary>
    /// <param name="header">The application header bytes; may be empty.</param>
    /// <param name="lengthNymVector">The nym-vector length <c>N = length(prover_nyms)</c>.</param>
    /// <param name="pool">The pool to rent the combined buffer from.</param>
    /// <returns>The rented owner (the caller disposes it) and the exact combined length within it.</returns>
    public static (IMemoryOwner<byte> Owner, int Length) ComputeCombinedHeader(
        ReadOnlyMemory<byte> header,
        int lengthNymVector,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegative(lengthNymVector);

        int length = header.Length + 8;
        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            Span<byte> destination = owner.Memory.Span[..length];
            header.Span.CopyTo(destination);
            BinaryPrimitives.WriteUInt64BigEndian(destination[header.Length..], (ulong)lengthNymVector);

            return (owner, length);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Computes the pseudonym base point <c>OP = hash_to_curve_g1(context_id, api_id)</c>
    /// per Sections 7.3.1/7.3.2 step 1: the api_id itself is the
    /// hash-to-curve DST, so each Interface and ciphersuite yields an
    /// independent base for the same <c>context_id</c>.
    /// </summary>
    public static G1Point ComputeOriginPoint(
        ReadOnlySpan<byte> contextId,
        string apiId,
        G1HashToCurveDelegate g1HashToCurve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(apiId);
        ArgumentNullException.ThrowIfNull(g1HashToCurve);
        ArgumentNullException.ThrowIfNull(pool);

        byte[] dst = Encoding.UTF8.GetBytes(apiId);

        return G1Point.FromHashToCurve(contextId, dst, g1HashToCurve, CurveParameterSet.Bls12Curve381, pool);
    }


    /// <summary>
    /// Computes the polynomial evaluation point
    /// <c>z = hash_to_scalar(context_id, api_id || "VECT_NYM_SECRETS")</c>
    /// per Sections 7.3.1/7.3.2 step 2.
    /// </summary>
    public static Scalar ComputeEvaluationPoint(
        ReadOnlySpan<byte> contextId,
        string apiId,
        ScalarHashToScalarDelegate hashToScalar,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(apiId);
        ArgumentNullException.ThrowIfNull(hashToScalar);
        ArgumentNullException.ThrowIfNull(pool);

        byte[] dst = BbsAlgorithm.ComputeDst(apiId, WellKnownBbsDomainSeparationTags.PseudonymSecretsVectorDstSuffix);

        return Scalar.FromHashToScalar(contextId, dst, hashToScalar, CurveParameterSet.Bls12Curve381, pool);
    }


    /// <summary>
    /// Evaluates <c>sum_{i=0}^{N-1} coefficients[i] * z^i</c> in the
    /// scalar field via Horner's rule (iteratively, highest coefficient
    /// first), per the polynomial commitment construction of Sections 4
    /// and 7.3. With <c>N = 1</c> this degenerates to a copy of the
    /// single coefficient.
    /// </summary>
    /// <param name="coefficients">The polynomial coefficients, lowest degree first; at least one. The caller retains ownership.</param>
    /// <param name="evaluationPoint">The point <c>z</c> to evaluate at.</param>
    /// <param name="scalarAdd">Backend scalar addition.</param>
    /// <param name="scalarMultiply">Backend scalar multiplication.</param>
    /// <param name="pool">The pool to rent destination buffers from.</param>
    /// <returns>A freshly-owned scalar holding the evaluation.</returns>
    public static Scalar EvaluateNymPolynomial(
        ReadOnlySpan<Scalar> coefficients,
        Scalar evaluationPoint,
        ScalarAddDelegate scalarAdd,
        ScalarMultiplyDelegate scalarMultiply,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(evaluationPoint);
        ArgumentNullException.ThrowIfNull(scalarAdd);
        ArgumentNullException.ThrowIfNull(scalarMultiply);
        ArgumentNullException.ThrowIfNull(pool);
        if(coefficients.Length < 1)
        {
            throw new ArgumentException("Polynomial evaluation requires at least one coefficient.", nameof(coefficients));
        }

        Scalar accumulator = Scalar.FromCanonical(coefficients[^1].AsReadOnlySpan(), CurveParameterSet.Bls12Curve381, pool);
        try
        {
            for(int i = coefficients.Length - 2; i >= 0; i--)
            {
                using Scalar shifted = accumulator.Multiply(evaluationPoint, scalarMultiply, pool);
                Scalar next = shifted.Add(coefficients[i], scalarAdd, pool);
                accumulator.Dispose();
                accumulator = next;
            }

            return accumulator;
        }
        catch
        {
            //A backend throw mid-loop leaves the running accumulator — pooled
            //secret material — owned here rather than by the caller.
            accumulator.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Computes the pseudonym point <c>OP * poly(nym_secrets, z)</c> per
    /// Section 4 (with the DST-qualified <c>OP</c>/<c>z</c> of Section
    /// 7.3.1). The caller checks the returned point against the
    /// identity/BP1 constraints of Section 3.3.
    /// </summary>
    public static G1Point ComputePseudonymPoint(
        ReadOnlySpan<Scalar> nymSecrets,
        ReadOnlySpan<byte> contextId,
        string apiId,
        ScalarHashToScalarDelegate hashToScalar,
        ScalarAddDelegate scalarAdd,
        ScalarMultiplyDelegate scalarMultiply,
        G1HashToCurveDelegate g1HashToCurve,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);

        using G1Point originPoint = ComputeOriginPoint(contextId, apiId, g1HashToCurve, pool);
        using Scalar evaluationPoint = ComputeEvaluationPoint(contextId, apiId, hashToScalar, pool);
        using Scalar polynomial = EvaluateNymPolynomial(nymSecrets, evaluationPoint, scalarAdd, scalarMultiply, pool);

        return originPoint.ScalarMultiply(polynomial, g1ScalarMultiply, pool);
    }


    /// <summary>
    /// Implements <c>PseudonymProofInit</c> per Section 7.3.1: evaluates
    /// the nym polynomial over the secrets and — in parallel, at the same
    /// point <c>z</c> — over the proof randomness, producing the
    /// pseudonym and the Schnorr announcement <c>Ut = OP * poly(m~)</c>.
    /// </summary>
    /// <param name="nymSecrets">The full <c>nym_secrets</c> vector, in commitment order.</param>
    /// <param name="randomScalars">
    /// The last <c>N</c> random scalars of the BBS proof draw — the
    /// <c>m~</c> blinding values <c>BBS.ProofInit</c> already consumed
    /// for the (always-undisclosed, tail-positioned) nym message slots.
    /// Reusing exactly this randomness, rather than drawing fresh values,
    /// is the binding between the pseudonym proof and the BBS proof: the
    /// shared responses force both relations to hold for the same
    /// <c>nym_secrets</c>.
    /// </param>
    /// <param name="contextId">The verifier-supplied context octets.</param>
    /// <param name="apiId">The pseudonym Interface api_id.</param>
    /// <param name="hashToScalar">Backend hash-to-scalar.</param>
    /// <param name="scalarAdd">Backend scalar addition.</param>
    /// <param name="scalarMultiply">Backend scalar multiplication.</param>
    /// <param name="g1HashToCurve">Backend G1 hash-to-curve.</param>
    /// <param name="g1ScalarMultiply">Backend G1 scalar multiplication.</param>
    /// <param name="pool">The pool to rent destination buffers from.</param>
    /// <returns>The pseudonym and <c>Ut</c> (both caller-owned), or <see langword="null"/> when either degenerates to the identity (Section 7.3.1 step 9).</returns>
    public static (G1Point Pseudonym, G1Point Ut)? PseudonymProofInit(
        ReadOnlySpan<Scalar> nymSecrets,
        ReadOnlySpan<Scalar> randomScalars,
        ReadOnlySpan<byte> contextId,
        string apiId,
        ScalarHashToScalarDelegate hashToScalar,
        ScalarAddDelegate scalarAdd,
        ScalarMultiplyDelegate scalarMultiply,
        G1HashToCurveDelegate g1HashToCurve,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        if(nymSecrets.Length != randomScalars.Length)
        {
            throw new ArgumentException("PseudonymProofInit requires one random scalar per nym secret.", nameof(randomScalars));
        }

        using G1Point originPoint = ComputeOriginPoint(contextId, apiId, g1HashToCurve, pool);
        using Scalar evaluationPoint = ComputeEvaluationPoint(contextId, apiId, hashToScalar, pool);
        using Scalar pseudonymPolynomial = EvaluateNymPolynomial(nymSecrets, evaluationPoint, scalarAdd, scalarMultiply, pool);
        using Scalar proofPolynomial = EvaluateNymPolynomial(randomScalars, evaluationPoint, scalarAdd, scalarMultiply, pool);

        G1Point pseudonym = originPoint.ScalarMultiply(pseudonymPolynomial, g1ScalarMultiply, pool);
        G1Point? ut = null;
        try
        {
            ut = originPoint.ScalarMultiply(proofPolynomial, g1ScalarMultiply, pool);
            if(pseudonym.IsIdentity || ut.IsIdentity)
            {
                pseudonym.Dispose();
                ut.Dispose();

                return null;
            }

            return (pseudonym, ut);
        }
        catch
        {
            pseudonym.Dispose();
            ut?.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Implements <c>PseudonymProofVerifyInit</c> per Section 7.3.2:
    /// recomputes the announcement from the responses as
    /// <c>Uv = OP * poly(m^) - pseudonym * challenge</c>, which equals
    /// the prover's <c>Ut</c> exactly when the <c>m^</c> responses are
    /// consistent with the same <c>nym_secrets</c> that produced the
    /// pseudonym.
    /// </summary>
    /// <param name="pseudonym">The pseudonym point, already validated (on-curve, non-identity, prime-order subgroup) by the caller.</param>
    /// <param name="nymSecretCommitments">The last <c>N</c> undisclosed-message response scalars <c>m^</c> from the proof — those of the nym message slots.</param>
    /// <param name="proofChallenge">The proof's challenge scalar <c>cp</c>.</param>
    /// <param name="contextId">The verifier-supplied context octets.</param>
    /// <param name="apiId">The pseudonym Interface api_id.</param>
    /// <param name="hashToScalar">Backend hash-to-scalar.</param>
    /// <param name="scalarAdd">Backend scalar addition.</param>
    /// <param name="scalarMultiply">Backend scalar multiplication.</param>
    /// <param name="scalarNegate">Backend scalar negation (for <c>-cp</c>).</param>
    /// <param name="g1HashToCurve">Backend G1 hash-to-curve.</param>
    /// <param name="g1MultiScalarMultiply">Backend G1 multi-scalar multiplication.</param>
    /// <param name="pool">The pool to rent destination buffers from.</param>
    /// <returns>The recomputed announcement <c>Uv</c> (caller-owned), or <see langword="null"/> when it degenerates to the identity (Section 7.3.2 step 7).</returns>
    public static G1Point? PseudonymProofVerifyInit(
        G1Point pseudonym,
        ReadOnlySpan<Scalar> nymSecretCommitments,
        Scalar proofChallenge,
        ReadOnlySpan<byte> contextId,
        string apiId,
        ScalarHashToScalarDelegate hashToScalar,
        ScalarAddDelegate scalarAdd,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarNegateDelegate scalarNegate,
        G1HashToCurveDelegate g1HashToCurve,
        G1MultiScalarMultiplyDelegate g1MultiScalarMultiply,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pseudonym);
        ArgumentNullException.ThrowIfNull(proofChallenge);
        ArgumentNullException.ThrowIfNull(scalarNegate);
        ArgumentNullException.ThrowIfNull(g1MultiScalarMultiply);

        using G1Point originPoint = ComputeOriginPoint(contextId, apiId, g1HashToCurve, pool);
        using Scalar evaluationPoint = ComputeEvaluationPoint(contextId, apiId, hashToScalar, pool);
        using Scalar proofPolynomial = EvaluateNymPolynomial(nymSecretCommitments, evaluationPoint, scalarAdd, scalarMultiply, pool);
        using Scalar negatedChallenge = proofChallenge.Negate(scalarNegate, pool);

        //Uv = OP * poly(m^) + pseudonym * (-cp): one MSM over two pairs.
        G1Point[] uvPoints = [originPoint, pseudonym];
        Scalar[] uvScalars = [proofPolynomial, negatedChallenge];
        G1Point uv = BbsProofAlgorithm.MultiScalarMultiply(uvPoints, uvScalars, g1MultiScalarMultiply, pool);
        if(uv.IsIdentity)
        {
            uv.Dispose();

            return null;
        }

        return uv;
    }


    /// <summary>
    /// Implements <c>ProofWithPseudonymChallengeCalculate</c> per Section
    /// 8.1. Serialises
    /// <c>(R, i1, msg_i1, ..., iR, msg_iR, Abar, Bbar, D, T1, T2, pseudonym, Ut, domain)
    /// || I2OSP(len(ph), 8) || ph || I2OSP(len(context_id), 8) || context_id</c>
    /// and hashes to a scalar via the <c>api_id || "H2S_"</c> DST. Two
    /// deltas from the core challenge: the pseudonym and its announcement
    /// are absorbed between <c>T2</c> and <c>domain</c>, and the
    /// length-prefixed <c>context_id</c> follows the presentation-header
    /// tail.
    /// </summary>
    /// <param name="disclosedIndices">The disclosed indices, in the full combined message-vector index space.</param>
    /// <param name="disclosedMessageScalars">The disclosed message scalars, parallel to <paramref name="disclosedIndices"/>.</param>
    /// <param name="initResult">The BBS proof-init tuple whose <c>Abar</c>, <c>Bbar</c>, <c>D</c>, <c>T1</c>, <c>T2</c> and <c>domain</c> are absorbed.</param>
    /// <param name="pseudonym">The pseudonym point.</param>
    /// <param name="announcement">The announcement point: the prover's <c>Ut</c> or the verifier's recomputed <c>Uv</c>.</param>
    /// <param name="contextId">The verifier-supplied context octets.</param>
    /// <param name="presentationHeader">The presentation-header bytes.</param>
    /// <param name="apiId">The pseudonym Interface api_id.</param>
    /// <param name="hashToScalar">Backend hash-to-scalar.</param>
    /// <param name="pool">The pool to rent destination buffers from.</param>
    public static Scalar CalculateChallengeWithPseudonym(
        ReadOnlySpan<int> disclosedIndices,
        ReadOnlySpan<Scalar> disclosedMessageScalars,
        BbsProofInitResult initResult,
        G1Point pseudonym,
        G1Point announcement,
        ReadOnlySpan<byte> contextId,
        ReadOnlyMemory<byte> presentationHeader,
        string apiId,
        ScalarHashToScalarDelegate hashToScalar,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(initResult);
        ArgumentNullException.ThrowIfNull(pseudonym);
        ArgumentNullException.ThrowIfNull(announcement);
        ArgumentNullException.ThrowIfNull(apiId);
        ArgumentNullException.ThrowIfNull(hashToScalar);
        ArgumentNullException.ThrowIfNull(pool);
        if(disclosedIndices.Length != disclosedMessageScalars.Length)
        {
            throw new ArgumentException("Disclosed indices and disclosed message scalars must have the same length.", nameof(disclosedMessageScalars));
        }

        int r = disclosedIndices.Length;
        int pointBytes = WellKnownCurves.Bls12Curve381G1CompressedSizeBytes;
        int scalarBytes = Scalar.SizeBytes;

        //serialize(c_arr): I2OSP(R, 8)
        //                  || for i in 1..R: I2OSP(idx_i, 8) || msg_scalar_i (32)
        //                  || Abar || Bbar || D || T1 || T2 || pseudonym || Ut (48 each)
        //                  || domain (32)
        //c_octs = serialized || I2OSP(len(ph), 8) || ph || I2OSP(len(context_id), 8) || context_id
        int totalLength =
            8
            + r * (8 + scalarBytes)
            + 7 * pointBytes
            + scalarBytes
            + 8 + presentationHeader.Length
            + 8 + contextId.Length;
        using IMemoryOwner<byte> cOctsOwner = pool.Rent(totalLength);
        Span<byte> cOcts = cOctsOwner.Memory.Span[..totalLength];
        Span<byte> cursor = cOcts;

        BinaryPrimitives.WriteUInt64BigEndian(cursor, (ulong)r);
        cursor = cursor[8..];

        for(int i = 0; i < r; i++)
        {
            BinaryPrimitives.WriteUInt64BigEndian(cursor, (ulong)disclosedIndices[i]);
            cursor = cursor[8..];
            disclosedMessageScalars[i].AsReadOnlySpan().CopyTo(cursor);
            cursor = cursor[scalarBytes..];
        }

        initResult.ABar.AsReadOnlySpan().CopyTo(cursor);
        cursor = cursor[pointBytes..];
        initResult.BBar.AsReadOnlySpan().CopyTo(cursor);
        cursor = cursor[pointBytes..];
        initResult.D.AsReadOnlySpan().CopyTo(cursor);
        cursor = cursor[pointBytes..];
        initResult.T1.AsReadOnlySpan().CopyTo(cursor);
        cursor = cursor[pointBytes..];
        initResult.T2.AsReadOnlySpan().CopyTo(cursor);
        cursor = cursor[pointBytes..];
        pseudonym.AsReadOnlySpan().CopyTo(cursor);
        cursor = cursor[pointBytes..];
        announcement.AsReadOnlySpan().CopyTo(cursor);
        cursor = cursor[pointBytes..];
        initResult.Domain.AsReadOnlySpan().CopyTo(cursor);
        cursor = cursor[scalarBytes..];

        BinaryPrimitives.WriteUInt64BigEndian(cursor, (ulong)presentationHeader.Length);
        cursor = cursor[8..];
        presentationHeader.Span.CopyTo(cursor);
        cursor = cursor[presentationHeader.Length..];

        BinaryPrimitives.WriteUInt64BigEndian(cursor, (ulong)contextId.Length);
        cursor = cursor[8..];
        contextId.CopyTo(cursor);

        byte[] h2sDst = BbsAlgorithm.ComputeDst(apiId, WellKnownBbsDomainSeparationTags.HashToScalarDstSuffix);

        return Scalar.FromHashToScalar(cOcts, h2sDst, hashToScalar, CurveParameterSet.Bls12Curve381, pool);
    }
}
