using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Numerics;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Commitments;

/// <summary>
/// Prime-order-subgroup screening tests for the two Hyrax verify surfaces,
/// <see cref="HyraxOpeningProofExtensions.VerifyOpening"/> and
/// <see cref="HyraxWeightedOpeningExtensions.VerifyWeightedSum"/>. Every
/// prover-supplied G1 point — the row commitment(s), the fresh <c>C_f</c>,
/// and every IPA round point — is screened before any multi-scalar
/// multiplication or scalar multiplication runs. BLS12-381 G1 has a
/// non-trivial cofactor, so a spliced point can decode onto the curve
/// while still lying outside the prime-order subgroup; BN254 G1 has
/// cofactor 1 and carries no such probe, so these tests are BLS12-381 only.
/// </summary>
[TestClass]
internal sealed class HyraxSubgroupValidationTests
{
    private const string OpeningTranscriptDomain = "veridical.test.hyrax.subgroup.v1";
    private const string WeightedTranscriptDomain = "veridical.test.hyrax.subgroup.weighted.v1";

    //RowCount = 4, ColumnCount = 4 (2 IPA rounds): the smallest shape with
    //both a distinct first/last row and a distinct first/last IPA round,
    //so the tail-splice cases exercise real, different slots.
    private const int OpeningVariableCount = 4;

    //Vector length 8 (3 IPA rounds): the weighted path always commits a
    //single row, so only the variable count needs to be picked; kept
    //small because the subgroup predicate is a full [r]P per point.
    private const int WeightedVariableCount = 3;

    private const int RowZeroSeed = 9101;
    private const int LastRowSeed = 9102;
    private const int FCommitmentSeed = 9103;
    private const int Round0LeftSeed = 9104;
    private const int LastRoundRightSeed = 9105;
    private const int OpeningPositiveControlSeed = 9106;
    private const int WeightedRowSeed = 9201;
    private const int WeightedFCommitmentSeed = 9202;
    private const int WeightedRoundSeed = 9203;
    private const int WeightedPositiveControlSeed = 9204;

    private const int FixedRandomHashInputSizeBytes = 8;
    private const int Sha256DigestSizeBytes = 32;

    //The proof's leading point is always C_f.
    private const int FCommitmentByteOffset = 0;

    private static G1HashToCurveDelegate HashToCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;
    private static G1IsOnCurveDelegate G1IsOnCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetIsOnCurve();
    private static G1IsInPrimeOrderSubgroupDelegate G1IsInPrimeOrderSubgroup { get; } = Bls12Curve381BigIntegerG1Reference.GetIsInPrimeOrderSubgroup();
    private static ScalarAddDelegate ScalarAdd { get; } = TestScalarBackends.Bls12Curve381.Add;
    private static ScalarSubtractDelegate ScalarSubtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;
    private static ScalarMultiplyDelegate ScalarMul { get; } = TestScalarBackends.Bls12Curve381.Multiply;
    private static ScalarInvertDelegate ScalarInvert { get; } = TestScalarBackends.Bls12Curve381.Invert;
    private static ScalarReduceDelegate ScalarReduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    private static int G1SizeBytes { get; } = WellKnownCurves.GetG1CompressedSizeBytes(CurveParameterSet.Bls12Curve381);

    //Pre-calculated wrong-subgroup probe: the BLS12-381 G1 point with x = 0
    //(y^2 = 4, roots +-2) is on the curve but outside the r-order subgroup:
    //[r]P != O while [h1 * r]P == O for the G1 cofactor h1. ZCash-convention
    //encoding: compression flag 0x80 plus y-parity flag 0x20 because the
    //encoded root y = p - 2 is the lexicographically larger one; the x bytes
    //are all zero. Copied from BbsSubgroupValidationTests.WrongSubgroupG1Compressed.
    private static byte[] WrongSubgroupG1Compressed { get; } = Convert.FromHexString(
        "a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");


    /// <summary>
    /// Pins the probe literal itself: it must decode on-curve yet fail the
    /// prime-order-subgroup check, otherwise every rejection test below
    /// would pass for the wrong reason.
    /// </summary>
    [TestMethod]
    public void ProbeIsOnCurveButOutsideSubgroup()
    {
        Assert.IsTrue(G1IsOnCurve(WrongSubgroupG1Compressed, CurveParameterSet.Bls12Curve381), "The probe must lie on the curve.");
        Assert.IsFalse(G1IsInPrimeOrderSubgroup(WrongSubgroupG1Compressed, CurveParameterSet.Bls12Curve381), "The probe must lie outside the prime-order subgroup.");
    }


    /// <summary>Verify rejects a splice into the commitment's first row, before any MSM or scalar-multiply runs.</summary>
    [TestMethod]
    public void VerifyOpeningRejectsTamperedRowZeroCommitment()
    {
        using OpeningFixture fixture = CreateOpeningFixture(RowZeroSeed);
        using HyraxCommitment tamperedCommitment = SpliceCommitmentRow(fixture.Commitment, rowIndex: 0);
        using FiatShamirTranscript verifierTranscript = NewOpeningTranscript();
        PointOperationRecorder recorder = new();

        bool verified = tamperedCommitment.VerifyOpening(
            fixture.Point.AsSpan, fixture.ClaimedValue, fixture.Proof, fixture.Key, verifierTranscript,
            Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert,
            G1Add, recorder.ScalarMul, recorder.Msm, G1IsOnCurve, recorder.Subgroup, BaseMemoryPool.Shared);

        Assert.IsFalse(verified, "Verify must reject a row-0 commitment splice outside the prime-order subgroup.");
        Assert.IsTrue(recorder.SubgroupChecked, "The subgroup delegate must be consulted for the row commitments.");
        Assert.IsFalse(recorder.MsmCalled, "Rejection must happen before any MSM runs.");
        Assert.IsFalse(recorder.ScalarMulCalled, "Rejection must happen before any G1 scalar multiplication runs.");
    }


    /// <summary>Verify rejects a splice into the commitment's last row, exercising the tail of the row screen.</summary>
    [TestMethod]
    public void VerifyOpeningRejectsTamperedLastRowCommitment()
    {
        using OpeningFixture fixture = CreateOpeningFixture(LastRowSeed);
        using HyraxCommitment tamperedCommitment = SpliceCommitmentRow(fixture.Commitment, fixture.Commitment.RowCount - 1);
        using FiatShamirTranscript verifierTranscript = NewOpeningTranscript();
        PointOperationRecorder recorder = new();

        bool verified = tamperedCommitment.VerifyOpening(
            fixture.Point.AsSpan, fixture.ClaimedValue, fixture.Proof, fixture.Key, verifierTranscript,
            Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert,
            G1Add, recorder.ScalarMul, recorder.Msm, G1IsOnCurve, recorder.Subgroup, BaseMemoryPool.Shared);

        Assert.IsFalse(verified, "Verify must reject a last-row commitment splice outside the prime-order subgroup.");
        Assert.IsTrue(recorder.SubgroupChecked, "The subgroup delegate must be consulted for every row commitment up to the tampered one.");
        Assert.IsFalse(recorder.MsmCalled, "Rejection must happen before any MSM runs.");
        Assert.IsFalse(recorder.ScalarMulCalled, "Rejection must happen before any G1 scalar multiplication runs.");
    }


    /// <summary>Verify rejects a splice into the proof's fresh C_f commitment.</summary>
    [TestMethod]
    public void VerifyOpeningRejectsTamperedFCommitment()
    {
        using OpeningFixture fixture = CreateOpeningFixture(FCommitmentSeed);
        using HyraxOpeningProof tamperedProof = SpliceProofPoint(fixture.Proof, FCommitmentByteOffset);
        using FiatShamirTranscript verifierTranscript = NewOpeningTranscript();
        PointOperationRecorder recorder = new();

        bool verified = fixture.Commitment.VerifyOpening(
            fixture.Point.AsSpan, fixture.ClaimedValue, tamperedProof, fixture.Key, verifierTranscript,
            Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert,
            G1Add, recorder.ScalarMul, recorder.Msm, G1IsOnCurve, recorder.Subgroup, BaseMemoryPool.Shared);

        Assert.IsFalse(verified, "Verify must reject a C_f splice outside the prime-order subgroup.");
        Assert.IsTrue(recorder.SubgroupChecked, "The subgroup delegate must be consulted for C_f.");
        Assert.IsFalse(recorder.MsmCalled, "Rejection must happen before any MSM runs.");
        Assert.IsFalse(recorder.ScalarMulCalled, "Rejection must happen before any G1 scalar multiplication runs.");
    }


    /// <summary>Verify rejects a splice into IPA round 0's left point.</summary>
    [TestMethod]
    public void VerifyOpeningRejectsTamperedIpaRoundZeroLeftPoint()
    {
        using OpeningFixture fixture = CreateOpeningFixture(Round0LeftSeed);
        int offset = GetIpaRoundPointOffset(round: 0, isRightPoint: false);
        using HyraxOpeningProof tamperedProof = SpliceProofPoint(fixture.Proof, offset);
        using FiatShamirTranscript verifierTranscript = NewOpeningTranscript();
        PointOperationRecorder recorder = new();

        bool verified = fixture.Commitment.VerifyOpening(
            fixture.Point.AsSpan, fixture.ClaimedValue, tamperedProof, fixture.Key, verifierTranscript,
            Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert,
            G1Add, recorder.ScalarMul, recorder.Msm, G1IsOnCurve, recorder.Subgroup, BaseMemoryPool.Shared);

        Assert.IsFalse(verified, "Verify must reject an IPA round-0 left-point splice outside the prime-order subgroup.");
        Assert.IsTrue(recorder.SubgroupChecked, "The subgroup delegate must be consulted for the row commitments and C_f before reaching the round points.");
        Assert.IsFalse(recorder.MsmCalled, "Rejection must happen before any MSM runs.");
        Assert.IsFalse(recorder.ScalarMulCalled, "Rejection must happen before any G1 scalar multiplication runs.");
    }


    /// <summary>Verify rejects a splice into the last IPA round's right point, exercising the tail of the round-point screen.</summary>
    [TestMethod]
    public void VerifyOpeningRejectsTamperedLastIpaRoundRightPoint()
    {
        using OpeningFixture fixture = CreateOpeningFixture(LastRoundRightSeed);
        int offset = GetIpaRoundPointOffset(fixture.Proof.IpaRoundCount - 1, isRightPoint: true);
        using HyraxOpeningProof tamperedProof = SpliceProofPoint(fixture.Proof, offset);
        using FiatShamirTranscript verifierTranscript = NewOpeningTranscript();
        PointOperationRecorder recorder = new();

        bool verified = fixture.Commitment.VerifyOpening(
            fixture.Point.AsSpan, fixture.ClaimedValue, tamperedProof, fixture.Key, verifierTranscript,
            Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert,
            G1Add, recorder.ScalarMul, recorder.Msm, G1IsOnCurve, recorder.Subgroup, BaseMemoryPool.Shared);

        Assert.IsFalse(verified, "Verify must reject a last-IPA-round right-point splice outside the prime-order subgroup.");
        Assert.IsTrue(recorder.SubgroupChecked, "The subgroup delegate must be consulted for every earlier round point up to the tampered one.");
        Assert.IsFalse(recorder.MsmCalled, "Rejection must happen before any MSM runs.");
        Assert.IsFalse(recorder.ScalarMulCalled, "Rejection must happen before any G1 scalar multiplication runs.");
    }


    /// <summary>An untampered opening passes the subgroup screen and verifies, proving the screen is not vacuously rejecting everything.</summary>
    [TestMethod]
    public void UntamperedOpeningPassesScreeningAndVerifies()
    {
        using OpeningFixture fixture = CreateOpeningFixture(OpeningPositiveControlSeed);
        using FiatShamirTranscript verifierTranscript = NewOpeningTranscript();
        PointOperationRecorder recorder = new();

        bool verified = fixture.Commitment.VerifyOpening(
            fixture.Point.AsSpan, fixture.ClaimedValue, fixture.Proof, fixture.Key, verifierTranscript,
            Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert,
            G1Add, recorder.ScalarMul, recorder.Msm, G1IsOnCurve, recorder.Subgroup, BaseMemoryPool.Shared);

        Assert.IsTrue(verified, "An untampered opening must verify.");
        Assert.IsTrue(recorder.SubgroupChecked, "The subgroup delegate must be consulted even when every point is legitimate.");
        Assert.IsTrue(recorder.MsmCalled, "A passing screen must let the row-combination MSM run.");
    }


    /// <summary>Verify rejects a splice into the weighted commitment's single row.</summary>
    [TestMethod]
    public void VerifyWeightedSumRejectsTamperedRowCommitment()
    {
        using WeightedFixture fixture = CreateWeightedFixture(WeightedRowSeed);
        using HyraxCommitment tamperedCommitment = SpliceCommitmentRow(fixture.Commitment, rowIndex: 0);
        using FiatShamirTranscript verifierTranscript = NewWeightedTranscript();
        PointOperationRecorder recorder = new();

        bool verified = tamperedCommitment.VerifyWeightedSum(
            fixture.Weights, fixture.ClaimedValue, fixture.Proof, fixture.Key, verifierTranscript,
            Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert,
            G1Add, recorder.ScalarMul, recorder.Msm, G1IsOnCurve, recorder.Subgroup, BaseMemoryPool.Shared);

        Assert.IsFalse(verified, "VerifyWeightedSum must reject a row-commitment splice outside the prime-order subgroup.");
        Assert.IsTrue(recorder.SubgroupChecked, "The subgroup delegate must be consulted for the row commitment.");
        Assert.IsFalse(recorder.MsmCalled, "Rejection must happen before any MSM runs.");
        Assert.IsFalse(recorder.ScalarMulCalled, "Rejection must happen before any G1 scalar multiplication runs.");
    }


    /// <summary>Verify rejects a splice into the weighted proof's fresh C_f commitment.</summary>
    [TestMethod]
    public void VerifyWeightedSumRejectsTamperedFCommitment()
    {
        using WeightedFixture fixture = CreateWeightedFixture(WeightedFCommitmentSeed);
        using HyraxOpeningProof tamperedProof = SpliceProofPoint(fixture.Proof, FCommitmentByteOffset);
        using FiatShamirTranscript verifierTranscript = NewWeightedTranscript();
        PointOperationRecorder recorder = new();

        bool verified = fixture.Commitment.VerifyWeightedSum(
            fixture.Weights, fixture.ClaimedValue, tamperedProof, fixture.Key, verifierTranscript,
            Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert,
            G1Add, recorder.ScalarMul, recorder.Msm, G1IsOnCurve, recorder.Subgroup, BaseMemoryPool.Shared);

        Assert.IsFalse(verified, "VerifyWeightedSum must reject a C_f splice outside the prime-order subgroup.");
        Assert.IsTrue(recorder.SubgroupChecked, "The subgroup delegate must be consulted for C_f.");
        Assert.IsFalse(recorder.MsmCalled, "Rejection must happen before any MSM runs.");
        Assert.IsFalse(recorder.ScalarMulCalled, "Rejection must happen before any G1 scalar multiplication runs.");
    }


    /// <summary>Verify rejects a splice into the weighted proof's IPA round-0 left point.</summary>
    [TestMethod]
    public void VerifyWeightedSumRejectsTamperedIpaRoundPoint()
    {
        using WeightedFixture fixture = CreateWeightedFixture(WeightedRoundSeed);
        int offset = GetIpaRoundPointOffset(round: 0, isRightPoint: false);
        using HyraxOpeningProof tamperedProof = SpliceProofPoint(fixture.Proof, offset);
        using FiatShamirTranscript verifierTranscript = NewWeightedTranscript();
        PointOperationRecorder recorder = new();

        bool verified = fixture.Commitment.VerifyWeightedSum(
            fixture.Weights, fixture.ClaimedValue, tamperedProof, fixture.Key, verifierTranscript,
            Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert,
            G1Add, recorder.ScalarMul, recorder.Msm, G1IsOnCurve, recorder.Subgroup, BaseMemoryPool.Shared);

        Assert.IsFalse(verified, "VerifyWeightedSum must reject an IPA round-0 left-point splice outside the prime-order subgroup.");
        Assert.IsTrue(recorder.SubgroupChecked, "The subgroup delegate must be consulted for the row commitment and C_f before reaching the round points.");
        Assert.IsFalse(recorder.MsmCalled, "Rejection must happen before any MSM runs.");
        Assert.IsFalse(recorder.ScalarMulCalled, "Rejection must happen before any G1 scalar multiplication runs.");
    }


    /// <summary>An untampered weighted opening passes the subgroup screen and verifies, proving the screen is not vacuously rejecting everything.</summary>
    [TestMethod]
    public void UntamperedWeightedSumPassesScreeningAndVerifies()
    {
        using WeightedFixture fixture = CreateWeightedFixture(WeightedPositiveControlSeed);
        using FiatShamirTranscript verifierTranscript = NewWeightedTranscript();
        PointOperationRecorder recorder = new();

        bool verified = fixture.Commitment.VerifyWeightedSum(
            fixture.Weights, fixture.ClaimedValue, fixture.Proof, fixture.Key, verifierTranscript,
            Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert,
            G1Add, recorder.ScalarMul, recorder.Msm, G1IsOnCurve, recorder.Subgroup, BaseMemoryPool.Shared);

        Assert.IsTrue(verified, "An untampered weighted opening must verify.");
        Assert.IsTrue(recorder.SubgroupChecked, "The subgroup delegate must be consulted even when every point is legitimate.");

        //Unlike VerifyOpening, VerifyWeightedSum never calls g1Msm: the row
        //combination is trivial for a single-row commitment, so the
        //blinding-correction check reaches g1ScalarMul (and g1Add) directly.
        Assert.IsTrue(recorder.ScalarMulCalled, "A passing screen must let the blinding-correction scalar multiplication run.");
    }


    /// <summary>Builds a fresh commitment, witness, MLE, key, evaluation point, and opening proof for <see cref="OpeningVariableCount"/> variables.</summary>
    private static OpeningFixture CreateOpeningFixture(int seed)
    {
        var dimensions = HyraxCommitmentDimensions.ForVariableCount(OpeningVariableCount);
        HyraxCommitmentKey key = HyraxCommitmentKey.Derive(dimensions.ColumnCount, WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bls12Curve381, HashToCurve, BaseMemoryPool.Shared);
        MultilinearExtension mle = BuildMultilinearExtension(OpeningVariableCount, i => (i * 13) + 7);
        ScalarRandomDelegate fixedRandom = MakeFixedRandom(seed);
        (HyraxCommitment commitment, HyraxOpeningWitness witness) = key.CommitMultilinearExtension(mle, fixedRandom, G1Msm, BaseMemoryPool.Shared);
        PointArray point = BuildEvaluationPoint(OpeningVariableCount);

        using FiatShamirTranscript proverTranscript = NewOpeningTranscript();
        (HyraxOpeningProof proof, Scalar claimedValue) = commitment.Open(
            witness, mle, point.AsSpan, key, proverTranscript,
            Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert, fixedRandom,
            G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);

        return new OpeningFixture(key, commitment, witness, mle, point, proof, claimedValue);
    }


    /// <summary>Builds a fresh single-row vector commitment, weight vector, key, and weighted-opening proof for <see cref="WeightedVariableCount"/> variables.</summary>
    private static WeightedFixture CreateWeightedFixture(int seed)
    {
        int vectorLength = 1 << WeightedVariableCount;
        HyraxCommitmentKey key = HyraxCommitmentKey.Derive(vectorLength, WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bls12Curve381, HashToCurve, BaseMemoryPool.Shared);
        MultilinearExtension vector = BuildMultilinearExtension(WeightedVariableCount, i => (i * 13) + 7);
        MultilinearExtension weights = BuildMultilinearExtension(WeightedVariableCount, i => (i * 5) + 3);
        ScalarRandomDelegate fixedRandom = MakeFixedRandom(seed);
        (HyraxCommitment commitment, HyraxOpeningWitness witness) = key.CommitVector(vector, fixedRandom, G1Msm, BaseMemoryPool.Shared);

        using FiatShamirTranscript proverTranscript = NewWeightedTranscript();
        (HyraxOpeningProof proof, Scalar claimedValue) = commitment.OpenWeightedSum(
            witness, vector, weights, key, proverTranscript,
            Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert, fixedRandom,
            G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);

        return new WeightedFixture(key, commitment, witness, vector, weights, proof, claimedValue);
    }


    /// <summary>
    /// Copies the receiver commitment's bytes into a pool-rented scratch
    /// buffer, splices <see cref="WrongSubgroupG1Compressed"/> into the row
    /// at <paramref name="rowIndex"/>, and rehydrates a new commitment via
    /// <see cref="HyraxCommitment.FromBytes"/> — which validates length
    /// only, so the splice reaches the verifier undetected until the
    /// subgroup screen runs.
    /// </summary>
    private static HyraxCommitment SpliceCommitmentRow(HyraxCommitment commitment, int rowIndex)
    {
        int totalSizeBytes = commitment.AsReadOnlySpan().Length;
        using IMemoryOwner<byte> tamperedOwner = BaseMemoryPool.Shared.Rent(totalSizeBytes);
        Span<byte> tampered = tamperedOwner.Memory.Span[..totalSizeBytes];
        commitment.AsReadOnlySpan().CopyTo(tampered);
        WrongSubgroupG1Compressed.CopyTo(tampered.Slice(rowIndex * G1SizeBytes, G1SizeBytes));

        return HyraxCommitment.FromBytes(tampered, commitment.RowCount, commitment.ColumnCount, commitment.VariableCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Copies the receiver proof's bytes into a pool-rented scratch buffer,
    /// splices <see cref="WrongSubgroupG1Compressed"/> at
    /// <paramref name="byteOffset"/>, and rehydrates a new proof via
    /// <see cref="HyraxOpeningProof.FromBytes"/> — which validates length
    /// only, so the splice reaches the verifier undetected until the
    /// subgroup screen runs.
    /// </summary>
    private static HyraxOpeningProof SpliceProofPoint(HyraxOpeningProof proof, int byteOffset)
    {
        int totalSizeBytes = proof.AsReadOnlySpan().Length;
        using IMemoryOwner<byte> tamperedOwner = BaseMemoryPool.Shared.Rent(totalSizeBytes);
        Span<byte> tampered = tamperedOwner.Memory.Span[..totalSizeBytes];
        proof.AsReadOnlySpan().CopyTo(tampered);
        WrongSubgroupG1Compressed.CopyTo(tampered.Slice(byteOffset, G1SizeBytes));

        return HyraxOpeningProof.FromBytes(tampered, proof.IpaRoundCount, proof.Curve, BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Computes the proof-buffer byte offset of an IPA round point: C_f
    /// occupies the leading <see cref="G1SizeBytes"/>, then each round
    /// contributes a left/right pair of <see cref="G1SizeBytes"/> points.
    /// </summary>
    private static int GetIpaRoundPointOffset(int round, bool isRightPoint)
    {
        int pairSizeBytes = 2 * G1SizeBytes;
        int offset = G1SizeBytes + (round * pairSizeBytes) + (isRightPoint ? G1SizeBytes : 0);

        return offset;
    }


    private static FiatShamirTranscript NewOpeningTranscript() =>
        FiatShamirTranscript.Initialise(new FiatShamirDomainLabel(OpeningTranscriptDomain), ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);


    private static FiatShamirTranscript NewWeightedTranscript() =>
        FiatShamirTranscript.Initialise(new FiatShamirDomainLabel(WeightedTranscriptDomain), ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);


    /// <summary>Builds an MLE of <paramref name="variableCount"/> variables whose evaluation at index <c>i</c> is <paramref name="valueAt"/>(i), reduced modulo the scalar field order.</summary>
    private static MultilinearExtension BuildMultilinearExtension(int variableCount, Func<int, int> valueAt)
    {
        int evaluationCount = 1 << variableCount;
        int elementSizeBytes = Scalar.SizeBytes;
        using IMemoryOwner<byte> bufferOwner = BaseMemoryPool.Shared.Rent(evaluationCount * elementSizeBytes);
        Span<byte> buffer = bufferOwner.Memory.Span[..(evaluationCount * elementSizeBytes)];
        for(int i = 0; i < evaluationCount; i++)
        {
            WriteCanonical(new BigInteger(valueAt(i)), buffer.Slice(i * elementSizeBytes, elementSizeBytes));
        }

        return MultilinearExtension.FromEvaluations(buffer, variableCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    /// <summary>Builds the evaluation point <c>(3, 8, 13, ...)</c> as a fresh array of scalars, one per variable.</summary>
    private static PointArray BuildEvaluationPoint(int variableCount)
    {
        var scalars = new Scalar[variableCount];
        for(int i = 0; i < variableCount; i++)
        {
            scalars[i] = MakeScalar((i * 5) + 3);
        }

        return new PointArray(scalars);
    }


    private static Scalar MakeScalar(int value)
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(Scalar.SizeBytes);
        Span<byte> span = owner.Memory.Span[..Scalar.SizeBytes];
        WriteCanonical(new BigInteger(value), span);

        return Scalar.FromCanonical(span, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        BigInteger fieldOrder = Bls12Curve381BigIntegerScalarReference.FieldOrder;
        BigInteger nonNegative = ((value % fieldOrder) + fieldOrder) % fieldOrder;
        if(!nonNegative.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Reduced scalar did not fit in the canonical span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }


    /// <summary>Builds a deterministic scalar-random delegate: each call hashes (seed, call index) through SHA-256 and reduces the digest into the scalar field.</summary>
    private static ScalarRandomDelegate MakeFixedRandom(int seed)
    {
        int counter = 0;
        return Sample;

        Tag Sample(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
        {
            Span<byte> hashInput = stackalloc byte[FixedRandomHashInputSizeBytes];
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(hashInput[..4], seed);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(hashInput[4..], counter);
            counter++;

            Span<byte> wide = stackalloc byte[Sha256DigestSizeBytes];
            SHA256.HashData(hashInput, wide);
            ScalarReduceDelegate reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();
            reduce(wide, destination, curve);

            return inboundTag;
        }
    }


    /// <summary>
    /// Bundles the artefacts of one evaluation opening (key, commitment,
    /// witness, MLE, evaluation point, proof, claimed value) so a test can
    /// dispose them all with a single <see langword="using"/> declaration.
    /// </summary>
    private sealed record OpeningFixture(
        HyraxCommitmentKey Key,
        HyraxCommitment Commitment,
        HyraxOpeningWitness Witness,
        MultilinearExtension Mle,
        PointArray Point,
        HyraxOpeningProof Proof,
        Scalar ClaimedValue): IDisposable
    {
        /// <summary>Disposes every owned artefact in the fixture.</summary>
        public void Dispose()
        {
            Key.Dispose();
            Commitment.Dispose();
            Witness.Dispose();
            Mle.Dispose();
            Point.Dispose();
            Proof.Dispose();
            ClaimedValue.Dispose();
        }
    }


    /// <summary>
    /// Bundles the artefacts of one weighted opening (key, single-row
    /// commitment, witness, vector, weights, proof, claimed value) so a
    /// test can dispose them all with a single <see langword="using"/>
    /// declaration.
    /// </summary>
    private sealed record WeightedFixture(
        HyraxCommitmentKey Key,
        HyraxCommitment Commitment,
        HyraxOpeningWitness Witness,
        MultilinearExtension Vector,
        MultilinearExtension Weights,
        HyraxOpeningProof Proof,
        Scalar ClaimedValue): IDisposable
    {
        /// <summary>Disposes every owned artefact in the fixture.</summary>
        public void Dispose()
        {
            Key.Dispose();
            Commitment.Dispose();
            Witness.Dispose();
            Vector.Dispose();
            Weights.Dispose();
            Proof.Dispose();
            ClaimedValue.Dispose();
        }
    }


    /// <summary>
    /// Wraps the G1 scalar-multiply, multi-scalar-multiply, and
    /// prime-order-subgroup delegates with call-observed flags, so a
    /// rejection test can assert not only the boolean verdict but which
    /// algebraic operations the verifier actually reached before returning
    /// it.
    /// </summary>
    private sealed class PointOperationRecorder
    {
        /// <summary>Whether the prime-order-subgroup delegate was invoked at least once.</summary>
        public bool SubgroupChecked { get; private set; }

        /// <summary>Whether the multi-scalar-multiply delegate was invoked at least once.</summary>
        public bool MsmCalled { get; private set; }

        /// <summary>Whether the scalar-multiply delegate was invoked at least once.</summary>
        public bool ScalarMulCalled { get; private set; }

        /// <summary>Records the call and forwards to the reference prime-order-subgroup predicate.</summary>
        public bool Subgroup(ReadOnlySpan<byte> point, CurveParameterSet curve)
        {
            SubgroupChecked = true;

            return G1IsInPrimeOrderSubgroup(point, curve);
        }

        /// <summary>Records the call and forwards to the reference multi-scalar-multiply backend.</summary>
        public void Msm(ReadOnlySpan<byte> pointsConcatenated, ReadOnlySpan<byte> scalarsConcatenated, int count, Span<byte> result, CurveParameterSet curve)
        {
            MsmCalled = true;
            G1Msm(pointsConcatenated, scalarsConcatenated, count, result, curve);
        }

        /// <summary>Records the call and forwards to the reference scalar-multiply backend.</summary>
        public void ScalarMul(ReadOnlySpan<byte> point, ReadOnlySpan<byte> scalar, Span<byte> result, CurveParameterSet curve)
        {
            ScalarMulCalled = true;
            G1ScalarMul(point, scalar, result, curve);
        }
    }


    /// <summary>An owned array of evaluation-point scalars, disposed as a unit.</summary>
    private readonly struct PointArray: IDisposable
    {
        private readonly Scalar[] scalars;

        /// <summary>Wraps the supplied scalars; ownership transfers to the <see cref="PointArray"/>.</summary>
        public PointArray(Scalar[] scalars)
        {
            this.scalars = scalars;
        }

        /// <summary>The scalars as a read-only span, in evaluation-point order.</summary>
        public ReadOnlySpan<Scalar> AsSpan => scalars;

        /// <summary>Disposes every scalar owned by this array.</summary>
        public void Dispose()
        {
            if(scalars is null)
            {
                return;
            }

            foreach(Scalar s in scalars)
            {
                s?.Dispose();
            }
        }
    }
}
