using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Buffers.Binary;

namespace Lumoin.Veridical.Tests.Commitments.Ligero;

/// <summary>
/// The byte-identity gate for the scalar-field NTT row extender: over
/// representative Ligero shapes on both wired curves the
/// <see cref="ScalarNttLigeroRowExtenders"/> engine must produce exactly the
/// codeword the barycentric <see cref="LigeroReedSolomonEncoder"/> reference
/// path produces, and through the full
/// <see cref="LigeroPolynomialCommitmentScheme"/> the commitment and opening
/// bytes must be identical with and without the extender — field arithmetic is
/// exact, so equality of the mathematical map is equality of the bytes.
/// </summary>
[TestClass]
internal sealed class ScalarNttLigeroRowExtenderTests
{
    private const int ScalarSize = Scalar.SizeBytes;
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    //A fill salt distinct from the streams other Ligero tests draw.
    private const int MessageFillSalt = 4301;

    //The representative shapes: the degenerate and small PCS shapes, the
    //CLI-wired rate-1/16 row shape (8, 128), a rateless no-extension shape and
    //non-power-of-two codeword lengths that pad up to the next transform size.
    private static (int MessageLength, int CodewordLength)[] Shapes { get; } =
    [
        (1, 4),
        (2, 8),
        (4, 4),
        (5, 16),
        (8, 128),
        (9, 23),
        (16, 64),
    ];

    private static (string Prefix, CurveParameterSet Curve, ScalarAddDelegate Add, ScalarSubtractDelegate Subtract, ScalarMultiplyDelegate Multiply, ScalarInvertDelegate Invert, ScalarReduceDelegate Reduce)[] Fields { get; } =
    [
        (
            "bls12381",
            CurveParameterSet.Bls12Curve381,
            Bls12Curve381BigIntegerScalarReference.GetAdd(),
            Bls12Curve381BigIntegerScalarReference.GetSubtract(),
            Bls12Curve381BigIntegerScalarReference.GetMultiply(),
            Bls12Curve381BigIntegerScalarReference.GetInvert(),
            Bls12Curve381BigIntegerScalarReference.GetReduce()
        ),
        (
            "bn254",
            CurveParameterSet.Bn254,
            Bn254BigIntegerScalarReference.GetAdd(),
            Bn254BigIntegerScalarReference.GetSubtract(),
            Bn254BigIntegerScalarReference.GetMultiply(),
            Bn254BigIntegerScalarReference.GetInvert(),
            Bn254BigIntegerScalarReference.GetReduce()
        ),
    ];

    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;


    [TestMethod]
    public void TheNttExtenderMatchesTheBarycentricEncoderByteForByte()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        foreach((string prefix, CurveParameterSet curve, ScalarAddDelegate add, ScalarSubtractDelegate subtract, ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert, ScalarReduceDelegate reduce) in Fields)
        {
            using var extenders = new ScalarNttLigeroRowExtenders(add, subtract, multiply, invert, curve, pool);

            foreach((int messageLength, int codewordLength) in Shapes)
            {
                using IMemoryOwner<byte> messageOwner = pool.Rent(messageLength * ScalarSize);
                Span<byte> message = messageOwner.Memory.Span[..(messageLength * ScalarSize)];
                DeterministicScalarFill.FillCanonical(message, MessageFillSalt + messageLength, reduce, curve);

                using IMemoryOwner<byte> barycentricOwner = pool.Rent(codewordLength * ScalarSize);
                Span<byte> barycentric = barycentricOwner.Memory.Span[..(codewordLength * ScalarSize)];
                LigeroReedSolomonEncoder.Encode(message, messageLength, barycentric, codewordLength, add, subtract, multiply, invert, curve, pool);

                using IMemoryOwner<byte> transformedOwner = pool.Rent(codewordLength * ScalarSize);
                Span<byte> transformed = transformedOwner.Memory.Span[..(codewordLength * ScalarSize)];
                message.CopyTo(transformed[..(messageLength * ScalarSize)]);
                LigeroRowExtender? extender = extenders.Create(messageLength, codewordLength);
                Assert.IsNotNull(extender, $"The extender factory must accept the ({messageLength}, {codewordLength}) shape for {prefix}.");
                extender(transformed);

                Assert.IsTrue(
                    transformed.SequenceEqual(barycentric),
                    $"The NTT codeword must be byte-identical to the barycentric codeword at shape ({messageLength}, {codewordLength}) for {prefix}.");
            }
        }
    }


    [TestMethod]
    public void TheExtenderLeavesTheSystematicPrefixUntouched()
    {
        const int MessageLength = 9;
        const int CodewordLength = 23;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Span<byte> expectedPrefix = stackalloc byte[MessageLength * ScalarSize];
        foreach((string prefix, CurveParameterSet curve, ScalarAddDelegate add, ScalarSubtractDelegate subtract, ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert, ScalarReduceDelegate reduce) in Fields)
        {
            using var extenders = new ScalarNttLigeroRowExtenders(add, subtract, multiply, invert, curve, pool);

            using IMemoryOwner<byte> codewordOwner = pool.Rent(CodewordLength * ScalarSize);
            Span<byte> codeword = codewordOwner.Memory.Span[..(CodewordLength * ScalarSize)];
            codeword.Clear();
            DeterministicScalarFill.FillCanonical(codeword[..(MessageLength * ScalarSize)], MessageFillSalt, reduce, curve);
            codeword[..(MessageLength * ScalarSize)].CopyTo(expectedPrefix);

            LigeroRowExtender? extender = extenders.Create(MessageLength, CodewordLength);
            Assert.IsNotNull(extender);
            extender(codeword);

            Assert.IsTrue(
                codeword[..(MessageLength * ScalarSize)].SequenceEqual(expectedPrefix),
                $"The systematic prefix must be unchanged by the extension for {prefix}.");
        }
    }


    [TestMethod]
    public void TheBatchedMultiplyConfigurationMatchesThePerElementCodeword()
    {
        //The CLI wires the managed backend's BatchMultiply, so this pins the
        //batched weight stages against the per-element path byte-for-byte on
        //the production delegate set, at the CLI row shape and a
        //non-power-of-two codeword.
        (int MessageLength, int CodewordLength)[] shapes = [(8, 128), (9, 23)];
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        foreach(CurveParameterSet curve in (CurveParameterSet[])[CurveParameterSet.Bls12Curve381, CurveParameterSet.Bn254])
        {
            using ScalarArithmeticBackend backend = curve.Code == CurveParameterSet.Bls12Curve381.Code
                ? Bls12Curve381ManagedScalarBackend.Create()
                : Bn254ManagedScalarBackend.Create();
            using var perElement = new ScalarNttLigeroRowExtenders(backend.Add, backend.Subtract, backend.Multiply, backend.Invert, curve, pool);
            using var batched = new ScalarNttLigeroRowExtenders(backend.Add, backend.Subtract, backend.Multiply, backend.Invert, curve, pool, backend.BatchMultiply);

            foreach((int messageLength, int codewordLength) in shapes)
            {
                using IMemoryOwner<byte> messageOwner = pool.Rent(messageLength * ScalarSize);
                Span<byte> message = messageOwner.Memory.Span[..(messageLength * ScalarSize)];
                DeterministicScalarFill.FillCanonical(message, MessageFillSalt + codewordLength, backend.Reduce, curve);

                using IMemoryOwner<byte> perElementOwner = pool.Rent(codewordLength * ScalarSize);
                Span<byte> perElementCodeword = perElementOwner.Memory.Span[..(codewordLength * ScalarSize)];
                message.CopyTo(perElementCodeword[..(messageLength * ScalarSize)]);
                LigeroRowExtender? perElementExtender = perElement.Create(messageLength, codewordLength);
                Assert.IsNotNull(perElementExtender);
                perElementExtender(perElementCodeword);

                using IMemoryOwner<byte> batchedOwner = pool.Rent(codewordLength * ScalarSize);
                Span<byte> batchedCodeword = batchedOwner.Memory.Span[..(codewordLength * ScalarSize)];
                message.CopyTo(batchedCodeword[..(messageLength * ScalarSize)]);
                LigeroRowExtender? batchedExtender = batched.Create(messageLength, codewordLength);
                Assert.IsNotNull(batchedExtender);
                batchedExtender(batchedCodeword);

                Assert.IsTrue(
                    batchedCodeword.SequenceEqual(perElementCodeword),
                    $"The batched configuration must produce the per-element codeword at shape ({messageLength}, {codewordLength}) on {curve}.");
            }
        }
    }


    [TestMethod]
    public void ADisposedSourceRejectsCreateAndDisposeIsIdempotent()
    {
        const int MessageLength = 5;
        const int CodewordLength = 16;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        foreach((string prefix, CurveParameterSet curve, ScalarAddDelegate add, ScalarSubtractDelegate subtract, ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert, _) in Fields)
        {
            var extenders = new ScalarNttLigeroRowExtenders(add, subtract, multiply, invert, curve, pool);
            extenders.Dispose();
            extenders.Dispose();

            Assert.ThrowsExactly<ObjectDisposedException>(
                () => extenders.Create(MessageLength, CodewordLength),
                $"A disposed source must reject Create for {prefix}.");
        }
    }


    [TestMethod]
    public void TheCommitmentAndOpeningAreIdenticalWithAndWithoutTheExtender()
    {
        foreach((string prefix, CurveParameterSet curve, ScalarAddDelegate add, ScalarSubtractDelegate subtract, ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert, ScalarReduceDelegate reduce) in Fields)
        {
            AssertCommitmentIdentity(prefix, curve, add, subtract, multiply, invert, reduce);
        }
    }


    private static void AssertCommitmentIdentity(
        string prefix,
        CurveParameterSet curve,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ScalarReduceDelegate reduce)
    {
        //The end-to-end byte-identity confirmation through the Merkle roots at
        //the wired CLI parameters: rate 1/16 with query count 64 puts the
        //(8, 128) row shape through the real commit → open → verify path.
        const int VariableCount = 6;
        const int InverseRate = 16;
        const int QueryCount = 64;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var extenders = new ScalarNttLigeroRowExtenders(add, subtract, multiply, invert, curve, pool);
        using PolynomialCommitmentProvider reference = NewProvider(curve, add, subtract, multiply, invert, reduce, QueryCount, InverseRate, rowExtenderFactory: null);
        using PolynomialCommitmentProvider accelerated = NewProvider(curve, add, subtract, multiply, invert, reduce, QueryCount, InverseRate, extenders.Create);

        using MultilinearExtension mle = BuildMle(VariableCount, reduce, curve, pool);
        Scalar[] point = BuildPoint(VariableCount, reduce, curve, pool);
        try
        {
            (PolynomialCommitment referenceCommitment, PolynomialCommitmentBlind referenceBlind) = reference.Commit(mle, pool);
            (PolynomialCommitment acceleratedCommitment, PolynomialCommitmentBlind acceleratedBlind) = accelerated.Commit(mle, pool);

            using(referenceCommitment)
            using(referenceBlind)
            using(acceleratedCommitment)
            using(acceleratedBlind)
            {
                Assert.IsTrue(
                    acceleratedCommitment.AsReadOnlySpan().SequenceEqual(referenceCommitment.AsReadOnlySpan()),
                    $"The commitment bytes must be identical with and without the extender for {prefix}.");

                using FiatShamirTranscript referenceTranscript = NewTranscript();
                (PolynomialOpening referenceOpening, Scalar referenceValue) = reference.Open(referenceCommitment, referenceBlind, mle, point, referenceTranscript, pool);

                using FiatShamirTranscript acceleratedTranscript = NewTranscript();
                (PolynomialOpening acceleratedOpening, Scalar acceleratedValue) = accelerated.Open(acceleratedCommitment, acceleratedBlind, mle, point, acceleratedTranscript, pool);

                using(referenceOpening)
                using(referenceValue)
                using(acceleratedOpening)
                using(acceleratedValue)
                {
                    Assert.IsTrue(
                        acceleratedValue.AsReadOnlySpan().SequenceEqual(referenceValue.AsReadOnlySpan()),
                        $"The claimed value must be identical with and without the extender for {prefix}.");
                    Assert.IsTrue(
                        acceleratedOpening.AsReadOnlySpan().SequenceEqual(referenceOpening.AsReadOnlySpan()),
                        $"The opening bytes must be identical with and without the extender for {prefix}.");

                    //The untouched verifier accepts the accelerated opening.
                    using FiatShamirTranscript verifyTranscript = NewTranscript();
                    bool verified = reference.VerifyEvaluation(acceleratedCommitment, point, acceleratedValue, acceleratedOpening, verifyTranscript, pool);
                    Assert.IsTrue(verified, $"The accelerated opening must verify against the reference verifier for {prefix}.");
                }
            }
        }
        finally
        {
            foreach(Scalar coordinate in point)
            {
                coordinate.Dispose();
            }
        }
    }


    private static PolynomialCommitmentProvider NewProvider(
        CurveParameterSet curve,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ScalarReduceDelegate reduce,
        int queryCount,
        int inverseRate,
        LigeroRowExtenderFactory? rowExtenderFactory)
    {
        return LigeroPolynomialCommitmentScheme.Create(
            curve,
            queryCount,
            add,
            subtract,
            multiply,
            invert,
            reduce,
            Hash,
            Squeeze,
            Hash,
            Merkle,
            WellKnownHashAlgorithms.Blake3,
            inverseRate: inverseRate,
            rowExtenderFactory: rowExtenderFactory);
    }


    private static FiatShamirTranscript NewTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownLigeroEvaluationLabels.DomainV1),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    private static MultilinearExtension BuildMle(int variableCount, ScalarReduceDelegate reduce, CurveParameterSet curve, BaseMemoryPool pool)
    {
        int evaluationCount = 1 << variableCount;
        using IMemoryOwner<byte> owner = pool.Rent(evaluationCount * ScalarSize);
        Span<byte> evaluations = owner.Memory.Span[..(evaluationCount * ScalarSize)];
        DeterministicScalarFill.FillCanonical(evaluations, MessageFillSalt + variableCount, reduce, curve);

        return MultilinearExtension.FromEvaluations(evaluations, variableCount, curve, pool);
    }


    private static Scalar[] BuildPoint(int variableCount, ScalarReduceDelegate reduce, CurveParameterSet curve, BaseMemoryPool pool)
    {
        var point = new Scalar[variableCount];
        Span<byte> wide = stackalloc byte[ScalarSize];
        for(int i = 0; i < variableCount; i++)
        {
            wide.Clear();
            BinaryPrimitives.WriteInt32BigEndian(wide[..sizeof(int)], MessageFillSalt + (i * 29) + 7);
            IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
            reduce(wide, owner.Memory.Span[..ScalarSize], curve);
            point[i] = new Scalar(owner, curve, WellKnownAlgebraicTags.ScalarFor(curve));
        }

        return point;
    }


    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }
}
