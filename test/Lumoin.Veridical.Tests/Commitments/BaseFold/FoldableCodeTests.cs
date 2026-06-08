using CsCheck;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Commitments.BaseFold;

/// <summary>
/// Tests for the BaseFold random foldable code (AB.1): the recursive encoding
/// and the FRI-style fold. Correctness is asserted against the construction's
/// defining linearity property rather than hand-computed codewords: folding a
/// codeword under a challenge must yield the encoding of the folded message
/// (<c>fold_α(Enc_d(m)) = Enc_{d-1}(m_l + α·m_r)</c>). Because the diagonals are
/// derived from <c>(seed, layer, position)</c> independently of the total layer
/// count, a code of depth <c>d-1</c> over the same seed shares the lower
/// diagonals with the depth-<c>d</c> code, so the folded codeword can be
/// compared directly against an independent depth-<c>d-1</c> encoding.
/// </summary>
[TestClass]
internal sealed class FoldableCodeTests
{
    private static readonly ScalarAddDelegate Add = TestScalarBackends.Bls12Curve381.Add;
    private static readonly ScalarSubtractDelegate Subtract = TestScalarBackends.Bls12Curve381.Subtract;
    private static readonly ScalarMultiplyDelegate Multiply = TestScalarBackends.Bls12Curve381.Multiply;
    private static readonly ScalarInvertDelegate Invert = TestScalarBackends.Bls12Curve381.Invert;
    private static readonly ScalarReduceDelegate Reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static readonly ScalarHashToScalarDelegate HashToScalar = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();

    private const int ScalarSize = 32;
    private const int IterationCount = 60;

    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(3)]
    [DataRow(4)]
    public void FoldYieldsEncodingOfFoldedMessage(int layerCount)
    {
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(layerCount, Curve);
        FoldableCodeParameters foldedParameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(layerCount - 1, Curve);

        using FoldableCode code = FoldableCode.Derive(parameters, Seed, HashToScalar, pool);
        using FoldableCode foldedCode = FoldableCode.Derive(foldedParameters, Seed, HashToScalar, pool);

        int messageElements = parameters.MessageLength;

        using IMemoryOwner<byte> messageOwner = pool.Rent(messageElements * ScalarSize);
        Span<byte> message = messageOwner.Memory.Span[..(messageElements * ScalarSize)];
        for(int i = 0; i < messageElements; i++)
        {
            WriteSmallScalar(message.Slice(i * ScalarSize, ScalarSize), i + 1);
        }

        Span<byte> challenge = stackalloc byte[ScalarSize];
        WriteSmallScalar(challenge, 7);

        bool matched = FoldMatchesFoldedMessageEncoding(code, foldedCode, parameters, foldedParameters, message, challenge, pool);

        Assert.IsTrue(matched, $"fold(Enc_d(m)) must equal Enc_(d-1)(m_l + alpha*m_r) for d = {layerCount}.");
    }


    [TestMethod]
    public void DeriveIsDeterministicForTheSameSeed()
    {
        const int LayerCount = 3;
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(LayerCount, Curve);

        using FoldableCode first = FoldableCode.Derive(parameters, Seed, HashToScalar, pool);
        using FoldableCode second = FoldableCode.Derive(parameters, Seed, HashToScalar, pool);

        int messageElements = parameters.MessageLength;
        int codewordElements = parameters.CodewordLength;

        using IMemoryOwner<byte> messageOwner = pool.Rent(messageElements * ScalarSize);
        Span<byte> message = messageOwner.Memory.Span[..(messageElements * ScalarSize)];
        for(int i = 0; i < messageElements; i++)
        {
            WriteSmallScalar(message.Slice(i * ScalarSize, ScalarSize), (3 * i) + 1);
        }

        using IMemoryOwner<byte> firstCodewordOwner = pool.Rent(codewordElements * ScalarSize);
        using IMemoryOwner<byte> secondCodewordOwner = pool.Rent(codewordElements * ScalarSize);
        Span<byte> firstCodeword = firstCodewordOwner.Memory.Span[..(codewordElements * ScalarSize)];
        Span<byte> secondCodeword = secondCodewordOwner.Memory.Span[..(codewordElements * ScalarSize)];

        first.Encode(message, firstCodeword, Add, Subtract, Multiply, pool);
        second.Encode(message, secondCodeword, Add, Subtract, Multiply, pool);

        Assert.IsTrue(firstCodeword.SequenceEqual(secondCodeword), "The same seed and parameters must reproduce the same code, hence the same codeword.");
    }


    [TestMethod]
    public void RandomMessagesFoldToTheFoldedMessageEncoding()
    {
        Gen.Int[1, 4]
            .SelectMany(layerCount =>
            {
                int messageElements = 1 << layerCount;
                return Gen.Select(
                    Gen.Const(layerCount),
                    Gen.Byte.Array[messageElements * ScalarSize],
                    Gen.Byte.Array[ScalarSize]);
            })
            .Sample((layerCount, messageBytes, challengeBytes) =>
            {
                SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
                FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(layerCount, Curve);
                FoldableCodeParameters foldedParameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(layerCount - 1, Curve);

                using FoldableCode code = FoldableCode.Derive(parameters, Seed, HashToScalar, pool);
                using FoldableCode foldedCode = FoldableCode.Derive(foldedParameters, Seed, HashToScalar, pool);

                int messageElements = parameters.MessageLength;
                using IMemoryOwner<byte> messageOwner = pool.Rent(messageElements * ScalarSize);
                Span<byte> message = messageOwner.Memory.Span[..(messageElements * ScalarSize)];
                for(int i = 0; i < messageElements; i++)
                {
                    //Reduce each random chunk to a canonical scalar.
                    Reduce(messageBytes.AsSpan(i * ScalarSize, ScalarSize), message.Slice(i * ScalarSize, ScalarSize), Curve);
                }

                Span<byte> challenge = stackalloc byte[ScalarSize];
                Reduce(challengeBytes, challenge, Curve);

                return FoldMatchesFoldedMessageEncoding(code, foldedCode, parameters, foldedParameters, message, challenge, pool);
            }, iter: IterationCount);
    }


    //Encodes the message under the depth-d code, folds the codeword once, and
    //checks the result equals the depth-(d-1) encoding of m_l + alpha*m_r.
    private static bool FoldMatchesFoldedMessageEncoding(
        FoldableCode code,
        FoldableCode foldedCode,
        FoldableCodeParameters parameters,
        FoldableCodeParameters foldedParameters,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> challenge,
        SensitiveMemoryPool<byte> pool)
    {
        int layerCount = parameters.LayerCount;
        int halfElements = parameters.MessageLength / 2;
        int codewordElements = parameters.CodewordLength;
        int foldedElements = foldedParameters.CodewordLength;

        using IMemoryOwner<byte> codewordOwner = pool.Rent(codewordElements * ScalarSize);
        Span<byte> codeword = codewordOwner.Memory.Span[..(codewordElements * ScalarSize)];
        code.Encode(message, codeword, Add, Subtract, Multiply, pool);

        using IMemoryOwner<byte> foldedOwner = pool.Rent(foldedElements * ScalarSize);
        Span<byte> folded = foldedOwner.Memory.Span[..(foldedElements * ScalarSize)];
        code.Fold(codeword, layerCount, challenge, folded, Add, Subtract, Multiply, Invert);

        //m' = m_l + alpha * m_r, component-wise.
        using IMemoryOwner<byte> foldedMessageOwner = pool.Rent(halfElements * ScalarSize);
        Span<byte> foldedMessage = foldedMessageOwner.Memory.Span[..(halfElements * ScalarSize)];
        Span<byte> term = stackalloc byte[ScalarSize];
        for(int i = 0; i < halfElements; i++)
        {
            Multiply(challenge, message.Slice((halfElements + i) * ScalarSize, ScalarSize), term, Curve);
            Add(message.Slice(i * ScalarSize, ScalarSize), term, foldedMessage.Slice(i * ScalarSize, ScalarSize), Curve);
        }

        using IMemoryOwner<byte> expectedOwner = pool.Rent(foldedElements * ScalarSize);
        Span<byte> expected = expectedOwner.Memory.Span[..(foldedElements * ScalarSize)];
        foldedCode.Encode(foldedMessage, expected, Add, Subtract, Multiply, pool);

        return folded.SequenceEqual(expected);
    }


    //A distinct small canonical scalar: the value in the last four big-endian
    //bytes, which is far below the field order, so it is already canonical.
    private static void WriteSmallScalar(Span<byte> destination, int value)
    {
        destination.Clear();
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(destination[^4..], value);
    }


    private static ReadOnlySpan<byte> Seed => "Lumoin.Veridical.BaseFold.AB1.FoldableCode.Test"u8;
}
