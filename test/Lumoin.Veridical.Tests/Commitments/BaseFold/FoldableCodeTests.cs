using CsCheck;
using Lumoin.Veridical.Backends.Managed;
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
/// Tests for the BaseFold random foldable code: the recursive encoding
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
    /// <summary>The BLS12-381 scalar addition backend used by Encode and Fold.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;

    /// <summary>The BLS12-381 scalar subtraction backend used by Encode and Fold.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;

    /// <summary>The BLS12-381 scalar multiplication backend used by Encode and Fold.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;

    /// <summary>The BLS12-381 scalar inversion backend used by Fold.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;

    /// <summary>The BLS12-381 scalar reduction backend used to canonicalize random sampled bytes.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>The BLS12-381 hash-to-scalar backend the code's diagonals are derived through.</summary>
    private static ScalarHashToScalarDelegate HashToScalar { get; } = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();

    /// <summary>The canonical scalar width in bytes.</summary>
    private const int ScalarSize = 32;

    /// <summary>The number of random samples the property-based fold test draws.</summary>
    private const int IterationCount = 60;

    /// <summary>The curve every code, message and scalar in this suite is over.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    /// <summary>Pins the construction's defining linearity property at layer counts one through four: folding the depth-d encoding of a fixed message under a fixed challenge equals the independent depth-(d-1) encoding of the folded message.</summary>
    [TestMethod]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(3)]
    [DataRow(4)]
    public void FoldYieldsEncodingOfFoldedMessage(int layerCount)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
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


    /// <summary>Pins that deriving a code twice from the same seed and parameters produces codes that encode the same message to the same codeword.</summary>
    [TestMethod]
    public void DeriveIsDeterministicForTheSameSeed()
    {
        const int LayerCount = 3;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
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


    /// <summary>Pins the same fold-equals-folded-encoding property as <see cref="FoldYieldsEncodingOfFoldedMessage"/>, but over random layer counts, messages and challenges.</summary>
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
                BaseMemoryPool pool = BaseMemoryPool.Shared;
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


    /// <summary>Encodes the message under the depth-d code, folds the codeword once, and checks the result equals the depth-(d-1) encoding of m_l + alpha*m_r.</summary>
    private static bool FoldMatchesFoldedMessageEncoding(
        FoldableCode code,
        FoldableCode foldedCode,
        FoldableCodeParameters parameters,
        FoldableCodeParameters foldedParameters,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> challenge,
        BaseMemoryPool pool)
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


    /// <summary>Writes a distinct small canonical scalar: the value in the last four big-endian bytes, which is far below the field order, so it is already canonical.</summary>
    private static void WriteSmallScalar(Span<byte> destination, int value)
    {
        destination.Clear();
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(destination[^4..], value);
    }


    /// <summary>The fixed domain-separated seed every code in this suite is derived from.</summary>
    private static ReadOnlySpan<byte> Seed => "Lumoin.Veridical.BaseFold.FoldableCode.Test"u8;
}
