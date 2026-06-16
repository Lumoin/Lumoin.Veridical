using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The binary-field Reed–Solomon domain: encoding over <c>GF(2^128)</c> with the
/// <see cref="LigeroNodeDomain.BinaryField"/> weights. The nodes and points are the bit-pattern
/// elements <c>0..n−1</c> — distinct in characteristic two, where the consecutive-integer
/// factorial weights do not apply because node differences are <c>element(i ⊕ j)</c>. Gated
/// against a naive Lagrange oracle computed directly from the basis-polynomial definition, and
/// against the systematic property.
/// </summary>
[TestClass]
internal sealed class Gf2k128ReedSolomonTests
{
    private const int ScalarSize = 32;
    private const int MessageLength = 13;
    private const int CodewordLength = 41;

    private static ScalarAddDelegate Add { get; } = Gf2k128Reference.GetAdd();

    private static ScalarSubtractDelegate Subtract { get; } = Gf2k128Reference.GetSubtract();

    private static ScalarMultiplyDelegate Multiply { get; } = Gf2k128Reference.GetMultiply();

    private static ScalarInvertDelegate Invert { get; } = Gf2k128Reference.GetInvert();


    private const int MessageBytes = MessageLength * ScalarSize;
    private const int CodewordBytes = CodewordLength * ScalarSize;


    [TestMethod]
    public void BinaryDomainEncodingMatchesTheNaiveLagrangeOracle()
    {
        //A deterministic message with bits across the whole element width.
        using IMemoryOwner<byte> messageOwner = BaseMemoryPool.Shared.Rent(MessageBytes);
        Span<byte> message = messageOwner.Memory.Span[..MessageBytes];
        message.Clear();
        for(int i = 0; i < MessageLength; i++)
        {
            for(int b = 16; b < ScalarSize; b++)
            {
                message[(i * ScalarSize) + b] = (byte)((73 * i) + (31 * b) + 7);
            }
        }

        using IMemoryOwner<byte> codewordOwner = BaseMemoryPool.Shared.Rent(CodewordBytes);
        Span<byte> codeword = codewordOwner.Memory.Span[..CodewordBytes];
        LigeroReedSolomonEncoder.Encode(
            message, MessageLength, codeword, CodewordLength, LigeroNodeDomain.BinaryField,
            Add, Subtract, Multiply, Invert, CurveParameterSet.None, BaseMemoryPool.Shared);

        Assert.IsTrue(codeword[..MessageBytes].SequenceEqual(message), "The systematic prefix must be the message verbatim.");

        //The naive oracle: p(x) = Σ_i y_i · Π_{j≠i} (x − x_j)/(x_i − x_j) with XOR differences.
        Span<byte> expected = stackalloc byte[ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];
        Span<byte> factor = stackalloc byte[ScalarSize];
        Span<byte> numerator = stackalloc byte[ScalarSize];
        Span<byte> denominator = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];
        for(int point = MessageLength; point < CodewordLength; point++)
        {
            expected.Clear();
            for(int i = 0; i < MessageLength; i++)
            {
                message.Slice(i * ScalarSize, ScalarSize).CopyTo(term);
                for(int j = 0; j < MessageLength; j++)
                {
                    if(j == i)
                    {
                        continue;
                    }

                    Element(point ^ j, numerator);
                    Element(i ^ j, denominator);
                    Invert(denominator, scratch, CurveParameterSet.None);
                    Multiply(numerator, scratch, factor, CurveParameterSet.None);
                    Multiply(term, factor, scratch, CurveParameterSet.None);
                    scratch.CopyTo(term);
                }

                Add(expected, term, scratch, CurveParameterSet.None);
                scratch.CopyTo(expected);
            }

            Assert.IsTrue(
                codeword.Slice(point * ScalarSize, ScalarSize).SequenceEqual(expected),
                $"The extension at point {point} must match the naive Lagrange oracle.");
        }
    }


    //Writes the field element whose bit pattern is the given non-negative integer.
    private static void Element(int value, Span<byte> destination)
    {
        destination.Clear();
        destination[ScalarSize - 4] = (byte)(value >> 24);
        destination[ScalarSize - 3] = (byte)(value >> 16);
        destination[ScalarSize - 2] = (byte)(value >> 8);
        destination[ScalarSize - 1] = (byte)value;
    }
}
