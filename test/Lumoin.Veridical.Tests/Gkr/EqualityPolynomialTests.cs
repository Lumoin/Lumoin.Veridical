using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Gkr;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers;
using System.Numerics;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Gkr;

/// <summary>
/// The equality polynomial table (<see cref="EqualityPolynomial.BuildTable"/>) over the P-256 base
/// field Fp256: every hypercube entry must equal the direct product
/// <c>Π_b (g_b if bit b of x is set else 1 − g_b)</c>, and the whole table must sum to 1 (the
/// <c>Σ_x eq_g(x) = 1</c> identity). This is the selector GKR multiplies into a layer sum.
/// </summary>
[TestClass]
internal sealed class EqualityPolynomialTests
{
    private const int ScalarSize = 32;
    private static BigInteger P { get; } = P256BigIntegerG1Reference.BaseFieldPrime;

    private static ScalarSubtractDelegate Subtract { get; } = P256BaseFieldReference.GetSubtract();

    private static ScalarMultiplyDelegate Multiply { get; } = P256BaseFieldReference.GetMultiply();


    [TestMethod]
    public void EqualityTableMatchesTheProductFormulaAndSumsToOne()
    {
        const int variableCount = 8;
        const int size = 1 << variableCount;
        const int tableBytes = size * ScalarSize;

        BigInteger[] coordinates = new BigInteger[variableCount];
        byte[] point = new byte[variableCount * ScalarSize];
        for(int b = 0; b < variableCount; b++)
        {
            coordinates[b] = RandomFieldElement(b + 31);
            WriteCanonical(coordinates[b], point.AsSpan(b * ScalarSize, ScalarSize));
        }

        using IMemoryOwner<byte> tableOwner = BaseMemoryPool.Shared.Rent(tableBytes);
        Span<byte> table = tableOwner.Memory.Span[..tableBytes];
        table.Clear();
        EqualityPolynomial.BuildTable(point, variableCount, table, Subtract, Multiply, CurveParameterSet.None);

        BigInteger total = BigInteger.Zero;
        for(int x = 0; x < size; x++)
        {
            BigInteger expected = BigInteger.One;
            for(int b = 0; b < variableCount; b++)
            {
                BigInteger factor = ((x >> b) & 1) == 1 ? coordinates[b] : Mod(BigInteger.One - coordinates[b]);
                expected = (expected * factor) % P;
            }

            BigInteger actual = ToInteger(table.Slice(x * ScalarSize, ScalarSize));
            Assert.AreEqual(expected, actual, $"eq table entry {x} must equal the product formula.");
            total = (total + actual) % P;
        }

        Assert.AreEqual(BigInteger.One, total, "The equality table must sum to 1 over the hypercube.");
    }


    private static BigInteger RandomFieldElement(int index)
    {
        Span<byte> seed = stackalloc byte[4];
        seed[0] = (byte)(index >> 24);
        seed[1] = (byte)(index >> 16);
        seed[2] = (byte)(index >> 8);
        seed[3] = (byte)index;
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(seed, digest);

        return ToInteger(digest);
    }


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        BigInteger reduced = Mod(value);
        Span<byte> little = stackalloc byte[ScalarSize + 1];
        if(reduced.TryWriteBytes(little, out int written, isUnsigned: true, isBigEndian: false))
        {
            for(int i = 0; i < ScalarSize && i < written; i++)
            {
                destination[ScalarSize - 1 - i] = little[i];
            }
        }
    }


    private static BigInteger ToInteger(ReadOnlySpan<byte> bytes) => new(bytes, isUnsigned: true, isBigEndian: true);


    private static BigInteger Mod(BigInteger value) => ((value % P) + P) % P;
}
