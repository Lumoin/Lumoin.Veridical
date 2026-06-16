using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Byte-identical agreement between the fast <see cref="Gf2k128Backend"/> (ulong limbs,
/// PCLMULQDQ where available) and the BigInteger <see cref="Gf2k128Reference"/> oracle, over
/// samples chosen to exercise the carry-less halves and both fold stages (high bits set, the
/// spill past position 128, all-ones limbs). The software 64×64 carry-less path is gated
/// directly against a BigInteger shift-XOR oracle, since hardware with the intrinsic would
/// otherwise never execute it.
/// <para>
/// The pairing is deliberate and recurs across this codebase: every optimized arithmetic
/// backend keeps a slow, independently-written reference twin (BigInteger here; the same for
/// the P-256 base field and its Montgomery backend), and the gate is BYTE-IDENTITY on shared
/// inputs, not plausibility. The reference is written for obviousness and never optimized,
/// so the two implementations do not share the bug surface; the production tests then run on
/// whichever backend fits, knowing the pair cannot silently drift apart.
/// </para>
/// </summary>
[TestClass]
internal sealed class Gf2k128BackendAgreementTests
{
    private const int ScalarSize = 32;

    private static ScalarAddDelegate ReferenceAdd { get; } = Gf2k128Reference.GetAdd();

    private static ScalarMultiplyDelegate ReferenceMultiply { get; } = Gf2k128Reference.GetMultiply();

    private static ScalarInvertDelegate ReferenceInvert { get; } = Gf2k128Reference.GetInvert();

    private static ScalarReduceDelegate ReferenceReduce { get; } = Gf2k128Reference.GetReduce();

    private static ScalarAddDelegate BackendAdd { get; } = Gf2k128Backend.GetAdd();

    private static ScalarSubtractDelegate BackendSubtract { get; } = Gf2k128Backend.GetSubtract();

    private static ScalarMultiplyDelegate BackendMultiply { get; } = Gf2k128Backend.GetMultiply();

    private static ScalarInvertDelegate BackendInvert { get; } = Gf2k128Backend.GetInvert();

    private static ScalarReduceDelegate BackendReduce { get; } = Gf2k128Backend.GetReduce();

    //Bit patterns spread across both limbs, the limb boundary, the top bits (the fold), and
    //the degenerate ends.
    private static BigInteger[] Samples { get; } =
    [
        BigInteger.Zero,
        BigInteger.One,
        new BigInteger(2),
        new BigInteger(0x87),
        BigInteger.Parse("0123456789abcdef0fedcba987654321", System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture),
        BigInteger.Parse("0deadbeefcafebabe0123456789abcde", System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture),
        (BigInteger.One << 127) + 1,
        (BigInteger.One << 127) + (BigInteger.One << 64) + (BigInteger.One << 63) + 1,
        (BigInteger.One << 128) - 1,
        ((BigInteger.One << 64) - 1) << 64,
        (BigInteger.One << 64) - 1,
        BigInteger.Parse("0fffffffffffffff8000000000000001", System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture),
    ];


    [TestMethod]
    public void MultiplyAndAddAgreeWithTheReference()
    {
        Span<byte> a = stackalloc byte[ScalarSize];
        Span<byte> b = stackalloc byte[ScalarSize];
        Span<byte> expected = stackalloc byte[ScalarSize];
        Span<byte> actual = stackalloc byte[ScalarSize];

        foreach(BigInteger left in Samples)
        {
            Element(left, a);
            foreach(BigInteger right in Samples)
            {
                Element(right, b);

                ReferenceMultiply(a, b, expected, CurveParameterSet.None);
                BackendMultiply(a, b, actual, CurveParameterSet.None);
                Assert.IsTrue(actual.SequenceEqual(expected), $"Multiply must agree for {left:x} · {right:x}.");

                ReferenceAdd(a, b, expected, CurveParameterSet.None);
                BackendAdd(a, b, actual, CurveParameterSet.None);
                Assert.IsTrue(actual.SequenceEqual(expected), $"Add must agree for {left:x} + {right:x}.");

                BackendSubtract(a, b, actual, CurveParameterSet.None);
                Assert.IsTrue(actual.SequenceEqual(expected), $"Subtract must equal add for {left:x}, {right:x}.");
            }
        }
    }


    [TestMethod]
    public void InvertAgreesWithTheReference()
    {
        Span<byte> a = stackalloc byte[ScalarSize];
        Span<byte> expected = stackalloc byte[ScalarSize];
        Span<byte> actual = stackalloc byte[ScalarSize];

        foreach(BigInteger sample in Samples)
        {
            if(sample.IsZero)
            {
                continue;
            }

            Element(sample, a);
            ReferenceInvert(a, expected, CurveParameterSet.None);
            BackendInvert(a, actual, CurveParameterSet.None);
            Assert.IsTrue(actual.SequenceEqual(expected), $"Invert must agree for {sample:x}.");
        }
    }


    [TestMethod]
    public void ReduceAgreesWithTheReferenceOnWideInput()
    {
        //Wide pseudo-random inputs as the transcript squeeze produces them.
        Span<byte> wide = stackalloc byte[64];
        Span<byte> expected = stackalloc byte[ScalarSize];
        Span<byte> actual = stackalloc byte[ScalarSize];
        for(int seed = 0; seed < 8; seed++)
        {
            for(int i = 0; i < wide.Length; i++)
            {
                wide[i] = (byte)((31 * i) + (97 * seed) + 5);
            }

            ReferenceReduce(wide, expected, CurveParameterSet.None);
            BackendReduce(wide, actual, CurveParameterSet.None);
            Assert.IsTrue(actual.SequenceEqual(expected), $"Reduce must agree on the wide sample {seed}.");
        }
    }


    [TestMethod]
    public void TheSoftwareCarrylessPathMatchesABigIntegerOracle()
    {
        //The intrinsic path runs on this hardware; the portable path is gated explicitly.
        ulong[] operands =
        [
            0, 1, 2, 0x87, ulong.MaxValue, 0x8000000000000001, 0x0123456789abcdef,
            0xdeadbeefcafebabe, 0xfffffffffffffff8, 1UL << 63,
        ];
        foreach(ulong a in operands)
        {
            foreach(ulong b in operands)
            {
                (ulong high, ulong low) = Gf2k128Backend.SoftwareCarrylessMultiply64(a, b);

                BigInteger oracle = BigInteger.Zero;
                for(int bit = 0; bit < 64; bit++)
                {
                    if(((b >> bit) & 1) != 0)
                    {
                        oracle ^= new BigInteger(a) << bit;
                    }
                }

                var combined = ((BigInteger)high << 64) + low;
                Assert.AreEqual(oracle, combined, $"The software carry-less product must match the oracle for {a:x} · {b:x}.");
            }
        }
    }


    private static void Element(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        Span<byte> little = stackalloc byte[ScalarSize + 1];
        if(value.TryWriteBytes(little, out int written, isUnsigned: true, isBigEndian: false))
        {
            for(int i = 0; i < written && i < ScalarSize; i++)
            {
                destination[ScalarSize - 1 - i] = little[i];
            }
        }
    }
}
