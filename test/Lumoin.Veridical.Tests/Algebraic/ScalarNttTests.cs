using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The conformance gates for <see cref="ScalarNtt"/>: the per-curve domain
/// constants re-derived from the field orders, the run-time root derivation
/// pinned to the externally computed anchor, the forward–inverse transform
/// identity, and the transform-based cyclic convolution checked against the
/// schoolbook product. Both wired curves run through every gate.
/// </summary>
[TestClass]
internal sealed class ScalarNttTests
{
    private const int ScalarSize = Scalar.SizeBytes;

    private const string AnchorRelativePath = "TestMaterial/ScalarNtt/scalar-ntt-anchor-output.txt";

    //A fill salt distinct from the streams other algebraic tests draw.
    private const int DataFillSalt = 4101;

    private static Dictionary<string, string> Anchors { get; } = LoadAnchors();

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


    [TestMethod]
    public void TheDomainConstantsMatchTheFieldOrder()
    {
        foreach((string prefix, CurveParameterSet curve, _, _, _, _, _) in Fields)
        {
            BigInteger order = WellKnownCurves.GetScalarFieldOrder(curve);
            BigInteger oddPart = order - BigInteger.One;
            int derivedAdicity = 0;
            while(oddPart.IsEven)
            {
                oddPart >>= 1;
                derivedAdicity++;
            }

            Assert.AreEqual(derivedAdicity, ScalarNtt.TwoAdicity(curve), $"The recorded 2-adicity must match the field order for {prefix}.");

            //Euler criterion: the domain generator must be a quadratic nonresidue,
            //which is what gives the derived roots their exact power-of-two order.
            BigInteger generator = ScalarNtt.DomainGenerator(curve);
            BigInteger euler = BigInteger.ModPow(generator, (order - BigInteger.One) / 2, order);
            Assert.AreEqual(order - BigInteger.One, euler, $"The domain generator must be a quadratic nonresidue for {prefix}.");
        }
    }


    [TestMethod]
    public void TheDerivedRootsMatchTheAnchor()
    {
        Span<byte> root = stackalloc byte[ScalarSize];
        Span<byte> smallValue = stackalloc byte[ScalarSize];
        foreach((string prefix, CurveParameterSet curve, _, ScalarSubtractDelegate subtract, ScalarMultiplyDelegate multiply, _, _) in Fields)
        {
            //Encoding-convention anchors: the working-domain small-integer writer
            //must agree with the fixture's canonical big-endian layout.
            WriteCanonicalUInt(1, smallValue);
            Assert.IsTrue(smallValue.SequenceEqual(AnchorElement($"{prefix}_one")), $"The canonical one must match the anchor for {prefix}.");
            WriteCanonicalUInt(300, smallValue);
            Assert.IsTrue(smallValue.SequenceEqual(AnchorElement($"{prefix}_of_scalar_300")), $"The canonical 300 must match the anchor for {prefix}.");

            //4 and 6 exercise multi-stage domains below the full 2-adicity; the
            //last entry pins the maximum supported domain of each field.
            foreach(int lengthLog2 in (int[])[4, 6, ScalarNtt.TwoAdicity(curve)])
            {
                ScalarNtt.DeriveRootOfUnity(lengthLog2, root, subtract, multiply, WriteCanonicalUInt, curve);
                Assert.IsTrue(root.SequenceEqual(AnchorElement($"{prefix}_omega_2p{lengthLog2}")), $"The derived 2^{lengthLog2}-th root must match the anchor for {prefix}.");
            }
        }
    }


    [TestMethod]
    public void TheDerivationRejectsLengthsBeyondTheTwoAdicity()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        foreach((_, CurveParameterSet curve, _, ScalarSubtractDelegate subtract, ScalarMultiplyDelegate multiply, _, _) in Fields)
        {
            int excessive = ScalarNtt.TwoAdicity(curve) + 1;
            using IMemoryOwner<byte> rootOwner = pool.Rent(ScalarSize);
            Memory<byte> rootMemory = rootOwner.Memory[..ScalarSize];
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                () => ScalarNtt.DeriveRootOfUnity(excessive, rootMemory.Span, subtract, multiply, WriteCanonicalUInt, curve),
                "A domain longer than the field's 2-adic subgroup must be rejected.");
        }
    }


    [TestMethod]
    public void ForwardThenInverseScalesByLength()
    {
        //Covers the degenerate lengths (1, 2) alongside multi-stage transforms.
        int[] lengths = [1, 2, 8, 16];
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Span<byte> root = stackalloc byte[ScalarSize];
        Span<byte> inverseRoot = stackalloc byte[ScalarSize];
        Span<byte> lengthValue = stackalloc byte[ScalarSize];
        foreach((string prefix, CurveParameterSet curve, ScalarAddDelegate add, ScalarSubtractDelegate subtract, ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert, ScalarReduceDelegate reduce) in Fields)
        {
            foreach(int length in lengths)
            {
                using IMemoryOwner<byte> dataOwner = pool.Rent(length * ScalarSize);
                using IMemoryOwner<byte> originalOwner = pool.Rent(length * ScalarSize);
                using IMemoryOwner<byte> twiddleOwner = pool.Rent(Math.Max(length / 2, 1) * ScalarSize);
                using IMemoryOwner<byte> inverseTwiddleOwner = pool.Rent(Math.Max(length / 2, 1) * ScalarSize);
                Span<byte> data = dataOwner.Memory.Span[..(length * ScalarSize)];
                Span<byte> original = originalOwner.Memory.Span[..(length * ScalarSize)];
                Span<byte> twiddles = twiddleOwner.Memory.Span[..((length / 2) * ScalarSize)];
                Span<byte> inverseTwiddles = inverseTwiddleOwner.Memory.Span[..((length / 2) * ScalarSize)];

                DeterministicScalarFill.FillCanonical(data, DataFillSalt + length, reduce, curve);
                data.CopyTo(original);

                int lengthLog2 = BitOperations.Log2((uint)length);
                ScalarNtt.DeriveRootOfUnity(lengthLog2, root, subtract, multiply, WriteCanonicalUInt, curve);
                invert(root, inverseRoot, curve);
                ScalarNtt.BuildTwiddles(root, length, twiddles, multiply, WriteCanonicalUInt, curve);
                ScalarNtt.BuildTwiddles(inverseRoot, length, inverseTwiddles, multiply, WriteCanonicalUInt, curve);

                ScalarNtt.Forward(data, length, twiddles, add, subtract, multiply, curve);
                ScalarNtt.Inverse(data, length, inverseTwiddles, add, subtract, multiply, curve);

                WriteCanonicalUInt((uint)length, lengthValue);
                for(int i = 0; i < length; i++)
                {
                    multiply(original.Slice(i * ScalarSize, ScalarSize), lengthValue, original.Slice(i * ScalarSize, ScalarSize), curve);
                }

                Assert.IsTrue(data.SequenceEqual(original), $"Inverse(Forward(x)) must equal length·x at length {length} for {prefix}.");
            }
        }
    }


    [TestMethod]
    public void TheConvolutionMatchesTheSchoolbookCyclicProduct()
    {
        //A single multi-stage length keeps the schoolbook oracle readable while
        //still exercising every butterfly layer and the twiddle striding.
        const int Length = 8;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Span<byte> root = stackalloc byte[ScalarSize];
        Span<byte> inverseRoot = stackalloc byte[ScalarSize];
        Span<byte> inverseLength = stackalloc byte[ScalarSize];
        Span<byte> product = stackalloc byte[ScalarSize];
        foreach((string prefix, CurveParameterSet curve, ScalarAddDelegate add, ScalarSubtractDelegate subtract, ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert, ScalarReduceDelegate reduce) in Fields)
        {
            using IMemoryOwner<byte> leftOwner = pool.Rent(Length * ScalarSize);
            using IMemoryOwner<byte> rightOwner = pool.Rent(Length * ScalarSize);
            using IMemoryOwner<byte> expectedOwner = pool.Rent(Length * ScalarSize);
            using IMemoryOwner<byte> twiddleOwner = pool.Rent((Length / 2) * ScalarSize);
            using IMemoryOwner<byte> inverseTwiddleOwner = pool.Rent((Length / 2) * ScalarSize);
            Span<byte> left = leftOwner.Memory.Span[..(Length * ScalarSize)];
            Span<byte> right = rightOwner.Memory.Span[..(Length * ScalarSize)];
            Span<byte> expected = expectedOwner.Memory.Span[..(Length * ScalarSize)];
            Span<byte> twiddles = twiddleOwner.Memory.Span[..((Length / 2) * ScalarSize)];
            Span<byte> inverseTwiddles = inverseTwiddleOwner.Memory.Span[..((Length / 2) * ScalarSize)];

            DeterministicScalarFill.FillCanonical(left, DataFillSalt + 100, reduce, curve);
            DeterministicScalarFill.FillCanonical(right, DataFillSalt + 200, reduce, curve);

            //Schoolbook cyclic convolution: expected[k] = Σ_i left[i]·right[(k−i) mod L].
            expected.Clear();
            for(int k = 0; k < Length; k++)
            {
                Span<byte> destination = expected.Slice(k * ScalarSize, ScalarSize);
                for(int i = 0; i < Length; i++)
                {
                    int wrapped = (k - i + Length) % Length;
                    multiply(left.Slice(i * ScalarSize, ScalarSize), right.Slice(wrapped * ScalarSize, ScalarSize), product, curve);
                    add(destination, product, destination, curve);
                }
            }

            ScalarNtt.DeriveRootOfUnity(BitOperations.Log2(Length), root, subtract, multiply, WriteCanonicalUInt, curve);
            invert(root, inverseRoot, curve);
            ScalarNtt.BuildTwiddles(root, Length, twiddles, multiply, WriteCanonicalUInt, curve);
            ScalarNtt.BuildTwiddles(inverseRoot, Length, inverseTwiddles, multiply, WriteCanonicalUInt, curve);

            ScalarNtt.Forward(left, Length, twiddles, add, subtract, multiply, curve);
            ScalarNtt.Forward(right, Length, twiddles, add, subtract, multiply, curve);
            for(int i = 0; i < Length; i++)
            {
                multiply(left.Slice(i * ScalarSize, ScalarSize), right.Slice(i * ScalarSize, ScalarSize), left.Slice(i * ScalarSize, ScalarSize), curve);
            }

            ScalarNtt.Inverse(left, Length, inverseTwiddles, add, subtract, multiply, curve);

            WriteCanonicalUInt(Length, inverseLength);
            invert(inverseLength, inverseLength, curve);
            for(int i = 0; i < Length; i++)
            {
                multiply(left.Slice(i * ScalarSize, ScalarSize), inverseLength, left.Slice(i * ScalarSize, ScalarSize), curve);
            }

            Assert.IsTrue(left.SequenceEqual(expected), $"The transform convolution must match the schoolbook cyclic product for {prefix}.");
        }
    }


    private static byte[] AnchorElement(string key)
    {
        Assert.IsTrue(Anchors.TryGetValue(key, out string? hex), $"The anchor must contain '{key}'.");

        return Convert.FromHexString(hex!);
    }


    private static Dictionary<string, string> LoadAnchors()
    {
        string path = $"../../../{AnchorRelativePath}";
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach(string line in File.ReadAllLines(path))
        {
            int separator = line.IndexOf('=', StringComparison.Ordinal);
            if(separator < 0)
            {
                continue;
            }

            string key = line[..separator];
            string value = line[(separator + 1)..];

            //Anchor data lines are key=hex with no spaces; the provenance header lines are skipped here.
            if(value.Length > 0 && IsHex(value))
            {
                map[key] = value;
            }
        }

        return map;
    }


    private static bool IsHex(string value)
    {
        foreach(char c in value)
        {
            if(c is not ((>= '0' and <= '9') or (>= 'a' and <= 'f') or (>= 'A' and <= 'F')))
            {
                return false;
            }
        }

        return true;
    }


    private static void WriteCanonicalUInt(uint value, Span<byte> destination)
    {
        destination.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(destination[(ScalarSize - sizeof(uint))..], value);
    }
}
