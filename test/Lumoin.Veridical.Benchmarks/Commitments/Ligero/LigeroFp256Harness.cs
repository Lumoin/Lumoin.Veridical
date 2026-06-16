using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Commitments.Ligero.Gadgets;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers.Binary;
using System.Globalization;
using System.Numerics;

namespace Lumoin.Veridical.Benchmarks.Commitments.Ligero;

/// <summary>
/// Wiring for proving representative Fp256 elliptic-curve circuits with the
/// promoted Core <see cref="LigeroConstraintSystemBuilder"/> +
/// <see cref="WeierstrassGadgetExtensions"/>, shared by the full-prove benchmark and the
/// <c>--ligero-attribution</c> driver. It mirrors the test project's private
/// gadget wiring (delegates from <see cref="P256BaseFieldReference"/>, a
/// Blake3 Fiat–Shamir transcript and two-to-one Merkle, a deterministic Fp256
/// randomness source) so the benchmarked path is exactly the one the tests
/// exercise.
/// </summary>
internal static class LigeroFp256Harness
{
    public const int ScalarSize = Lumoin.Veridical.Core.Algebraic.Scalar.SizeBytes;
    public const int InverseRate = 4;
    public const int OpenedColumns = 4;
    public const int Block = 64;

    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    public static readonly BigInteger P = P256BigIntegerG1Reference.BaseFieldPrime;

    //The standard P-256 base point (FIPS 186-4 / SEC2 secp256r1).
    public static readonly BigInteger GeneratorX = BigInteger.Parse(
        "06b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", NumberStyles.HexNumber, CultureInfo.InvariantCulture);
    public static readonly BigInteger GeneratorY = BigInteger.Parse(
        "04fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", NumberStyles.HexNumber, CultureInfo.InvariantCulture);

    public static readonly byte[] CurveABytes = ToCanonical(P256BigIntegerG1Reference.CurveA);
    public static readonly byte[] CurveBBytes = ToCanonical(P256BigIntegerG1Reference.CurveB);

    private static readonly byte[] TranscriptSeed = System.Text.Encoding.UTF8.GetBytes("veridical.longfellow.bench.v1");
    private static readonly byte[] RandomnessSeed = System.Text.Encoding.UTF8.GetBytes("veridical.longfellow.bench.rng.v1");

    private static readonly FiatShamirHashDelegate Hash = Blake3FiatShamirBackend.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = Blake3FiatShamirBackend.GetSqueeze();
    private static readonly MerkleHashDelegate Merkle = HashTwoToOne;


    public static (LigeroConstraintSystemBuilder Builder, WeierstrassCurve Curve) NewGadget(
        ScalarAddDelegate add, ScalarSubtractDelegate subtract, ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert, ScalarReduceDelegate reduce)
    {
        var builder = new LigeroConstraintSystemBuilder(add, subtract, multiply, invert, reduce, CurveParameterSet.None, InverseRate, OpenedColumns, Block, BaseMemoryPool.Shared);

        return (builder, WeierstrassCurve.Create(builder, CurveABytes, CurveBBytes));
    }


    //A chain of `count` complete projective additions accumulating G, 2G, 3G, …
    //— a small, fast circuit for the BenchmarkDotNet prove benchmark.
    public static LigeroConstraintSystemBuilder BuildChainedAddition(
        int count, ScalarAddDelegate add, ScalarSubtractDelegate subtract, ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert, ScalarReduceDelegate reduce)
    {
        (LigeroConstraintSystemBuilder builder, WeierstrassCurve ec) = NewGadget(add, subtract, multiply, invert, reduce);

        (int X, int Y, int Z) accumulator = (Wire(builder, GeneratorX), Wire(builder, GeneratorY), Const(builder, BigInteger.One));
        (int X, int Y, int Z) generator = (Wire(builder, GeneratorX), Wire(builder, GeneratorY), Const(builder, BigInteger.One));
        for(int i = 0; i < count; i++)
        {
            accumulator = builder.AddCompleteProjectiveAddition(ec, accumulator.X, accumulator.Y, accumulator.Z, generator.X, generator.Y, generator.Z);
        }

        return builder;
    }


    //A `width`-bit witnessed double-and-add ladder for the scalar `k` over G —
    //the realistic-scale circuit for the attribution driver.
    public static LigeroConstraintSystemBuilder BuildSingleScalarLadder(
        int width, int k, ScalarAddDelegate add, ScalarSubtractDelegate subtract, ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert, ScalarReduceDelegate reduce)
    {
        (LigeroConstraintSystemBuilder builder, WeierstrassCurve ec) = NewGadget(add, subtract, multiply, invert, reduce);

        int px = Wire(builder, GeneratorX), py = Wire(builder, GeneratorY), pz = Const(builder, BigInteger.One);
        int[] bits = AddScalarBits(builder, k, width);
        builder.AddScalarMultiplyLadder(ec, bits, px, py, pz);

        return builder;
    }


    public static LigeroProof Prove(
        LigeroConstraintSystemBuilder builder, ScalarAddDelegate add, ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert, ScalarReduceDelegate reduce) => LigeroProver.Prove(
            builder.BuildParameters(), builder.WitnessBytes(), builder.LinearConstraintCount, builder.LinearConstraints(),
            builder.TargetBytes(), builder.QuadraticConstraints(), TranscriptSeed,
            new DeterministicFp256Random(RandomnessSeed).AsDelegate(),
            add, subtract, multiply, invert, reduce,
            Hash, Squeeze, Hash, Merkle, WellKnownHashAlgorithms.Blake3,
            CurveParameterSet.None, BaseMemoryPool.Shared);


    public static bool Verify(
        LigeroConstraintSystemBuilder builder, LigeroProof proof, ScalarAddDelegate add, ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert, ScalarReduceDelegate reduce) => LigeroVerifier.Verify(
            builder.BuildParameters(), proof, builder.LinearConstraintCount, builder.LinearConstraints(),
            builder.TargetBytes(), builder.QuadraticConstraints(), TranscriptSeed,
            add, subtract, multiply, invert, reduce,
            Hash, Squeeze, Hash, Merkle, WellKnownHashAlgorithms.Blake3,
            CurveParameterSet.None, BaseMemoryPool.Shared);


    public static int Wire(LigeroConstraintSystemBuilder builder, BigInteger value)
    {
        Span<byte> bytes = stackalloc byte[ScalarSize];
        WriteCanonical(Mod(value), bytes);

        return builder.AddWire(bytes);
    }


    public static int Const(LigeroConstraintSystemBuilder builder, BigInteger value)
    {
        Span<byte> bytes = stackalloc byte[ScalarSize];
        WriteCanonical(Mod(value), bytes);

        return builder.AddConstant(bytes);
    }


    public static int[] AddScalarBits(LigeroConstraintSystemBuilder builder, BigInteger scalar, int width)
    {
        int[] bitsMostSignificantFirst = new int[width];
        Span<byte> bit = stackalloc byte[ScalarSize];
        for(int i = 0; i < width; i++)
        {
            int bitIndex = width - 1 - i;
            WriteCanonical((scalar >> bitIndex) & BigInteger.One, bit);
            bitsMostSignificantFirst[i] = builder.AddBit(bit);
        }

        return bitsMostSignificantFirst;
    }


    public static BigInteger Mod(BigInteger value) => ((value % P) + P) % P;


    private static byte[] ToCanonical(BigInteger value)
    {
        byte[] bytes = new byte[ScalarSize];
        WriteCanonical(((value % P) + P) % P, bytes);

        return bytes;
    }


    public static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true);
        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }


    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Lumoin.Veridical.Hashing.Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    private sealed class DeterministicFp256Random
    {
        private readonly byte[] seed;
        private int counter;

        public DeterministicFp256Random(ReadOnlySpan<byte> seed) => this.seed = seed.ToArray();

        public ScalarRandomDelegate AsDelegate() => Fill;

        private Tag Fill(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
        {
            Span<byte> input = stackalloc byte[seed.Length + sizeof(int)];
            seed.CopyTo(input);
            BinaryPrimitives.WriteInt32BigEndian(input[seed.Length..], counter);
            counter++;

            Span<byte> wide = stackalloc byte[64];
            Lumoin.Veridical.Hashing.Blake3.Hash(input, wide);
            WriteCanonical(new BigInteger(wide, isUnsigned: true, isBigEndian: true) % P, destination);

            return inboundTag;
        }
    }
}
