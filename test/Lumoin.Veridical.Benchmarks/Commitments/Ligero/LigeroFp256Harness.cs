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
using System.Buffers;
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
    /// <summary>The canonical scalar width in bytes.</summary>
    public const int ScalarSize = Lumoin.Veridical.Core.Algebraic.Scalar.SizeBytes;

    /// <summary>The Ligero code's inverse rate this harness fixes for every benchmarked circuit.</summary>
    public const int InverseRate = 4;

    /// <summary>The number of Ligero columns opened per proof, fixed for every benchmarked circuit.</summary>
    public const int OpenedColumns = 4;

    /// <summary>The Ligero block size (row width) fixed for every benchmarked circuit.</summary>
    public const int Block = 64;

    /// <summary>The Merkle digest width in bytes, taken from the default digest size.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    /// <summary>The P-256 base field's prime modulus.</summary>
    public static BigInteger P { get; } = P256BigIntegerG1Reference.BaseFieldPrime;

    /// <summary>The P-256 base point's x-coordinate (FIPS 186-4 / SEC2 secp256r1).</summary>
    public static BigInteger GeneratorX { get; } = BigInteger.Parse(
        "06b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", NumberStyles.HexNumber, CultureInfo.InvariantCulture);

    /// <summary>The P-256 base point's y-coordinate (FIPS 186-4 / SEC2 secp256r1).</summary>
    public static BigInteger GeneratorY { get; } = BigInteger.Parse(
        "04fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", NumberStyles.HexNumber, CultureInfo.InvariantCulture);

    /// <summary>The P-256 short-Weierstrass curve coefficient <c>a</c>, canonical bytes.</summary>
    public static byte[] CurveABytes { get; } = ToCanonical(P256BigIntegerG1Reference.CurveA);

    /// <summary>The P-256 short-Weierstrass curve coefficient <c>b</c>, canonical bytes.</summary>
    public static byte[] CurveBBytes { get; } = ToCanonical(P256BigIntegerG1Reference.CurveB);

    /// <summary>The fixed Fiat–Shamir transcript seed shared by every benchmarked prove and verify.</summary>
    private static byte[] TranscriptSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.longfellow.bench.v1");

    /// <summary>The fixed seed for the deterministic Fp256 randomness source shared by every benchmarked prove.</summary>
    private static byte[] RandomnessSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.longfellow.bench.rng.v1");

    /// <summary>The Blake3-backed Fiat–Shamir hash delegate.</summary>
    private static FiatShamirHashDelegate Hash { get; } = Blake3FiatShamirBackend.GetHash();

    /// <summary>The Blake3-backed Fiat–Shamir squeeze delegate.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = Blake3FiatShamirBackend.GetSqueeze();

    /// <summary>The two-to-one Blake3 Merkle compression delegate.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;


    /// <summary>Creates a fresh Ligero constraint-system builder and its P-256 Weierstrass curve gadget, wired with this harness's fixed Ligero parameters.</summary>
    /// <param name="add">Backend scalar addition.</param>
    /// <param name="subtract">Backend scalar subtraction.</param>
    /// <param name="multiply">Backend scalar multiplication.</param>
    /// <param name="invert">Backend scalar inversion.</param>
    /// <param name="reduce">Backend scalar reduction.</param>
    /// <returns>The new builder and its curve gadget.</returns>
    public static (LigeroConstraintSystemBuilder Builder, WeierstrassCurve Curve) NewGadget(
        ScalarAddDelegate add, ScalarSubtractDelegate subtract, ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert, ScalarReduceDelegate reduce)
    {
        var builder = new LigeroConstraintSystemBuilder(add, subtract, multiply, invert, reduce, CurveParameterSet.None, InverseRate, OpenedColumns, Block, BaseMemoryPool.Shared);

        return (builder, WeierstrassCurve.Create(builder, CurveABytes, CurveBBytes));
    }


    /// <summary>
    /// Builds a chain of <paramref name="count"/> complete projective additions accumulating
    /// <c>G, 2G, 3G, …</c> — a small, fast circuit for the BenchmarkDotNet prove benchmark.
    /// </summary>
    /// <param name="count">The number of chained additions.</param>
    /// <param name="add">Backend scalar addition.</param>
    /// <param name="subtract">Backend scalar subtraction.</param>
    /// <param name="multiply">Backend scalar multiplication.</param>
    /// <param name="invert">Backend scalar inversion.</param>
    /// <param name="reduce">Backend scalar reduction.</param>
    /// <returns>The builder holding the chained-addition circuit.</returns>
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


    /// <summary>
    /// Builds a <paramref name="width"/>-bit witnessed double-and-add ladder for the scalar
    /// <paramref name="k"/> over <c>G</c> — the realistic-scale circuit for the attribution driver.
    /// </summary>
    /// <param name="width">The ladder's bit width.</param>
    /// <param name="k">The scalar to multiply by.</param>
    /// <param name="add">Backend scalar addition.</param>
    /// <param name="subtract">Backend scalar subtraction.</param>
    /// <param name="multiply">Backend scalar multiplication.</param>
    /// <param name="invert">Backend scalar inversion.</param>
    /// <param name="reduce">Backend scalar reduction.</param>
    /// <returns>The builder holding the scalar-ladder circuit.</returns>
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


    /// <summary>Proves with pooled snapshots that remain owned until the prover returns.</summary>
    public static LigeroProof Prove(
        LigeroConstraintSystemBuilder builder, ScalarAddDelegate add, ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert, ScalarReduceDelegate reduce)
    {
        using IMemoryOwner<byte>? witnessOwner = builder.WitnessBytes();
        using IMemoryOwner<byte>? targetsOwner = builder.TargetBytes();

        return LigeroProver.Prove(
            builder.BuildParameters(), (witnessOwner?.Memory ?? Memory<byte>.Empty).Span, builder.LinearConstraintCount, builder.LinearConstraints(),
            (targetsOwner?.Memory ?? Memory<byte>.Empty).Span, builder.QuadraticConstraints(), TranscriptSeed,
            new DeterministicFp256Random(RandomnessSeed).AsDelegate(),
            add, subtract, multiply, invert, reduce,
            Hash, Squeeze, Hash, Merkle, WellKnownHashAlgorithms.Blake3,
            CurveParameterSet.None, BaseMemoryPool.Shared);
    }


    /// <summary>Verifies with a pooled target snapshot owned until verification returns.</summary>
    public static bool Verify(
        LigeroConstraintSystemBuilder builder, LigeroProof proof, ScalarAddDelegate add, ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert, ScalarReduceDelegate reduce)
    {
        using IMemoryOwner<byte>? targetsOwner = builder.TargetBytes();

        return LigeroVerifier.Verify(
            builder.BuildParameters(), proof, builder.LinearConstraintCount, builder.LinearConstraints(),
            (targetsOwner?.Memory ?? Memory<byte>.Empty).Span, builder.QuadraticConstraints(), TranscriptSeed,
            add, subtract, multiply, invert, reduce,
            Hash, Squeeze, Hash, Merkle, WellKnownHashAlgorithms.Blake3,
            CurveParameterSet.None, BaseMemoryPool.Shared);
    }


    /// <summary>Adds a witnessed wire holding the canonical reduction of <paramref name="value"/> mod <c>p</c>.</summary>
    /// <param name="builder">The constraint system being built.</param>
    /// <param name="value">The integer value to reduce and witness.</param>
    /// <returns>The new wire's index.</returns>
    public static int Wire(LigeroConstraintSystemBuilder builder, BigInteger value)
    {
        Span<byte> bytes = stackalloc byte[ScalarSize];
        WriteCanonical(Mod(value), bytes);

        return builder.AddWire(bytes);
    }


    /// <summary>Adds a constant wire holding the canonical reduction of <paramref name="value"/> mod <c>p</c>.</summary>
    /// <param name="builder">The constraint system being built.</param>
    /// <param name="value">The integer value to reduce and constrain as a constant.</param>
    /// <returns>The new constant wire's index.</returns>
    public static int Const(LigeroConstraintSystemBuilder builder, BigInteger value)
    {
        Span<byte> bytes = stackalloc byte[ScalarSize];
        WriteCanonical(Mod(value), bytes);

        return builder.AddConstant(bytes);
    }


    /// <summary>Adds <paramref name="width"/> constrained bit wires for <paramref name="scalar"/>, most-significant first.</summary>
    /// <param name="builder">The constraint system being built.</param>
    /// <param name="scalar">The scalar to decompose into bits.</param>
    /// <param name="width">The number of bits to emit.</param>
    /// <returns>The bit wires' indices, most-significant first.</returns>
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


    /// <summary>Reduces <paramref name="value"/> into the range <c>[0, p)</c>.</summary>
    /// <param name="value">The integer to reduce.</param>
    /// <returns>The reduced, non-negative value.</returns>
    public static BigInteger Mod(BigInteger value) => ((value % P) + P) % P;


    /// <summary>Reduces <paramref name="value"/> mod <c>p</c> and writes it as canonical big-endian bytes.</summary>
    /// <param name="value">The integer to reduce and encode.</param>
    /// <returns>The canonical big-endian bytes.</returns>
    private static byte[] ToCanonical(BigInteger value)
    {
        byte[] bytes = new byte[ScalarSize];
        WriteCanonical(((value % P) + P) % P, bytes);

        return bytes;
    }


    /// <summary>Writes <paramref name="value"/> as a canonical big-endian, unsigned integer, left-padding with zero bytes.</summary>
    /// <param name="value">The non-negative integer to encode.</param>
    /// <param name="destination">Receives the canonical big-endian bytes.</param>
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


    /// <summary>Computes the two-to-one Merkle compression <c>Blake3(left ‖ right)</c>.</summary>
    /// <param name="left">The left digest.</param>
    /// <param name="right">The right digest.</param>
    /// <param name="output">Receives the combined digest.</param>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Lumoin.Veridical.Hashing.Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>A deterministic Fp256 randomness source: each draw hashes an incrementing counter under the fixed seed, so a benchmark run is reproducible.</summary>
    private sealed class DeterministicFp256Random
    {
        /// <summary>The fixed seed bytes each draw's counter is hashed alongside.</summary>
        private byte[] Seed { get; }

        /// <summary>The number of draws made so far; incremented and absorbed into the hash on every draw.</summary>
        private int counter;

        /// <summary>Creates a source seeded with a copy of <paramref name="seed"/>.</summary>
        /// <param name="seed">The seed bytes to copy.</param>
        public DeterministicFp256Random(ReadOnlySpan<byte> seed) => this.Seed = seed.ToArray();

        /// <summary>Returns this source's <see cref="ScalarRandomDelegate"/>.</summary>
        /// <returns>The random-scalar delegate bound to this instance.</returns>
        public ScalarRandomDelegate AsDelegate() => Fill;

        /// <summary>Computes the next draw: <c>Blake3(seed ‖ counter)</c> reduced mod <c>p</c>, written as a canonical scalar.</summary>
        /// <param name="destination">Receives the canonical scalar.</param>
        /// <param name="curve">Unused; accepted for delegate-signature compatibility.</param>
        /// <param name="inboundTag">Returned unchanged.</param>
        /// <returns><paramref name="inboundTag"/>, unchanged.</returns>
        private Tag Fill(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
        {
            Span<byte> input = stackalloc byte[Seed.Length + sizeof(int)];
            Seed.CopyTo(input);
            BinaryPrimitives.WriteInt32BigEndian(input[Seed.Length..], counter);
            counter++;

            Span<byte> wide = stackalloc byte[64];
            Lumoin.Veridical.Hashing.Blake3.Hash(input, wide);
            WriteCanonical(new BigInteger(wide, isUnsigned: true, isBigEndian: true) % P, destination);

            return inboundTag;
        }
    }
}
