using Lumoin.Base;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The gates for the FIPS 204 Reed–Solomon row-encoding engines behind the sextic ML-DSA ZK
/// profile: the auxiliary-prime convolver against a naive modular convolution, the scalar engine
/// against direct polynomial evaluation, the sextic row encoder byte-for-byte against the
/// field-generic barycentric reference path (the encoder doctrine's independent oracle), and the
/// construction guards.
/// </summary>
[TestClass]
internal sealed class Fp24SexticReedSolomonTests
{
    /// <summary>The canonical scalar container width.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The FIPS 204 prime modulus.</summary>
    private const uint Modulus = Fp24SexticBackend.Modulus;

    /// <summary>The extension degree.</summary>
    private const int LimbCount = Fp24SexticBackend.LimbCount;

    /// <summary>One coordinate's width in bytes inside the canonical container.</summary>
    private const int LimbBytes = 4;

    /// <summary>The byte offset of coordinate 0 inside the canonical container.</summary>
    private const int LimbZeroOffset = ScalarSize - LimbBytes;

    /// <summary>The deterministic residue generator's multiplier (a fixed odd constant; the values only need to be spread and reproducible).</summary>
    private const ulong FillMultiplier = 6364136223846793005;

    /// <summary>The deterministic residue generator's increment.</summary>
    private const ulong FillIncrement = 1442695040888963407;

    /// <summary>The stale-byte pattern pre-filling extension regions, proving the encoder overwrites every byte including the zero prefix.</summary>
    private const byte StalePattern = 0xA5;

    /// <summary>One above the convolver's input-length bound (2^17), the smallest rejected length.</summary>
    private const int BeyondMaximumInputLength = (1 << 17) + 1;

    /// <summary>The pool every gate rents from.</summary>
    private static BaseMemoryPool Pool { get; } = BaseMemoryPool.Shared;


    /// <summary>
    /// Pins the auxiliary-prime convolver against a naive modular convolution over shapes whose padded
    /// transform covers the full acyclic length, so every output index is exact.
    /// </summary>
    [TestMethod]
    public void TheConvolverMatchesTheNaiveModularConvolution()
    {
        //Each shape's padding (next power of two at or above m) is at least m + n − 1, so the cyclic
        //transform equals the acyclic convolution at every retained index.
        (int InputLength, int OutputLength)[] shapes = [(5, 17), (64, 193), (100, 300)];
        ulong state = 1;
        foreach((int inputLength, int outputLength) in shapes)
        {
            using IMemoryOwner<byte> valuesOwner = Pool.Rent((inputLength + (2 * outputLength)) * sizeof(uint));
            Span<uint> lanes = MemoryMarshal.Cast<byte, uint>(valuesOwner.Memory.Span)[..(inputLength + (2 * outputLength))];
            Span<uint> values = lanes[..inputLength];
            Span<uint> kernel = lanes.Slice(inputLength, outputLength);
            Span<uint> outputs = lanes.Slice(inputLength + outputLength, outputLength);
            FillResidues(values, ref state);
            FillResidues(kernel, ref state);

            using var convolver = new Fp24CrtConvolution(inputLength, outputLength, kernel, Pool);
            convolver.Convolve(values, outputs);

            for(int k = 0; k < outputLength; k++)
            {
                ulong expected = 0;
                for(int i = 0; i <= Math.Min(k, inputLength - 1); i++)
                {
                    expected = (expected + ((ulong)values[i] * kernel[k - i])) % Modulus;
                }

                Assert.AreEqual((uint)expected, outputs[k], $"Convolution output {k} must match the naive sum at shape ({inputLength}, {outputLength}).");
            }
        }
    }


    /// <summary>
    /// Pins the scalar engine against direct polynomial evaluation: the extension of a known
    /// polynomial's evaluations at <c>0..n−1</c> must equal the polynomial's values at <c>n..m−1</c>.
    /// </summary>
    [TestMethod]
    public void TheScalarEngineExtendsPolynomialEvaluations()
    {
        (int Dimension, int BlockLength)[] shapes = [(1, 9), (2, 11), (7, 23), (33, 101)];
        ulong state = 2;
        foreach((int dimension, int blockLength) in shapes)
        {
            using IMemoryOwner<byte> lanesOwner = Pool.Rent((dimension + blockLength) * sizeof(uint));
            Span<uint> lanes = MemoryMarshal.Cast<byte, uint>(lanesOwner.Memory.Span)[..(dimension + blockLength)];
            Span<uint> coefficients = lanes[..dimension];
            Span<uint> evaluations = lanes.Slice(dimension, blockLength);
            FillResidues(coefficients, ref state);

            for(int point = 0; point < dimension; point++)
            {
                evaluations[point] = EvaluatePolynomial(coefficients, (uint)point);
            }

            using var engine = new Fp24ReedSolomon(dimension, blockLength, Pool);
            engine.Interpolate(evaluations);

            for(int point = 0; point < blockLength; point++)
            {
                Assert.AreEqual(EvaluatePolynomial(coefficients, (uint)point), evaluations[point], $"The extension at point {point} must equal the polynomial's value at shape ({dimension}, {blockLength}).");
            }
        }
    }


    /// <summary>
    /// Pins the sextic row encoder byte-for-byte against the field-generic barycentric consecutive-integer
    /// path driven by the sextic backend delegates — the mathematically identical map computed by an
    /// independent implementation — including full overwrite of a stale extension region.
    /// </summary>
    [TestMethod]
    public void TheSexticRowEncoderMatchesTheBarycentricReferencePath()
    {
        (int Dimension, int BlockLength)[] shapes = [(1, 4), (6, 24), (40, 167)];
        ScalarAddDelegate add = Fp24SexticBackend.GetAdd();
        ScalarSubtractDelegate subtract = Fp24SexticBackend.GetSubtract();
        ScalarMultiplyDelegate multiply = Fp24SexticBackend.GetMultiply();
        ScalarInvertDelegate invert = Fp24SexticBackend.GetInvert();
        ulong state = 3;
        foreach((int dimension, int blockLength) in shapes)
        {
            using IMemoryOwner<byte> rowOwner = Pool.Rent(blockLength * ScalarSize);
            using IMemoryOwner<byte> oracleOwner = Pool.Rent(blockLength * ScalarSize);
            Span<byte> row = rowOwner.Memory.Span[..(blockLength * ScalarSize)];
            Span<byte> oracle = oracleOwner.Memory.Span[..(blockLength * ScalarSize)];

            //The message prefix carries fresh sextic elements; the extension region carries a stale
            //pattern the engine must fully overwrite, zero prefix included.
            row.Fill(StalePattern);
            for(int element = 0; element < dimension; element++)
            {
                FillSexticElement(row.Slice(element * ScalarSize, ScalarSize), ref state);
            }

            oracle.Clear();
            LigeroReedSolomonEncoder.Encode(
                row[..(dimension * ScalarSize)], dimension, oracle, blockLength, LigeroNodeDomain.ConsecutiveIntegers,
                add, subtract, multiply, invert, CurveParameterSet.None, Pool);

            using var encoder = new Fp24SexticReedSolomon(dimension, blockLength, Pool);
            encoder.Interpolate(row);

            Assert.AreSequenceEqual(oracle.ToArray(), row.ToArray(), $"The sextic engine must equal the barycentric oracle byte-for-byte at shape ({dimension}, {blockLength}).");
        }
    }


    /// <summary>Pins the construction guards: the auxiliary basis's input-length bound, the kernel-length match, and the distinct-evaluation-point modulus bound.</summary>
    [TestMethod]
    public void TheConstructionGuardsRejectOutOfRangeShapes()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => new Fp24CrtConvolution(BeyondMaximumInputLength, BeyondMaximumInputLength, [], Pool),
            "An input length beyond the auxiliary basis bound must be rejected.");

        //In-range dimensions with a short kernel reach the kernel-length guard itself; the
        //out-of-range shape above throws before it.
        const int GuardDimension = 2;
        const int GuardBlockLength = 8;
        using IMemoryOwner<byte> kernelOwner = Pool.Rent((GuardBlockLength - 1) * sizeof(uint));
        Memory<byte> shortKernel = kernelOwner.Memory[..((GuardBlockLength - 1) * sizeof(uint))];
        Assert.ThrowsExactly<ArgumentException>(
            () => new Fp24CrtConvolution(GuardDimension, GuardBlockLength, MemoryMarshal.Cast<byte, uint>(shortKernel.Span), Pool),
            "A kernel not matching the output length must be rejected.");

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => new Fp24ReedSolomon(1, (int)Modulus, Pool),
            "A block length reaching the modulus has repeated evaluation points and must be rejected.");
    }


    /// <summary>Pins the span-length and disposal guards on the sextic encoder's interpolate surface.</summary>
    [TestMethod]
    public void TheInterpolateGuardsRejectMismatchedSpansAndDisposedEngines()
    {
        const int Dimension = 2;
        const int BlockLength = 8;
        var encoder = new Fp24SexticReedSolomon(Dimension, BlockLength, Pool);
        using IMemoryOwner<byte> shortOwner = Pool.Rent((BlockLength - 1) * ScalarSize);
        try
        {
            Assert.ThrowsExactly<ArgumentException>(
                () => encoder.Interpolate(shortOwner.Memory.Span[..((BlockLength - 1) * ScalarSize)]),
                "A short evaluation buffer must be rejected.");
        }
        finally
        {
            encoder.Dispose();
        }

        using IMemoryOwner<byte> rowOwner = Pool.Rent(BlockLength * ScalarSize);
        Assert.ThrowsExactly<ObjectDisposedException>(
            () => encoder.Interpolate(rowOwner.Memory.Span[..(BlockLength * ScalarSize)]),
            "A disposed engine must reject interpolation.");
    }


    /// <summary>Fills the lanes with deterministic residues below the modulus.</summary>
    /// <param name="destination">The residue lanes to fill.</param>
    /// <param name="state">The generator state, advanced per residue.</param>
    private static void FillResidues(Span<uint> destination, ref ulong state)
    {
        for(int i = 0; i < destination.Length; i++)
        {
            state = (state * FillMultiplier) + FillIncrement;
            destination[i] = (uint)(state % Modulus);
        }
    }


    /// <summary>Writes one canonical sextic element with deterministic coordinates below the modulus.</summary>
    /// <param name="container">The 32-byte canonical container to fill.</param>
    /// <param name="state">The generator state, advanced per coordinate.</param>
    private static void FillSexticElement(Span<byte> container, ref ulong state)
    {
        container.Clear();
        for(int limb = 0; limb < LimbCount; limb++)
        {
            state = (state * FillMultiplier) + FillIncrement;
            BinaryPrimitives.WriteUInt32BigEndian(container.Slice(LimbZeroOffset - (limb * LimbBytes), LimbBytes), (uint)(state % Modulus));
        }
    }


    /// <summary>Evaluates the coefficient polynomial at the given point by Horner's rule modulo the FIPS 204 prime.</summary>
    /// <param name="coefficients">The coefficients, constant term first.</param>
    /// <param name="point">The evaluation point.</param>
    /// <returns>The value residue.</returns>
    private static uint EvaluatePolynomial(ReadOnlySpan<uint> coefficients, uint point)
    {
        ulong value = 0;
        for(int i = coefficients.Length; i-- > 0;)
        {
            value = ((value * point) + coefficients[i]) % Modulus;
        }

        return (uint)value;
    }
}
