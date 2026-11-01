using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;

namespace Lumoin.Veridical.Tests.TestInfrastructure;

/// <summary>
/// A batch scalar kernel under test: concatenated left operands, concatenated right operands,
/// the concatenated results, and the element count.
/// </summary>
/// <param name="left">The concatenated left operands.</param>
/// <param name="right">The concatenated right operands.</param>
/// <param name="result">The concatenated results.</param>
/// <param name="count">The number of elements in each concatenation.</param>
internal delegate void BatchScalarCoreDelegate(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> result, int count);


/// <summary>
/// A unary scalar kernel under test.
/// </summary>
/// <param name="a">The operand.</param>
/// <param name="result">The result.</param>
internal delegate void UnaryScalarCoreDelegate(ReadOnlySpan<byte> a, Span<byte> result);


/// <summary>
/// A binary reference operation over single scalars.
/// </summary>
/// <param name="a">The left operand.</param>
/// <param name="b">The right operand.</param>
/// <param name="result">The result.</param>
/// <param name="curve">The curve whose scalar field the operation works in.</param>
internal delegate void BinaryScalarReferenceDelegate(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve);


/// <summary>
/// A unary reference operation over single scalars.
/// </summary>
/// <param name="a">The operand.</param>
/// <param name="result">The result.</param>
/// <param name="curve">The curve whose scalar field the operation works in.</param>
internal delegate void UnaryScalarReferenceDelegate(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve);


/// <summary>
/// Seeded differential sweeps that compare a scalar kernel with its BigInteger reference.
/// Each sweep first runs a boundary pass that places every canonical and raw boundary value
/// of the field in every batch position, then a pass of uniformly random operands drawn from
/// a <see cref="SeededByteStream"/>. Raw operands are reduced through the reference reduce
/// delegate before both sides see them, and a mismatch names the seed, the pass and the
/// iteration so the exact inputs regenerate.
/// </summary>
internal static class WasmScalarAgreementSweep
{
    /// <summary>
    /// Compares a batch kernel with a per-element reference.
    /// </summary>
    /// <param name="operation">The operation name used in failure messages.</param>
    /// <param name="seed">The seed of the random operand stream.</param>
    /// <param name="iterations">The number of random batches.</param>
    /// <param name="batchCount">The number of elements per batch.</param>
    /// <param name="fieldOrder">The scalar field order the boundary values are computed against.</param>
    /// <param name="curve">The curve whose scalar field is under test.</param>
    /// <param name="reduce">The reference reduce delegate.</param>
    /// <param name="core">The kernel under test.</param>
    /// <param name="reference">The per-element reference.</param>
    public static void RunBatch(
        string operation,
        ulong seed,
        long iterations,
        int batchCount,
        BigInteger fieldOrder,
        CurveParameterSet curve,
        ScalarReduceDelegate reduce,
        BatchScalarCoreDelegate core,
        BinaryScalarReferenceDelegate reference)
    {
        int size = Scalar.SizeBytes;
        int total = batchCount * size;
        IReadOnlyList<byte[]> boundaries = BoundaryCorpus.AllValues(fieldOrder);
        SeededByteStream stream = new(seed);
        Span<byte> leftRaw = stackalloc byte[total];
        Span<byte> rightRaw = stackalloc byte[total];

        for(int position = 0; position < batchCount; position++)
        {
            for(int leftIndex = 0; leftIndex < boundaries.Count; leftIndex++)
            {
                for(int rightIndex = 0; rightIndex < boundaries.Count; rightIndex++)
                {
                    stream.Fill(leftRaw);
                    stream.Fill(rightRaw);
                    boundaries[leftIndex].CopyTo(leftRaw.Slice(position * size, size));
                    boundaries[rightIndex].CopyTo(rightRaw.Slice(position * size, size));
                    string where = string.Create(
                        CultureInfo.InvariantCulture,
                        $"boundary pass, position {position}, left value {leftIndex}, right value {rightIndex}");
                    CheckBatch(operation, seed, where, batchCount, curve, reduce, core, reference, leftRaw, rightRaw);
                }
            }
        }

        for(long iteration = 0; iteration < iterations; iteration++)
        {
            stream.Fill(leftRaw);
            stream.Fill(rightRaw);
            string where = string.Create(CultureInfo.InvariantCulture, $"random pass, iteration {iteration}");
            CheckBatch(operation, seed, where, batchCount, curve, reduce, core, reference, leftRaw, rightRaw);
        }
    }


    /// <summary>
    /// Compares a unary kernel with its reference.
    /// </summary>
    /// <param name="operation">The operation name used in failure messages.</param>
    /// <param name="seed">The seed of the random operand stream.</param>
    /// <param name="iterations">The number of random operands.</param>
    /// <param name="fieldOrder">The scalar field order the boundary values are computed against.</param>
    /// <param name="curve">The curve whose scalar field is under test.</param>
    /// <param name="reduce">The reference reduce delegate.</param>
    /// <param name="core">The kernel under test.</param>
    /// <param name="reference">The reference.</param>
    public static void RunUnary(
        string operation,
        ulong seed,
        long iterations,
        BigInteger fieldOrder,
        CurveParameterSet curve,
        ScalarReduceDelegate reduce,
        UnaryScalarCoreDelegate core,
        UnaryScalarReferenceDelegate reference)
    {
        int size = Scalar.SizeBytes;
        IReadOnlyList<byte[]> boundaries = BoundaryCorpus.AllValues(fieldOrder);
        SeededByteStream stream = new(seed);
        Span<byte> raw = stackalloc byte[size];

        for(int index = 0; index < boundaries.Count; index++)
        {
            boundaries[index].CopyTo(raw);
            string where = string.Create(CultureInfo.InvariantCulture, $"boundary pass, value {index}");
            CheckUnary(operation, seed, where, curve, reduce, core, reference, raw);
        }

        for(long iteration = 0; iteration < iterations; iteration++)
        {
            stream.Fill(raw);
            string where = string.Create(CultureInfo.InvariantCulture, $"random pass, iteration {iteration}");
            CheckUnary(operation, seed, where, curve, reduce, core, reference, raw);
        }
    }


    /// <summary>Reduces the raw operands, runs the batch kernel and the reference, and fails on a difference.</summary>
    private static void CheckBatch(
        string operation,
        ulong seed,
        string where,
        int batchCount,
        CurveParameterSet curve,
        ScalarReduceDelegate reduce,
        BatchScalarCoreDelegate core,
        BinaryScalarReferenceDelegate reference,
        ReadOnlySpan<byte> leftRaw,
        ReadOnlySpan<byte> rightRaw)
    {
        int size = Scalar.SizeBytes;
        int total = batchCount * size;
        Span<byte> left = stackalloc byte[total];
        Span<byte> right = stackalloc byte[total];
        Span<byte> actual = stackalloc byte[total];
        Span<byte> expected = stackalloc byte[total];

        for(int i = 0; i < batchCount; i++)
        {
            int offset = i * size;
            reduce(leftRaw.Slice(offset, size), left.Slice(offset, size), curve);
            reduce(rightRaw.Slice(offset, size), right.Slice(offset, size), curve);
        }

        core(left, right, actual, batchCount);

        for(int i = 0; i < batchCount; i++)
        {
            int offset = i * size;
            reference(left.Slice(offset, size), right.Slice(offset, size), expected.Slice(offset, size), curve);
        }

        if(!actual.SequenceEqual(expected))
        {
            Assert.Fail(string.Create(
                CultureInfo.InvariantCulture,
                $"{operation} disagreed with the BigInteger reference at {where} (seed 0x{seed:X16})."));
        }
    }


    /// <summary>Reduces the raw operand, runs the unary kernel and the reference, and fails on a difference.</summary>
    private static void CheckUnary(
        string operation,
        ulong seed,
        string where,
        CurveParameterSet curve,
        ScalarReduceDelegate reduce,
        UnaryScalarCoreDelegate core,
        UnaryScalarReferenceDelegate reference,
        ReadOnlySpan<byte> raw)
    {
        int size = Scalar.SizeBytes;
        Span<byte> operand = stackalloc byte[size];
        Span<byte> actual = stackalloc byte[size];
        Span<byte> expected = stackalloc byte[size];

        reduce(raw, operand, curve);
        core(operand, actual);
        reference(operand, expected, curve);

        if(!actual.SequenceEqual(expected))
        {
            Assert.Fail(string.Create(
                CultureInfo.InvariantCulture,
                $"{operation} disagreed with the BigInteger reference at {where} (seed 0x{seed:X16})."));
        }
    }
}
