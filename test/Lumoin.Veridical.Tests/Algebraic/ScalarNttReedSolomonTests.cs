using CsCheck;
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
/// The conformance gates for <see cref="ScalarNttReedSolomon"/>: the codewords
/// pinned to the externally computed anchor, the systematic-prefix contract,
/// boundary-seeded round trips against direct Horner evaluation as an
/// independent oracle, and a deterministic operation-trace gate pinning that
/// the interpolation's field-operation sequence depends only on the public
/// shape, never on the witness values. Both wired curves run through every
/// gate.
/// </summary>
[TestClass]
internal sealed class ScalarNttReedSolomonTests
{
    private const int ScalarSize = Scalar.SizeBytes;

    private const string AnchorRelativePath = "TestMaterial/ScalarNtt/scalar-ntt-anchor-output.txt";

    //A fill salt distinct from the streams other algebraic tests draw.
    private const int MessageFillSalt = 4201;

    private const long PropertyIterationCount = 40;

    //The property-test shape: small enough to keep the CsCheck loop fast while
    //still crossing a multi-stage transform (L = 16).
    private const int PropertyMessageDimension = 5;
    private const int PropertyBlockLength = 16;

    //The anchored shapes: a power-of-two codeword and a non-power-of-two
    //codeword whose transform pads 23 up to L = 32.
    private static (int MessageLength, int CodewordLength)[] AnchorShapes { get; } =
    [
        (5, 16),
        (9, 23),
    ];

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
    public void TheCodewordsMatchTheAnchor()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        foreach((string prefix, CurveParameterSet curve, ScalarAddDelegate add, ScalarSubtractDelegate subtract, ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert, _) in Fields)
        {
            foreach((int messageLength, int codewordLength) in AnchorShapes)
            {
                using IMemoryOwner<byte> coefficientOwner = pool.Rent(messageLength * ScalarSize);
                Span<byte> coefficients = coefficientOwner.Memory.Span[..(messageLength * ScalarSize)];
                for(int i = 0; i < messageLength; i++)
                {
                    //The anchor's fixed coefficients: c_i = i² + 42 + 1000·N + M.
                    WriteCanonicalUInt((uint)((i * i) + 42 + (1000 * messageLength) + codewordLength), coefficients.Slice(i * ScalarSize, ScalarSize));
                }

                using IMemoryOwner<byte> evaluationOwner = pool.Rent(codewordLength * ScalarSize);
                Span<byte> evaluations = evaluationOwner.Memory.Span[..(codewordLength * ScalarSize)];
                evaluations.Clear();
                for(int point = 0; point < messageLength; point++)
                {
                    EvaluatePolynomialAt(coefficients, messageLength, (uint)point, evaluations.Slice(point * ScalarSize, ScalarSize), add, multiply, curve);
                }

                using var engine = new ScalarNttReedSolomon(messageLength, codewordLength, add, subtract, multiply, invert, WriteCanonicalUInt, curve, pool);
                engine.Interpolate(evaluations);

                for(int point = 0; point < codewordLength; point++)
                {
                    byte[] expected = AnchorElement($"{prefix}_cw{messageLength}x{codewordLength}[{point}]");
                    Assert.IsTrue(
                        evaluations.Slice(point * ScalarSize, ScalarSize).SequenceEqual(expected),
                        $"{prefix}_cw{messageLength}x{codewordLength}[{point}] must match the anchor.");
                }
            }
        }
    }


    [TestMethod]
    public void TheEncoderIsSystematic()
    {
        const int MessageLength = 9;
        const int CodewordLength = 23;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Span<byte> expectedPrefix = stackalloc byte[MessageLength * ScalarSize];
        foreach((string prefix, CurveParameterSet curve, ScalarAddDelegate add, ScalarSubtractDelegate subtract, ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert, ScalarReduceDelegate reduce) in Fields)
        {
            using IMemoryOwner<byte> evaluationOwner = pool.Rent(CodewordLength * ScalarSize);
            Span<byte> evaluations = evaluationOwner.Memory.Span[..(CodewordLength * ScalarSize)];
            evaluations.Clear();
            DeterministicScalarFill.FillCanonical(evaluations[..(MessageLength * ScalarSize)], MessageFillSalt, reduce, curve);
            evaluations[..(MessageLength * ScalarSize)].CopyTo(expectedPrefix);

            using var engine = new ScalarNttReedSolomon(MessageLength, CodewordLength, add, subtract, multiply, invert, WriteCanonicalUInt, curve, pool);
            engine.Interpolate(evaluations);

            Assert.IsTrue(
                evaluations[..(MessageLength * ScalarSize)].SequenceEqual(expectedPrefix),
                $"The systematic prefix must be unchanged by the extension for {prefix}.");
        }
    }


    [TestMethod]
    public void InterpolateOfBoundarySeededCoefficientsMatchesDirectEvaluationEverywhere()
    {
        //Round trip plus the systematic property in one identity: for a
        //degree-(< N) polynomial whose coefficients are boundary-seeded, every
        //one of the M interpolated outputs must equal the same polynomial
        //evaluated directly by Horner — an oracle independent of both the
        //transform and the barycentric reference path.
        foreach((string prefix, CurveParameterSet curve, ScalarAddDelegate add, ScalarSubtractDelegate subtract, ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert, ScalarReduceDelegate reduce) in Fields)
        {
            BigInteger order = WellKnownCurves.GetScalarFieldOrder(curve);
            BoundaryCorpusGen.CanonicalDomain(order).Array[PropertyMessageDimension].Sample(rawCoefficients =>
            {
                BaseMemoryPool pool = BaseMemoryPool.Shared;
                using IMemoryOwner<byte> coefficientOwner = pool.Rent(PropertyMessageDimension * ScalarSize);
                Span<byte> coefficients = coefficientOwner.Memory.Span[..(PropertyMessageDimension * ScalarSize)];
                for(int i = 0; i < PropertyMessageDimension; i++)
                {
                    reduce(rawCoefficients[i], coefficients.Slice(i * ScalarSize, ScalarSize), curve);
                }

                using IMemoryOwner<byte> evaluationOwner = pool.Rent(PropertyBlockLength * ScalarSize);
                Span<byte> evaluations = evaluationOwner.Memory.Span[..(PropertyBlockLength * ScalarSize)];
                evaluations.Clear();
                for(int point = 0; point < PropertyMessageDimension; point++)
                {
                    EvaluatePolynomialAt(coefficients, PropertyMessageDimension, (uint)point, evaluations.Slice(point * ScalarSize, ScalarSize), add, multiply, curve);
                }

                using var engine = new ScalarNttReedSolomon(PropertyMessageDimension, PropertyBlockLength, add, subtract, multiply, invert, WriteCanonicalUInt, curve, pool);
                engine.Interpolate(evaluations);

                Span<byte> expected = stackalloc byte[ScalarSize];
                for(int point = 0; point < PropertyBlockLength; point++)
                {
                    EvaluatePolynomialAt(coefficients, PropertyMessageDimension, (uint)point, expected, add, multiply, curve);
                    if(!evaluations.Slice(point * ScalarSize, ScalarSize).SequenceEqual(expected))
                    {
                        return false;
                    }
                }

                return true;
            }, iter: PropertyIterationCount);
        }
    }


    [TestMethod]
    public void TheInterpolationOperationTraceIsWitnessIndependent()
    {
        //A deterministic obliviousness gate with no wall-clock involvement: the
        //sequence of field operations Interpolate issues is recorded through
        //wrapped delegates and must be identical for different witness values,
        //and its totals must equal the closed forms fixed by the public shape
        //alone. The trace sees delegate granularity — operation kind, count and
        //order; indexing is loop-counter-derived by construction and inside a
        //single field operation the backend's own discipline applies.
        const int MessageLength = 9;
        const int CodewordLength = 23;
        const int PaddedLength = 32;
        const int PaddedLengthLog2 = 5;
        const int ButterflyCount = (PaddedLength / 2) * PaddedLengthLog2;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        foreach((string prefix, CurveParameterSet curve, ScalarAddDelegate add, ScalarSubtractDelegate subtract, ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert, ScalarReduceDelegate reduce) in Fields)
        {
            var trace = new List<char>();
            ScalarAddDelegate tracedAdd = (a, b, result, c) =>
            {
                trace.Add('a');
                add(a, b, result, c);
            };
            ScalarSubtractDelegate tracedSubtract = (a, b, result, c) =>
            {
                trace.Add('s');
                subtract(a, b, result, c);
            };
            ScalarMultiplyDelegate tracedMultiply = (a, b, result, c) =>
            {
                trace.Add('m');
                multiply(a, b, result, c);
            };

            using var engine = new ScalarNttReedSolomon(MessageLength, CodewordLength, tracedAdd, tracedSubtract, tracedMultiply, invert, WriteCanonicalUInt, curve, pool);

            char[] firstTrace = RunTracedInterpolation(engine, trace, MessageFillSalt + 1, reduce, curve, pool);
            char[] secondTrace = RunTracedInterpolation(engine, trace, MessageFillSalt + 2, reduce, curve, pool);
            char[] zeroTrace = RunTracedInterpolation(engine, trace, MessageFillSalt, reduce, curve, pool, zeroWitness: true);

            Assert.IsTrue(firstTrace.AsSpan().SequenceEqual(secondTrace), $"The operation trace must not depend on the witness values for {prefix}.");
            //The all-zero witness pins that no skip-on-zero shortcut can creep in.
            Assert.IsTrue(firstTrace.AsSpan().SequenceEqual(zeroTrace), $"The operation trace must not depend on zero operands for {prefix}.");

            //Closed forms for the shape: multiplications = blockLength + L + L·log2(L)
            //(weighted prefix + pointwise product + both transforms' butterflies plus
            //the tail products), additions = subtractions = L·log2(L).
            int multiplications = 0;
            int additions = 0;
            int subtractions = 0;
            foreach(char operation in firstTrace)
            {
                if(operation is 'm')
                {
                    multiplications++;
                }
                else if(operation is 'a')
                {
                    additions++;
                }
                else
                {
                    subtractions++;
                }
            }

            Assert.AreEqual(CodewordLength + PaddedLength + (2 * ButterflyCount), multiplications, $"The multiplication count must be fixed by the shape for {prefix}.");
            Assert.AreEqual(2 * ButterflyCount, additions, $"The addition count must be fixed by the shape for {prefix}.");
            Assert.AreEqual(2 * ButterflyCount, subtractions, $"The subtraction count must be fixed by the shape for {prefix}.");
        }
    }


    [TestMethod]
    public void ADisposedEngineRejectsInterpolationAndDisposeIsIdempotent()
    {
        const int MessageLength = 5;
        const int CodewordLength = 16;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        foreach((string prefix, CurveParameterSet curve, ScalarAddDelegate add, ScalarSubtractDelegate subtract, ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert, _) in Fields)
        {
            var engine = new ScalarNttReedSolomon(MessageLength, CodewordLength, add, subtract, multiply, invert, WriteCanonicalUInt, curve, pool);
            engine.Dispose();
            engine.Dispose();

            using IMemoryOwner<byte> evaluationOwner = pool.Rent(CodewordLength * ScalarSize);
            Memory<byte> evaluations = evaluationOwner.Memory[..(CodewordLength * ScalarSize)];
            Assert.ThrowsExactly<ObjectDisposedException>(
                () => engine.Interpolate(evaluations.Span),
                $"A disposed engine must reject interpolation for {prefix}.");
        }
    }


    private static char[] RunTracedInterpolation(
        ScalarNttReedSolomon engine,
        List<char> trace,
        int salt,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        bool zeroWitness = false)
    {
        using IMemoryOwner<byte> evaluationOwner = pool.Rent(engine.BlockLength * ScalarSize);
        Span<byte> evaluations = evaluationOwner.Memory.Span[..(engine.BlockLength * ScalarSize)];
        evaluations.Clear();
        if(!zeroWitness)
        {
            DeterministicScalarFill.FillCanonical(evaluations[..(engine.Dimension * ScalarSize)], salt, reduce, curve);
        }

        trace.Clear();
        engine.Interpolate(evaluations);
        char[] snapshot = [.. trace];
        evaluations.Clear();

        return snapshot;
    }


    private static void EvaluatePolynomialAt(
        ReadOnlySpan<byte> coefficients,
        int coefficientCount,
        uint point,
        Span<byte> destination,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        Span<byte> x = stackalloc byte[ScalarSize];
        WriteCanonicalUInt(point, x);
        destination.Clear();
        for(int i = coefficientCount - 1; i >= 0; i--)
        {
            multiply(destination, x, destination, curve);
            add(destination, coefficients.Slice(i * ScalarSize, ScalarSize), destination, curve);
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
