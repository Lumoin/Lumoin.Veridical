using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.ConstraintSystems.Interop;
using Lumoin.Veridical.Core.ConstraintSystems.Interop.Circom;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Numerics;
using System.Threading;

namespace Lumoin.Veridical.Tests.ConstraintSystems.Interop.Circom;

/// <summary>
/// Pins the <see cref="CircomR1csReader"/> contract that linear-combination terms
/// may arrive in <em>any</em> wire order within a constraint — circom emits them
/// in construction order, not ascending. This was a latent reader bug (it required
/// strictly-ascending order) surfaced by Batch V.4's owned Poseidon fixture; these
/// tests pin the behaviour directly rather than relying on a fixture's term
/// ordering happening to be non-trivial.
/// </summary>
/// <remarks>
/// The committed multiplier2 / poseidon fixtures cannot target this directly:
/// multiplier2's linear combinations are single-term (no order to vary), and the
/// poseidon fixture's ordering is whatever circom happened to emit. So this gate
/// uses a minimal in-test `.r1cs` encoder (<see cref="EncodeR1cs"/>) to feed the
/// SAME constraint system in different term orders.
/// </remarks>
[TestClass]
internal sealed class CircomR1csReaderOrderingTests
{
    private static readonly BigInteger Bls12Curve381Prime = Bls12Curve381BigIntegerScalarReference.FieldOrder;
    private static ScalarAddDelegate Add { get; } = Bls12Curve381BigIntegerScalarReference.GetAdd();
    private static ScalarMultiplyDelegate Multiply { get; } = Bls12Curve381BigIntegerScalarReference.GetMultiply();


    [TestMethod]
    public void ReaderAcceptsNonAscendingWireOrderWithinConstraint()
    {
        //One constraint, (z[1] + z[2]) · z[0] = z[3], with A's two terms emitted in
        //DESCENDING wire order (wire 2 before wire 1) — the shape the reader used to
        //reject. z = (1, 2, 3, 5) satisfies it: (2 + 3)·1 = 5.
        byte[] bytes = EncodeR1cs(
            Bls12Curve381Prime,
            wireCount: 4,
            constraints:
            [
                new ConstraintTriple(
                    A: [(2, BigInteger.One), (1, BigInteger.One)],
                    B: [(0, BigInteger.One)],
                    C: [(3, BigInteger.One)]),
            ]);

        using RawR1csInstance instance = ParseR1cs(bytes);

        //The reader sorts, so the parsed A triples are in ascending (row, column)
        //order regardless of the emitted order.
        Assert.AreEqual(2, instance.A.NonzeroCount);
        Assert.AreEqual((0, 1), instance.A.GetTriplePosition(0), "A[0] should sort to (constraint 0, wire 1)");
        Assert.AreEqual((0, 2), instance.A.GetTriplePosition(1), "A[1] should sort to (constraint 0, wire 2)");

        using RawR1csWitness witness = BuildWitness(2, 3, 5);
        using R1csSatisfaction satisfaction = instance.CheckSatisfiedBy(witness, Add, Multiply, SensitiveMemoryPool<byte>.Shared);
        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(satisfaction);
    }


    [TestMethod]
    public void ReaderIsInvariantToWireOrderWithinConstraint()
    {
        //The same constraint system encoded twice — A's terms ascending in one,
        //descending in the other. The reader must produce byte-identical matrices.
        byte[] ascending = EncodeR1cs(
            Bls12Curve381Prime,
            wireCount: 4,
            constraints:
            [
                new ConstraintTriple(
                    A: [(1, new BigInteger(7)), (2, new BigInteger(9))],
                    B: [(0, BigInteger.One)],
                    C: [(3, BigInteger.One)]),
            ]);

        byte[] descending = EncodeR1cs(
            Bls12Curve381Prime,
            wireCount: 4,
            constraints:
            [
                new ConstraintTriple(
                    A: [(2, new BigInteger(9)), (1, new BigInteger(7))],
                    B: [(0, BigInteger.One)],
                    C: [(3, BigInteger.One)]),
            ]);

        using RawR1csInstance fromAscending = ParseR1cs(ascending);
        using RawR1csInstance fromDescending = ParseR1cs(descending);

        AssertMatricesEqual(fromAscending.A, fromDescending.A, "A");
        AssertMatricesEqual(fromAscending.B, fromDescending.B, "B");
        AssertMatricesEqual(fromAscending.C, fromDescending.C, "C");
    }


    private static void AssertMatricesEqual(R1csMatrix expected, R1csMatrix actual, string name)
    {
        Assert.AreEqual(expected.NonzeroCount, actual.NonzeroCount, $"{name}.NonzeroCount");
        Assert.IsTrue(expected.GetRowIndicesBytes().SequenceEqual(actual.GetRowIndicesBytes()), $"{name} row indices differ");
        Assert.IsTrue(expected.GetColumnIndicesBytes().SequenceEqual(actual.GetColumnIndicesBytes()), $"{name} column indices differ");
        Assert.IsTrue(expected.GetValuesBytes().SequenceEqual(actual.GetValuesBytes()), $"{name} values differ");
    }


    private static RawR1csInstance ParseR1cs(byte[] bytes)
    {
        var stream = new MemoryStream(bytes, writable: false);
        PipeReader pipe = PipeReader.Create(stream);
        return CircomR1csReader.Reader(
            pipe,
            WellKnownR1csFormatLabel.CircomBinary,
            CurveParameterSet.Bls12Curve381,
            SensitiveMemoryPool<byte>.Shared,
            CancellationToken.None);
    }


    private static RawR1csWitness BuildWitness(int z1, int z2, int z3)
    {
        int scalarSize = Scalar.SizeBytes;
        Span<byte> witness = stackalloc byte[3 * scalarSize];
        WriteCanonical(new BigInteger(z1), witness[..scalarSize]);
        WriteCanonical(new BigInteger(z2), witness.Slice(scalarSize, scalarSize));
        WriteCanonical(new BigInteger(z3), witness.Slice(2 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witness, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
    }


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Value did not fit in the canonical span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }


    private readonly record struct ConstraintTriple(
        IReadOnlyList<(int Wire, BigInteger Coefficient)> A,
        IReadOnlyList<(int Wire, BigInteger Coefficient)> B,
        IReadOnlyList<(int Wire, BigInteger Coefficient)> C);


    /// <summary>
    /// Minimal iden3 <c>.r1cs</c> writer for tests: file header + section 1
    /// (header) + section 2 (constraints), terms emitted in exactly the order
    /// supplied (so callers can vary intra-constraint wire order). Field size is
    /// fixed at 32 bytes, matching the wired curves.
    /// </summary>
    private static byte[] EncodeR1cs(BigInteger prime, int wireCount, IReadOnlyList<ConstraintTriple> constraints)
    {
        const int FieldSize = 32;
        var file = new List<byte>();

        //File header: magic "r1cs", version 1, section count 2.
        file.AddRange("r1cs"u8.ToArray());
        AddUInt32(file, 1);
        AddUInt32(file, 2);

        //Section 1 (header), 64-byte payload.
        AddUInt32(file, 1);
        AddUInt64(file, 4 + FieldSize + 4 + 4 + 4 + 4 + 8 + 4);
        AddUInt32(file, FieldSize);
        AddFieldLittleEndian(file, prime, FieldSize);
        AddUInt32(file, (uint)wireCount);
        AddUInt32(file, 1);                       //nPubOut (one output wire; convention-irrelevant to the reader)
        AddUInt32(file, 0);                       //nPubIn
        AddUInt32(file, (uint)(wireCount - 2));   //nPrvIn (arbitrary; not load-bearing here)
        AddUInt64(file, (ulong)wireCount);        //nLabels
        AddUInt32(file, (uint)constraints.Count); //nConstraints

        //Section 2 (constraints): A, B, C per constraint, each nTerms then (wire, coef_LE).
        var body = new List<byte>();
        foreach(ConstraintTriple constraint in constraints)
        {
            AppendLinearCombination(body, constraint.A, FieldSize);
            AppendLinearCombination(body, constraint.B, FieldSize);
            AppendLinearCombination(body, constraint.C, FieldSize);
        }

        AddUInt32(file, 2);
        AddUInt64(file, (ulong)body.Count);
        file.AddRange(body);

        return [.. file];
    }


    private static void AppendLinearCombination(List<byte> destination, IReadOnlyList<(int Wire, BigInteger Coefficient)> terms, int fieldSize)
    {
        AddUInt32(destination, (uint)terms.Count);
        foreach((int wire, BigInteger coefficient) in terms)
        {
            AddUInt32(destination, (uint)wire);
            AddFieldLittleEndian(destination, coefficient, fieldSize);
        }
    }


    private static void AddUInt32(List<byte> destination, uint value)
    {
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(buffer, value);
        destination.AddRange(buffer);
    }


    private static void AddUInt64(List<byte> destination, ulong value)
    {
        Span<byte> buffer = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(buffer, value);
        destination.AddRange(buffer);
    }


    private static void AddFieldLittleEndian(List<byte> destination, BigInteger value, int fieldSize)
    {
        Span<byte> buffer = stackalloc byte[fieldSize];
        buffer.Clear();
        if(!value.TryWriteBytes(buffer, out _, isUnsigned: true, isBigEndian: false))
        {
            throw new InvalidOperationException($"Coefficient does not fit in {fieldSize} little-endian bytes.");
        }

        destination.AddRange(buffer);
    }
}
