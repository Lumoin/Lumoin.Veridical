using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;
using Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;
using System;
using System.Globalization;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The evaluation-mode semantic gates for the ported mdoc revocation statements, following
/// google/longfellow-zk <c>circuits/tests/mdoc/mdoc_revocation_test.cc</c>: the reference span
/// tuple satisfies the span statement under a panicking evaluation backend, every violated span
/// premise — a bound-touching or out-of-span identifier, a tampered epoch, a swapped authority
/// key, a flipped digest bit — is rejected, and the small-list statement accepts exactly the
/// identifiers off the list.
/// </summary>
[TestClass]
internal sealed class LongfellowMdocRevocationCircuitTests
{
    /// <summary>The field element width in bytes used for every column entry.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The P-256 scalar bit count driving the advice shape.</summary>
    private const int ScalarBitCount = 256;

    /// <summary>One SHA-256 block's byte width.</summary>
    private const int BytesPerBlock = 64;

    /// <summary>The evaluation list's element count — small, since the eval gate checks semantics, not the pinned 50000-element shape.</summary>
    private const int EvalListLength = 5;

    /// <summary>The evaluation list's first element value; the list holds this and the next consecutive integers.</summary>
    private const int EvalListFirstValue = 1001;

    /// <summary>An identifier value off the evaluation list.</summary>
    private const int EvalUnlistedIdValue = 4242;

    /// <summary>The list position the listed-identifier gates reuse as the identifier.</summary>
    private const int EvalListedIndex = 2;

    /// <summary>The P-256 base field's modulus.</summary>
    private static BigInteger Prime { get; } = P256BaseFieldReference.FieldOrder;

    /// <summary>The curve constants shared by the circuit and the witness generator.</summary>
    private static LongfellowEllipticCurveParameters Curve { get; } = LongfellowEllipticCurveParameters.CreateP256();

    /// <summary>The order-field multiplication delegate.</summary>
    private static ScalarMultiplyDelegate OrderMultiply { get; } = P256ScalarMontgomeryBackend.GetMultiply();

    /// <summary>The order-field subtraction delegate.</summary>
    private static ScalarSubtractDelegate OrderSubtract { get; } = P256ScalarMontgomeryBackend.GetSubtract();

    /// <summary>The order-field inversion delegate.</summary>
    private static ScalarInvertDelegate OrderInvert { get; } = P256ScalarMontgomeryBackend.GetInvert();


    /// <summary>Pins that the reference span tuple's witness satisfies the whole span statement in evaluation; the non-panicking backend makes the latched-flag check the live failure signal.</summary>
    [TestMethod]
    public void TheReferenceSpanSatisfiesTheStatementInEvaluation()
    {
        LongfellowLogicFieldOperations field = NewFp256Bundle();
        var backend = new LongfellowEvaluationLogicBackend(field, panicOnAssertionFailure: false);
        var logic = new LongfellowLogic(backend, field);

        LongfellowMdocRevocationTestVectors.SpanVector vector = LongfellowMdocRevocationTestVectors.ReferenceSpan;
        byte[] id = ParseScalar(vector.Id);

        var generator = NewWitnessGenerator(field);
        Assert.IsTrue(ComputeReferenceWitness(generator, id, ParseScalar(vector.Left), ParseScalar(vector.Right), vector.Epoch), "The reference span tuple must produce a witness.");

        byte[] column = new byte[generator.ElementCount * ScalarSize];
        generator.FillWitness(column);

        var circuit = new LongfellowMdocRevocationSpanCircuit(logic, Curve);
        LongfellowMdocRevocationSpanWitnessWires witness = InternColumn(backend, logic, column);

        circuit.AssertNotOnList(backend.Constant(ParseScalar(vector.PkX)), backend.Constant(ParseScalar(vector.PkY)), backend.Constant(id), witness);

        Assert.IsFalse(backend.AssertionFailed, "The reference span tuple must satisfy every statement assertion.");
    }


    /// <summary>Pins the strict upper comparison: an identifier equal to the span's upper bound is rejected.</summary>
    [TestMethod]
    public void AnIdentifierAtTheUpperBoundIsRejectedInEvaluation()
    {
        LongfellowMdocRevocationTestVectors.SpanVector vector = LongfellowMdocRevocationTestVectors.ReferenceSpan;

        Assert.IsTrue(SpanEvaluationFails(id: ParseScalar(vector.Right)), "An identifier at the upper bound must fail the strict range assertion.");
    }


    /// <summary>Pins the strict lower comparison: an identifier equal to the span's lower bound is rejected.</summary>
    [TestMethod]
    public void AnIdentifierAtTheLowerBoundIsRejectedInEvaluation()
    {
        LongfellowMdocRevocationTestVectors.SpanVector vector = LongfellowMdocRevocationTestVectors.ReferenceSpan;

        Assert.IsTrue(SpanEvaluationFails(id: ParseScalar(vector.Left)), "An identifier at the lower bound must fail the strict range assertion.");
    }


    /// <summary>Pins the range direction: an identifier above the span is rejected.</summary>
    [TestMethod]
    public void AnIdentifierAboveTheSpanIsRejectedInEvaluation()
    {
        LongfellowMdocRevocationTestVectors.SpanVector vector = LongfellowMdocRevocationTestVectors.ReferenceSpan;
        BigInteger aboveSpan = ParseBigInteger(vector.Right) + 1;

        Assert.IsTrue(SpanEvaluationFails(id: Canonical(aboveSpan)), "An identifier above the span must fail the range assertion.");
    }


    /// <summary>Pins the digest binding: a span whose epoch differs from the signed one hashes to a different digest and is rejected.</summary>
    [TestMethod]
    public void ATamperedEpochIsRejectedInEvaluation()
    {
        LongfellowMdocRevocationTestVectors.SpanVector vector = LongfellowMdocRevocationTestVectors.ReferenceSpan;

        Assert.IsTrue(SpanEvaluationFails(id: ParseScalar(vector.Id), epoch: vector.Epoch + 1), "A tampered epoch must break the digest assertion.");
    }


    /// <summary>Pins the signature binding: the statement rejects under a key other than the one that signed the span.</summary>
    [TestMethod]
    public void ASwappedAuthorityKeyIsRejectedInEvaluation()
    {
        LongfellowMdocRevocationTestVectors.SpanVector vector = LongfellowMdocRevocationTestVectors.ReferenceSpan;

        Assert.IsTrue(
            SpanEvaluationFails(id: ParseScalar(vector.Id), circuitPkX: ParseScalar(vector.PkY), circuitPkY: ParseScalar(vector.PkX)),
            "A swapped authority key must break the signature verification.");
    }


    /// <summary>Pins the digest binding: flipping the least significant digest bit in the column breaks both consumers of that bit — the hash-target tie and the bit-to-element recomposition.</summary>
    [TestMethod]
    public void AFlippedDigestBitIsRejectedInEvaluation()
    {
        LongfellowMdocRevocationTestVectors.SpanVector vector = LongfellowMdocRevocationTestVectors.ReferenceSpan;

        Assert.IsTrue(
            SpanEvaluationFails(id: ParseScalar(vector.Id), corruptColumn: column => FlipBitElement(column, EBitsElementOffset())),
            "A flipped digest bit must break the recomposition assertion.");
    }


    /// <summary>Pins that the small-list statement accepts an identifier off the list with the helper's inverse; the non-panicking backend makes the latched-flag check the live failure signal.</summary>
    [TestMethod]
    public void TheListStatementAcceptsAnUnlistedIdentifierInEvaluation()
    {
        LongfellowLogicFieldOperations field = NewFp256Bundle();
        var backend = new LongfellowEvaluationLogicBackend(field, panicOnAssertionFailure: false);
        var logic = new LongfellowLogic(backend, field);

        ReadOnlyMemory<byte>[] list = BuildEvalList();
        byte[] id = Canonical(EvalUnlistedIdValue);
        byte[] inverse = LongfellowMdocRevocationListWitness.ComputeProductInverse(field, id, list);

        var circuit = new LongfellowMdocRevocationListCircuit(logic);
        circuit.AssertNotOnList(InternList(backend, list), backend.Constant(id), backend.Constant(inverse));

        Assert.IsFalse(backend.AssertionFailed, "An unlisted identifier with the computed inverse must satisfy the statement.");
    }


    /// <summary>Pins that the small-list statement rejects a listed identifier, whose product has no inverse (the helper emits the zero non-witness).</summary>
    [TestMethod]
    public void TheListStatementRejectsAListedIdentifierInEvaluation()
    {
        LongfellowLogicFieldOperations field = NewFp256Bundle();
        var backend = new LongfellowEvaluationLogicBackend(field, panicOnAssertionFailure: false);
        var logic = new LongfellowLogic(backend, field);

        ReadOnlyMemory<byte>[] list = BuildEvalList();
        byte[] id = list[EvalListedIndex].ToArray();
        byte[] inverse = LongfellowMdocRevocationListWitness.ComputeProductInverse(field, id, list);

        var circuit = new LongfellowMdocRevocationListCircuit(logic);
        circuit.AssertNotOnList(InternList(backend, list), backend.Constant(id), backend.Constant(inverse));

        Assert.IsTrue(backend.AssertionFailed, "A listed identifier must fail the product assertion.");
    }


    /// <summary>Pins that the small-list statement rejects a wrong claimed inverse for an unlisted identifier.</summary>
    [TestMethod]
    public void TheListStatementRejectsAWrongInverseInEvaluation()
    {
        LongfellowLogicFieldOperations field = NewFp256Bundle();
        var backend = new LongfellowEvaluationLogicBackend(field, panicOnAssertionFailure: false);
        var logic = new LongfellowLogic(backend, field);

        ReadOnlyMemory<byte>[] list = BuildEvalList();
        byte[] id = Canonical(EvalUnlistedIdValue);

        var circuit = new LongfellowMdocRevocationListCircuit(logic);
        circuit.AssertNotOnList(InternList(backend, list), backend.Constant(id), backend.Constant(Canonical(BigInteger.One)));

        Assert.IsTrue(backend.AssertionFailed, "A wrong inverse must fail the product assertion.");
    }


    /// <summary>Pins the helper's listed-identifier behavior: the zero product yields the zero non-witness without consulting the inversion backend.</summary>
    [TestMethod]
    public void TheListHelperReturnsZeroForAListedIdentifier()
    {
        LongfellowLogicFieldOperations field = NewFp256Bundle();
        ReadOnlyMemory<byte>[] list = BuildEvalList();

        byte[] inverse = LongfellowMdocRevocationListWitness.ComputeProductInverse(field, list[EvalListedIndex].Span, list);

        CollectionAssert.AreEqual(new byte[ScalarSize], inverse, "A listed identifier's product inverse must be the zero non-witness.");
    }


    /// <summary>
    /// Runs the span statement under a non-panicking evaluation backend with the reference tuple's
    /// signature data and the given overrides, and reports whether any assertion failed.
    /// </summary>
    /// <param name="id">The identifier to witness and pass to the statement.</param>
    /// <param name="epoch">The span epoch, defaulting to the reference tuple's.</param>
    /// <param name="circuitPkX">The x coordinate handed to the circuit, defaulting to the reference authority key's.</param>
    /// <param name="circuitPkY">The y coordinate handed to the circuit, defaulting to the reference authority key's.</param>
    /// <param name="corruptColumn">An optional column mutation applied before interning.</param>
    /// <returns>Whether the evaluation latched an assertion failure.</returns>
    private static bool SpanEvaluationFails(byte[] id, ulong? epoch = null, byte[]? circuitPkX = null, byte[]? circuitPkY = null, Action<byte[]>? corruptColumn = null)
    {
        LongfellowLogicFieldOperations field = NewFp256Bundle();
        var backend = new LongfellowEvaluationLogicBackend(field, panicOnAssertionFailure: false);
        var logic = new LongfellowLogic(backend, field);

        LongfellowMdocRevocationTestVectors.SpanVector vector = LongfellowMdocRevocationTestVectors.ReferenceSpan;

        var generator = NewWitnessGenerator(field);
        Assert.IsTrue(
            ComputeReferenceWitness(generator, id, ParseScalar(vector.Left), ParseScalar(vector.Right), epoch ?? vector.Epoch),
            "The signature advice must compute for every override (the overrides violate the statement, not the signature).");

        byte[] column = new byte[generator.ElementCount * ScalarSize];
        generator.FillWitness(column);
        corruptColumn?.Invoke(column);

        var circuit = new LongfellowMdocRevocationSpanCircuit(logic, Curve);
        LongfellowMdocRevocationSpanWitnessWires witness = InternColumn(backend, logic, column);

        circuit.AssertNotOnList(
            backend.Constant(circuitPkX ?? ParseScalar(vector.PkX)),
            backend.Constant(circuitPkY ?? ParseScalar(vector.PkY)),
            backend.Constant(id),
            witness);

        return backend.AssertionFailed;
    }


    /// <summary>Computes the reference tuple's witness with the given span parameters.</summary>
    /// <param name="generator">The generator to fill.</param>
    /// <param name="id">The identifier.</param>
    /// <param name="lowerBound">The span's lower bound.</param>
    /// <param name="upperBound">The span's upper bound.</param>
    /// <param name="epoch">The span's epoch.</param>
    /// <returns>Whether the generator produced a complete witness.</returns>
    private static bool ComputeReferenceWitness(LongfellowMdocRevocationSpanWitness generator, byte[] id, byte[] lowerBound, byte[] upperBound, ulong epoch)
    {
        LongfellowMdocRevocationTestVectors.SpanVector vector = LongfellowMdocRevocationTestVectors.ReferenceSpan;

        return generator.ComputeWitness(
            ParseScalar(vector.PkX),
            ParseScalar(vector.PkY),
            ParseScalar(vector.E),
            ParseScalar(vector.R),
            ParseScalar(vector.S),
            id,
            lowerBound,
            upperBound,
            epoch);
    }


    /// <summary>Builds the witness generator over the production Montgomery field backends.</summary>
    /// <param name="field">The base-field bundle.</param>
    /// <returns>The generator.</returns>
    private static LongfellowMdocRevocationSpanWitness NewWitnessGenerator(LongfellowLogicFieldOperations field)
    {
        return new LongfellowMdocRevocationSpanWitness(field, OrderMultiply, OrderSubtract, OrderInvert, CurveParameterSet.P256, Curve);
    }


    /// <summary>The digest-bit region's first element offset inside the generator's column: after the three scalars, the advice, the preimage bits and the identifier bits.</summary>
    /// <returns>The element offset.</returns>
    private static int EBitsElementOffset()
    {
        var probe = new LongfellowEcdsaVerifyWitness(NewFp256Bundle(), OrderMultiply, OrderSubtract, OrderInvert, CurveParameterSet.P256, Curve);

        return 3
            + probe.ElementCount
            + (LongfellowMdocRevocationConstants.SpanBlockCount * BytesPerBlock * LongfellowLogic.BitWidth8)
            + LongfellowLogic.BitWidth256;
    }


    /// <summary>Flips a column element between the zero and one bit encodings.</summary>
    /// <param name="column">The column to mutate.</param>
    /// <param name="elementOffset">The element to flip.</param>
    private static void FlipBitElement(byte[] column, int elementOffset)
    {
        column[(elementOffset * ScalarSize) + ScalarSize - 1] ^= 0x01;
    }


    /// <summary>Builds the deterministic evaluation list: consecutive small canonical values.</summary>
    /// <returns>The list elements.</returns>
    private static ReadOnlyMemory<byte>[] BuildEvalList()
    {
        var list = new ReadOnlyMemory<byte>[EvalListLength];
        for(int i = 0; i < EvalListLength; i++)
        {
            list[i] = Canonical(EvalListFirstValue + i);
        }

        return list;
    }


    /// <summary>Interns the list elements as evaluation constants.</summary>
    /// <param name="backend">The evaluation backend.</param>
    /// <param name="list">The list elements.</param>
    /// <returns>The list wires.</returns>
    private static int[] InternList(LongfellowEvaluationLogicBackend backend, ReadOnlyMemory<byte>[] list)
    {
        var wires = new int[list.Length];
        for(int i = 0; i < list.Length; i++)
        {
            wires[i] = backend.Constant(list[i].Span);
        }

        return wires;
    }


    /// <summary>
    /// Interns the generator's witness column as evaluation wires following the declaration layout:
    /// element regions as interned constants, bit regions decoded back to their integers and
    /// rebuilt as constant bit vectors.
    /// </summary>
    /// <param name="backend">The evaluation backend to intern into.</param>
    /// <param name="logic">The gadget layer producing constant bit vectors.</param>
    /// <param name="column">The filled witness column.</param>
    /// <returns>The wire bundle.</returns>
    private static LongfellowMdocRevocationSpanWitnessWires InternColumn(LongfellowEvaluationLogicBackend backend, LongfellowLogic logic, byte[] column)
    {
        int elementCount = column.Length / ScalarSize;

        int cursor = 0;
        int NextElement()
        {
            int wire = backend.Constant(column.AsSpan(cursor * ScalarSize, ScalarSize));
            cursor++;

            return wire;
        }

        ulong NextValue(int bitCount)
        {
            ulong value = 0;
            for(int i = 0; i < bitCount; i++)
            {
                bool isOne = !LongfellowCompilerFieldOperations.ElementIsZero(column.AsSpan(cursor * ScalarSize, ScalarSize));
                value |= (isOne ? 1UL : 0UL) << i;
                cursor++;
            }

            return value;
        }

        int r = NextElement();
        int s = NextElement();
        int e = NextElement();

        LongfellowEcdsaVerifyWitnessWires signature = InternEcdsaAdvice(NextElement);

        var preimage = new LongfellowBitWire[LongfellowMdocRevocationConstants.SpanBlockCount * BytesPerBlock][];
        for(int i = 0; i < preimage.Length; i++)
        {
            preimage[i] = logic.BitVector(LongfellowLogic.BitWidth8, NextValue(LongfellowLogic.BitWidth8));
        }

        var idBits = new LongfellowBitWire[ScalarBitCount];
        for(int i = 0; i < ScalarBitCount; i++)
        {
            idBits[i] = logic.Bit((int)NextValue(1));
        }

        var eBits = new LongfellowBitWire[ScalarBitCount];
        for(int i = 0; i < ScalarBitCount; i++)
        {
            eBits[i] = logic.Bit((int)NextValue(1));
        }

        var encoder = new LongfellowBitPluckerEncoder(logic.Field, LongfellowMdocRevocationConstants.ShaRevocationPluckerBits);
        var sha = new LongfellowFlatSha256PackedBlockWitness[LongfellowMdocRevocationConstants.SpanBlockCount];
        for(int j = 0; j < sha.Length; j++)
        {
            sha[j] = new LongfellowFlatSha256PackedBlockWitness();
            InternPackedWords(sha[j].ScheduleExtension, encoder.PackedV32ElementCount, NextElement, interleaved: null);
            InternPackedWords(sha[j].RegisterEWitness, encoder.PackedV32ElementCount, NextElement, interleaved: sha[j].RegisterAWitness);
            InternPackedWords(sha[j].FinalState, encoder.PackedV32ElementCount, NextElement, interleaved: null);
        }

        Assert.AreEqual(elementCount, cursor, "The interning walk must cover the whole column exactly.");

        return new LongfellowMdocRevocationSpanWitnessWires(r, s, e, signature, preimage, idBits, eBits, sha);
    }


    /// <summary>Interns one packed-word table in the fill order: each entry receives its packed elements consecutively; an interleaved companion table alternates entries with the primary one.</summary>
    /// <param name="table">The primary table.</param>
    /// <param name="elementsPerWord">The packed element count per word.</param>
    /// <param name="nextElement">The column walker.</param>
    /// <param name="interleaved">The companion table interleaved entry-for-entry, or <see langword="null"/>.</param>
    private static void InternPackedWords(int[][] table, int elementsPerWord, Func<int> nextElement, int[][]? interleaved)
    {
        for(int k = 0; k < table.Length; k++)
        {
            table[k] = InternPackedWord(elementsPerWord, nextElement);
            if(interleaved is not null)
            {
                interleaved[k] = InternPackedWord(elementsPerWord, nextElement);
            }
        }
    }


    /// <summary>Interns one packed word's consecutive elements.</summary>
    /// <param name="elementsPerWord">The packed element count per word.</param>
    /// <param name="nextElement">The column walker.</param>
    /// <returns>The wire array.</returns>
    private static int[] InternPackedWord(int elementsPerWord, Func<int> nextElement)
    {
        var wires = new int[elementsPerWord];
        for(int i = 0; i < elementsPerWord; i++)
        {
            wires[i] = nextElement();
        }

        return wires;
    }


    /// <summary>Interns one ECDSA advice bundle from the column walker in the declaration order.</summary>
    /// <param name="nextElement">The column walker.</param>
    /// <returns>The wire bundle.</returns>
    private static LongfellowEcdsaVerifyWitnessWires InternEcdsaAdvice(Func<int> nextElement)
    {
        int rx = nextElement();
        int ry = nextElement();
        int rxInverse = nextElement();
        int sInverse = nextElement();
        int pkInverse = nextElement();

        var pre = new int[LongfellowEcdsaVerifyWitnessWires.PreTableLength];
        for(int i = 0; i < pre.Length; i++)
        {
            pre[i] = nextElement();
        }

        var bi = new int[ScalarBitCount];
        var intX = new int[ScalarBitCount - 1];
        var intY = new int[ScalarBitCount - 1];
        var intZ = new int[ScalarBitCount - 1];
        for(int i = 0; i < ScalarBitCount; i++)
        {
            bi[i] = nextElement();
            if(i < ScalarBitCount - 1)
            {
                intX[i] = nextElement();
                intY[i] = nextElement();
                intZ[i] = nextElement();
            }
        }

        return new LongfellowEcdsaVerifyWitnessWires(rx, ry, rxInverse, sInverse, pkInverse, pre, bi, intX, intY, intZ);
    }


    /// <summary>Builds the P-256 base field bundle over the production Montgomery backend delegates.</summary>
    /// <returns>The bundle.</returns>
    private static LongfellowLogicFieldOperations NewFp256Bundle()
    {
        return LongfellowLogicFieldOperations.CreateFp256(
            P256BaseFieldMontgomeryBackend.GetAdd(),
            P256BaseFieldMontgomeryBackend.GetSubtract(),
            P256BaseFieldMontgomeryBackend.GetMultiply(),
            P256BaseFieldMontgomeryBackend.GetInvert(),
            Canonical(Prime - 1));
    }


    /// <summary>Parses a reference vector scalar's <c>0x</c>-prefixed hexadecimal into its canonical big-endian form.</summary>
    /// <param name="text">The scalar text.</param>
    /// <returns>The canonical bytes.</returns>
    private static byte[] ParseScalar(string text)
    {
        return Canonical(ParseBigInteger(text));
    }


    /// <summary>Parses a reference vector scalar's <c>0x</c>-prefixed hexadecimal into a big integer.</summary>
    /// <param name="text">The scalar text.</param>
    /// <returns>The value.</returns>
    private static BigInteger ParseBigInteger(string text)
    {
        return BigInteger.Parse("0" + text[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
    }


    /// <summary>Encodes a non-negative integer as a canonical big-endian scalar, zero-padded to <see cref="ScalarSize"/> bytes.</summary>
    /// <param name="value">The non-negative integer to encode.</param>
    /// <returns>The canonical bytes.</returns>
    private static byte[] Canonical(BigInteger value)
    {
        byte[] canonical = new byte[ScalarSize];
        byte[] bigEndian = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        bigEndian.CopyTo(canonical.AsSpan(ScalarSize - bigEndian.Length));

        return canonical;
    }
}
