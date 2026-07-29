using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;
using Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;
using System;
using System.Globalization;
using System.Numerics;
using System.Text;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The evaluation-mode semantic gates for the ported JWT statement, following google/longfellow-zk
/// <c>circuits/tests/jwt/jwt_test.cc</c>'s <c>EvalJWT</c>/<c>EvalFailureJWT</c>: the reference
/// token's full witness satisfies <c>AssertJwtAttributes</c> under a panicking evaluation backend,
/// every malformed reference token is rejected by the witness generator, and the block-capacity
/// guard rejects an oversized token.
/// </summary>
[TestClass]
internal sealed class LongfellowJwtCircuitTests
{
    /// <summary>The field element width in bytes used for every column entry.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The block capacity the reference evaluation tests instantiate (<c>kSHAEvalTest</c>).</summary>
    private const int EvalShaBlocks = 11;

    /// <summary>One SHA-256 block's byte width.</summary>
    private const int BytesPerBlock = 64;

    /// <summary>The P-256 scalar bit count driving the advice shape.</summary>
    private const int ScalarBitCount = 256;

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


    /// <summary>Pins that the reference token's witness satisfies the whole statement under a panicking evaluation backend, and that the witness generator's key-binding digest equals the reference vector's public <c>e2</c>.</summary>
    [TestMethod]
    public void TheReferenceTokenSatisfiesTheStatementInEvaluation()
    {
        LongfellowLogicFieldOperations field = NewFp256Bundle();
        var backend = new LongfellowEvaluationLogicBackend(field, panicOnAssertionFailure: true);
        var logic = new LongfellowLogic(backend, field);

        LongfellowJwtTestVectors.TokenVector vector = LongfellowJwtTestVectors.ErikaToken;
        byte[] token = Encoding.ASCII.GetBytes(vector.Token);
        byte[] pkX = ParseScalar(vector.PkX);
        byte[] pkY = ParseScalar(vector.PkY);
        byte[] e2 = ParseScalar(vector.E2);
        var attribute = LongfellowJwtOpenedAttribute.FromStrings("given_name", "Erika");

        var generator = NewWitnessGenerator(field);
        Assert.IsTrue(generator.ComputeWitness(token, pkX, pkY, [attribute]), "The reference token must produce a witness.");
        CollectionAssert.AreEqual(e2, generator.KbDigest.ToArray(), "The key-binding digest must equal the reference vector's public e2.");

        var circuit = new LongfellowJwtCircuit(logic, Curve, EvalShaBlocks);
        LongfellowJwtWitnessWires witness = InternWitness(backend, logic, field, generator, attributeCount: 1);
        LongfellowJwtOpenedAttributeWires attributeWires = BuildAttributeWires(logic, attribute);

        circuit.AssertJwtAttributes(backend.Constant(pkX), backend.Constant(pkY), backend.Constant(e2), [attributeWires], witness);

        Assert.IsFalse(backend.AssertionFailed, "The reference token must satisfy every statement assertion.");
    }


    /// <summary>Pins that every malformed reference token is rejected by the witness generator.</summary>
    [TestMethod]
    public void TheMalformedTokensAreRejectedByTheWitnessGenerator()
    {
        LongfellowLogicFieldOperations field = NewFp256Bundle();
        foreach(LongfellowJwtTestVectors.FailureVector vector in LongfellowJwtTestVectors.FailureTokens)
        {
            var generator = NewWitnessGenerator(field);
            byte[] token = Encoding.ASCII.GetBytes(vector.Token);
            byte[] pkX = ParseScalar(vector.PkX);
            byte[] pkY = ParseScalar(vector.PkY);
            var attribute = LongfellowJwtOpenedAttribute.FromStrings(vector.AttributeId, vector.AttributeValue);

            Assert.IsFalse(generator.ComputeWitness(token, pkX, pkY, [attribute]), $"The malformed token starting '{vector.Token[..Math.Min(24, vector.Token.Length)]}' must be rejected.");
        }
    }


    /// <summary>Pins the block-capacity guard: a token one byte past the padded capacity is rejected (the reference's 705-character all-<c>a</c> probe).</summary>
    [TestMethod]
    public void AnOversizedTokenIsRejectedByTheCapacityGuard()
    {
        LongfellowLogicFieldOperations field = NewFp256Bundle();
        var generator = NewWitnessGenerator(field);

        byte[] oversized = new byte[(EvalShaBlocks * BytesPerBlock) + 1];
        Array.Fill(oversized, (byte)'a');
        byte[] one = Canonical(BigInteger.One);

        Assert.IsFalse(generator.ComputeWitness(oversized, one, one, []), "A token past the padded block capacity must be rejected.");
    }


    /// <summary>Builds the witness generator over the production Montgomery field backends at the evaluation block capacity.</summary>
    /// <param name="field">The base-field bundle.</param>
    /// <returns>The generator.</returns>
    private static LongfellowJwtWitness NewWitnessGenerator(LongfellowLogicFieldOperations field)
    {
        return new LongfellowJwtWitness(field, OrderMultiply, OrderSubtract, OrderInvert, CurveParameterSet.P256, Curve, EvalShaBlocks);
    }


    /// <summary>
    /// Interns the generator's witness column as evaluation wires following the declaration layout
    /// (the reference's <c>fill_eval_witness</c>): element regions as interned constants, bit
    /// regions decoded back to their integers and rebuilt as constant bit vectors.
    /// </summary>
    /// <param name="backend">The evaluation backend to intern into.</param>
    /// <param name="logic">The gadget layer producing constant bit vectors.</param>
    /// <param name="field">The field bundle.</param>
    /// <param name="generator">The computed witness generator.</param>
    /// <param name="attributeCount">The disclosed attribute count.</param>
    /// <returns>The wire bundle.</returns>
    private static LongfellowJwtWitnessWires InternWitness(
        LongfellowEvaluationLogicBackend backend,
        LongfellowLogic logic,
        LongfellowLogicFieldOperations field,
        LongfellowJwtWitness generator,
        int attributeCount)
    {
        int elementCount = generator.GetElementCount(attributeCount);
        byte[] column = new byte[elementCount * ScalarSize];
        generator.FillWitness(column);

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

        int e = NextElement();
        int dpkX = NextElement();
        int dpkY = NextElement();

        LongfellowEcdsaVerifyWitnessWires jwtSignature = InternEcdsaAdvice(NextElement);
        LongfellowEcdsaVerifyWitnessWires kbSignature = InternEcdsaAdvice(NextElement);

        var preimage = new LongfellowBitWire[EvalShaBlocks * BytesPerBlock][];
        for(int i = 0; i < preimage.Length; i++)
        {
            preimage[i] = logic.BitVector(LongfellowLogic.BitWidth8, NextValue(LongfellowLogic.BitWidth8));
        }

        var eBits = new LongfellowBitWire[ScalarBitCount];
        for(int i = 0; i < ScalarBitCount; i++)
        {
            eBits[i] = logic.Bit((int)NextValue(1));
        }

        var encoder = new LongfellowBitPluckerEncoder(field, LongfellowJwtConstants.ShaJwtPluckerBits);
        var sha = new LongfellowFlatSha256PackedBlockWitness[EvalShaBlocks];
        for(int j = 0; j < EvalShaBlocks; j++)
        {
            sha[j] = new LongfellowFlatSha256PackedBlockWitness();
            InternPackedWords(sha[j].ScheduleExtension, encoder.PackedV32ElementCount, NextElement, interleaved: null);
            InternPackedWords(sha[j].RegisterEWitness, encoder.PackedV32ElementCount, NextElement, interleaved: sha[j].RegisterAWitness);
            InternPackedWords(sha[j].FinalState, encoder.PackedV32ElementCount, NextElement, interleaved: null);
        }

        LongfellowBitWire[] blockNumber = logic.BitVector(LongfellowLogic.BitWidth8, NextValue(LongfellowLogic.BitWidth8));

        var attributeIndices = new LongfellowBitWire[attributeCount][];
        for(int i = 0; i < attributeCount; i++)
        {
            attributeIndices[i] = logic.BitVector(LongfellowJwtConstants.JwtIndexBits, NextValue(LongfellowJwtConstants.JwtIndexBits));
        }

        LongfellowBitWire[] payloadIndex = logic.BitVector(LongfellowJwtConstants.JwtIndexBits, NextValue(LongfellowJwtConstants.JwtIndexBits));
        LongfellowBitWire[] payloadLength = logic.BitVector(LongfellowJwtConstants.JwtIndexBits, NextValue(LongfellowJwtConstants.JwtIndexBits));

        Assert.AreEqual(elementCount, cursor, "The interning walk must cover the whole column exactly.");

        return new LongfellowJwtWitnessWires(e, dpkX, dpkY, jwtSignature, kbSignature, preimage, eBits, sha, blockNumber, attributeIndices, payloadIndex, payloadLength);
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


    /// <summary>Builds one disclosed attribute's public wires as constant bit vectors (the reference evaluation test's pattern construction).</summary>
    /// <param name="logic">The gadget layer producing constant bit vectors.</param>
    /// <param name="attribute">The attribute.</param>
    /// <returns>The wire bundle.</returns>
    private static LongfellowJwtOpenedAttributeWires BuildAttributeWires(LongfellowLogic logic, LongfellowJwtOpenedAttribute attribute)
    {
        byte[] pattern = attribute.BuildPattern();
        var patternWires = new LongfellowBitWire[LongfellowJwtOpenedAttributeWires.PatternLength][];
        for(int i = 0; i < patternWires.Length; i++)
        {
            patternWires[i] = logic.BitVector(LongfellowLogic.BitWidth8, i < pattern.Length ? pattern[i] : 0UL);
        }

        LongfellowBitWire[] length = logic.BitVector(LongfellowLogic.BitWidth8, (ulong)pattern.Length);

        return new LongfellowJwtOpenedAttributeWires(patternWires, length);
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


    /// <summary>Parses a reference vector scalar — hexadecimal with a <c>0x</c> prefix or plain decimal — into its canonical big-endian form.</summary>
    /// <param name="text">The scalar text.</param>
    /// <returns>The canonical bytes.</returns>
    private static byte[] ParseScalar(string text)
    {
        BigInteger value = text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? BigInteger.Parse("0" + text[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture)
            : BigInteger.Parse(text, CultureInfo.InvariantCulture);

        return Canonical(value);
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
