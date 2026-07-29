using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;
using System;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The evaluation-mode and host-side semantic gates for the ported ML-DSA stack: the host
/// reference reproduces the transcribed ExpandA, SampleInBall, UseHint, w1Encode and NTT vectors;
/// the witness generator accepts every FIPS 204 signature example and rejects every failing one;
/// every reference evaluation test (SampleInBall, UseHintSingle, W1Encode, NTT consistency, and
/// the full verification relation) accepts under the evaluation backend; and the reference's two
/// soundness probes (an out-of-bound response coefficient and a cheated UseHint sign bit) are
/// rejected in evaluation.
/// </summary>
[TestClass]
internal sealed class LongfellowMlDsaCircuitTests
{
    /// <summary>The sextic extension's subfield width, selecting the three-way SHAKE re-anchoring split.</summary>
    private const int SexticSubfieldBits = 32;

    /// <summary>The lane grid's side length.</summary>
    private const int GridSize = 5;

    /// <summary>One lane's bit width.</summary>
    private const int LaneBits = 64;

    /// <summary>The message representative's byte count.</summary>
    private const int MuBytes = 64;

    /// <summary>The reference soundness probe's low-bits value (a positive remainder, so the honest shift is plus one).</summary>
    private const uint ProbeLowPart = 1;

    /// <summary>The reference soundness probe's high-bits value.</summary>
    private const uint ProbeHighPart = 5;

    /// <summary>The reference soundness probe's cheated hinted high bits (the minus-one shift instead of the honest plus-one).</summary>
    private const uint ProbeCheatedHint = 4;

    /// <summary>The first sliced Keccak round, where the message-representative corruption gate fires.</summary>
    private const int FirstSlicedRound = 5;


    /// <summary>The FIPS 202 SHAKE128 example message: 1600 bits of the repeated byte, crossing the 168-byte rate so the mid-stream absorb permutation runs.</summary>
    private const byte Fips202ExampleMessageByte = 0xA3;

    /// <summary>The FIPS 202 SHAKE128 example message's byte count.</summary>
    private const int Fips202ExampleMessageBytes = 200;

    /// <summary>The FIPS 202 SHAKE128 example output of the empty message, first 32 bytes.</summary>
    private const string Fips202EmptyMessageDigest = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26";

    /// <summary>The FIPS 202 SHAKE128 example output of the 1600-bit message, first 32 bytes.</summary>
    private const string Fips202LongMessageDigest = "131ab8d2b594946b9c81333f9bb6e0ce75c3b93104fa3469d3917457385da037";


    /// <summary>Pins the host SHAKE128 against the FIPS 202 example vectors: the empty message, and the 1600-bit message whose absorb crosses the rate — the only exerciser of the mid-stream absorb permutation.</summary>
    [TestMethod]
    public void TheHostShake128MatchesTheFipsExampleVectors()
    {
        var emptyDigest = new byte[Fips202EmptyMessageDigest.Length / 2];
        LongfellowSha3Witness.Shake128Hash([], emptyDigest);
        CollectionAssert.AreEqual(Convert.FromHexString(Fips202EmptyMessageDigest), emptyDigest, "The host SHAKE128 must reproduce the FIPS 202 empty-message example.");

        var longMessage = new byte[Fips202ExampleMessageBytes];
        Array.Fill(longMessage, Fips202ExampleMessageByte);
        var longDigest = new byte[Fips202LongMessageDigest.Length / 2];
        LongfellowSha3Witness.Shake128Hash(longMessage, longDigest);
        CollectionAssert.AreEqual(Convert.FromHexString(Fips202LongMessageDigest), longDigest, "The host SHAKE128 must reproduce the FIPS 202 1600-bit-message example.");
    }


    /// <summary>Pins the host matrix expansion against the transcribed reference vectors — the conformance gate for the SHAKE128 path and the rejection sampler, at both parameter sets.</summary>
    [TestMethod]
    public void TheHostExpandAMatchesTheReferenceVectors()
    {
        AssertExpandA(LongfellowMlDsaParameters.MlDsa44, LongfellowMlDsa44SamplingVectors.ExpandASeed, LongfellowMlDsa44SamplingVectors.ExpectedExpandA, "ml_dsa_44");
        AssertExpandA(LongfellowMlDsaParameters.MlDsa65, LongfellowMlDsa65AlgorithmVectors.ExpandASeed, LongfellowMlDsa65AlgorithmVectors.ExpectedExpandA, "ml_dsa_65");
    }


    /// <summary>Pins the host SampleInBall against the transcribed reference vectors, at both parameter sets.</summary>
    [TestMethod]
    public void TheHostSampleInBallMatchesTheReferenceVectors()
    {
        AssertHostSampleInBall(LongfellowMlDsaParameters.MlDsa44, LongfellowMlDsa44SamplingVectors.SampleInBallVectors, "ml_dsa_44");
        AssertHostSampleInBall(LongfellowMlDsaParameters.MlDsa65, LongfellowMlDsa65AlgorithmVectors.SampleInBallVectors, "ml_dsa_65");
    }


    /// <summary>Pins the host UseHint against the transcribed reference cases, at both parameter sets.</summary>
    [TestMethod]
    public void TheHostUseHintMatchesTheReferenceCases()
    {
        AssertHostUseHint(LongfellowMlDsaParameters.MlDsa44, LongfellowMlDsa44SamplingVectors.UseHintCases, "ml_dsa_44");
        AssertHostUseHint(LongfellowMlDsaParameters.MlDsa65, LongfellowMlDsa65AlgorithmVectors.UseHintCases, "ml_dsa_65");
    }


    /// <summary>Pins the host w1Encode against the transcribed reference vectors, at both parameter sets.</summary>
    [TestMethod]
    public void TheHostW1EncodeMatchesTheReferenceVectors()
    {
        AssertHostW1Encode(LongfellowMlDsaParameters.MlDsa44, LongfellowMlDsa44EncodingVectors.W1EncodeVectors, "ml_dsa_44");
        AssertHostW1Encode(LongfellowMlDsaParameters.MlDsa65, LongfellowMlDsa65AlgorithmVectors.W1EncodeVectors, "ml_dsa_65");
    }


    /// <summary>Pins the host NTT against the transcribed reference vectors, and the inverse transform as their round trip.</summary>
    [TestMethod]
    public void TheHostNttMatchesTheReferenceVectors()
    {
        for(int t = 0; t < LongfellowMlDsa44EncodingVectors.NttVectors.Count; t++)
        {
            LongfellowMlDsaNttVector vector = LongfellowMlDsa44EncodingVectors.NttVectors[t];

            var forward = (uint[])vector.Input.Clone();
            LongfellowMlDsaReference.NumberTheoreticTransform(forward);
            CollectionAssert.AreEqual(vector.Output, forward, $"The host NTT must reproduce reference vector {t}.");

            var backward = (uint[])vector.Output.Clone();
            LongfellowMlDsaReference.InverseNumberTheoreticTransform(backward);
            CollectionAssert.AreEqual(vector.Input, backward, $"The host inverse NTT must invert reference vector {t}.");
        }
    }


    /// <summary>Pins <see cref="LongfellowMlDsaWitness.SymmetricReduce"/> against the reference's own unit cases.</summary>
    [TestMethod]
    public void TheSymmetricReduceMatchesTheReference()
    {
        long q = LongfellowMlDsaParameters.Modulus;

        Assert.AreEqual(100, LongfellowMlDsaWitness.SymmetricReduce(100), "A small positive value must be unchanged.");
        Assert.AreEqual(0, LongfellowMlDsaWitness.SymmetricReduce(0), "Zero must be unchanged.");
        Assert.AreEqual(-1, LongfellowMlDsaWitness.SymmetricReduce(q - 1), "The modulus less one must reduce to minus one.");
        Assert.AreEqual(q / 2, LongfellowMlDsaWitness.SymmetricReduce(q / 2), "The half modulus must be unchanged.");
        Assert.AreEqual((q / 2) + 1 - q, LongfellowMlDsaWitness.SymmetricReduce((q / 2) + 1), "One past the half modulus must wrap negative.");
        Assert.AreEqual(-100, LongfellowMlDsaWitness.SymmetricReduce(-100), "A small negative value must be unchanged.");
        Assert.AreEqual(-q / 2, LongfellowMlDsaWitness.SymmetricReduce(-q / 2), "The negative half modulus must be unchanged.");
    }


    /// <summary>Pins that the witness generator accepts every transcribed signature example and reproduces each example's transcribed message representative, at both parameter sets.</summary>
    [TestMethod]
    public void TheWitnessComputesForEveryExample()
    {
        AssertWitnessAccepts(LongfellowMlDsaParameters.MlDsa44, LongfellowMlDsa44ExampleVectors.SignatureExamples, "ml_dsa_44");
        AssertWitnessAccepts(LongfellowMlDsaParameters.MlDsa65, LongfellowMlDsa65ExampleVectors.SignatureExamples, "ml_dsa_65");
    }


    /// <summary>Pins that the witness generator rejects every transcribed failing example, at both parameter sets.</summary>
    [TestMethod]
    public void TheWitnessRejectsEveryFailingExample()
    {
        AssertWitnessRejects(LongfellowMlDsaParameters.MlDsa44, LongfellowMlDsa44ExampleVectors.FailingSignatureExamples, "ml_dsa_44");
        AssertWitnessRejects(LongfellowMlDsaParameters.MlDsa65, LongfellowMlDsa65ExampleVectors.FailingSignatureExamples, "ml_dsa_65");
    }


    /// <summary>Pins that the SampleInBall assertion accepts each set's first transcribed reference vector under the evaluation backend; the remaining vectors run in the slow sweep.</summary>
    [TestMethod]
    public void TheSampleInBallAssertionAcceptsTheFirstReferenceVectorInEvaluation()
    {
        AssertSampleInBallEvaluation(LongfellowMlDsaParameters.MlDsa44, LongfellowMlDsa44SamplingVectors.SampleInBallVectors, 0, 1, "ml_dsa_44");
        AssertSampleInBallEvaluation(LongfellowMlDsaParameters.MlDsa65, LongfellowMlDsa65AlgorithmVectors.SampleInBallVectors, 0, 1, "ml_dsa_65");
    }


    /// <summary>Pins that the SampleInBall assertion accepts every remaining transcribed reference vector under the evaluation backend, at both parameter sets.</summary>
    [TestMethod]
    [TestCategory("Slow")]
    public void TheSampleInBallAssertionAcceptsEveryRemainingReferenceVectorInEvaluation()
    {
        AssertSampleInBallEvaluation(LongfellowMlDsaParameters.MlDsa44, LongfellowMlDsa44SamplingVectors.SampleInBallVectors, 1, LongfellowMlDsa44SamplingVectors.SampleInBallVectors.Count, "ml_dsa_44");
        AssertSampleInBallEvaluation(LongfellowMlDsaParameters.MlDsa65, LongfellowMlDsa65AlgorithmVectors.SampleInBallVectors, 1, LongfellowMlDsa65AlgorithmVectors.SampleInBallVectors.Count, "ml_dsa_65");
    }


    /// <summary>Pins that the single-coefficient UseHint assertion accepts every transcribed reference case under the evaluation backend, at both parameter sets.</summary>
    [TestMethod]
    public void TheUseHintSingleAssertionAcceptsEveryReferenceCaseInEvaluation()
    {
        AssertUseHintSingleEvaluation(LongfellowMlDsaParameters.MlDsa44, LongfellowMlDsa44SamplingVectors.UseHintCases, "ml_dsa_44");
        AssertUseHintSingleEvaluation(LongfellowMlDsaParameters.MlDsa65, LongfellowMlDsa65AlgorithmVectors.UseHintCases, "ml_dsa_65");
    }


    /// <summary>Pins that the w1Encode assertion accepts every transcribed reference vector under the evaluation backend, at both parameter sets.</summary>
    [TestMethod]
    public void TheW1EncodeAssertionAcceptsEveryReferenceVectorInEvaluation()
    {
        AssertW1EncodeEvaluation(LongfellowMlDsaParameters.MlDsa44, LongfellowMlDsa44EncodingVectors.W1EncodeVectors, "ml_dsa_44");
        AssertW1EncodeEvaluation(LongfellowMlDsaParameters.MlDsa65, LongfellowMlDsa65AlgorithmVectors.W1EncodeVectors, "ml_dsa_65");
    }


    /// <summary>Pins that the NTT and inverse-NTT assertions accept every transcribed reference vector under the evaluation backend.</summary>
    [TestMethod]
    public void TheNttAssertionsAcceptEveryReferenceVectorInEvaluation()
    {
        LongfellowLogicFieldOperations field = NewFp24SexticBundle();
        var backend = new LongfellowEvaluationLogicBackend(field, panicOnAssertionFailure: false);
        var logic = new LongfellowLogic(backend, field);
        var verify = new LongfellowMlDsaVerifyCircuit(logic, LongfellowMlDsaParameters.MlDsa44, SexticSubfieldBits);

        for(int t = 0; t < LongfellowMlDsa44EncodingVectors.NttVectors.Count; t++)
        {
            LongfellowMlDsaNttVector vector = LongfellowMlDsa44EncodingVectors.NttVectors[t];
            verify.AssertNtt(InternPolynomial(backend, field, vector.Input), InternPolynomial(backend, field, vector.Output));
            Assert.IsFalse(backend.AssertionFailed, $"NTT vector {t} must satisfy the forward transform assertion.");
        }

        for(int t = 0; t < LongfellowMlDsa44EncodingVectors.NttVectors.Count; t++)
        {
            LongfellowMlDsaNttVector vector = LongfellowMlDsa44EncodingVectors.NttVectors[t];
            verify.AssertInverseNtt(InternPolynomial(backend, field, vector.Output), InternPolynomial(backend, field, vector.Input));
            Assert.IsFalse(backend.AssertionFailed, $"NTT vector {t} must satisfy the inverse transform assertion.");
        }
    }


    /// <summary>Pins that the full verification relation accepts each set's first transcribed signature example under the evaluation backend; the remaining examples run in the slow sweep.</summary>
    [TestMethod]
    public void TheValidSignatureAssertionAcceptsTheFirstExampleInEvaluation()
    {
        AssertValidSignatureEvaluation(LongfellowMlDsaParameters.MlDsa44, LongfellowMlDsa44ExampleVectors.SignatureExamples, 0, 1, "ml_dsa_44");
        AssertValidSignatureEvaluation(LongfellowMlDsaParameters.MlDsa65, LongfellowMlDsa65ExampleVectors.SignatureExamples, 0, 1, "ml_dsa_65");
    }


    /// <summary>Pins that the full verification relation accepts every remaining transcribed signature example under the evaluation backend, at both parameter sets.</summary>
    [TestMethod]
    [TestCategory("Slow")]
    public void TheValidSignatureAssertionAcceptsEveryRemainingExampleInEvaluation()
    {
        AssertValidSignatureEvaluation(LongfellowMlDsaParameters.MlDsa44, LongfellowMlDsa44ExampleVectors.SignatureExamples, 1, LongfellowMlDsa44ExampleVectors.SignatureExamples.Count, "ml_dsa_44");
        AssertValidSignatureEvaluation(LongfellowMlDsaParameters.MlDsa65, LongfellowMlDsa65ExampleVectors.SignatureExamples, 1, LongfellowMlDsa65ExampleVectors.SignatureExamples.Count, "ml_dsa_65");
    }


    /// <summary>
    /// Pins the infinity-norm soundness probes in evaluation at both parameter sets: the
    /// reference's coefficient at the negated bound fails the decomposition-equality binding (no
    /// representable witness can match its shift), and a coefficient exactly one past the bound —
    /// whose equality binding holds — fails the range comparator itself.
    /// </summary>
    [TestMethod]
    public void TheInfinityNormAssertionRejectsAnOutOfBoundCoefficientInEvaluation()
    {
        AssertInfinityNormRejection(LongfellowMlDsaParameters.MlDsa44, "ml_dsa_44");
        AssertInfinityNormRejection(LongfellowMlDsaParameters.MlDsa65, "ml_dsa_65");
    }


    /// <summary>Pins the reference's UseHint soundness probe in evaluation: a cheated sign bit claiming the wrong shift direction must fail the sign constraint, at both parameter sets.</summary>
    [TestMethod]
    public void TheUseHintSingleAssertionRejectsACheatedSignBitInEvaluation()
    {
        AssertUseHintSignRejection(LongfellowMlDsaParameters.MlDsa44, "ml_dsa_44");
        AssertUseHintSignRejection(LongfellowMlDsaParameters.MlDsa65, "ml_dsa_65");
    }


    /// <summary>Pins the message-representative sponge assertion in evaluation: the first example's <c>mu</c> is accepted with the generator's witnesses, and a corrupted witness lane is rejected.</summary>
    [TestMethod]
    public void TheMuAssertionAcceptsTheExampleAndRejectsACorruptedWitnessInEvaluation()
    {
        LongfellowMlDsaParameters parameters = LongfellowMlDsaParameters.MlDsa44;
        LongfellowMlDsaSignatureExample example = LongfellowMlDsa44ExampleVectors.SignatureExamples[0];
        byte[] context = Convert.FromHexString(example.Context);
        byte[] message = Convert.FromHexString(example.Message);

        LongfellowMlDsaWitness? witness = ComputeWitness(parameters, example);
        Assert.IsNotNull(witness, "The example witness must compute.");

        var boundMessage = new byte[2 + context.Length + message.Length];
        boundMessage[1] = (byte)context.Length;
        context.CopyTo(boundMessage.AsSpan(2));
        message.CopyTo(boundMessage.AsSpan(2 + context.Length));

        var spongeInput = new byte[witness.Tr.Length + boundMessage.Length];
        witness.Tr.CopyTo(spongeInput.AsSpan(0));
        boundMessage.CopyTo(spongeInput.AsSpan(witness.Tr.Length));

        LongfellowLogicFieldOperations field = NewFp24SexticBundle();
        var backend = new LongfellowEvaluationLogicBackend(field, panicOnAssertionFailure: false);
        var logic = new LongfellowLogic(backend, field);
        var verify = new LongfellowMlDsaVerifyCircuit(logic, parameters, SexticSubfieldBits);

        IReadOnlyList<LongfellowSha3BlockWitness> spongeWitnesses = LongfellowSha3Witness.ComputeWitnessShake256(spongeInput, MuBytes);
        verify.AssertMu(
            InternBytes(logic, witness.Tr),
            InternBytes(logic, boundMessage),
            InternBlockWitnesses(logic, spongeWitnesses),
            InternBytes(logic, witness.Mu));
        Assert.IsFalse(backend.AssertionFailed, "The example's message representative must satisfy the sponge assertion.");

        var corruptedBackend = new LongfellowEvaluationLogicBackend(field, panicOnAssertionFailure: false);
        var corruptedLogic = new LongfellowLogic(corruptedBackend, field);
        var corruptedVerify = new LongfellowMlDsaVerifyCircuit(corruptedLogic, parameters, SexticSubfieldBits);

        IReadOnlyList<LongfellowSha3BlockWitness> corruptedWitnesses = LongfellowSha3Witness.ComputeWitnessShake256(spongeInput, MuBytes);
        corruptedWitnesses[0].AIntermediate[FirstSlicedRound][0][0] ^= 1UL;
        corruptedVerify.AssertMu(
            InternBytes(corruptedLogic, witness.Tr),
            InternBytes(corruptedLogic, boundMessage),
            InternBlockWitnesses(corruptedLogic, corruptedWitnesses),
            InternBytes(corruptedLogic, witness.Mu));
        Assert.IsTrue(corruptedBackend.AssertionFailed, "A corrupted sponge witness lane must fail the re-anchoring assertion.");
    }


    /// <summary>Runs one parameter set's ExpandA conformance sweep.</summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="seed">The transcribed expansion seed.</param>
    /// <param name="expected">The transcribed expected matrix.</param>
    /// <param name="setName">The parameter set's name, for the failure messages.</param>
    private static void AssertExpandA(LongfellowMlDsaParameters parameters, byte[] seed, uint[][][] expected, string setName)
    {
        uint[][][] matrix = LongfellowMlDsaReference.ExpandMatrix(parameters, seed);

        for(int row = 0; row < parameters.RowCount; row++)
        {
            for(int column = 0; column < parameters.ColumnCount; column++)
            {
                CollectionAssert.AreEqual(
                    expected[row][column],
                    matrix[row][column],
                    $"The {setName} expanded matrix must match the reference at row {row} column {column}.");
            }
        }
    }


    /// <summary>Runs one parameter set's host SampleInBall conformance sweep.</summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="vectors">The transcribed vectors.</param>
    /// <param name="setName">The parameter set's name, for the failure messages.</param>
    private static void AssertHostSampleInBall(LongfellowMlDsaParameters parameters, IReadOnlyList<LongfellowMlDsaSampleInBallVector> vectors, string setName)
    {
        for(int t = 0; t < vectors.Count; t++)
        {
            uint[] challenge = LongfellowMlDsaReference.SampleInBall(parameters, vectors[t].Seed);
            CollectionAssert.AreEqual(vectors[t].Coefficients, challenge, $"The {setName} host SampleInBall must reproduce reference vector {t}.");
        }
    }


    /// <summary>Runs one parameter set's host UseHint conformance sweep.</summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="cases">The transcribed cases.</param>
    /// <param name="setName">The parameter set's name, for the failure messages.</param>
    private static void AssertHostUseHint(LongfellowMlDsaParameters parameters, IReadOnlyList<LongfellowMlDsaUseHintCase> cases, string setName)
    {
        for(int t = 0; t < cases.Count; t++)
        {
            uint hinted = LongfellowMlDsaReference.UseHint(parameters, cases[t].Hint, cases[t].R);
            Assert.AreEqual(cases[t].Expected, hinted, $"The {setName} host UseHint must reproduce reference case {t}.");
        }
    }


    /// <summary>Runs one parameter set's host w1Encode conformance sweep.</summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="vectors">The transcribed vectors.</param>
    /// <param name="setName">The parameter set's name, for the failure messages.</param>
    private static void AssertHostW1Encode(LongfellowMlDsaParameters parameters, IReadOnlyList<LongfellowMlDsaW1EncodeVector> vectors, string setName)
    {
        for(int t = 0; t < vectors.Count; t++)
        {
            var highBits = new uint[parameters.RowCount][];
            for(int row = 0; row < parameters.RowCount; row++)
            {
                highBits[row] = new uint[LongfellowMlDsaParameters.CoefficientCount];
                for(int i = 0; i < LongfellowMlDsaParameters.CoefficientCount; i++)
                {
                    highBits[row][i] = (uint)vectors[t].Coefficients[row][i];
                }
            }

            byte[] encoded = LongfellowMlDsaReference.W1Encode(parameters, highBits);
            CollectionAssert.AreEqual(vectors[t].Encoded, encoded, $"The {setName} host w1Encode must reproduce reference vector {t}.");
        }
    }


    /// <summary>Runs one parameter set's witness acceptance sweep, cross-checking each computed message representative against the transcription.</summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="examples">The transcribed accepting examples.</param>
    /// <param name="setName">The parameter set's name, for the failure messages.</param>
    private static void AssertWitnessAccepts(LongfellowMlDsaParameters parameters, IReadOnlyList<LongfellowMlDsaSignatureExample> examples, string setName)
    {
        for(int t = 0; t < examples.Count; t++)
        {
            LongfellowMlDsaWitness? witness = ComputeWitness(parameters, examples[t]);
            Assert.IsNotNull(witness, $"The {setName} witness must compute for example {t}.");
            CollectionAssert.AreEqual(
                Convert.FromHexString(examples[t].Mu),
                witness.Mu,
                $"The {setName} witness must reproduce example {t}'s transcribed message representative.");
        }
    }


    /// <summary>Runs one parameter set's witness rejection sweep.</summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="examples">The transcribed failing examples.</param>
    /// <param name="setName">The parameter set's name, for the failure messages.</param>
    private static void AssertWitnessRejects(LongfellowMlDsaParameters parameters, IReadOnlyList<LongfellowMlDsaSignatureExample> examples, string setName)
    {
        for(int t = 0; t < examples.Count; t++)
        {
            LongfellowMlDsaWitness? witness = ComputeWitness(parameters, examples[t]);
            Assert.IsNull(witness, $"The {setName} witness must reject failing example {t}.");
        }
    }


    /// <summary>Runs one parameter set's SampleInBall evaluation sweep over a vector range, building the rejection-walk witness exactly as the reference evaluation test does.</summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="vectors">The transcribed vectors.</param>
    /// <param name="firstVector">The inclusive first vector index.</param>
    /// <param name="vectorEnd">The exclusive end index.</param>
    /// <param name="setName">The parameter set's name, for the failure messages.</param>
    private static void AssertSampleInBallEvaluation(LongfellowMlDsaParameters parameters, IReadOnlyList<LongfellowMlDsaSampleInBallVector> vectors, int firstVector, int vectorEnd, string setName)
    {
        LongfellowLogicFieldOperations field = NewFp24SexticBundle();
        Span<byte> stream = stackalloc byte[LongfellowMlDsaReference.SampleInBallHashBytes];
        for(int t = firstVector; t < vectorEnd; t++)
        {
            var backend = new LongfellowEvaluationLogicBackend(field, panicOnAssertionFailure: false);
            var logic = new LongfellowLogic(backend, field);
            var verify = new LongfellowMlDsaVerifyCircuit(logic, parameters, SexticSubfieldBits);

            byte[] seed = vectors[t].Seed;
            LongfellowSha3Witness.Shake256Hash(seed, stream);

            var witness = new LongfellowMlDsaSampleInBallWitnessWires(parameters);
            int streamIndex = LongfellowMlDsaReference.SampleInBallStreamStart;
            var currentPositions = new List<byte>(parameters.ChallengeWeight);
            for(int s = 0; s < parameters.ChallengeWeight; s++)
            {
                int i = LongfellowMlDsaParameters.CoefficientCount - parameters.ChallengeWeight + s;
                byte j;
                do
                {
                    j = stream[streamIndex++];
                }
                while(j > i);

                witness.JValues[s] = logic.BitVector(LongfellowLogic.BitWidth8, j);
                witness.JIndices[s] = logic.BitVector(LongfellowLogic.BitWidth16, (ulong)(streamIndex - 1));

                for(int p = 0; p < currentPositions.Count; p++)
                {
                    if(currentPositions[p] == j)
                    {
                        currentPositions[p] = (byte)i;

                        break;
                    }
                }

                currentPositions.Add(j);
                for(int p = 0; p <= s; p++)
                {
                    witness.PositionTrace[s][p] = logic.BitVector(LongfellowLogic.BitWidth8, currentPositions[p]);
                }
            }

            IReadOnlyList<LongfellowSha3BlockWitness> spongeWitnesses = LongfellowSha3Witness.ComputeWitnessShake256(seed, LongfellowMlDsaReference.SampleInBallHashBytes);
            InternBlockWitness(logic, spongeWitnesses[0], witness.BlockWitness);

            var challenge = new LongfellowMlDsaPolynomialWires();
            for(int i = 0; i < LongfellowMlDsaParameters.CoefficientCount; i++)
            {
                challenge.Coefficients[i] = backend.Constant(field.OfScalar(vectors[t].Coefficients[i]).Span);
            }

            verify.AssertSampleInBall(InternBytes(logic, seed), challenge, witness);
            Assert.IsFalse(backend.AssertionFailed, $"The {setName} SampleInBall assertion must accept reference vector {t}.");
        }
    }


    /// <summary>Runs one parameter set's UseHintSingle evaluation sweep, deriving the interval-shift witness exactly as the reference evaluation test does.</summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="cases">The transcribed cases.</param>
    /// <param name="setName">The parameter set's name, for the failure messages.</param>
    private static void AssertUseHintSingleEvaluation(LongfellowMlDsaParameters parameters, IReadOnlyList<LongfellowMlDsaUseHintCase> cases, string setName)
    {
        LongfellowLogicFieldOperations field = NewFp24SexticBundle();
        var backend = new LongfellowEvaluationLogicBackend(field, panicOnAssertionFailure: false);
        var logic = new LongfellowLogic(backend, field);
        var verify = new LongfellowMlDsaVerifyCircuit(logic, parameters, SexticSubfieldBits);

        for(int t = 0; t < cases.Count; t++)
        {
            LongfellowMlDsaUseHintCase testCase = cases[t];
            (int highPart, _) = LongfellowMlDsaReference.Decompose(parameters, testCase.R);

            long gamma2 = parameters.RoundingRange;
            long delta = testCase.R - (highPart * 2L * gamma2);
            delta %= LongfellowMlDsaParameters.Modulus;
            if(delta > LongfellowMlDsaParameters.Modulus / 2)
            {
                delta -= LongfellowMlDsaParameters.Modulus;
            }
            else if(delta < -(long)LongfellowMlDsaParameters.Modulus / 2)
            {
                delta += LongfellowMlDsaParameters.Modulus;
            }

            ulong shiftedRemainder = (ulong)(delta + gamma2);
            ulong signBit = delta > 0 ? 0UL : 1UL;
            ulong auxBits = shiftedRemainder | (signBit << parameters.LowBitsWidth);

            verify.AssertUseHintSingle(
                backend.Constant(field.OfScalar(NormalizeModQ(testCase.Hint ? 1 : 0)).Span),
                backend.Constant(field.OfScalar(NormalizeModQ(testCase.R)).Span),
                backend.Constant(field.OfScalar(NormalizeModQ(highPart)).Span),
                logic.BitVector(parameters.HighBitsWidth, NormalizeModQ(highPart)),
                logic.BitVector(parameters.LowBitsWidth + 1, NormalizeModQ((long)auxBits)),
                backend.Constant(field.OfScalar(testCase.Expected).Span),
                logic.BitVector(parameters.HighBitsWidth, testCase.Expected));
            Assert.IsFalse(backend.AssertionFailed, $"The {setName} UseHintSingle assertion must accept reference case {t}.");
        }
    }


    /// <summary>Runs one parameter set's W1Encode evaluation sweep.</summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="vectors">The transcribed vectors.</param>
    /// <param name="setName">The parameter set's name, for the failure messages.</param>
    private static void AssertW1EncodeEvaluation(LongfellowMlDsaParameters parameters, IReadOnlyList<LongfellowMlDsaW1EncodeVector> vectors, string setName)
    {
        LongfellowLogicFieldOperations field = NewFp24SexticBundle();
        var backend = new LongfellowEvaluationLogicBackend(field, panicOnAssertionFailure: false);
        var logic = new LongfellowLogic(backend, field);
        var verify = new LongfellowMlDsaVerifyCircuit(logic, parameters, SexticSubfieldBits);

        for(int t = 0; t < vectors.Count; t++)
        {
            var coefficientBits = new LongfellowBitWire[parameters.RowCount][][];
            for(int row = 0; row < parameters.RowCount; row++)
            {
                coefficientBits[row] = new LongfellowBitWire[LongfellowMlDsaParameters.CoefficientCount][];
                for(int i = 0; i < LongfellowMlDsaParameters.CoefficientCount; i++)
                {
                    coefficientBits[row][i] = logic.BitVector(parameters.HighBitsWidth, (ulong)vectors[t].Coefficients[row][i]);
                }
            }

            var putative = new LongfellowBitWire[vectors[t].Encoded.Length][];
            for(int i = 0; i < vectors[t].Encoded.Length; i++)
            {
                putative[i] = logic.BitVector(LongfellowLogic.BitWidth8, vectors[t].Encoded[i]);
            }

            verify.AssertW1Encode(coefficientBits, putative);
            Assert.IsFalse(backend.AssertionFailed, $"The {setName} W1Encode assertion must accept reference vector {t}.");
        }
    }


    /// <summary>Runs one parameter set's full-relation evaluation sweep over an example range.</summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="examples">The transcribed accepting examples.</param>
    /// <param name="firstExample">The inclusive first example index.</param>
    /// <param name="exampleEnd">The exclusive end index.</param>
    /// <param name="setName">The parameter set's name, for the failure messages.</param>
    private static void AssertValidSignatureEvaluation(LongfellowMlDsaParameters parameters, IReadOnlyList<LongfellowMlDsaSignatureExample> examples, int firstExample, int exampleEnd, string setName)
    {
        LongfellowLogicFieldOperations field = NewFp24SexticBundle();
        for(int t = firstExample; t < exampleEnd; t++)
        {
            LongfellowMlDsaWitness? witnessData = ComputeWitness(parameters, examples[t]);
            Assert.IsNotNull(witnessData, $"The {setName} witness must compute for example {t}.");

            var backend = new LongfellowEvaluationLogicBackend(field, panicOnAssertionFailure: false);
            var logic = new LongfellowLogic(backend, field);
            var verify = new LongfellowMlDsaVerifyCircuit(logic, parameters, SexticSubfieldBits);

            LongfellowMlDsaPublicKeyWires publicKey = ConvertPublicKey(backend, logic, field, parameters, witnessData);
            LongfellowMlDsaSignatureWires signature = ConvertSignature(backend, logic, field, parameters, witnessData);
            LongfellowMlDsaWitnessWires witness = ConvertWitness(backend, logic, field, parameters, witnessData);

            verify.AssertValidSignatureOnMu(publicKey, signature, InternBytes(logic, witnessData.Mu), witness);
            Assert.IsFalse(backend.AssertionFailed, $"The {setName} verification relation must accept example {t}.");
        }
    }


    /// <summary>
    /// Runs one parameter set's infinity-norm rejection probes: the reference's negated-bound
    /// coefficient (whose shift no witness decomposition can represent, so the equality binding
    /// fires) and the minimal out-of-bound coefficient (whose decomposition is honest, so only the
    /// range comparator can fire).
    /// </summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="setName">The parameter set's name, for the failure messages.</param>
    private static void AssertInfinityNormRejection(LongfellowMlDsaParameters parameters, string setName)
    {
        ulong bound = parameters.MaskingBound - parameters.RejectionBound;

        ulong negatedBoundValue = LongfellowMlDsaParameters.Modulus - bound;
        AssertInfinityNormProbe(
            parameters,
            negatedBoundValue,
            probeBits: 0UL,
            bound,
            $"The {setName} infinity-norm assertion must reject a coefficient at the negated bound through the decomposition-equality binding.");

        AssertInfinityNormProbe(
            parameters,
            probeValue: bound,
            probeBits: (2 * bound) - 1,
            bound,
            $"The {setName} infinity-norm assertion must reject the minimal out-of-bound coefficient through the range comparator.");
    }


    /// <summary>Runs one infinity-norm probe with a single out-of-bound coefficient and its claimed decomposition.</summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="probeValue">The probed coefficient's canonical value.</param>
    /// <param name="probeBits">The probed coefficient's claimed shifted decomposition.</param>
    /// <param name="bound">The strict infinity-norm bound.</param>
    /// <param name="message">The failure message.</param>
    private static void AssertInfinityNormProbe(LongfellowMlDsaParameters parameters, ulong probeValue, ulong probeBits, ulong bound, string message)
    {
        LongfellowLogicFieldOperations field = NewFp24SexticBundle();
        var backend = new LongfellowEvaluationLogicBackend(field, panicOnAssertionFailure: false);
        var logic = new LongfellowLogic(backend, field);
        var verify = new LongfellowMlDsaVerifyCircuit(logic, parameters, SexticSubfieldBits);

        var z = new LongfellowMlDsaPolynomialWires[parameters.ColumnCount];
        var zBits = new LongfellowBitWire[parameters.ColumnCount][][];
        for(int i = 0; i < parameters.ColumnCount; i++)
        {
            z[i] = new LongfellowMlDsaPolynomialWires();
            zBits[i] = new LongfellowBitWire[LongfellowMlDsaParameters.CoefficientCount][];
            for(int j = 0; j < LongfellowMlDsaParameters.CoefficientCount; j++)
            {
                bool isProbe = i == 0 && j == 0;
                z[i].Coefficients[j] = backend.Constant(field.OfScalar(isProbe ? probeValue : 0UL).Span);
                zBits[i][j] = logic.BitVector(parameters.ResponseBitWidth, isProbe ? probeBits : bound - 1);
            }
        }

        verify.AssertInfinityNorm(z, zBits, bound);
        Assert.IsTrue(backend.AssertionFailed, message);
    }


    /// <summary>Runs one parameter set's UseHint sign-cheat rejection probe.</summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="setName">The parameter set's name, for the failure messages.</param>
    private static void AssertUseHintSignRejection(LongfellowMlDsaParameters parameters, string setName)
    {
        LongfellowLogicFieldOperations field = NewFp24SexticBundle();
        var backend = new LongfellowEvaluationLogicBackend(field, panicOnAssertionFailure: false);
        var logic = new LongfellowLogic(backend, field);
        var verify = new LongfellowMlDsaVerifyCircuit(logic, parameters, SexticSubfieldBits);

        ulong twoGamma2 = 2UL * parameters.RoundingRange;
        ulong r = ((ProbeHighPart * twoGamma2) + ProbeLowPart) % LongfellowMlDsaParameters.Modulus;
        ulong shiftedRemainder = parameters.RoundingRange + ProbeLowPart;
        ulong cheatedAuxBits = shiftedRemainder | (1UL << parameters.LowBitsWidth);

        verify.AssertUseHintSingle(
            backend.Constant(field.Compiler.One.Span),
            backend.Constant(field.OfScalar(r).Span),
            backend.Constant(field.OfScalar(ProbeHighPart).Span),
            logic.BitVector(parameters.HighBitsWidth, ProbeHighPart),
            logic.BitVector(parameters.LowBitsWidth + 1, cheatedAuxBits),
            backend.Constant(field.OfScalar(ProbeCheatedHint).Span),
            logic.BitVector(parameters.HighBitsWidth, ProbeCheatedHint));

        Assert.IsTrue(backend.AssertionFailed, $"The {setName} UseHint assertion must reject the cheated sign bit.");
    }


    /// <summary>Computes the witness for one transcribed example.</summary>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="example">The example.</param>
    /// <returns>The witness, or <see langword="null"/> when the generator rejects it.</returns>
    private static LongfellowMlDsaWitness? ComputeWitness(LongfellowMlDsaParameters parameters, LongfellowMlDsaSignatureExample example)
    {
        return LongfellowMlDsaWitness.Compute(
            parameters,
            Convert.FromHexString(example.PublicKey),
            Convert.FromHexString(example.Signature),
            Convert.FromHexString(example.Message),
            Convert.FromHexString(example.Context));
    }


    /// <summary>The reference evaluation test's <c>convert_pk</c>: interns the decoded key's values as constants.</summary>
    /// <param name="backend">The evaluation backend.</param>
    /// <param name="logic">The gadget layer.</param>
    /// <param name="field">The field bundle.</param>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="witness">The computed witness.</param>
    /// <returns>The interned bundle.</returns>
    private static LongfellowMlDsaPublicKeyWires ConvertPublicKey(
        LongfellowEvaluationLogicBackend backend,
        LongfellowLogic logic,
        LongfellowLogicFieldOperations field,
        LongfellowMlDsaParameters parameters,
        LongfellowMlDsaWitness witness)
    {
        var publicKey = new LongfellowMlDsaPublicKeyWires(parameters);
        for(int row = 0; row < parameters.RowCount; row++)
        {
            for(int column = 0; column < parameters.ColumnCount; column++)
            {
                InternPolynomial(backend, field, witness.PublicKey.MatrixA[row][column], publicKey.MatrixA.Rows[row][column]);
            }
        }

        for(int row = 0; row < parameters.RowCount; row++)
        {
            InternPolynomial(backend, field, witness.NttT1[row], publicKey.NttT1[row]);
        }

        for(int i = 0; i < witness.Tr.Length; i++)
        {
            publicKey.Tr[i] = logic.BitVector(LongfellowLogic.BitWidth8, witness.Tr[i]);
        }

        return publicKey;
    }


    /// <summary>The reference evaluation test's <c>convert_sig</c>: interns the decoded signature's values as constants.</summary>
    /// <param name="backend">The evaluation backend.</param>
    /// <param name="logic">The gadget layer.</param>
    /// <param name="field">The field bundle.</param>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="witness">The computed witness.</param>
    /// <returns>The interned bundle.</returns>
    private static LongfellowMlDsaSignatureWires ConvertSignature(
        LongfellowEvaluationLogicBackend backend,
        LongfellowLogic logic,
        LongfellowLogicFieldOperations field,
        LongfellowMlDsaParameters parameters,
        LongfellowMlDsaWitness witness)
    {
        var signature = new LongfellowMlDsaSignatureWires(parameters);
        for(int i = 0; i < parameters.CommitmentBytes; i++)
        {
            signature.CommitmentHash[i] = logic.BitVector(LongfellowLogic.BitWidth8, witness.CommitmentHash[i]);
        }

        for(int i = 0; i < parameters.ColumnCount; i++)
        {
            InternPolynomial(backend, field, witness.Signature.Z[i], signature.Z[i]);
            for(int j = 0; j < LongfellowMlDsaParameters.CoefficientCount; j++)
            {
                signature.ZBits[i][j] = logic.BitVector(parameters.ResponseBitWidth, witness.ZBits[i][j]);
            }
        }

        for(int i = 0; i < parameters.RowCount; i++)
        {
            for(int j = 0; j < LongfellowMlDsaParameters.CoefficientCount; j++)
            {
                signature.Hints[i].Coefficients[j] = backend.Constant(witness.Signature.Hints[i][j] ? field.Compiler.One.Span : field.Compiler.Zero.Span);
            }
        }

        return signature;
    }


    /// <summary>The reference evaluation test's <c>convert_witness</c>: interns every witness region as constants.</summary>
    /// <param name="backend">The evaluation backend.</param>
    /// <param name="logic">The gadget layer.</param>
    /// <param name="field">The field bundle.</param>
    /// <param name="parameters">The parameter set.</param>
    /// <param name="witness">The computed witness.</param>
    /// <returns>The interned bundle.</returns>
    private static LongfellowMlDsaWitnessWires ConvertWitness(
        LongfellowEvaluationLogicBackend backend,
        LongfellowLogic logic,
        LongfellowLogicFieldOperations field,
        LongfellowMlDsaParameters parameters,
        LongfellowMlDsaWitness witness)
    {
        var wires = new LongfellowMlDsaWitnessWires(parameters, witness.CommitmentBlockWitnesses.Count);
        InternPolynomial(backend, field, witness.ChallengeCoefficients, wires.Challenge);

        InternBlockWitness(logic, witness.SampleInBallBlockWitness, wires.SampleInBall.BlockWitness);
        for(int i = 0; i < parameters.ChallengeWeight; i++)
        {
            wires.SampleInBall.JValues[i] = logic.BitVector(LongfellowLogic.BitWidth8, witness.JValues[i]);
            wires.SampleInBall.JIndices[i] = logic.BitVector(LongfellowLogic.BitWidth16, witness.JIndices[i]);
        }

        for(int s = 0; s < parameters.ChallengeWeight; s++)
        {
            for(int k = 0; k <= s; k++)
            {
                wires.SampleInBall.PositionTrace[s][k] = logic.BitVector(LongfellowLogic.BitWidth8, witness.PositionTrace[s][k]);
            }
        }

        for(int i = 0; i < parameters.ColumnCount; i++)
        {
            InternPolynomial(backend, field, witness.NttZ[i], wires.NttZ[i]);
        }

        InternPolynomial(backend, field, witness.NttC, wires.NttC);
        for(int i = 0; i < parameters.RowCount; i++)
        {
            InternPolynomial(backend, field, witness.WPrimeApprox[i], wires.WPrimeApprox[i]);
        }

        for(int i = 0; i < parameters.RowCount; i++)
        {
            for(int k = 0; k < LongfellowMlDsaParameters.CoefficientCount; k++)
            {
                int highValue = witness.W1[i][k];
                if(highValue < 0)
                {
                    highValue += (int)LongfellowMlDsaParameters.Modulus;
                }

                wires.W1[i].Coefficients[k] = backend.Constant(field.OfScalar((ulong)highValue).Span);
                wires.HintAuxBits[i][k] = logic.BitVector(parameters.LowBitsWidth + 1, witness.HintAuxBits[i][k]);
                wires.W1Bits[i][k] = logic.BitVector(parameters.HighBitsWidth, witness.W1Bits[i][k]);
            }
        }

        for(int i = 0; i < parameters.RowCount; i++)
        {
            for(int k = 0; k < LongfellowMlDsaParameters.CoefficientCount; k++)
            {
                wires.WPrime1[i].Coefficients[k] = backend.Constant(field.OfScalar((ulong)witness.WPrime1[i][k]).Span);
                wires.WPrime1Bits[i][k] = logic.BitVector(parameters.HighBitsWidth, witness.WPrime1Bits[i][k]);
            }
        }

        for(int i = 0; i < witness.W1Tilde.Length; i++)
        {
            wires.W1Tilde[i] = logic.BitVector(LongfellowLogic.BitWidth8, witness.W1Tilde[i]);
        }

        for(int i = 0; i < witness.CommitmentBlockWitnesses.Count; i++)
        {
            InternBlockWitness(logic, witness.CommitmentBlockWitnesses[i], wires.CommitmentBlockWitnesses[i]);
        }

        wires.HintSumBits = logic.BitVector(parameters.HintWeightBitWidth, witness.HintSum);

        return wires;
    }


    /// <summary>Interns a polynomial's canonical coefficients as constant element wires.</summary>
    /// <param name="backend">The evaluation backend.</param>
    /// <param name="field">The field bundle.</param>
    /// <param name="values">The canonical coefficients.</param>
    /// <param name="destination">The bundle to fill.</param>
    private static void InternPolynomial(LongfellowEvaluationLogicBackend backend, LongfellowLogicFieldOperations field, uint[] values, LongfellowMlDsaPolynomialWires destination)
    {
        for(int i = 0; i < LongfellowMlDsaParameters.CoefficientCount; i++)
        {
            destination.Coefficients[i] = backend.Constant(field.OfScalar(values[i]).Span);
        }
    }


    /// <summary>Interns a polynomial's canonical coefficients as a fresh constant bundle.</summary>
    /// <param name="backend">The evaluation backend.</param>
    /// <param name="field">The field bundle.</param>
    /// <param name="values">The canonical coefficients.</param>
    /// <returns>The interned bundle.</returns>
    private static LongfellowMlDsaPolynomialWires InternPolynomial(LongfellowEvaluationLogicBackend backend, LongfellowLogicFieldOperations field, uint[] values)
    {
        var destination = new LongfellowMlDsaPolynomialWires();
        InternPolynomial(backend, field, values, destination);

        return destination;
    }


    /// <summary>The reference evaluation test's <c>convert_block_witness</c>: interns every round's lanes as constant bit vectors.</summary>
    /// <param name="logic">The gadget layer.</param>
    /// <param name="witness">The host-side witness.</param>
    /// <param name="destination">The wire bundle to fill.</param>
    private static void InternBlockWitness(LongfellowLogic logic, LongfellowSha3BlockWitness witness, LongfellowSha3BlockWitnessWires destination)
    {
        for(int round = 0; round < LongfellowSha3Constants.RoundCount; round++)
        {
            for(int x = 0; x < GridSize; x++)
            {
                for(int y = 0; y < GridSize; y++)
                {
                    destination.AIntermediate[round][x][y] = logic.BitVector(LaneBits, witness.AIntermediate[round][x][y]);
                }
            }
        }
    }


    /// <summary>Interns a witness list as constant wire bundles.</summary>
    /// <param name="logic">The gadget layer.</param>
    /// <param name="witnesses">The host-side witnesses.</param>
    /// <returns>The interned bundles.</returns>
    private static LongfellowSha3BlockWitnessWires[] InternBlockWitnesses(LongfellowLogic logic, IReadOnlyList<LongfellowSha3BlockWitness> witnesses)
    {
        var bundles = new LongfellowSha3BlockWitnessWires[witnesses.Count];
        for(int i = 0; i < witnesses.Count; i++)
        {
            bundles[i] = new LongfellowSha3BlockWitnessWires();
            InternBlockWitness(logic, witnesses[i], bundles[i]);
        }

        return bundles;
    }


    /// <summary>Interns bytes as constant eight-bit vectors.</summary>
    /// <param name="logic">The gadget layer.</param>
    /// <param name="bytes">The bytes to intern.</param>
    /// <returns>The byte vectors.</returns>
    private static LongfellowBitWire[][] InternBytes(LongfellowLogic logic, ReadOnlySpan<byte> bytes)
    {
        var vectors = new LongfellowBitWire[bytes.Length][];
        for(int i = 0; i < bytes.Length; i++)
        {
            vectors[i] = logic.BitVector(LongfellowLogic.BitWidth8, bytes[i]);
        }

        return vectors;
    }


    /// <summary>The reference evaluation test's <c>normalize</c>: reduces a signed value into the canonical range.</summary>
    /// <param name="value">The value to reduce.</param>
    /// <returns>The canonical representative.</returns>
    private static ulong NormalizeModQ(long value)
    {
        long reduced = value % LongfellowMlDsaParameters.Modulus;
        if(reduced < 0)
        {
            reduced += LongfellowMlDsaParameters.Modulus;
        }

        return (ulong)reduced;
    }


    /// <summary>Builds the sextic-extension field bundle over the backend delegates.</summary>
    /// <returns>The bundle.</returns>
    private static LongfellowLogicFieldOperations NewFp24SexticBundle()
    {
        var minusOne = new byte[Scalar.SizeBytes];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(minusOne.AsSpan(Scalar.SizeBytes - 4, 4), Fp24SexticBackend.Modulus - 1);

        return LongfellowLogicFieldOperations.CreateFp24Sextic(
            Fp24SexticBackend.GetAdd(),
            Fp24SexticBackend.GetSubtract(),
            Fp24SexticBackend.GetMultiply(),
            Fp24SexticBackend.GetInvert(),
            minusOne);
    }
}
