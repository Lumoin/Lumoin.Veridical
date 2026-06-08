using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

using static Lumoin.Veridical.Tests.Spartan.MaskedSpartanTestFixtures;

namespace Lumoin.Veridical.Tests.ConstraintSystems;

/// <summary>
/// Tests for the Nova-style relaxed-R1CS fold step
/// (<see cref="RelaxedR1csFold"/>): the folded pair satisfies the
/// relaxed identity, a folded accumulator can be folded again (a real
/// chain with a non-trivial <c>u</c>, error vector, and error
/// commitment on the left), and the homomorphically-combined error
/// commitment genuinely opens to the folded error vector under the
/// folded blinding.
/// </summary>
[TestClass]
internal sealed class RelaxedR1csFoldTests
{
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;

    private static SensitiveMemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000", Justification = "Test composes ownership through using declarations; everything is disposed before the assertion completes.")]
    public void FoldOfTwoPreparedInstancesSatisfiesTheRelaxedIdentity()
    {
        using PolynomialCommitmentProvider provider = BuildProvider(BuildCommitmentKey());

        using PreparedPair a = PreparedPair.From(BuildOneMultiplyInstance(), BuildOneMultiplyWitness());
        using PreparedPair b = PreparedPair.From(BuildOneMultiplyInstance(), BuildAlternativeOneMultiplyWitness());

        using FiatShamirTranscript transcript = FreshTranscript();
        (RelaxedR1csInstance folded, RelaxedR1csWitness foldedWitness, PolynomialCommitmentBlind foldedErrorOpeningWitness) =
            RelaxedR1csFold.Fold(
                a.Instance, a.Witness, a.ErrorOpeningWitness,
                b.Instance, b.Witness, b.ErrorOpeningWitness,
                provider, transcript,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, ScalarRandom,
                G1Add, G1ScalarMul, G1Msm, Pool);

        using(folded)
        using(foldedWitness)
        using(foldedErrorOpeningWitness)
        {
            using R1csSatisfaction satisfaction = folded.CheckSatisfiedBy(foldedWitness, Add, Multiply, Pool);
            Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(
                satisfaction,
                "The fold of two satisfied relaxed instances must satisfy the relaxed identity.");
        }
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000", Justification = "Test composes ownership through using declarations; everything is disposed before the assertion completes.")]
    public void FoldedAccumulatorCanBeFoldedAgain()
    {
        //The second fold's left operand is a real folded accumulator —
        //u != 1, a non-zero error vector, and a non-identity error
        //commitment with real blinding — so this exercises the general
        //fold, not just the prepared (identity) case.
        using PolynomialCommitmentProvider provider = BuildProvider(BuildCommitmentKey());

        using PreparedPair a = PreparedPair.From(BuildOneMultiplyInstance(), BuildOneMultiplyWitness());
        using PreparedPair b = PreparedPair.From(BuildOneMultiplyInstance(), BuildAlternativeOneMultiplyWitness());
        using PreparedPair c = PreparedPair.From(BuildOneMultiplyInstance(), BuildOneMultiplyWitness());

        using FiatShamirTranscript firstTranscript = FreshTranscript();
        (RelaxedR1csInstance acc1, RelaxedR1csWitness accW1, PolynomialCommitmentBlind accEow1) =
            RelaxedR1csFold.Fold(
                a.Instance, a.Witness, a.ErrorOpeningWitness,
                b.Instance, b.Witness, b.ErrorOpeningWitness,
                provider, firstTranscript,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, ScalarRandom,
                G1Add, G1ScalarMul, G1Msm, Pool);

        using(acc1)
        using(accW1)
        using(accEow1)
        {
            using FiatShamirTranscript secondTranscript = FreshTranscript();
            (RelaxedR1csInstance acc2, RelaxedR1csWitness accW2, PolynomialCommitmentBlind accEow2) =
                RelaxedR1csFold.Fold(
                    acc1, accW1, accEow1,
                    c.Instance, c.Witness, c.ErrorOpeningWitness,
                    provider, secondTranscript,
                    Hash, Squeeze, Reduce, Add, Subtract, Multiply, ScalarRandom,
                    G1Add, G1ScalarMul, G1Msm, Pool);

            using(acc2)
            using(accW2)
            using(accEow2)
            {
                using R1csSatisfaction satisfaction = acc2.CheckSatisfiedBy(accW2, Add, Multiply, Pool);
                Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(
                    satisfaction,
                    "Folding a third instance into the accumulator must keep the relaxed identity satisfied.");
            }
        }
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000", Justification = "Test composes ownership through using declarations; everything is disposed before the assertion completes.")]
    public void FoldedErrorCommitmentOpensToTheFoldedErrorVector()
    {
        using HyraxCommitmentKey commitmentKey = BuildCommitmentKey();
        using PolynomialCommitmentProvider provider = HyraxPolynomialCommitmentScheme.Create(
            commitmentKey,
            Curve,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
            G1Add, G1ScalarMul, G1Msm,
            ownsKey: false);

        using PreparedPair a = PreparedPair.From(BuildOneMultiplyInstance(), BuildOneMultiplyWitness());
        using PreparedPair b = PreparedPair.From(BuildOneMultiplyInstance(), BuildAlternativeOneMultiplyWitness());

        using FiatShamirTranscript foldTranscript = FreshTranscript();
        (RelaxedR1csInstance folded, RelaxedR1csWitness foldedWitness, PolynomialCommitmentBlind foldedErrorOpeningWitness) =
            RelaxedR1csFold.Fold(
                a.Instance, a.Witness, a.ErrorOpeningWitness,
                b.Instance, b.Witness, b.ErrorOpeningWitness,
                provider, foldTranscript,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, ScalarRandom,
                G1Add, G1ScalarMul, G1Msm, Pool);

        using(folded)
        using(foldedWitness)
        using(foldedErrorOpeningWitness)
        {
            int rowVariableCount = BitOperations.Log2((uint)folded.A.RowCount);

            using MultilinearExtension errorMle = MultilinearExtension.FromEvaluations(
                foldedWitness.GetErrorBytes(), rowVariableCount, Curve, Pool);

            //The generic error commitment / blind carry the same canonical bytes
            //a Hyrax commitment / opening witness expose; rebuild the Hyrax views
            //(matrix shape derives from the error MLE's variable count) to drive
            //the Hyrax open/verify extension methods directly.
            HyraxCommitmentDimensions dimensions = HyraxCommitmentDimensions.ForVariableCount(rowVariableCount);

            using HyraxCommitment errorCommitment = HyraxCommitment.FromBytes(
                folded.ErrorCommitment.AsReadOnlySpan(),
                dimensions.RowCount,
                dimensions.ColumnCount,
                rowVariableCount,
                Curve,
                Pool);
            using HyraxOpeningWitness errorOpeningWitness = HyraxOpeningWitness.FromCanonical(
                foldedErrorOpeningWitness.AsReadOnlySpan(), Curve, Pool);

            Scalar[] point = BuildPoint(rowVariableCount);
            try
            {
                using FiatShamirTranscript openTranscript = FreshTranscript();
                (HyraxOpeningProof proof, Scalar claimedValue) = errorCommitment.Open(
                    errorOpeningWitness, errorMle, point, commitmentKey, openTranscript,
                    Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
                    G1Add, G1ScalarMul, G1Msm, Pool);

                using(proof)
                using(claimedValue)
                {
                    using FiatShamirTranscript verifyTranscript = FreshTranscript();
                    bool verified = errorCommitment.VerifyOpening(
                        point, claimedValue, proof, commitmentKey, verifyTranscript,
                        Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
                        G1Add, G1ScalarMul, G1Msm, Pool);

                    Assert.IsTrue(
                        verified,
                        "The homomorphically-combined folded error commitment must open to the folded error vector under the folded blinding.");
                }
            }
            finally
            {
                foreach(Scalar scalar in point)
                {
                    scalar.Dispose();
                }
            }
        }
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the derived key transfers to the caller's using declaration.")]
    private static HyraxCommitmentKey BuildCommitmentKey()
    {
        return HyraxCommitmentKey.Derive(
            2,
            WellKnownHyraxDomainLabels.CanonicalSeedV1,
            Curve,
            HashToCurve,
            SensitiveMemoryPool<byte>.Shared);
    }


    private static Scalar[] BuildPoint(int variableCount)
    {
        int scalarSize = Scalar.SizeBytes;
        Scalar[] point = new Scalar[variableCount];
        Span<byte> buffer = stackalloc byte[scalarSize];
        for(int i = 0; i < variableCount; i++)
        {
            buffer.Clear();
            //Arbitrary distinct small evaluation coordinates.
            WriteCanonical(new BigInteger(7 + i), buffer);
            point[i] = Scalar.FromCanonical(buffer, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
        }

        return point;
    }


    /// <summary>
    /// A raw instance + witness prepared into relaxed form (<c>u = 1</c>,
    /// zero error, identity error commitment) with its matching all-zero
    /// error opening witness. Owns and disposes the prepared trio.
    /// </summary>
    private sealed class PreparedPair: IDisposable
    {
        public RelaxedR1csInstance Instance { get; }
        public RelaxedR1csWitness Witness { get; }
        public PolynomialCommitmentBlind ErrorOpeningWitness { get; }

        private PreparedPair(RelaxedR1csInstance instance, RelaxedR1csWitness witness, PolynomialCommitmentBlind errorOpeningWitness)
        {
            Instance = instance;
            Witness = witness;
            ErrorOpeningWitness = errorOpeningWitness;
        }

        [SuppressMessage("Reliability", "CA2000", Justification = "The raw instance and witness are disposed within this factory; the prepared relaxed objects transfer to the returned PreparedPair, which owns their disposal.")]
        public static PreparedPair From(RawR1csInstance rawInstance, RawR1csWitness rawWitness)
        {
            using(rawInstance)
            using(rawWitness)
            {
                RelaxedR1csInstance instance = rawInstance.Prepare(SensitiveMemoryPool<byte>.Shared);
                RelaxedR1csWitness witness = rawWitness.Prepare(rawInstance.A.RowCount, SensitiveMemoryPool<byte>.Shared);

                //The error commitment has one Hyrax row per matrix-shape row; the
                //blind is one scalar per row, so its length is rowCount × scalar size.
                int rowVariableCount = BitOperations.Log2((uint)rawInstance.A.RowCount);
                int errorCommitmentRowCount = HyraxCommitmentDimensions.ForVariableCount(rowVariableCount).RowCount;
                PolynomialCommitmentBlind errorOpeningWitness = PolynomialCommitmentBlind.CreateZero(
                    errorCommitmentRowCount * Scalar.SizeBytes, CurveParameterSet.Bls12Curve381, CommitmentScheme.Hyrax, SensitiveMemoryPool<byte>.Shared);

                return new PreparedPair(instance, witness, errorOpeningWitness);
            }
        }

        public void Dispose()
        {
            Instance.Dispose();
            Witness.Dispose();
            ErrorOpeningWitness.Dispose();
        }
    }
}