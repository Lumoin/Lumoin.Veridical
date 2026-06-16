using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Spartan;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

using static Lumoin.Veridical.Tests.Spartan.FoldChainTestFixtures;
using static Lumoin.Veridical.Tests.Spartan.MaskedSpartanTestFixtures;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// Soundness leg of the <see cref="FoldChain"/> gate: folding a
/// statement whose witness does not satisfy the constraints yields an
/// unsatisfied accumulator that cannot be compressed. The fold step
/// itself performs no satisfaction check — it folds the claimed error
/// vectors algebraically — so an unsatisfied incoming statement leaves
/// the accumulator's stored error vector inconsistent with its true
/// error by the <c>r²</c>-weighted incoming residual. The masked
/// prover's satisfaction check at compression time catches this and
/// throws <see cref="R1csNotSatisfiedException"/>, matching the base and
/// masked provers' soundness contract.
/// </summary>
[TestClass]
internal sealed class FoldChainSoundnessTests
{
    private const int HyraxVectorLength = 2;


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000", Justification = "Test composes ownership through using declarations.")]
    public void FoldingAnUnsatisfiedStatementFailsToCompress()
    {
        //BuildUnsatisfyingWitness violates constraint 0 (3·5 = 15 but z[3] = 99).
        AssertUnsatisfiedStatementRejected(BuildUnsatisfyingWitness());
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000", Justification = "Test composes ownership through using declarations.")]
    public void FoldingAnOffByOneStatementFailsToCompress()
    {
        //Almost-satisfying: z = (1, 3, 5, 16) instead of (1, 3, 5, 15).
        AssertUnsatisfiedStatementRejected(BuildOffByOneWitness());
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Test composes ownership through using declarations; the unsatisfying witness is consumed by the fold step.")]
    private static void AssertUnsatisfiedStatementRejected(RawR1csWitness unsatisfyingWitness)
    {
        using PolynomialCommitmentProvider provider = BuildProvider(BuildCommitmentKey(HyraxVectorLength), ScalarRandom);
        using MaskedSpartanProver prover = BuildMaskedProver(HyraxVectorLength, ScalarRandom);

        using RawR1csInstance template = BuildOneMultiplyInstance();
        using FiatShamirTranscript foldTranscript = FreshTranscript();
        using FoldChain chain = StartChain(template, provider, foldTranscript, ScalarRandom);

        //The fold step does not validate satisfaction — it completes,
        //leaving the accumulator unsatisfied.
        StepRaw(chain, BuildOneMultiplyInstance(), unsatisfyingWitness, ScalarRandom);

        using FiatShamirTranscript proverTranscript = FreshTranscript();
        Assert.ThrowsExactly<R1csNotSatisfiedException>(() =>
        {
            using MaskedSpartanProof _ = Compress(chain, prover, proverTranscript, ScalarRandom);
        });
    }


    private static RawR1csWitness BuildOffByOneWitness()
    {
        int scalarSize = Scalar.SizeBytes;
        byte[] witnessBytes = new byte[3 * scalarSize];
        WriteCanonical(new BigInteger(3), witnessBytes.AsSpan(0 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(5), witnessBytes.AsSpan(1 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(16), witnessBytes.AsSpan(2 * scalarSize, scalarSize));

        return RawR1csWitness.FromCanonical(witnessBytes, Curve, Pool);
    }
}