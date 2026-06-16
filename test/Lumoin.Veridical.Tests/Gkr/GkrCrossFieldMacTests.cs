using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Gkr;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using System;
using System.Buffers;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Gkr;

/// <summary>
/// The COMPLETE cross-field MAC: one 256-bit value — a real SHA-256 digest — committed
/// independently on the Fp256 side and the GF(2^128) side, bound by
/// <c>mac_h = (a_p,h + a_v)·x_h</c> with both commitments fixed before the shared transcript
/// yields <c>a_v</c>. The GF side checks its macs natively (the one-layer instance); the Fp side
/// simulates the same GF arithmetic as pure Ligero statement work — committed carry-less
/// products, fold-parity linear constraints with post-challenge public coefficients, and the
/// masked-quotient publication (see <see cref="GkrCrossFieldMacSupport"/>). The fold-map parity
/// simulation is gated directly against the carry-less backend before any proof trusts it. The
/// reference's canonicity (vlt) check is deliberately absent: the bits ARE the message on both
/// sides; canonicity matters only when recomposing bits into a unique field element, which is
/// the separately-solved LF.5 problem.
/// </summary>
[TestClass]
internal sealed class GkrCrossFieldMacTests
{
    private const int ScalarSize = GkrCrossFieldMacSupport.ScalarSize;
    private const int HalfBits = GkrCrossFieldMacSupport.HalfBits;
    private const int Halves = GkrCrossFieldMacSupport.Halves;
    private const int FpWitnessBytes = GkrCrossFieldMacSupport.FpWitnessBytes;

    private const int InverseRate = 4;
    private const int OpenedColumns = 4;
    private const int Block = 64;

    private static FiatShamirDomainLabel Domain { get; } = new("veridical.gkr.crossmac.test");

    private static FiatShamirOperationLabel FpSeedLabel { get; } = new("veridical.gkr.crossmac.fp.seed");

    private static byte[] FpRandomnessSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.gkr.crossmac.fp.rng.v1");

    private static byte[] GfRandomnessSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.gkr.crossmac.gf.rng.v1");

    private static byte[] MaskSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.gkr.crossmac.mask.v1");

    private static byte[][] KeyShares { get; } =
    [
        GkrCrossFieldMacSupport.Element(0x0123456789abcdefUL, 0x0fedcba987654321UL),
        GkrCrossFieldMacSupport.Element(0xdeadbeefcafebabeUL, 0x13579bdf2468ace0UL),
    ];

    //The 256-bit value bound across the two fields: a real digest.
    private static byte[] Value { get; } = SHA256.HashData("abc"u8);


    [TestMethod]
    public void TheFoldedParitySimulationMatchesTheCarrylessBackend()
    {
        //Several verifier keys, including degenerate ones; the simulated mac bits must match
        //the native multiplication for every half.
        byte[][] verifierKeys =
        [
            GkrCrossFieldMacSupport.Element(0, 0),
            GkrCrossFieldMacSupport.Element(0, 1),
            GkrCrossFieldMacSupport.Element(0xffffffffffffffffUL, 0xffffffffffffffffUL),
            GkrCrossFieldMacSupport.Element(0x0f1e2d3c4b5a6978UL, 0x8796a5b4c3d2e1f0UL),
        ];
        Span<byte> expected = stackalloc byte[ScalarSize];
        Span<byte> key = stackalloc byte[ScalarSize];
        Span<byte> half = stackalloc byte[ScalarSize];
        foreach(byte[] verifierKey in verifierKeys)
        {
            for(int h = 0; h < Halves; h++)
            {
                GkrGf2kMacSupport.HalfElement(Value, h, half);
                GkrGf2kTestSupport.Add(KeyShares[h], verifierKey, key, CurveParameterSet.None);
                GkrGf2kTestSupport.Multiply(key, half, expected, CurveParameterSet.None);

                long[] integers = IntegerColumnSums(h, verifierKey);
                for(int j = 0; j < HalfBits; j++)
                {
                    int simulated = (int)(integers[j] & 1);
                    Assert.AreEqual(GkrCrossFieldMacSupport.ElementBit(expected, j), simulated, $"Mac bit {j} of half {h} must match the carry-less backend.");
                }
            }
        }
    }


    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void TheCrossFieldMacBindsTheTwoCommitments()
    {
        //On the order of five to ten minutes, hardware-dependent (the 41k-quadratic Fp
        //BigInteger tableau dominates): the full two-commitment protocol through the real
        //provers. The default-suite gate checks the fold-parity simulation against the
        //carry-less backend cheaply, so this gate adds the end-to-end proving, not the logic
        //coverage.
        using IMemoryOwner<byte> fpWitnessOwner = BaseMemoryPool.Shared.Rent(FpWitnessBytes);
        Span<byte> fpWitness = fpWitnessOwner.Memory.Span[..FpWitnessBytes];
        GkrCrossFieldMacSupport.PackFpWitness(fpWitness, Value, KeyShares, MaskSeed);
        using IMemoryOwner<byte> gfWitnessOwner = BaseMemoryPool.Shared.Rent(GkrGf2kMacSupport.WitnessBytes);
        Span<byte> gfWitness = gfWitnessOwner.Memory.Span[..GkrGf2kMacSupport.WitnessBytes];
        GkrGf2kMacSupport.PackGfWitness(gfWitness, Value, KeyShares);

        Span<byte> verifierKey = stackalloc byte[ScalarSize];
        Span<byte> macs = stackalloc byte[Halves * ScalarSize];
        ulong[] maskedQuotients = new ulong[Halves * HalfBits];
        (LigeroProof fpProof, GkrCommittedProof gfProof) = ProveCrossField(fpWitness, gfWitness, Value, verifierKey, macs, maskedQuotients);
        using LigeroProof fp = fpProof;
        using GkrCommittedProof gf = gfProof;

        Assert.IsTrue(VerifyCrossField(fp, gf, macs, maskedQuotients), "Both halves of the cross-field MAC must verify against the shared post-commit key.");

        //A flipped mac byte must be rejected — by the GF walk and by the Fp parity targets.
        Span<byte> wrongMacs = stackalloc byte[Halves * ScalarSize];
        macs.CopyTo(wrongMacs);
        wrongMacs[ScalarSize - 1] ^= 0x01;
        Assert.IsFalse(VerifyCrossField(fp, gf, wrongMacs, maskedQuotients), "A mac differing in one byte must be rejected.");
    }


    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void AFpCommitmentOfADifferentValueIsUnprovable()
    {
        //On the order of a few minutes, hardware-dependent — the prove attempt must build the
        //full Fp tableau before the parity statement fails.
        //The Fp side commits a value differing in one bit; the GF side holds the honest value,
        //so the macs reflect it. For some mac bit the Fp integer column sum has the wrong
        //parity, no masked quotient exists, and the parity constraint is unsatisfiable.
        byte[] tampered = (byte[])Value.Clone();
        tampered[3] ^= 0x40;
        byte[] fpWitness = new byte[FpWitnessBytes];
        GkrCrossFieldMacSupport.PackFpWitness(fpWitness, tampered, KeyShares, MaskSeed);
        byte[] gfWitness = new byte[GkrGf2kMacSupport.WitnessBytes];
        GkrGf2kMacSupport.PackGfWitness(gfWitness, Value, KeyShares);

        byte[] keyCopy = new byte[ScalarSize];
        byte[] macsCopy = new byte[Halves * ScalarSize];
        ulong[] maskedQuotients = new ulong[Halves * HalfBits];

        Assert.ThrowsExactly<InvalidOperationException>(
            () => ProveCrossField(fpWitness, gfWitness, Value, keyCopy, macsCopy, maskedQuotients),
            "An Fp commitment of a different value cannot satisfy the parity constraints for the honest macs.");
    }


    //The full prover protocol: commit Fp, commit GF (both roots into the shared transcript),
    //squeeze the verifier key, compute the macs from the GF-side value, prove the GF instance,
    //then prove the Fp parity statement under a transcript-derived seed.
    private static (LigeroProof FpProof, GkrCommittedProof GfProof) ProveCrossField(
        ReadOnlySpan<byte> fpWitness,
        ReadOnlySpan<byte> gfWitness,
        ReadOnlySpan<byte> gfValue,
        Span<byte> verifierKey,
        Span<byte> macs,
        ulong[] maskedQuotients)
    {
        LigeroQuadraticConstraint[] fpQuadratics = GkrCrossFieldMacSupport.BuildFpQuadratics();
        var fpParameters = new LigeroParameters(GkrCrossFieldMacSupport.FpWitnessCount, fpQuadratics.Length, InverseRate, OpenedColumns, Block);
        LigeroQuadraticConstraint[] gfBitness = GkrGf2kMacSupport.BuildGfBitness();
        var gfParameters = new LigeroParameters(GkrGf2kMacSupport.CopyCount * GkrGf2kMacSupport.InputCount, gfBitness.Length, InverseRate, OpenedColumns, Block, LigeroNodeDomain.BinaryField);

        using FiatShamirTranscript transcript = NewTranscript();

        using LigeroCommitment fpCommitment = LigeroProver.Commit(
            fpParameters, fpWitness, fpQuadratics, new GkrCrossFieldMacSupport.FpDeterministicRandom(FpRandomnessSeed).AsDelegate(),
            GkrTestSupport.Add, GkrTestSupport.Subtract, GkrTestSupport.Multiply, GkrTestSupport.Invert,
            GkrTestSupport.Hash, WellKnownHashAlgorithms.Blake3, GkrTestSupport.Merkle, CurveParameterSet.None,
            BaseMemoryPool.Shared);
        transcript.AbsorbLigeroTableauRoot(fpCommitment.Root, GkrTestSupport.Hash);

        using LigeroCommitment gfCommitment = GkrCommittedProver.Commit(
            gfWitness, gfParameters, gfBitness,
            () => new GkrCrossFieldMacSupport.GfDeterministicRandom(GfRandomnessSeed).AsDelegate(),
            GkrGf2kTestSupport.Add, GkrGf2kTestSupport.Subtract, GkrGf2kTestSupport.Multiply, GkrGf2kTestSupport.Invert, CurveParameterSet.None,
            transcript, GkrGf2kTestSupport.Hash, GkrGf2kTestSupport.Hash, GkrTestSupport.Merkle, WellKnownHashAlgorithms.Blake3,
            BaseMemoryPool.Shared);

        //Both witnesses are now fixed; the verifier key and the public macs follow them.
        GkrGf2kMacSupport.SqueezeVerifierKey(transcript, verifierKey);
        GkrGf2kMacSupport.ComputeMacs(gfValue, KeyShares, verifierKey, macs);

        GkrCommittedInstance[] instances = [new GkrCommittedInstance(GkrGf2kMacSupport.BuildMacCircuit(verifierKey), GkrGf2kMacSupport.CopyCount)];
        GkrCommittedProof gfProof = GkrCommittedProver.Prove(
            gfCommitment, instances, [], [],
            GkrGf2kTestSupport.Add, GkrGf2kTestSupport.Subtract, GkrGf2kTestSupport.Multiply, GkrGf2kTestSupport.Invert, GkrGf2kTestSupport.Reduce, CurveParameterSet.None,
            transcript, GkrGf2kTestSupport.Squeeze, GkrGf2kTestSupport.Hash,
            BaseMemoryPool.Shared);

        //The Fp parity statement: the masked quotients come from THIS witness's integer sums.
        GkrCrossFieldMacSupport.ComputeMaskedQuotients(fpWitness, verifierKey, macs, maskedQuotients);
        (LigeroLinearConstraint[] constraints, byte[] targets) = GkrCrossFieldMacSupport.BuildParityStatement(verifierKey, macs, maskedQuotients);

        Span<byte> fpSeed = stackalloc byte[ScalarSize];
        transcript.SqueezeBytes(FpSeedLabel, fpSeed, GkrTestSupport.Squeeze, GkrTestSupport.Hash);

        LigeroProof fpProof;
        try
        {
            fpProof = LigeroProver.Prove(
                fpCommitment, Halves * HalfBits, constraints, targets, fpSeed,
                GkrTestSupport.Add, GkrTestSupport.Subtract, GkrTestSupport.Multiply, GkrTestSupport.Invert, GkrTestSupport.Reduce,
                GkrTestSupport.Hash, GkrTestSupport.Squeeze, CurveParameterSet.None,
                BaseMemoryPool.Shared);
        }
        catch
        {
            gfProof.Dispose();
            throw;
        }

        return (fpProof, gfProof);
    }


    //The full verifier protocol, mirroring the prover's transcript order exactly.
    private static bool VerifyCrossField(LigeroProof fpProof, GkrCommittedProof gfProof, ReadOnlySpan<byte> macs, ulong[] maskedQuotients)
    {
        LigeroQuadraticConstraint[] fpQuadratics = GkrCrossFieldMacSupport.BuildFpQuadratics();
        var fpParameters = new LigeroParameters(GkrCrossFieldMacSupport.FpWitnessCount, fpQuadratics.Length, InverseRate, OpenedColumns, Block);
        LigeroQuadraticConstraint[] gfBitness = GkrGf2kMacSupport.BuildGfBitness();
        var gfParameters = new LigeroParameters(GkrGf2kMacSupport.CopyCount * GkrGf2kMacSupport.InputCount, gfBitness.Length, InverseRate, OpenedColumns, Block, LigeroNodeDomain.BinaryField);

        using FiatShamirTranscript transcript = NewTranscript();
        transcript.AbsorbLigeroTableauRoot(fpProof.Root, GkrTestSupport.Hash);
        GkrCommittedVerifier.AbsorbCommitmentRoot(gfProof, transcript, GkrGf2kTestSupport.Hash);

        Span<byte> verifierKey = stackalloc byte[ScalarSize];
        GkrGf2kMacSupport.SqueezeVerifierKey(transcript, verifierKey);

        GkrCommittedInstance[] instances = [new GkrCommittedInstance(GkrGf2kMacSupport.BuildMacCircuit(verifierKey), GkrGf2kMacSupport.CopyCount)];
        Span<byte> outputs = stackalloc byte[GkrGf2kMacSupport.OutputBytes];
        outputs.Clear();
        for(int h = 0; h < Halves; h++)
        {
            macs.Slice(h * ScalarSize, ScalarSize).CopyTo(outputs.Slice(h * GkrGf2kMacSupport.OutputCount * ScalarSize, ScalarSize));
        }

        if(!GkrCommittedVerifier.VerifyFromAbsorbedRoot(
            instances, outputs, gfProof, gfParameters, [], [], gfBitness,
            GkrGf2kTestSupport.Add, GkrGf2kTestSupport.Subtract, GkrGf2kTestSupport.Multiply, GkrGf2kTestSupport.Invert, GkrGf2kTestSupport.Reduce, CurveParameterSet.None,
            transcript, GkrGf2kTestSupport.Squeeze, GkrGf2kTestSupport.Hash, GkrGf2kTestSupport.Hash, GkrTestSupport.Merkle, WellKnownHashAlgorithms.Blake3,
            BaseMemoryPool.Shared))
        {
            return false;
        }

        (LigeroLinearConstraint[] constraints, byte[] targets) = GkrCrossFieldMacSupport.BuildParityStatement(verifierKey, macs, maskedQuotients);

        Span<byte> fpSeed = stackalloc byte[ScalarSize];
        transcript.SqueezeBytes(FpSeedLabel, fpSeed, GkrTestSupport.Squeeze, GkrTestSupport.Hash);

        return LigeroVerifier.Verify(
            fpParameters, fpProof, Halves * HalfBits, constraints, targets, fpQuadratics, fpSeed,
            GkrTestSupport.Add, GkrTestSupport.Subtract, GkrTestSupport.Multiply, GkrTestSupport.Invert, GkrTestSupport.Reduce,
            GkrTestSupport.Hash, GkrTestSupport.Squeeze, GkrTestSupport.Hash, GkrTestSupport.Merkle, WellKnownHashAlgorithms.Blake3, CurveParameterSet.None,
            BaseMemoryPool.Shared);
    }


    //The integer column sums of one half, from the canonical value and key shares — the
    //oracle-side computation.
    private static long[] IntegerColumnSums(int half, ReadOnlySpan<byte> verifierKey)
    {
        long[] sums = new long[HalfBits];
        for(int k = 0; k < HalfBits; k++)
        {
            int keyBit = GkrCrossFieldMacSupport.ElementBit(KeyShares[half], k) ^ GkrCrossFieldMacSupport.ElementBit(verifierKey, k);
            if(keyBit == 0)
            {
                continue;
            }

            for(int i = 0; i < HalfBits; i++)
            {
                if(GkrGf2kMacSupport.HalfBit(Value, half, i) == 0)
                {
                    continue;
                }

                foreach(int position in GkrCrossFieldMacSupport.FoldMap[i + k])
                {
                    sums[position]++;
                }
            }
        }

        return sums;
    }


    private static FiatShamirTranscript NewTranscript() =>
        GkrGf2kTestSupport.NewTranscript(Domain, "veridical.gkr.crossmac.seed"u8, []);
}
