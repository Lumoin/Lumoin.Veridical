using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Gkr;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Gkr;

/// <summary>
/// The Longfellow cross-field MAC, GF(2^128) side (reference <c>lib/circuits/mac/</c>): a
/// 256-bit value <c>x</c> — here a real SHA-256 digest — splits into two 128-bit halves, and
/// <c>mac_h = (a_p,h + a_v) · x_h</c> binds each half across proofs. The prover COMMITS the key
/// shares <c>a_p</c> and the message bits; the verifier's <c>a_v</c> is squeezed from the
/// transcript AFTER the commitment root — for committed <c>x ≠ y</c> the macs collide with
/// probability at most <c>2^{-128}</c> over <c>a_v</c>. This requires the committed wrapper's
/// commit/prove split: the MAC circuit embeds <c>a_v</c> in its coefficients (uniform across
/// copies, so challenge-derived constants ARE legal coefficients), and is built between the
/// commit and the walks. The mac values are per-copy PUBLIC outputs. The shared machinery —
/// the circuit, the key squeeze, the packing conventions — lives in
/// <see cref="GkrGf2kMacSupport"/>; the Fp256 side of the binding is gated in the cross-field
/// test.
/// </summary>
[TestClass]
internal sealed class GkrGf2kMacTests
{
    private const int ScalarSize = GkrGf2kMacSupport.ScalarSize;
    private const int CopyCount = GkrGf2kMacSupport.CopyCount;
    private const int InputCount = GkrGf2kMacSupport.InputCount;
    private const int InputBytes = GkrGf2kMacSupport.WitnessBytes;
    private const int OutputCount = GkrGf2kMacSupport.OutputCount;
    private const int OutputBytes = GkrGf2kMacSupport.OutputBytes;

    private const int InverseRate = 4;
    private const int OpenedColumns = 4;
    private const int Block = 64;

    private static FiatShamirDomainLabel Domain { get; } = new("veridical.gkr.gf2k.mac.test");

    private static byte[] RandomnessSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.gkr.gf2k.mac.rng.v1");

    //The prover's committed key shares, one per half — fixed test elements with spread bits.
    private static byte[][] KeyShares { get; } =
    [
        Element(0x0123456789abcdefUL, 0x0fedcba987654321UL),
        Element(0xdeadbeefcafebabeUL, 0x13579bdf2468ace0UL),
    ];

    //The 256-bit value the MAC binds: a real digest.
    private static byte[] Value { get; } = SHA256.HashData("abc"u8);


    [TestMethod]
    public void TheMacBindsTheCommittedValueAcrossThePostCommitChallenge()
    {
        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(InputBytes);
        Span<byte> witness = witnessOwner.Memory.Span[..InputBytes];
        GkrGf2kMacSupport.PackGfWitness(witness, Value, KeyShares);
        LigeroQuadraticConstraint[] bitness = GkrGf2kMacSupport.BuildGfBitness();
        var parameters = new LigeroParameters(CopyCount * InputCount, bitness.Length, InverseRate, OpenedColumns, Block, LigeroNodeDomain.BinaryField);

        //Commit first; the verifier key exists only after the root is in the transcript.
        Span<byte> verifierKey = stackalloc byte[ScalarSize];
        Span<byte> macs = stackalloc byte[CopyCount * ScalarSize];
        using FiatShamirTranscript proverTranscript = NewTranscript();
        using GkrCommittedProof proof = ProveMac(witness, parameters, bitness, proverTranscript, verifierKey, macs);

        //The verifier replays: absorb the root, squeeze the same key, rebuild the instance.
        using(FiatShamirTranscript verifierTranscript = NewTranscript())
        {
            Assert.IsTrue(
                VerifyMac(proof, parameters, bitness, verifierTranscript, macs),
                "The committed halves must verify against the macs computed under the post-commit key.");
        }

        //A flipped mac byte is a different public claim.
        Span<byte> wrongMacs = stackalloc byte[CopyCount * ScalarSize];
        macs.CopyTo(wrongMacs);
        wrongMacs[ScalarSize - 1] ^= 0x01;
        using(FiatShamirTranscript verifierTranscript = NewTranscript())
        {
            Assert.IsFalse(
                VerifyMac(proof, parameters, bitness, verifierTranscript, wrongMacs),
                "A mac that differs in one byte must be rejected.");
        }
    }


    [TestMethod]
    public void ADifferentCommittedValueCannotMeetTheOriginalMacs()
    {
        //The honest run fixes the macs.
        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(InputBytes);
        Span<byte> witness = witnessOwner.Memory.Span[..InputBytes];
        GkrGf2kMacSupport.PackGfWitness(witness, Value, KeyShares);
        LigeroQuadraticConstraint[] bitness = GkrGf2kMacSupport.BuildGfBitness();
        var parameters = new LigeroParameters(CopyCount * InputCount, bitness.Length, InverseRate, OpenedColumns, Block, LigeroNodeDomain.BinaryField);

        Span<byte> honestKey = stackalloc byte[ScalarSize];
        Span<byte> honestMacs = stackalloc byte[CopyCount * ScalarSize];
        using(FiatShamirTranscript proverTranscript = NewTranscript())
        {
            ProveMac(witness, parameters, bitness, proverTranscript, honestKey, honestMacs).Dispose();
        }

        //A cheating prover commits a value differing in one bit. Its commitment root differs,
        //so its post-commit key differs — and its proof cannot meet the original macs.
        byte[] tampered = (byte[])Value.Clone();
        tampered[7] ^= 0x20;
        GkrGf2kMacSupport.PackGfWitness(witness, tampered, KeyShares);

        Span<byte> tamperedKey = stackalloc byte[ScalarSize];
        Span<byte> tamperedMacs = stackalloc byte[CopyCount * ScalarSize];
        using FiatShamirTranscript cheaterTranscript = NewTranscript();
        using GkrCommittedProof cheatingProof = ProveMac(witness, parameters, bitness, cheaterTranscript, tamperedKey, tamperedMacs);

        Assert.IsFalse(tamperedKey.SequenceEqual(honestKey), "A different commitment must yield a different post-commit verifier key.");

        using FiatShamirTranscript verifierTranscript = NewTranscript();
        Assert.IsFalse(
            VerifyMac(cheatingProof, parameters, bitness, verifierTranscript, honestMacs),
            "A proof over a different committed value must be rejected against the original macs.");
    }


    //The prover's side of the protocol: commit, squeeze the verifier key, compute the macs,
    //build the key-dependent instance, prove. The key and macs are returned to the caller —
    //they are the public statement.
    private static GkrCommittedProof ProveMac(
        ReadOnlySpan<byte> witness,
        LigeroParameters parameters,
        LigeroQuadraticConstraint[] bitness,
        FiatShamirTranscript transcript,
        Span<byte> verifierKey,
        Span<byte> macs)
    {
        using LigeroCommitment commitment = GkrCommittedProver.Commit(
            witness, parameters, bitness,
            () => new MacDeterministicRandom(RandomnessSeed).AsDelegate(),
            GkrGf2kTestSupport.Add, GkrGf2kTestSupport.Subtract, GkrGf2kTestSupport.Multiply, GkrGf2kTestSupport.Invert, CurveParameterSet.None,
            transcript, GkrGf2kTestSupport.Hash, GkrGf2kTestSupport.Hash, GkrTestSupport.Merkle, WellKnownHashAlgorithms.Blake3,
            BaseMemoryPool.Shared);

        GkrGf2kMacSupport.SqueezeVerifierKey(transcript, verifierKey);
        ComputeMacsFromWitness(witness, verifierKey, macs);

        GkrCommittedInstance[] instances = [new GkrCommittedInstance(GkrGf2kMacSupport.BuildMacCircuit(verifierKey), CopyCount)];

        return GkrCommittedProver.Prove(
            commitment, instances, [], [],
            GkrGf2kTestSupport.Add, GkrGf2kTestSupport.Subtract, GkrGf2kTestSupport.Multiply, GkrGf2kTestSupport.Invert, GkrGf2kTestSupport.Reduce, CurveParameterSet.None,
            transcript, GkrGf2kTestSupport.Squeeze, GkrGf2kTestSupport.Hash,
            BaseMemoryPool.Shared);
    }


    //The verifier's side: absorb the root from the proof, squeeze the same key, rebuild the
    //instance and the expected outputs from the claimed macs, verify.
    private static bool VerifyMac(
        GkrCommittedProof proof,
        LigeroParameters parameters,
        LigeroQuadraticConstraint[] bitness,
        FiatShamirTranscript transcript,
        ReadOnlySpan<byte> macs)
    {
        GkrCommittedVerifier.AbsorbCommitmentRoot(proof, transcript, GkrGf2kTestSupport.Hash);

        Span<byte> verifierKey = stackalloc byte[ScalarSize];
        GkrGf2kMacSupport.SqueezeVerifierKey(transcript, verifierKey);

        GkrCommittedInstance[] instances = [new GkrCommittedInstance(GkrGf2kMacSupport.BuildMacCircuit(verifierKey), CopyCount)];

        Span<byte> outputs = stackalloc byte[OutputBytes];
        outputs.Clear();
        for(int h = 0; h < CopyCount; h++)
        {
            macs.Slice(h * ScalarSize, ScalarSize).CopyTo(outputs.Slice(h * OutputCount * ScalarSize, ScalarSize));
        }

        return GkrCommittedVerifier.VerifyFromAbsorbedRoot(
            instances, outputs, proof, parameters, [], [], bitness,
            GkrGf2kTestSupport.Add, GkrGf2kTestSupport.Subtract, GkrGf2kTestSupport.Multiply, GkrGf2kTestSupport.Invert, GkrGf2kTestSupport.Reduce, CurveParameterSet.None,
            transcript, GkrGf2kTestSupport.Squeeze, GkrGf2kTestSupport.Hash, GkrGf2kTestSupport.Hash, GkrTestSupport.Merkle, WellKnownHashAlgorithms.Blake3,
            BaseMemoryPool.Shared);
    }


    //The macs from the packed witness bits and committed key shares — equivalent to computing
    //them from the value, but read where the proof reads them.
    private static void ComputeMacsFromWitness(ReadOnlySpan<byte> witness, ReadOnlySpan<byte> verifierKey, Span<byte> macs)
    {
        Span<byte> value = stackalloc byte[CopyCount * GkrGf2kMacSupport.HalfBytes];
        for(int h = 0; h < CopyCount; h++)
        {
            for(int i = 0; i < GkrGf2kMacSupport.HalfBits; i++)
            {
                if(witness[((h * InputCount) + i) * ScalarSize + ScalarSize - 1] != 0)
                {
                    value[(h * GkrGf2kMacSupport.HalfBytes) + GkrGf2kMacSupport.HalfBytes - 1 - (i >> 3)] |= (byte)(1 << (i & 7));
                }
            }
        }

        GkrGf2kMacSupport.ComputeMacs(value, KeyShares, verifierKey, macs);
    }


    private static byte[] Element(ulong high, ulong low)
    {
        byte[] bytes = new byte[ScalarSize];
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(16, 8), high);
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(24, 8), low);

        return bytes;
    }


    private static FiatShamirTranscript NewTranscript() =>
        GkrGf2kTestSupport.NewTranscript(Domain, "veridical.gkr.gf2k.mac.seed"u8, []);


    //A reproducible randomness source for the masking rows.
    private sealed class MacDeterministicRandom
    {
        private byte[] Seed { get; }

        private int Counter { get; set; }

        public MacDeterministicRandom(ReadOnlySpan<byte> seed) => Seed = seed.ToArray();

        public ScalarRandomDelegate AsDelegate() => Fill;

        private Tag Fill(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
        {
            Span<byte> input = stackalloc byte[Seed.Length + sizeof(int)];
            Seed.CopyTo(input);
            BinaryPrimitives.WriteInt32BigEndian(input[Seed.Length..], Counter);
            Counter++;

            Span<byte> digest = stackalloc byte[32];
            Blake3.Hash(input, digest);
            destination.Clear();
            digest[..16].CopyTo(destination[16..]);

            return inboundTag;
        }
    }
}
