using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Width-threading seam gates for the P-256 base-field (<c>Fp256</c>) instantiation of the wire-format
/// Longfellow stack (conformance step C.12, width-threading). These do NOT assert end-to-end conformance
/// against reference bytes — those land with the Fp256 Reed–Solomon wiring and the Docker dump harness in
/// the later steps. They gate that the threaded <see cref="LongfellowFieldProfile"/> for the prime field
/// produces the correct on-wire element width (32), the correct <c>of_bytes_field</c> rejection semantics,
/// and the correct third polynomial evaluation point (<c>poly_evaluation_point(2) = 2</c>) — the three
/// places the field profile changes the stack's behaviour between GF(2^128) and Fp256.
/// </summary>
/// <remarks>
/// The arithmetic uses <see cref="P256BaseFieldReference"/> (the BigInteger-backed P-256 base field); the
/// reference's <c>fp_generic.h of_bytes_field</c> reads the wire bytes as a little-endian integer and
/// returns the element only when it is below the modulus <c>p</c> (otherwise <c>std::nullopt</c>, which
/// every reference caller in this stack <c>check()</c>s), so the Fp256 profile rejects out-of-range draws.
/// </remarks>
[TestClass]
internal sealed class LongfellowFp256SeamTests
{
    private const int ScalarSize = Scalar.SizeBytes;
    private const int Fp256ElementBytes = 32;
    private const int GfElementBytes = 16;
    private const int TranscriptVersion = 6;
    private const int DigestSize = 32;

    //The Ligero rate / opened-column count the anchor flows use; small but valid for the synthetic gate.
    private const int InverseRate = 4;
    private const int OpenedColumnCount = 2;

    private static readonly byte[] TranscriptSeed = Encoding.ASCII.GetBytes("fp256-width-gate");

    private static BigInteger Prime { get; } = P256BaseFieldReference.FieldOrder;

    private static ScalarAddDelegate Add { get; } = P256BaseFieldReference.GetAdd();

    private static ScalarSubtractDelegate Subtract { get; } = P256BaseFieldReference.GetSubtract();

    private static ScalarMultiplyDelegate Multiply { get; } = P256BaseFieldReference.GetMultiply();

    private static ScalarInvertDelegate Invert { get; } = P256BaseFieldReference.GetInvert();


    //The Fp256 profile: of_scalar(u) reduces the integer u mod p; the fits predicate is the < p comparison.
    private static LongfellowFieldProfile Profile { get; } = LongfellowFieldProfile.ForFp256(OfScalar, InRange);


    [TestMethod]
    public void TheFp256ProfileFramesAtThirtyTwoBytes()
    {
        Assert.AreEqual(Fp256ElementBytes, Profile.ElementBytes, "The P-256 base-field on-wire element width is 32 bytes.");
    }


    [TestMethod]
    public void FromBytesFieldReversesAndRejectsOutOfRange()
    {
        //An in-range little-endian draw round-trips through of_bytes_field / to_bytes_field.
        BigInteger sample = (Prime - 7) % Prime;
        Span<byte> littleEndian = stackalloc byte[Fp256ElementBytes];
        WriteLittleEndian(sample, littleEndian);

        Span<byte> canonical = stackalloc byte[ScalarSize];
        Profile.FromBytesField(littleEndian, canonical);
        Assert.AreEqual(sample, ReadCanonicalBigEndian(canonical), "of_bytes_field must read the little-endian integer into the canonical scalar.");

        Span<byte> roundTrip = stackalloc byte[Fp256ElementBytes];
        Profile.ToBytesField(canonical, roundTrip);
        Assert.IsTrue(roundTrip.SequenceEqual(littleEndian), "to_bytes_field must reverse of_bytes_field exactly.");

        //p itself is out of range: of_bytes_field returns nullopt in the reference, which this port
        //surfaces as a rejection. The all-ones 32-byte draw (2^256 - 1) likewise exceeds p.
        byte[] atModulus = new byte[Fp256ElementBytes];
        WriteLittleEndian(Prime, atModulus);
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Reject(atModulus), "of_bytes_field must reject the integer p (not below the modulus).");

        byte[] allOnes = new byte[Fp256ElementBytes];
        allOnes.AsSpan().Fill(0xFF);
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Reject(allOnes), "of_bytes_field must reject a 32-byte draw above the modulus.");

        //p - 1 is the largest in-range draw and must be accepted.
        Span<byte> belowModulus = stackalloc byte[Fp256ElementBytes];
        WriteLittleEndian(Prime - 1, belowModulus);
        Span<byte> accepted = stackalloc byte[ScalarSize];
        Profile.FromBytesField(belowModulus, accepted);
        Assert.AreEqual(Prime - 1, ReadCanonicalBigEndian(accepted), "of_bytes_field must accept p - 1.");
    }


    [TestMethod]
    public void TheThirdEvaluationPointIsTwo()
    {
        Span<byte> third = stackalloc byte[ScalarSize];
        Profile.CopyThirdEvaluationPoint(third);

        Assert.AreEqual(new BigInteger(2), ReadCanonicalBigEndian(third), "The Fp256 poly_evaluation_point(2) is the integer 2.");
    }


    [TestMethod]
    public void TheWidthThirtyTwoSumcheckReplayDoesNotThrowOnAWidthSixteenBakedTranscript()
    {
        //The dual-field driver runs the Fp256 (width-32) sig-circuit replay on the ONE shared transcript that
        //is baked at the 16-byte GF(2^128) width (required for the 16-byte a_v generate_mac_key squeeze). Every
        //field-element ABSORB on that replay — the public-input absorbs in initialize_sumcheck_fiat_shamir, the
        //input-column array, and the per-round (p(0), p(2)) and wc absorbs — must frame at 32 bytes, NOT against
        //the transcript's baked 16. Before the width threading the absorbs validated 32 against the baked 16 and
        //the very first public-input absorb threw ArgumentException; this gate drives a real Fp256 sumcheck
        //replay through the width-16-baked transcript and requires the whole walk to run to a verdict without
        //throwing — the test that catches the baked-width blocker.
        LongfellowSumcheckCircuit circuit = Fp256SumcheckCircuit();

        //A synthetic in-range Fp256 sumcheck proof: every round point and claim is a small base-field element,
        //so to_bytes_field frames them at 32 bytes. The replay's round reconstruction is checked downstream
        //(the Ligero opening), never here, so the walk returns a verdict for any well-formed proof.
        using LongfellowSumcheckProof proof = SyntheticFp256Proof(circuit);

        byte[] inputElements = new byte[circuit.InputCount * Fp256ElementBytes];
        for(int i = 0; i < circuit.InputCount; i++)
        {
            Span<byte> littleEndian = inputElements.AsSpan(i * Fp256ElementBytes, Fp256ElementBytes);
            WriteLittleEndian(new BigInteger(3 + i), littleEndian);
        }

        //The transcript is baked at the 16-byte GF width — the cross-field driver's shared transcript.
        using LongfellowTranscript transcript = new(TranscriptSeed, TranscriptVersion, GfElementBytes, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());

        bool replayed = LongfellowSumcheckVerifier.Verify(
            circuit, proof, inputElements, transcript,
            Add, Subtract, Multiply, Invert, Profile, CurveParameterSet.None, BaseMemoryPool.Shared,
            out LongfellowSumcheckVerificationResult result);

        Assert.IsTrue(replayed, "The Fp256-width sumcheck replay must run to a verdict on the width-16-baked transcript without throwing.");
        Assert.AreEqual(LongfellowSumcheckVerificationResult.Accepted, result, "A well-formed replay reaches Accepted (the round soundness is the downstream Ligero layer's job).");

        //Capture the absorbed byte width: the same shape framed at the baked 16 would absorb 16 fewer bytes per
        //field element. The 32-byte framing must have consumed strictly more than a width-16 framing would, and
        //must match the width-32 element-count accounting exactly.
        int absorbed = transcript.AbsorbedLength;
        int width32Bytes = ExpectedFieldElementBytes(circuit) * Fp256ElementBytes;
        int width16Bytes = ExpectedFieldElementBytes(circuit) * GfElementBytes;
        Assert.IsGreaterThan(width16Bytes, width32Bytes, "The width-32 framing absorbs more field-element bytes than width-16.");
        Assert.IsGreaterThanOrEqualTo(width32Bytes, absorbed, "The transcript absorbed at least the width-32 field-element framing (plus the non-element byte-string writes).");
    }


    [TestMethod]
    public void TheWidthThirtyTwoDriverPathDoesNotThrowOnAWidthSixteenBakedTranscript()
    {
        //The REAL driver path the dual-field driver executes — LongfellowZkVerifier.VerifyFromAbsorbedRoot —
        //drives THREE width-32 field-element ABSORB groups against the ONE shared transcript baked at the
        //16-byte GF(2^128) width: (1) initialize_sumcheck_fiat_shamir's public-input absorbs (the site that
        //threw pre-fix, LongfellowZkVerifier.cs InitializeFiatShamir), (2) verifier_constraints' per-round
        //(p(0), p(2)) and wc absorbs (LongfellowZkConstraintBuilder.Build), and (3) the Ligero verify's
        //theorem-statement and response-row absorbs (LongfellowLigeroVerifier.Verify). The sumcheck-only gate
        //above drives LongfellowSumcheckVerifier.Verify, which this path never calls; this gate drives the
        //sites the driver actually executes. The synthetic proof makes the Ligero Merkle check reject (the
        //verdict is LigeroRejected), which is fine — the point is the absorbs frame at 32 bytes WITHOUT
        //throwing against the width-16-baked transcript.
        LongfellowSumcheckCircuit circuit = Fp256DriverCircuit();
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(circuit, InverseRate, OpenedColumnCount, Fp256ElementBytes, LongfellowFp256Encoding.SignatureSubFieldBytes);

        using LongfellowSumcheckProof sumcheckProof = SyntheticFp256Proof(circuit);
        using LongfellowLigeroProof ligeroProof = SyntheticFp256LigeroProof(parameters);

        //The public inputs: npub_in in-range Fp256 elements, npub_in · 32 little-endian element bytes, so the
        //FS-setup public-input absorb loop runs and frames at 32 bytes.
        byte[] publicInputs = new byte[circuit.PublicInputCount * Fp256ElementBytes];
        for(int i = 0; i < circuit.PublicInputCount; i++)
        {
            WriteLittleEndian(new BigInteger(5 + i), publicInputs.AsSpan(i * Fp256ElementBytes, Fp256ElementBytes));
        }

        //An arbitrary 32-byte commitment root (already absorbed in the real path via RecvCommitment); the
        //Ligero Merkle check re-derives leaves against it and rejects, which is the intended verdict here.
        byte[] root = new byte[DigestSize];
        root.AsSpan().Fill(0x5A);

        Fp256RealFft fft = NewFft();
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateEncoderFactory(
            fft, Add, Subtract, Multiply, Invert, OfScalar, CurveParameterSet.None, BaseMemoryPool.Shared);

        //The transcript is baked at the 16-byte GF width — the cross-field driver's shared transcript. The
        //root absorb is the byte-string write the real driver performs before VerifyFromAbsorbedRoot.
        using LongfellowTranscript transcript = new(TranscriptSeed, TranscriptVersion, GfElementBytes, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());
        LongfellowZkVerifier.RecvCommitment(root, transcript);

        bool verified = LongfellowZkVerifier.VerifyFromAbsorbedRoot(
            circuit, parameters, sumcheckProof, ligeroProof, root, publicInputs, transcript, encoderFactory, Profile,
            Add, Subtract, Multiply, Invert, Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256,
            CurveParameterSet.None, BaseMemoryPool.Shared, out LongfellowZkVerificationResult result);

        //The driver path ran to a verdict: the FS-setup + constraint-build + Ligero absorbs all framed at 32
        //bytes against the width-16-baked transcript without throwing. The verdict is a rejection (the
        //synthetic Merkle root does not match), which is exactly what the gate expects — it gates the absorb
        //framing, not proof soundness.
        Assert.IsFalse(verified, "The synthetic proof must not verify (the Merkle root does not match).");
        Assert.AreEqual(LongfellowZkVerificationResult.LigeroRejected, result, "A well-formed but unsatisfied proof reaches a Ligero rejection — the driver-path absorbs ran to a verdict without throwing.");
    }


    [TestMethod]
    public void TheSumcheckSegmentSizesAtThirtyTwoByteElements()
    {
        //A single-layer circuit with logw = 2: the sc segment is (logw*(3-1)*2 + 2) elements = 10
        //elements per layer, each Profile.ElementBytes wide. The size depends only on the shape and the
        //element width, so the Fp256 width (32) doubles the GF(2^128) width (16) byte-for-byte.
        LongfellowSumcheckLayer layer = new(inputCount: 4, handRounds: 2, termCount: 0);
        byte[] id = new byte[LongfellowSumcheckCircuit.IdLength];
        LongfellowSumcheckCircuit circuit = new(
            outputCount: 1, outputLogCount: 0, copyCount: 1, copyRounds: 0,
            inputCount: 4, publicInputCount: 0, id, [layer]);

        const int ElementsPerLayer = (2 * (3 - 1) * 2) + 2;
        int fp256Size = LongfellowSumcheckProofSerializer.SerializedSize(circuit, Profile);

        Assert.AreEqual(ElementsPerLayer * Fp256ElementBytes, fp256Size, "The sc segment sizes at 32-byte elements for the Fp256 profile.");
    }


    [TestMethod]
    public void TheProofPadDrawsAtThirtyTwoByteElements()
    {
        //The same single-layer logw = 2 shape: fill_pad draws 4·logw + 2 = 10 elements per layer and
        //computes the claim-pad product. Each Fp256 draw must consume Profile.ElementBytes (32) raw
        //bytes from the entropy source; the GF width (16) would leave half of every draw unread.
        LongfellowSumcheckLayer layer = new(inputCount: 4, handRounds: 2, termCount: 0);
        byte[] id = new byte[LongfellowSumcheckCircuit.IdLength];
        LongfellowSumcheckCircuit circuit = new(
            outputCount: 1, outputLogCount: 0, copyCount: 1, copyRounds: 0,
            inputCount: 4, publicInputCount: 0, id, [layer]);

        const int DrawnElements = (4 * 2) + 2;
        int consumed = 0;
        LongfellowRandomByteSource random = destination =>
        {
            //Deterministic bytes with the most significant little-endian byte zero, so every drawn
            //integer stays below the modulus and of_bytes_field accepts it.
            for(int i = 0; i < destination.Length; i++)
            {
                destination[i] = (byte)(31 + (7 * (consumed + i)));
            }

            destination[^1] = 0;
            consumed += destination.Length;
        };

        using LongfellowProofPad pad = LongfellowProofPad.Fill(circuit, random, Profile, Multiply, CurveParameterSet.None, BaseMemoryPool.Shared);

        Assert.AreEqual(DrawnElements * Fp256ElementBytes, consumed, "Each pad draw consumes one 32-byte Fp256 element.");
        Assert.AreEqual((4 * 2) + 3, pad.WitnessScalarCount, "The pad witness is 4·logw + 3 per layer.");
    }


    [TestMethod]
    public void TheLagrangeFoldOverFp256MatchesADirectEvaluation()
    {
        //A degree-2 polynomial p(x) = a0 + a1*x + a2*x^2 over Fp256, evaluated at the three nodes
        //{0, 1, 2}. Folding its three Lagrange values at a challenge r must equal p(r) computed directly.
        //This exercises the {0, 1, 2} third point the profile carries (2, not the GF generator g) through
        //the same Lagrange-weight + dot machinery the sumcheck verifier's fold uses.
        BigInteger a0 = 7;
        BigInteger a1 = 11;
        BigInteger a2 = 5;

        Span<byte> node0 = Canonical(0);
        Span<byte> node1 = Canonical(1);
        Span<byte> third = stackalloc byte[ScalarSize];
        Profile.CopyThirdEvaluationPoint(third);
        BigInteger node2 = ReadCanonicalBigEndian(third);

        //The three evaluation points {0, 1, 2}.
        Span<byte> evalPoints = stackalloc byte[3 * ScalarSize];
        node0.CopyTo(evalPoints[..ScalarSize]);
        node1.CopyTo(evalPoints.Slice(ScalarSize, ScalarSize));
        third.CopyTo(evalPoints.Slice(2 * ScalarSize, ScalarSize));

        //The polynomial's Lagrange values at the three nodes.
        Span<byte> values = stackalloc byte[3 * ScalarSize];
        Canonical(EvaluatePolynomial(a0, a1, a2, 0)).CopyTo(values[..ScalarSize]);
        Canonical(EvaluatePolynomial(a0, a1, a2, 1)).CopyTo(values.Slice(ScalarSize, ScalarSize));
        Canonical(EvaluatePolynomial(a0, a1, a2, node2)).CopyTo(values.Slice(2 * ScalarSize, ScalarSize));

        BigInteger challenge = 42;
        Span<byte> challengeBytes = Canonical(challenge);

        //Σ_k weight_k(challenge) * value_k, with the Lagrange weights over the {0, 1, 2} nodes.
        Span<byte> weights = stackalloc byte[3 * ScalarSize];
        LagrangeWeights(challengeBytes, evalPoints, weights);

        Span<byte> acc = stackalloc byte[ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];
        acc.Clear();
        for(int k = 0; k < 3; k++)
        {
            Multiply(weights.Slice(k * ScalarSize, ScalarSize), values.Slice(k * ScalarSize, ScalarSize), term, CurveParameterSet.None);
            Add(acc, term, acc, CurveParameterSet.None);
        }

        BigInteger expected = EvaluatePolynomial(a0, a1, a2, challenge);
        Assert.AreEqual(expected, ReadCanonicalBigEndian(acc), "The Lagrange fold over the {0, 1, 2} Fp256 nodes must reproduce p(challenge).");
    }


    //A minimal Fp256 sumcheck circuit (logc == 0): one layer, two public inputs, four inputs. The shape
    //exercises every absorb the replay drives — the public-input field elements, the input-column array, and
    //the per-round and wc absorbs — at the 32-byte Fp256 width.
    private static LongfellowSumcheckCircuit Fp256SumcheckCircuit()
    {
        LongfellowSumcheckLayer layer = new(inputCount: 4, handRounds: 2, termCount: 0);
        byte[] id = new byte[LongfellowSumcheckCircuit.IdLength];

        return new LongfellowSumcheckCircuit(
            outputCount: 1, outputLogCount: 0, copyCount: 1, copyRounds: 0,
            inputCount: 4, publicInputCount: 2, id, [layer]);
    }


    //A minimal Fp256 driver circuit (logc == 0) WITH per-layer Quad terms: two layers of logw = 2, two
    //public inputs, four inputs, logv = 0. The Quad terms (one per layer, gate 0 / left 0 / right 1, the
    //coefficient one) let verifier_constraints' bind_quad run to completion — verifier_constraints rejects a
    //layer with no quad terms, so the sumcheck-only seam circuit cannot drive the real driver path. The
    //shape exercises all three driver-path absorb groups: the FS-setup public-input absorbs, the constraint
    //build's per-round and wc absorbs, and the Ligero response absorbs.
    private static LongfellowSumcheckCircuit Fp256DriverCircuit()
    {
        const int HandRounds = 2;
        byte[] one = Canonical(1);
        var quadTerms = new LongfellowSumcheckQuadTerm[] { new(GateIndex: 0, LeftIndex: 0, RightIndex: 1, one) };

        var layers = new LongfellowSumcheckLayer[]
        {
            new(inputCount: 4, HandRounds, termCount: 1, quadTerms),
            new(inputCount: 4, HandRounds, termCount: 1, quadTerms),
        };

        byte[] id = new byte[LongfellowSumcheckCircuit.IdLength];

        return new LongfellowSumcheckCircuit(
            outputCount: 1, outputLogCount: 0, copyCount: 1, copyRounds: 0,
            inputCount: 4, publicInputCount: 2, id, layers);
    }


    //A synthetic Ligero com_proof sized for the circuit-derived parameters: response rows and opened
    //columns hold in-range Fp256 elements, nonces and the Merkle path are raw bytes. The Ligero verify
    //absorbs the response rows (the third driver-path absorb group) then rejects at the Merkle check (the
    //raw path does not reconstruct the root) — a verdict, not a throw. Mirrors the BuildSyntheticProof
    //pattern in LongfellowFp256EncodingTests.
    private static LongfellowLigeroProof SyntheticFp256LigeroProof(LongfellowLigeroParameters parameters)
    {
        const int NonceSize = 32;
        int block = parameters.Block;
        int dblock = parameters.DoubleBlock;
        int randomCount = parameters.RandomCount;
        int quadHigh = dblock - block;
        int rowCount = parameters.RowCount;
        int openedColumnCount = parameters.OpenedColumnCount;
        int pathLength = openedColumnCount;

        IMemoryOwner<byte> responseOwner = BaseMemoryPool.Shared.Rent(LongfellowLigeroProof.ResponseBufferSize(parameters));
        IMemoryOwner<byte> openedColumnsOwner = BaseMemoryPool.Shared.Rent(rowCount * openedColumnCount * ScalarSize);
        IMemoryOwner<byte> indicesOwner = BaseMemoryPool.Shared.Rent(openedColumnCount * sizeof(int));
        IMemoryOwner<byte> nonceOwner = BaseMemoryPool.Shared.Rent(openedColumnCount * NonceSize);
        IMemoryOwner<byte> pathOwner = BaseMemoryPool.Shared.Rent(pathLength * DigestSize);

        Span<byte> responses = responseOwner.Memory.Span[..LongfellowLigeroProof.ResponseBufferSize(parameters)];
        int responseElements = block + dblock + randomCount + quadHigh;
        for(int i = 0; i < responseElements; i++)
        {
            Profile.OfScalar((uint)((i * 13) + 1), responses.Slice(i * ScalarSize, ScalarSize));
        }

        Span<byte> openedColumns = openedColumnsOwner.Memory.Span[..(rowCount * openedColumnCount * ScalarSize)];
        for(int i = 0; i < rowCount * openedColumnCount; i++)
        {
            Profile.OfScalar((uint)((i * 7) + 3), openedColumns.Slice(i * ScalarSize, ScalarSize));
        }

        indicesOwner.Memory.Span[..(openedColumnCount * sizeof(int))].Clear();

        Span<byte> nonces = nonceOwner.Memory.Span[..(openedColumnCount * NonceSize)];
        for(int i = 0; i < nonces.Length; i++)
        {
            nonces[i] = (byte)((i * 17) + 5);
        }

        Span<byte> path = pathOwner.Memory.Span[..(pathLength * DigestSize)];
        for(int i = 0; i < path.Length; i++)
        {
            path[i] = (byte)((i * 11) + 2);
        }

        return new LongfellowLigeroProof(parameters, responseOwner, openedColumnsOwner, indicesOwner, nonceOwner, pathOwner, pathLength);
    }


    private static Fp256RealFft NewFft()
    {
        byte[] root = new byte[Fp256QuadraticExtension.ElementSize];
        LongfellowFp256Encoding.RootOfUnity(root);

        return new Fp256RealFft(root, LongfellowFp256Encoding.OmegaOrder, Add, Subtract, Multiply, Invert, OfScalar, CurveParameterSet.None, BaseMemoryPool.Shared);
    }


    private static void Sha256TwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSize];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        SHA256.HashData(combined[..(left.Length + right.Length)], output);
    }


    //A synthetic in-range Fp256 sumcheck proof: each round point and wc claim is a distinct small base-field
    //element. The replay folds p(1) = claim - p(0) and never range-checks the round points here, so any
    //well-formed proof drives the absorbs to a verdict.
    private static LongfellowSumcheckProof SyntheticFp256Proof(LongfellowSumcheckCircuit circuit)
    {
        var proof = new LongfellowSumcheckProof(circuit, BaseMemoryPool.Shared);
        try
        {
            int seed = 1;
            for(int layer = 0; layer < circuit.LayerCount; layer++)
            {
                int handRounds = circuit.Layers[layer].HandRounds;
                for(int round = 0; round < handRounds; round++)
                {
                    for(int hand = 0; hand < 2; hand++)
                    {
                        proof.SetRoundPolynomialPoint(layer, hand, round, 0, Canonical(seed++));
                        proof.SetRoundPolynomialPoint(layer, hand, round, 2, Canonical(seed++));
                    }
                }

                proof.SetClaim(layer, 0, Canonical(seed++));
                proof.SetClaim(layer, 1, Canonical(seed++));
            }

            return proof;
        }
        catch
        {
            proof.Dispose();
            throw;
        }
    }


    //The number of field elements the width-32 replay absorbs for the given shape: npub_in public inputs, the
    //pro-forma zero element, ninputs input-column elements, then per layer two points per hand per round plus
    //two wc claims. The byte-string writes (id, the nterms zero pad) are not field elements and are excluded.
    private static int ExpectedFieldElementBytes(LongfellowSumcheckCircuit circuit)
    {
        int elements = circuit.PublicInputCount + 1 + circuit.InputCount;
        foreach(LongfellowSumcheckLayer layer in circuit.Layers)
        {
            elements += (2 * 2 * layer.HandRounds) + 2;
        }

        return elements;
    }


    private static void Sha256OneShot(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction) => SHA256.HashData(input, output);


    private static void Aes256Ecb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.EncryptEcb(input, output, PaddingMode.None);
    }


    //weight[k] = Π_{j != k} (x - X[j]) / (X[k] - X[j]) over Fp256, the sumcheck verifier's dot_wpoly.coef.
    private static void LagrangeWeights(ReadOnlySpan<byte> x, ReadOnlySpan<byte> evalPoints, Span<byte> weights)
    {
        Span<byte> numerator = stackalloc byte[ScalarSize];
        Span<byte> denominator = stackalloc byte[ScalarSize];
        Span<byte> difference = stackalloc byte[ScalarSize];
        for(int k = 0; k < 3; k++)
        {
            Canonical(1).CopyTo(numerator);
            Canonical(1).CopyTo(denominator);
            ReadOnlySpan<byte> xk = evalPoints.Slice(k * ScalarSize, ScalarSize);
            for(int j = 0; j < 3; j++)
            {
                if(j == k)
                {
                    continue;
                }

                ReadOnlySpan<byte> xj = evalPoints.Slice(j * ScalarSize, ScalarSize);
                Subtract(x, xj, difference, CurveParameterSet.None);
                Multiply(numerator, difference, numerator, CurveParameterSet.None);
                Subtract(xk, xj, difference, CurveParameterSet.None);
                Multiply(denominator, difference, denominator, CurveParameterSet.None);
            }

            Invert(denominator, denominator, CurveParameterSet.None);
            Multiply(numerator, denominator, weights.Slice(k * ScalarSize, ScalarSize), CurveParameterSet.None);
        }
    }


    //of_scalar(u): the integer u reduced mod p as a canonical big-endian scalar.
    private static void OfScalar(uint coordinate, Span<byte> destination) =>
        Canonical(new BigInteger(coordinate) % Prime).CopyTo(destination);


    //fits(an): the canonical big-endian integer is below the modulus.
    private static bool InRange(ReadOnlySpan<byte> canonical) => ReadCanonicalBigEndian(canonical) < Prime;


    private static void Reject(ReadOnlySpan<byte> littleEndian)
    {
        Span<byte> sink = stackalloc byte[ScalarSize];
        Profile.FromBytesField(littleEndian, sink);
    }


    private static BigInteger EvaluatePolynomial(BigInteger a0, BigInteger a1, BigInteger a2, BigInteger x)
    {
        BigInteger value = (((a2 * x) + a1) * x) + a0;

        return ((value % Prime) + Prime) % Prime;
    }


    private static byte[] Canonical(BigInteger value)
    {
        byte[] canonical = new byte[ScalarSize];
        WriteCanonicalBigEndian(value, canonical);

        return canonical;
    }


    private static byte[] Canonical(int value) => Canonical(new BigInteger(value));


    private static BigInteger ReadCanonicalBigEndian(ReadOnlySpan<byte> bytes) => new(bytes, isUnsigned: true, isBigEndian: true);


    private static void WriteCanonicalBigEndian(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("The value did not fit in the canonical span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }


    //to_bytes_field for the test's own draws: the low 32 big-endian bytes reversed to little-endian.
    private static void WriteLittleEndian(BigInteger value, Span<byte> littleEndian)
    {
        Span<byte> canonical = stackalloc byte[ScalarSize];
        WriteCanonicalBigEndian(value, canonical);
        for(int i = 0; i < Fp256ElementBytes; i++)
        {
            littleEndian[i] = canonical[ScalarSize - 1 - i];
        }
    }
}
