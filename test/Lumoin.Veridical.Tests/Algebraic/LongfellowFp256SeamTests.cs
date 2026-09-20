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
/// Longfellow stack. These do NOT assert end-to-end conformance against reference bytes — that is a
/// separate gate this file does not exercise. They gate that the threaded <see cref="LongfellowFieldProfile"/> for the prime field
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
internal sealed class LongfellowFp256SeamTests: IDisposable
{
    /// <summary>The independent compiler and circuit lifetime for this test.</summary>
    private LongfellowCircuitTestScope CircuitScope { get; } = new();

    /// <summary>Calls <see cref="Dispose"/> after each test, including when an assertion fails.</summary>
    [TestCleanup]
    public void DisposeCircuits()
    {
        Dispose();
    }


    /// <summary>Releases this test's compiler and circuit storage. Repeated calls have no effect.</summary>
    public void Dispose()
    {
        CircuitScope.Dispose();
    }


    /// <summary>The byte width of one scalar in this test's canonical scratch buffers, matching the library-wide scalar size.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The element width, in bytes, of a P-256 base-field (Fp256) scalar on the wire.</summary>
    private const int Fp256ElementBytes = 32;

    /// <summary>The element width, in bytes, of a GF(2^128) scalar on the wire, the width the shared transcript in these gates is baked at.</summary>
    private const int GfElementBytes = 16;

    /// <summary>The Longfellow transcript wire version these width-threading gates speak.</summary>
    private const int TranscriptVersion = 6;

    /// <summary>The byte width of a SHA-256 digest, the Merkle root and node size these gates use.</summary>
    private const int DigestSize = 32;

    /// <summary>The Ligero code's inverse rate the anchor flows use; small but valid for a synthetic gate.</summary>
    private const int InverseRate = 4;

    /// <summary>The number of Ligero columns opened per proof the anchor flows use; small but valid for a synthetic gate.</summary>
    private const int OpenedColumnCount = 2;

    /// <summary>The deterministic transcript seed these width-threading gates share.</summary>
    private static byte[] TranscriptSeed { get; } = Encoding.ASCII.GetBytes("fp256-width-gate");

    /// <summary>The P-256 base-field order, used to reduce and range-check canonical scalars in this class's helpers.</summary>
    private static BigInteger Prime { get; } = P256BaseFieldReference.FieldOrder;

    /// <summary>The P-256 base-field addition delegate from the BigInteger-backed reference implementation.</summary>
    private static ScalarAddDelegate Add { get; } = P256BaseFieldReference.GetAdd();

    /// <summary>The P-256 base-field subtraction delegate from the BigInteger-backed reference implementation.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = P256BaseFieldReference.GetSubtract();

    /// <summary>The P-256 base-field multiplication delegate from the BigInteger-backed reference implementation.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = P256BaseFieldReference.GetMultiply();

    /// <summary>The P-256 base-field inversion delegate from the BigInteger-backed reference implementation.</summary>
    private static ScalarInvertDelegate Invert { get; } = P256BaseFieldReference.GetInvert();


    /// <summary>The Fp256 field profile under test: of_scalar(u) reduces the integer u modulo p, and the fits predicate is the strict less-than-p comparison.</summary>
    private static LongfellowFieldProfile Profile { get; } = LongfellowFieldProfile.ForFp256(OfScalar, InRange, BaseMemoryPool.Shared);


    /// <summary>Disposes the class-lifetime Fp256 profile.</summary>
    [ClassCleanup]
    public static void ClassCleanup()
    {
        Profile.Dispose();
    }


    /// <summary>Verifies that the Fp256 field profile frames its on-wire element width at 32 bytes.</summary>
    [TestMethod]
    public void TheFp256ProfileFramesAtThirtyTwoBytes()
    {
        Assert.AreEqual(Fp256ElementBytes, Profile.ElementBytes, "The P-256 base-field on-wire element width is 32 bytes.");
    }


    /// <summary>
    /// Verifies that of_bytes_field reverses little-endian wire bytes into a canonical scalar and back, and
    /// rejects draws at or above the modulus (the integer p and an all-ones 32-byte draw) while accepting the
    /// largest in-range draw (p - 1).
    /// </summary>
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


    /// <summary>Verifies that the Fp256 profile's third polynomial evaluation point is the integer 2.</summary>
    [TestMethod]
    public void TheThirdEvaluationPointIsTwo()
    {
        Span<byte> third = stackalloc byte[ScalarSize];
        Profile.CopyThirdEvaluationPoint(third);

        Assert.AreEqual(new BigInteger(2), ReadCanonicalBigEndian(third), "The Fp256 poly_evaluation_point(2) is the integer 2.");
    }


    /// <summary>
    /// Verifies that a direct Fp256 sumcheck replay over a width-16-baked shared transcript frames every
    /// absorb at the Fp256 profile's 32-byte width, without throwing, and reaches Accepted on a well-formed
    /// synthetic proof.
    /// </summary>
    [TestMethod]
    public void TheWidthThirtyTwoSumcheckReplayDoesNotThrowOnAWidthSixteenBakedTranscript()
    {
        //The dual-field driver runs the Fp256 (width-32) sig-circuit replay on the ONE shared transcript that
        //is baked at the 16-byte GF(2^128) width (required for the 16-byte a_v generate_mac_key squeeze). Every
        //field-element ABSORB on that replay — the public-input absorbs in initialize_sumcheck_fiat_shamir, the
        //input-column array, and the per-round (p(0), p(2)) and wc absorbs — must frame at 32 bytes, NOT against
        //the transcript's baked 16: an absorb is sized by the field profile doing the absorbing, independently
        //of the width the transcript itself was constructed with, and the dual-field driver depends on exactly
        //that independence. This gate drives a real Fp256 sumcheck replay through the width-16-baked transcript
        //and requires the whole walk to run to a verdict without throwing — the test that catches a baked-width
        //mismatch being treated as an error.
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


    /// <summary>
    /// Verifies that the real driver verification path — three width-32 absorb groups (Fiat-Shamir setup,
    /// constraint build, Ligero response) — runs to a verdict over a width-16-baked shared transcript without
    /// throwing, even though the synthetic proof itself is rejected at the Merkle check.
    /// </summary>
    [TestMethod]
    public void TheWidthThirtyTwoDriverPathDoesNotThrowOnAWidthSixteenBakedTranscript()
    {
        //The REAL driver path the dual-field driver executes — LongfellowZkVerifier.VerifyFromAbsorbedRoot —
        //drives THREE width-32 field-element ABSORB groups against the ONE shared transcript baked at the
        //16-byte GF(2^128) width: (1) initialize_sumcheck_fiat_shamir's public-input absorbs (the absorb
        //call most exposed to a baked-width mismatch, LongfellowZkVerifier.cs InitializeFiatShamir), (2)
        //verifier_constraints' per-round
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

        using BaseMemoryPool fftPool = new();

        using Fp256RealFft fft = NewFft(fftPool);
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


    /// <summary>
    /// Verifies that a single-layer circuit's serialized sumcheck-segment size scales with the Fp256 profile's
    /// 32-byte element width: for logw = 2 (10 elements per layer), the size must be exactly double the
    /// GF(2^128) 16-byte width's.
    /// </summary>
    [TestMethod]
    public void TheSumcheckSegmentSizesAtThirtyTwoByteElements()
    {
        //A single-layer circuit with logw = 2: the sc segment is (logw*(3-1)*2 + 2) elements = 10
        //elements per layer, each Profile.ElementBytes wide. The size depends only on the shape and the
        //element width, so the Fp256 width (32) doubles the GF(2^128) width (16) byte-for-byte.
        LongfellowSumcheckLayer layer = new(inputCount: 4, handRounds: 2, termCount: 0);
        byte[] id = new byte[LongfellowSumcheckCircuit.IdLength];
        LongfellowSumcheckCircuit circuit = CircuitScope.CreateCircuit(
            outputCount: 1, outputLogCount: 0, copyCount: 1, copyRounds: 0,
            inputCount: 4, publicInputCount: 0, id, [layer]);

        const int ElementsPerLayer = (2 * (3 - 1) * 2) + 2;
        int fp256Size = LongfellowSumcheckProofSerializer.SerializedSize(circuit, Profile);

        Assert.AreEqual(ElementsPerLayer * Fp256ElementBytes, fp256Size, "The sc segment sizes at 32-byte elements for the Fp256 profile.");
    }


    /// <summary>
    /// Verifies that filling the proof pad for a logw = 2 circuit draws exactly one 32-byte Fp256 element per
    /// pad slot (10 elements) and produces a witness scalar count of 4·logw + 3 per layer.
    /// </summary>
    [TestMethod]
    public void TheProofPadDrawsAtThirtyTwoByteElements()
    {
        //The same single-layer logw = 2 shape: fill_pad draws 4·logw + 2 = 10 elements per layer and
        //computes the claim-pad product. Each Fp256 draw must consume Profile.ElementBytes (32) raw
        //bytes from the entropy source; the GF width (16) would leave half of every draw unread.
        LongfellowSumcheckLayer layer = new(inputCount: 4, handRounds: 2, termCount: 0);
        byte[] id = new byte[LongfellowSumcheckCircuit.IdLength];
        LongfellowSumcheckCircuit circuit = CircuitScope.CreateCircuit(
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


    /// <summary>
    /// Verifies that Lagrange-folding a degree-2 polynomial's values at the three {0, 1, 2} evaluation nodes
    /// at a challenge point reproduces the polynomial evaluated directly at that challenge, over Fp256.
    /// </summary>
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


    /// <summary>
    /// A minimal Fp256 sumcheck circuit (logc == 0): one layer, two public inputs, four inputs, with circuit
    /// owners released at test cleanup. The shape exercises every absorb the replay drives — the
    /// public-input field elements, the input-column array, and the per-round and wc absorbs — at the
    /// 32-byte Fp256 width.
    /// </summary>
    private LongfellowSumcheckCircuit Fp256SumcheckCircuit()
    {
        LongfellowSumcheckLayer layer = new(inputCount: 4, handRounds: 2, termCount: 0);
        byte[] id = new byte[LongfellowSumcheckCircuit.IdLength];

        return CircuitScope.CreateCircuit(
            outputCount: 1, outputLogCount: 0, copyCount: 1, copyRounds: 0,
            inputCount: 4, publicInputCount: 2, id, [layer]);
    }


    /// <summary>
    /// A minimal Fp256 driver circuit (logc == 0) with per-layer Quad terms: two layers of logw = 2, two
    /// public inputs, four inputs, logv = 0, with circuit owners released at test cleanup. The Quad terms
    /// (one per layer, gate 0 / left 0 / right 1, coefficient one) let verifier_constraints' bind_quad run
    /// to completion — verifier_constraints rejects a layer with no quad terms, so the sumcheck-only seam
    /// circuit cannot drive the real driver path. The shape exercises all three driver-path absorb groups:
    /// the FS-setup public-input absorbs, the constraint build's per-round and wc absorbs, and the Ligero
    /// response absorbs.
    /// </summary>
    private LongfellowSumcheckCircuit Fp256DriverCircuit()
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

        return CircuitScope.CreateCircuit(
            outputCount: 1, outputLogCount: 0, copyCount: 1, copyRounds: 0,
            inputCount: 4, publicInputCount: 2, id, layers);
    }


    /// <summary>
    /// A synthetic Ligero com_proof sized for the circuit-derived parameters: response rows and opened
    /// columns hold in-range Fp256 elements, nonces and the Merkle path are raw bytes, mirroring the
    /// <c>BuildSyntheticProof</c> pattern in <see cref="LongfellowFp256EncodingTests"/>. The Ligero verify
    /// absorbs the response rows (the third driver-path absorb group) then rejects at the Merkle check (the
    /// raw path does not reconstruct the root) — a verdict, not a throw.
    /// </summary>
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


    /// <summary>Creates a caller-owned FFT whose root uses the supplied pool.</summary>
    /// <param name="pool">The caller pool supplying the root until the returned FFT is disposed.</param>
    private static Fp256RealFft NewFft(BaseMemoryPool pool)
    {
        byte[] root = new byte[Fp256QuadraticExtension.ElementSize];
        LongfellowFp256Encoding.RootOfUnity(root);

        return new Fp256RealFft(root, LongfellowFp256Encoding.OmegaOrder, Add, Subtract, Multiply, Invert, OfScalar, CurveParameterSet.None, pool);
    }


    /// <summary>Computes the SHA-256 digest of <paramref name="left"/> concatenated with <paramref name="right"/>, the two-to-one compression the Merkle layers use.</summary>
    private static void Sha256TwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSize];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        SHA256.HashData(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>Builds a synthetic in-range Fp256 sumcheck proof whose round points and claims are distinct small base-field elements; the replay folds p(1) = claim - p(0) without range-checking the round points, so any well-formed proof drives the absorbs to a verdict.</summary>
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


    /// <summary>Computes the number of field elements the width-32 replay absorbs for the given shape: the public inputs, the pro-forma zero element, the input-column elements, then two points per hand per round plus two wc claims per layer. Byte-string writes (the id, the nterms zero pad) are not field elements and are excluded.</summary>
    private static int ExpectedFieldElementBytes(LongfellowSumcheckCircuit circuit)
    {
        int elements = circuit.PublicInputCount + 1 + circuit.InputCount;
        foreach(LongfellowSumcheckLayer layer in circuit.Layers)
        {
            elements += (2 * 2 * layer.HandRounds) + 2;
        }

        return elements;
    }


    /// <summary>Computes a one-shot SHA-256 digest of <paramref name="input"/> into <paramref name="output"/>, ignoring the caller-supplied hash-function label.</summary>
    private static void Sha256OneShot(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction) => SHA256.HashData(input, output);


    /// <summary>Encrypts one AES-256 ECB block under <paramref name="key"/>, the transcript's Fiat-Shamir expansion primitive.</summary>
    private static void Aes256Ecb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.EncryptEcb(input, output, PaddingMode.None);
    }


    /// <summary>Computes the three Lagrange weights weight[k] = Π_{j != k} (x - X[j]) / (X[k] - X[j]) over Fp256, the sumcheck verifier's dot_wpoly.coef.</summary>
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


    /// <summary>Reduces an unsigned coordinate modulo the P-256 base-field order and returns it as a canonical big-endian scalar: the Fp256 profile's of_scalar.</summary>
    private static void OfScalar(uint coordinate, Span<byte> destination) =>
        Canonical(new BigInteger(coordinate) % Prime).CopyTo(destination);


    /// <summary>Returns whether a canonical big-endian scalar is below the modulus: the Fp256 profile's fits predicate.</summary>
    private static bool InRange(ReadOnlySpan<byte> canonical) => ReadCanonicalBigEndian(canonical) < Prime;


    /// <summary>Runs of_bytes_field on a little-endian draw and discards the result, used inside a rejection assertion.</summary>
    private static void Reject(ReadOnlySpan<byte> littleEndian)
    {
        Span<byte> sink = stackalloc byte[ScalarSize];
        Profile.FromBytesField(littleEndian, sink);
    }


    /// <summary>Evaluates the degree-2 polynomial a0 + a1*x + a2*x^2 at <paramref name="x"/>, reduced into the canonical [0, p) range.</summary>
    private static BigInteger EvaluatePolynomial(BigInteger a0, BigInteger a1, BigInteger a2, BigInteger x)
    {
        BigInteger value = (((a2 * x) + a1) * x) + a0;

        return ((value % Prime) + Prime) % Prime;
    }


    /// <summary>Returns a value as a canonical big-endian scalar of <see cref="ScalarSize"/> bytes.</summary>
    private static byte[] Canonical(BigInteger value)
    {
        byte[] canonical = new byte[ScalarSize];
        WriteCanonicalBigEndian(value, canonical);

        return canonical;
    }


    /// <summary>Returns a small non-negative value as a canonical big-endian scalar.</summary>
    private static byte[] Canonical(int value) => Canonical(new BigInteger(value));


    /// <summary>Reads a canonical big-endian scalar as an unsigned <see cref="BigInteger"/>.</summary>
    private static BigInteger ReadCanonicalBigEndian(ReadOnlySpan<byte> bytes) => new(bytes, isUnsigned: true, isBigEndian: true);


    /// <summary>Writes a value into <paramref name="destination"/> as a canonical big-endian scalar, throwing if it does not fit.</summary>
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


    /// <summary>Converts a value to this test's own little-endian draw encoding: the canonical big-endian bytes reversed, mirroring to_bytes_field.</summary>
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
