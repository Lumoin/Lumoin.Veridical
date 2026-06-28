using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The end-to-end wire-format-conformant ZK verifier, a faithful port of google/longfellow-zk's
/// <c>ZkVerifier&lt;Field, RSFactory&gt;</c> (<c>lib/zk/zk_verifier.h</c>). It parses a complete
/// <c>ZkProof</c> envelope (<c>com ‖ sc ‖ com_proof</c>), replays the sumcheck transcript to derive the
/// Ligero linear-constraint system through <see cref="LongfellowZkConstraintBuilder"/>
/// (<c>ZkCommon::verifier_constraints</c>), and runs the Ligero verifier
/// (<see cref="LongfellowLigeroVerifier"/>) with the circuit-derived parameters and the per-layer
/// claim-pad quadratic constraints (<c>setup_lqc</c>).
/// </summary>
/// <remarks>
/// <para>
/// The composition order mirrors the reference's <c>recv_commitment</c> then <c>verify</c>:
/// </para>
/// <list type="number">
///   <item><description><b>Parse.</b> Split the envelope into the 32-byte commitment root (<c>read_com</c>), the sumcheck segment (<c>read_sc_proof</c>, C.7), and the Ligero proof (<c>read_com_proof</c>, C.6).</description></item>
///   <item><description><b>Absorb the root.</b> <c>recv_commitment</c> writes the commitment root into the transcript (the Ligero layer's <c>receive_commitment</c>) before any challenge is squeezed.</description></item>
///   <item><description><b>Fiat–Shamir setup.</b> <c>initialize_sumcheck_fiat_shamir</c> absorbs the circuit id, the public inputs, a zero element, and <c>nterms()</c> zero bytes.</description></item>
///   <item><description><b>Build constraints.</b> <c>verifier_constraints</c> replays the layer walk over the sumcheck proof, building the sparse <c>A</c>, the targets <c>b</c>, and the constraint count <c>cn</c>, ending with the input-binding constraint.</description></item>
///   <item><description><b>Ligero verify.</b> <c>LigeroVerifier::verify</c> with the circuit-derived <see cref="LongfellowLigeroParameters"/> (<c>nw = n_witness + pad_size</c>, <c>nq = nl</c>), the theorem statement hash <c>{de,ad,be,ef,0…}</c>, the <c>A</c>/<c>b</c> system, and the <c>setup_lqc</c> claim-pad triples.</description></item>
/// </list>
/// <para>
/// The commitment root is absorbed BEFORE the Fiat–Shamir setup, exactly as the reference orders
/// <c>recv_commitment</c> (which absorbs the root) before <c>verify</c> (which performs the setup). The
/// Ligero verifier re-absorbs the theorem-statement hash and squeezes its own challenges from the same
/// continuing transcript — so the transcript handed to it is the one the constraint build left, with the
/// input-binding challenge already squeezed.
/// </para>
/// <para>
/// All primitives are delegate-injected (the GF(2^128) backend, the LCH14 RS engine, SHA-256, AES-256)
/// so the port stays consistent with the library's primitive-agnostic commitment infrastructure.
/// </para>
/// </remarks>
internal static class LongfellowZkVerifier
{
    private const int DigestLength = 32;

    //The reference's ZkProver hash_of_A: {0xde, 0xad, 0xbe, 0xef} then zero-filled to 32 bytes.
    private static readonly byte[] TheoremStatementHash = BuildTheoremStatementHash();


    /// <summary>
    /// The first witness index after the private inputs — the reference's <c>n_witness</c> — used as the
    /// first pad index by both the constraint build and the <c>setup_lqc</c> claim-pad layout.
    /// </summary>
    /// <param name="circuit">The circuit shape.</param>
    public static int WitnessCount(LongfellowSumcheckCircuit circuit)
    {
        ArgumentNullException.ThrowIfNull(circuit);

        return circuit.InputCount - circuit.PublicInputCount;
    }


    /// <summary>
    /// The proof-pad size of the circuit (<c>ZkCommon::pad_size</c>): the sum over layers of the without-
    /// overlap layer size <c>PadLayout(logw).layer_size()</c>. Added to <see cref="WitnessCount"/> it is
    /// the Ligero witness count <c>nw</c>.
    /// </summary>
    /// <param name="circuit">The circuit shape.</param>
    public static int PadSize(LongfellowSumcheckCircuit circuit)
    {
        ArgumentNullException.ThrowIfNull(circuit);

        int size = 0;
        foreach(LongfellowSumcheckLayer layer in circuit.Layers)
        {
            size += new LongfellowZkPadLayout(layer.HandRounds).LayerSize;
        }

        return size;
    }


    /// <summary>
    /// Derives the Ligero parameters from the circuit exactly as the reference's <c>ZkProof</c> /
    /// <c>ZkVerifier</c> constructor does: <c>nw = (ninputs − npub_in) + pad_size(c)</c>, <c>nq = nl</c>,
    /// and the given rate / opened-column count, over the field byte sizes.
    /// </summary>
    /// <param name="circuit">The circuit shape.</param>
    /// <param name="inverseRate">The inverse Reed–Solomon rate (<c>rateinv</c>).</param>
    /// <param name="openedColumnCount">The opened-column count (<c>nreq</c>).</param>
    /// <param name="fieldBytes">The full-field element byte size (16 for GF(2^128)).</param>
    /// <param name="subFieldBytes">The subfield element byte size (2 for GF(2^16)).</param>
    public static LongfellowLigeroParameters DeriveParameters(
        LongfellowSumcheckCircuit circuit,
        int inverseRate,
        int openedColumnCount,
        int fieldBytes,
        int subFieldBytes)
    {
        ArgumentNullException.ThrowIfNull(circuit);

        int nw = WitnessCount(circuit) + PadSize(circuit);

        return new LongfellowLigeroParameters(nw, circuit.LayerCount, inverseRate, openedColumnCount, fieldBytes, subFieldBytes);
    }


    /// <summary>
    /// Derives the Ligero parameters from a <em>pinned</em> <c>block_enc</c> exactly as the deployed v7
    /// path does: the reference no longer optimizes <c>block_enc</c> online but stores it in the
    /// <c>ZkSpecStruct</c> (<c>block_enc_hash</c> / <c>block_enc_sig</c>) and feeds it to both the
    /// <c>ZkProof</c> prover and the <c>ZkVerifier</c> (<c>mdoc_zk.cc:615-616, 659-662</c>). The witness
    /// and quadratic counts are derived from the circuit identically to the optimizing overload.
    /// </summary>
    /// <param name="circuit">The circuit shape.</param>
    /// <param name="inverseRate">The inverse Reed–Solomon rate (<c>rateinv</c>).</param>
    /// <param name="openedColumnCount">The opened-column count (<c>nreq</c>).</param>
    /// <param name="fieldBytes">The full-field element byte size (16 for GF(2^128)).</param>
    /// <param name="subFieldBytes">The subfield element byte size (2 for GF(2^16)).</param>
    /// <param name="blockEncoded">The pinned <c>block_enc</c> from the <c>ZkSpecStruct</c>.</param>
    public static LongfellowLigeroParameters DeriveParameters(
        LongfellowSumcheckCircuit circuit,
        int inverseRate,
        int openedColumnCount,
        int fieldBytes,
        int subFieldBytes,
        int blockEncoded)
    {
        ArgumentNullException.ThrowIfNull(circuit);

        int nw = WitnessCount(circuit) + PadSize(circuit);

        return new LongfellowLigeroParameters(nw, circuit.LayerCount, inverseRate, openedColumnCount, fieldBytes, subFieldBytes, blockEncoded);
    }


    /// <summary>
    /// Builds the per-layer claim-pad quadratic constraints, the reference's <c>setup_lqc</c>. Per layer
    /// <c>i</c> the constraint asserts <c>W[x]·W[y] = W[z]</c> where <c>x = pi + claim_pad(0)</c>,
    /// <c>y = pi + claim_pad(1)</c>, <c>z = pi + claim_pad(2)</c> at the pad index <c>pi</c> that starts at
    /// <c>n_witness</c> and advances by each layer's without-overlap size.
    /// </summary>
    /// <param name="circuit">The circuit shape.</param>
    /// <param name="firstPadIndex">The first pad index (<c>n_witness</c>).</param>
    /// <param name="destination">Receives the <see cref="LongfellowSumcheckCircuit.LayerCount"/> constraints.</param>
    /// <exception cref="ArgumentException">When <paramref name="destination"/> is the wrong length.</exception>
    public static void SetupLayerQuadraticConstraints(LongfellowSumcheckCircuit circuit, int firstPadIndex, Span<LigeroQuadraticConstraint> destination)
    {
        ArgumentNullException.ThrowIfNull(circuit);

        if(destination.Length != circuit.LayerCount)
        {
            throw new ArgumentException($"setup_lqc produces {circuit.LayerCount} constraints; the destination holds {destination.Length}.", nameof(destination));
        }

        int padIndex = firstPadIndex;
        for(int i = 0; i < circuit.LayerCount; i++)
        {
            var pad = new LongfellowZkPadLayout(circuit.Layers[i].HandRounds);
            destination[i] = new LigeroQuadraticConstraint(padIndex + pad.ClaimPad(0), padIndex + pad.ClaimPad(1), padIndex + pad.ClaimPad(2));
            padIndex += pad.LayerSize;
        }
    }


    /// <summary>
    /// Absorbs a <c>ZkProof</c> commitment root into the transcript, the reference's
    /// <c>ZkVerifier::recv_commitment</c> (which delegates to <c>LigeroVerifier::receive_commitment</c>,
    /// <c>zk_verifier.h:69-72</c>): the 32-byte root is written through the transcript's byte-string path
    /// before any challenge is squeezed. The dual-field driver calls this for BOTH the hash and the
    /// signature roots, in that order, before squeezing the shared MAC key — the cross-field binding.
    /// </summary>
    /// <param name="root">The 32-byte commitment root.</param>
    /// <param name="transcript">The shared transcript the root absorbs into.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="transcript"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="root"/> is not 32 bytes.</exception>
    public static void RecvCommitment(ReadOnlySpan<byte> root, LongfellowTranscript transcript)
    {
        ArgumentNullException.ThrowIfNull(transcript);

        transcript.AbsorbCommitmentRoot(root);
    }


    /// <summary>
    /// Verifies a parsed <c>ZkProof</c> against the public inputs, picking up AFTER the commitment root has
    /// been absorbed (<see cref="RecvCommitment"/>) — the post-<c>recv_commitment</c> body of the reference's
    /// <c>ZkVerifier::verify</c> (<c>zk_verifier.h:74-97</c>): the Fiat–Shamir setup, the
    /// <c>verifier_constraints</c> layer walk, and the Ligero verify. Field-generic per D2: the caller passes
    /// the row-encoder factory and the field profile, so one method serves both the GF(2^128) hash circuit
    /// and the Fp256 signature circuit on the same transcript.
    /// </summary>
    /// <param name="circuit">The circuit shape with its per-layer <c>Quad</c> terms; must have <c>logc == 0</c>.</param>
    /// <param name="parameters">The circuit-derived Ligero parameters (see <see cref="DeriveParameters(LongfellowSumcheckCircuit, int, int, int, int, int)"/>).</param>
    /// <param name="sumcheckProof">The parsed sumcheck segment (<c>read_sc_proof</c>).</param>
    /// <param name="ligeroProof">The parsed Ligero <c>com_proof</c> (<c>read_com_proof</c>).</param>
    /// <param name="root">The 32-byte commitment root the Ligero Merkle check re-derives leaves against (already absorbed via <see cref="RecvCommitment"/>).</param>
    /// <param name="publicInputs">The public inputs (the first <c>npub_in</c> witness elements), <c>npub_in</c> · the field's on-wire element width little-endian element bytes (16 for GF(2^128), 32 for Fp256).</param>
    /// <param name="transcript">The shared transcript, with the root already absorbed.</param>
    /// <param name="encoderFactory">The field's systematic Reed–Solomon row encoder factory (binary LCH14 or prime FFT-convolution).</param>
    /// <param name="profile">The field profile: element width, the third evaluation point, and the <c>sample</c> seam.</param>
    /// <param name="add">Field addition.</param>
    /// <param name="subtract">Field subtraction.</param>
    /// <param name="multiply">Field multiplication.</param>
    /// <param name="invert">Field inversion.</param>
    /// <param name="merkleHash">The two-to-one <c>SHA256(L ‖ R)</c> Merkle compression.</param>
    /// <param name="leafHash">The one-shot SHA-256 over a contiguous span.</param>
    /// <param name="hashAlgorithm">The canonical hash-function name (SHA-256).</param>
    /// <param name="curve">The field the delegates operate over (<see cref="CurveParameterSet.None"/> for GF(2^128)).</param>
    /// <param name="pool">The pool the working buffers rent from.</param>
    /// <param name="result">The verdict cause; <see cref="LongfellowZkVerificationResult.Accepted"/> on success.</param>
    /// <param name="bindQuadReduce">The optional fused <c>bind_quad</c> per-term reduce primitive; the GF(2^128) hash side supplies it, the Fp256 sig side leaves it <see langword="null"/> for the scalar fallback.</param>
    /// <param name="broadcastMultiplyAccumulate">The optional broadcast-scalar fused multiply primitive the <c>filleq</c> eq-array fills route their per-level scalar-times-vector products through; the GF(2^128) hash side supplies it, the Fp256 sig side leaves it <see langword="null"/> for the scalar fallback.</param>
    /// <param name="fp256BatchMultiply">The optional lane-parallel batch Montgomery multiply the <c>bind_quad</c> reduction routes its three-multiply-per-term chain through; the Fp256 sig side supplies it, the GF(2^128) hash side leaves it <see langword="null"/> (it supplies <paramref name="bindQuadReduce"/> instead).</param>
    /// <returns><see langword="true"/> when the proof verifies, <see langword="false"/> otherwise.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the circuit has copies.</exception>
    public static bool VerifyFromAbsorbedRoot(
        LongfellowSumcheckCircuit circuit,
        LongfellowLigeroParameters parameters,
        LongfellowSumcheckProof sumcheckProof,
        LongfellowLigeroProof ligeroProof,
        ReadOnlySpan<byte> root,
        ReadOnlySpan<byte> publicInputs,
        LongfellowTranscript transcript,
        LongfellowRowEncoderFactory encoderFactory,
        LongfellowFieldProfile profile,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate leafHash,
        string hashAlgorithm,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        out LongfellowZkVerificationResult result,
        ScalarBindQuadReduceDelegate? bindQuadReduce = null,
        ScalarBroadcastMultiplyAccumulateDelegate? broadcastMultiplyAccumulate = null,
        ScalarBatchMultiplyDelegate? fp256BatchMultiply = null)
    {
        ArgumentNullException.ThrowIfNull(circuit);
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(sumcheckProof);
        ArgumentNullException.ThrowIfNull(ligeroProof);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(encoderFactory);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(leafHash);
        ArgumentNullException.ThrowIfNull(hashAlgorithm);
        ArgumentNullException.ThrowIfNull(pool);

        if(circuit.CopyRounds != 0)
        {
            throw new ArgumentException($"The ZK verifier requires logc == 0; the circuit has logc = {circuit.CopyRounds}.", nameof(circuit));
        }

        result = LongfellowZkVerificationResult.Accepted;

        //initialize_sumcheck_fiat_shamir: id, public inputs, zero, nterms zero bytes.
        InitializeFiatShamir(circuit, publicInputs, profile, transcript, pool);

        int firstPadIndex = WitnessCount(circuit);

        //verifier_constraints: build the A/b system, driving the transcript through the layer walk.
        using LongfellowZkConstraintBuilder.ConstraintSystem system = LongfellowZkConstraintBuilder.Build(
            circuit, sumcheckProof, publicInputs, firstPadIndex, transcript, add, subtract, multiply, invert, profile, curve, pool, bindQuadReduce, broadcastMultiplyAccumulate, fp256BatchMultiply);

        //setup_lqc: the per-layer claim-pad quadratic constraints.
        Span<LigeroQuadraticConstraint> lqc = circuit.LayerCount <= 32 ? stackalloc LigeroQuadraticConstraint[circuit.LayerCount] : new LigeroQuadraticConstraint[circuit.LayerCount];
        SetupLayerQuadraticConstraints(circuit, firstPadIndex, lqc);

        //Flatten the sparse A terms and the targets for the Ligero verifier.
        int termCount = system.Terms.Count;
        LigeroLinearConstraint[] linearTerms = new LigeroLinearConstraint[termCount];
        for(int i = 0; i < termCount; i++)
        {
            linearTerms[i] = system.Terms[i];
        }

        bool ok = LongfellowLigeroVerifier.Verify(
            parameters,
            ligeroProof,
            root,
            transcript,
            TheoremStatementHash,
            system.ConstraintCount,
            linearTerms,
            system.Targets,
            lqc,
            encoderFactory,
            profile,
            add,
            subtract,
            multiply,
            merkleHash,
            leafHash,
            hashAlgorithm,
            curve,
            pool,
            out LongfellowLigeroVerificationResult ligeroResult);

        if(!ok)
        {
            result = LongfellowZkVerificationResult.LigeroRejected;

            return false;
        }

        return true;
    }


    /// <summary>
    /// Verifies a complete GF(2^128) <c>ZkProof</c> envelope against the circuit and the public inputs, the
    /// reference's <c>ZkVerifier::recv_commitment</c> + <c>verify</c>. The single-call form for the hash
    /// circuit; it parses the envelope, then delegates to <see cref="RecvCommitment"/> and
    /// <see cref="VerifyFromAbsorbedRoot"/> (the dual-field driver drives the two halves directly).
    /// </summary>
    /// <param name="circuit">The circuit shape with its per-layer <c>Quad</c> terms; must have <c>logc == 0</c>.</param>
    /// <param name="parameters">The circuit-derived Ligero parameters (see <see cref="DeriveParameters(LongfellowSumcheckCircuit, int, int, int, int, int)"/>).</param>
    /// <param name="proofBytes">The full proof envelope <c>com ‖ sc ‖ com_proof</c>.</param>
    /// <param name="publicInputs">The public inputs (the first <c>npub_in</c> witness elements), <c>npub_in</c> · 16 little-endian element bytes.</param>
    /// <param name="subFieldBytes">The subfield element byte size (2 for GF(2^16)).</param>
    /// <param name="transcript">A fresh transcript seeded the way the prover seeded it.</param>
    /// <param name="fft">The LCH14 additive-FFT engine.</param>
    /// <param name="add">GF(2^128) addition (XOR).</param>
    /// <param name="subtract">GF(2^128) subtraction (coincides with add).</param>
    /// <param name="multiply">GF(2^128) multiplication.</param>
    /// <param name="invert">GF(2^128) inversion.</param>
    /// <param name="merkleHash">The two-to-one <c>SHA256(L ‖ R)</c> Merkle compression.</param>
    /// <param name="leafHash">The one-shot SHA-256 over a contiguous span.</param>
    /// <param name="hashAlgorithm">The canonical hash-function name (SHA-256).</param>
    /// <param name="curve">The field the delegates operate over (<see cref="CurveParameterSet.None"/> for GF(2^128)).</param>
    /// <param name="pool">The pool the working buffers rent from.</param>
    /// <param name="result">The verdict cause; <see cref="LongfellowZkVerificationResult.Accepted"/> on success.</param>
    /// <param name="bindQuadReduce">The optional fused <c>bind_quad</c> per-term reduce primitive for the GF(2^128) hash side; <see langword="null"/> falls back to the scalar reduction.</param>
    /// <param name="broadcastMultiplyAccumulate">The optional broadcast-scalar fused multiply primitive the <c>filleq</c> eq-array fills route their per-level scalar-times-vector products through; the GF(2^128) hash side supplies it, the Fp256 sig side leaves it <see langword="null"/> for the scalar fallback.</param>
    /// <returns><see langword="true"/> when the full proof verifies, <see langword="false"/> otherwise.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the circuit has copies or a length is wrong.</exception>
    public static bool Verify(
        LongfellowSumcheckCircuit circuit,
        LongfellowLigeroParameters parameters,
        ReadOnlySpan<byte> proofBytes,
        ReadOnlySpan<byte> publicInputs,
        int subFieldBytes,
        LongfellowTranscript transcript,
        Lch14AdditiveFft fft,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate leafHash,
        string hashAlgorithm,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        out LongfellowZkVerificationResult result,
        ScalarBindQuadReduceDelegate? bindQuadReduce = null,
        ScalarBroadcastMultiplyAccumulateDelegate? broadcastMultiplyAccumulate = null)
    {
        ArgumentNullException.ThrowIfNull(circuit);
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(fft);
        ArgumentNullException.ThrowIfNull(pool);

        result = LongfellowZkVerificationResult.Accepted;

        //The GF binding of the row-encoder seam and the field profile, derived from the additive-FFT engine.
        LongfellowRowEncoderFactory encoderFactory = LongfellowGf2k128Encoding.CreateEncoderFactory(fft, pool);
        LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft);

        //Parse the envelope: com (32) || sc || com_proof.
        if(proofBytes.Length < DigestLength)
        {
            result = LongfellowZkVerificationResult.MalformedProof;

            return false;
        }

        ReadOnlySpan<byte> root = proofBytes[..DigestLength];
        int scSize = LongfellowSumcheckProofSerializer.SerializedSize(circuit, profile);
        if(proofBytes.Length < DigestLength + scSize)
        {
            result = LongfellowZkVerificationResult.MalformedProof;

            return false;
        }

        ReadOnlySpan<byte> scBytes = proofBytes.Slice(DigestLength, scSize);
        ReadOnlySpan<byte> comProofBytes = proofBytes[(DigestLength + scSize)..];

        using LongfellowSumcheckProof? sumcheckProof = LongfellowSumcheckProofSerializer.Read(circuit, profile, pool, scBytes, out _);
        if(sumcheckProof is null)
        {
            result = LongfellowZkVerificationResult.MalformedProof;

            return false;
        }

        using LongfellowLigeroProof? ligeroProof = LongfellowLigeroProofSerializer.Read(parameters, subFieldBytes, profile, fft, pool, comProofBytes, out _);
        if(ligeroProof is null)
        {
            result = LongfellowZkVerificationResult.MalformedProof;

            return false;
        }

        //recv_commitment: absorb the commitment root before any challenge.
        RecvCommitment(root, transcript);

        return VerifyFromAbsorbedRoot(
            circuit, parameters, sumcheckProof, ligeroProof, root, publicInputs, transcript, encoderFactory, profile,
            add, subtract, multiply, invert, merkleHash, leafHash, hashAlgorithm, curve, pool, out result, bindQuadReduce, broadcastMultiplyAccumulate);
    }


    //ZkCommon::initialize_sumcheck_fiat_shamir: id [byte string], each public input [field element],
    //F.zero() [field element], nterms() zero bytes [byte string]. The input column is NOT absorbed
    //here (the ZK verifier never sees the witness; that absorb is the non-ZK verifier's write_input).
    private static void InitializeFiatShamir(LongfellowSumcheckCircuit circuit, ReadOnlySpan<byte> publicInputs, LongfellowFieldProfile profile, LongfellowTranscript transcript, BaseMemoryPool pool)
    {
        transcript.AbsorbByteString(circuit.Id.Span);

        int elementBytes = profile.ElementBytes;
        for(int i = 0; i < circuit.PublicInputCount; i++)
        {
            transcript.AbsorbFieldElement(publicInputs.Slice(i * elementBytes, elementBytes), elementBytes);
        }

        Span<byte> zeroElement = stackalloc byte[Scalar.SizeBytes];
        transcript.AbsorbFieldElement(zeroElement[..elementBytes], elementBytes);

        int termCount = circuit.TermCount;
        using IMemoryOwner<byte> zerosOwner = pool.Rent(Math.Max(termCount, 1));
        Span<byte> zeros = zerosOwner.Memory.Span[..termCount];
        zeros.Clear();
        transcript.AbsorbByteString(zeros);
    }


    private static byte[] BuildTheoremStatementHash()
    {
        byte[] hash = new byte[DigestLength];
        hash[0] = 0xde;
        hash[1] = 0xad;
        hash[2] = 0xbe;
        hash[3] = 0xef;

        return hash;
    }
}
