using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Collections.Generic;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The end-to-end wire-format-conformant ZK PROVER, a faithful port of google/longfellow-zk's
/// <c>ZkProver&lt;Field, RSFactory&gt;</c> (<c>lib/zk/zk_prover.h</c>). It commits to a sumcheck witness
/// and a random pad that encrypts the sumcheck transcript, runs the sumcheck over the true claim and
/// witness while emitting the encrypted (padded) transcript, then proves with Ligero the statement that
/// the committed witness and pad — used to decrypt the transcript — satisfy the sumcheck verifier. The
/// output is a complete <c>ZkProof</c> envelope <c>com ‖ sc ‖ com_proof</c> byte-identical to the
/// reference's for the same circuit, witness, seed and counter randomness.
/// </summary>
/// <remarks>
/// <para>
/// The composition mirrors the reference's <c>commit</c> then <c>prove</c>:
/// </para>
/// <list type="number">
///   <item><description><b>Commit.</b> The committed witness is the circuit's private inputs (<c>W[npub_in..ninputs)</c>) followed by the proof pad. <see cref="LongfellowProofPad.Fill"/> draws the pad from the random source in <c>fill_pad</c> order; the SAME source continues into the Ligero commit, so the byte-consumption order matches. The per-layer claim-pad product triples are the <c>setup_lqc</c> quadratic constraints. The commitment root is absorbed into the transcript (the Ligero layer's <c>write_commitment</c>).</description></item>
///   <item><description><b>Fiat–Shamir setup.</b> <c>initialize_sumcheck_fiat_shamir</c> absorbs the circuit id, the public inputs, a zero element, and <c>nterms()</c> zero bytes onto the post-commit transcript.</description></item>
///   <item><description><b>Sumcheck.</b> The transcript is cloned (the reference's <c>tst = tsp.clone()</c>); the sumcheck prover (<see cref="LongfellowSumcheckProver"/>) runs on the clone, evaluating the circuit and emitting the padded round polynomials into the sc segment.</description></item>
///   <item><description><b>Constraints.</b> <see cref="LongfellowZkConstraintBuilder"/> replays the sumcheck on the original transcript, building the Ligero <c>A·w = b</c> system over the committed witness, ending with the input-binding constraint.</description></item>
///   <item><description><b>Ligero prove.</b> <see cref="LongfellowLigeroProver"/> proves the <c>A·w = b</c> system (and the claim-pad quadratics) over the standing commitment, continuing the original transcript from where the constraint build left it; the theorem-statement hash is the reference's <c>{de,ad,be,ef,0…}</c>.</description></item>
///   <item><description><b>Serialize.</b> The envelope is <c>write_com</c> (the 32-byte root) ‖ <c>write_sc_proof</c> (the sumcheck segment) ‖ <c>write_com_proof</c> (the Ligero proof).</description></item>
/// </list>
/// <para>
/// The pad/commit timing is the subtle invariant: the pad is drawn BEFORE the Ligero commit from the same
/// random stream, and the pad witnesses are appended after the private inputs, so the committed witness
/// vector is <c>[private inputs ‖ pad]</c> and the random byte order is <c>pad draws, then commit draws</c>.
/// The commitment binds the pad before any sumcheck challenge is squeezed (commit-then-challenge), which
/// is what lets the encrypted transcript hide the witness while the Ligero proof still checks it.
/// </para>
/// <para>
/// All primitives are delegate-injected (the GF(2^128) backend, the LCH14 RS engine, SHA-256, AES-256)
/// so the port stays consistent with the library's primitive-agnostic commitment infrastructure. The
/// working buffers are pool-rented and cleared on return.
/// </para>
/// </remarks>
internal static class LongfellowZkProver
{
    private const int ScalarSize = Scalar.SizeBytes;
    private const int DigestLength = 32;

    //The reference's ZkProver hash_of_A: {0xde, 0xad, 0xbe, 0xef} then zero-filled to 32 bytes.
    private static readonly byte[] TheoremStatementHash = BuildTheoremStatementHash();


    /// <summary>
    /// Produces a complete <c>ZkProof</c> envelope for <paramref name="circuit"/> and the full witness
    /// column <paramref name="witnessColumn"/>, the reference's <c>ZkProver::commit</c> + <c>prove</c> +
    /// <c>ZkProof::write</c>.
    /// </summary>
    /// <param name="circuit">The circuit shape with its per-layer Quad terms; must have <c>nc == 1</c>, <c>logc == 0</c>.</param>
    /// <param name="parameters">The circuit-derived Ligero parameters (<see cref="LongfellowZkVerifier.DeriveParameters(LongfellowSumcheckCircuit, int, int, int, int, int)"/>).</param>
    /// <param name="witnessColumn">The full input wire column <c>W</c> (one + public + private), <see cref="LongfellowSumcheckCircuit.InputCount"/> · 32 canonical bytes.</param>
    /// <param name="subFieldBytes">The subfield element byte size (2 for GF(2^16)).</param>
    /// <param name="subfieldBoundary">The reference's <c>subfield_boundary</c> rebased to start at <c>npub_in</c>; the commit draws subfield padding for witness rows below it.</param>
    /// <param name="random">The raw-byte entropy source, consumed in the reference's fixed order (pad draws, then the Ligero commit draws).</param>
    /// <param name="transcript">A fresh transcript seeded the way the reference seeds the prover's; this call absorbs the root, performs the FS setup and drives the sumcheck/constraint/Ligero flows.</param>
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
    /// <param name="broadcastMultiplyAccumulate">The optional broadcast-scalar fused multiply primitive the <c>filleq</c> eq-array fills in the constraint replay route their per-level scalar-times-vector products through; the GF(2^128) hash side supplies it, the Fp256 sig side leaves it <see langword="null"/> for the scalar fallback.</param>
    /// <param name="bindQuadReduce">The optional fused <c>bind_quad</c> per-term reduce primitive the constraint replay's <c>BindQuad</c> routes its three-multiply-per-term reduction through; the GF(2^128) hash side supplies it, the Fp256 sig side leaves it <see langword="null"/> for the scalar fallback.</param>
    /// <param name="gatherMultiplyAccumulate">The optional gather/scatter fused multiply-accumulate primitive the sumcheck prover's per-round <c>QW</c> corner precompute routes through; the GF(2^128) hash side supplies it, the Fp256 sig side leaves it <see langword="null"/> for the scalar fallback.</param>
    /// <returns>The full proof envelope <c>com ‖ sc ‖ com_proof</c>; the caller owns the returned array.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the circuit has copies or a length is wrong.</exception>
    /// <exception cref="InvalidOperationException">When the witness does not satisfy the circuit.</exception>
    public static byte[] Prove(
        LongfellowSumcheckCircuit circuit,
        LongfellowLigeroParameters parameters,
        ReadOnlySpan<byte> witnessColumn,
        int subFieldBytes,
        int subfieldBoundary,
        LongfellowRandomByteSource random,
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
        ScalarBroadcastMultiplyAccumulateDelegate? broadcastMultiplyAccumulate = null,
        ScalarBindQuadReduceDelegate? bindQuadReduce = null,
        ScalarGatherMultiplyAccumulateDelegate? gatherMultiplyAccumulate = null)
    {
        ArgumentNullException.ThrowIfNull(fft);
        ArgumentNullException.ThrowIfNull(pool);

        //The GF binding of the field profile, the row-encoder seam, and the subfield-run codec, all derived
        //from the additive-FFT engine; routing the GF path through the field-generic entry leaves its bytes
        //unchanged (the seam reproduces exactly the values the binary-only port baked in).
        LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft);
        LongfellowRowEncoderFactory encoderFactory = LongfellowGf2k128Encoding.CreateEncoderFactory(fft, pool);
        using LongfellowSubfieldRunCodec codec = LongfellowSubfieldRunCodec.ForGf2k128(profile, fft, subFieldBytes, pool);

        return Prove(
            circuit, parameters, witnessColumn, subfieldBoundary, random, transcript, encoderFactory, profile, codec,
            add, subtract, multiply, invert, merkleHash, leafHash, hashAlgorithm, curve, pool, broadcastMultiplyAccumulate, bindQuadReduce, gatherMultiplyAccumulate);
    }


    /// <summary>
    /// Produces a complete <c>ZkProof</c> envelope for <paramref name="circuit"/> and the full witness column
    /// <paramref name="witnessColumn"/> over an arbitrary field, the reference's <c>ZkProver::commit</c> +
    /// <c>prove</c> + <c>ZkProof::write</c>. Field-generic per D2 (mirroring
    /// <see cref="LongfellowZkVerifier.VerifyFromAbsorbedRoot"/>): the caller passes the row-encoder factory,
    /// the field profile and the subfield-run codec, so one method serves both the GF(2^128) hash circuit (via
    /// the convenience overload above) and the Fp256 signature circuit. It does NOT touch
    /// <see cref="LongfellowGf2k128Encoding"/>.
    /// </summary>
    /// <param name="circuit">The circuit shape with its per-layer Quad terms; must have <c>nc == 1</c>, <c>logc == 0</c>.</param>
    /// <param name="parameters">The circuit-derived Ligero parameters (<see cref="LongfellowZkVerifier.DeriveParameters(LongfellowSumcheckCircuit, int, int, int, int, int)"/>).</param>
    /// <param name="witnessColumn">The full input wire column <c>W</c> (one + public + private), <see cref="LongfellowSumcheckCircuit.InputCount"/> · 32 canonical bytes.</param>
    /// <param name="subfieldBoundary">The reference's <c>subfield_boundary</c> rebased to start at <c>npub_in</c>; the commit draws subfield padding for witness rows below it.</param>
    /// <param name="random">The raw-byte entropy source, consumed in the reference's fixed order (pad draws, then the Ligero commit draws).</param>
    /// <param name="transcript">A fresh transcript seeded the way the reference seeds the prover's; this call absorbs the root, performs the FS setup and drives the sumcheck/constraint/Ligero flows.</param>
    /// <param name="encoderFactory">The field's systematic Reed–Solomon row encoder factory (binary LCH14 or prime FFT-convolution); the commit and the Ligero prove both route through it.</param>
    /// <param name="profile">The field profile: the on-wire element width, the third evaluation point, the <c>sample</c> seam and the <c>to_bytes_field</c> framing.</param>
    /// <param name="codec">The subfield-run codec for the field (GF(2^128) basis solve or the Fp256 full-field identity); the serialize's run-length pass routes through it.</param>
    /// <param name="add">Field addition.</param>
    /// <param name="subtract">Field subtraction.</param>
    /// <param name="multiply">Field multiplication.</param>
    /// <param name="invert">Field inversion.</param>
    /// <param name="merkleHash">The two-to-one <c>SHA256(L ‖ R)</c> Merkle compression.</param>
    /// <param name="leafHash">The one-shot SHA-256 over a contiguous span.</param>
    /// <param name="hashAlgorithm">The canonical hash-function name (SHA-256).</param>
    /// <param name="curve">The field the delegates operate over (<see cref="CurveParameterSet.None"/> for GF(2^128)).</param>
    /// <param name="pool">The pool the working buffers rent from.</param>
    /// <param name="broadcastMultiplyAccumulate">The optional broadcast-scalar fused multiply primitive the <c>filleq</c> eq-array fills in the constraint replay route their per-level scalar-times-vector products through; the GF(2^128) hash side supplies it, the Fp256 sig side leaves it <see langword="null"/> for the scalar fallback.</param>
    /// <param name="bindQuadReduce">The optional fused <c>bind_quad</c> per-term reduce primitive the constraint replay's <c>BindQuad</c> routes its three-multiply-per-term reduction through; the GF(2^128) hash side supplies it, the Fp256 sig side leaves it <see langword="null"/> for the scalar fallback.</param>
    /// <param name="gatherMultiplyAccumulate">The optional gather/scatter fused multiply-accumulate primitive the sumcheck prover's per-round <c>QW</c> corner precompute routes through; the GF(2^128) hash side supplies it, the Fp256 sig side leaves it <see langword="null"/> for the scalar fallback.</param>
    /// <param name="fp256BatchMultiply">The optional lane-parallel batch Montgomery multiply the constraint replay's <c>bind_quad</c> reduction routes its three-multiply-per-term chain through; the Fp256 sig side supplies it, the GF(2^128) hash side leaves it <see langword="null"/> (it supplies <paramref name="bindQuadReduce"/> instead).</param>
    /// <returns>The full proof envelope <c>com ‖ sc ‖ com_proof</c>; the caller owns the returned array.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the circuit has copies or a length is wrong.</exception>
    /// <exception cref="InvalidOperationException">When the witness does not satisfy the circuit.</exception>
    public static byte[] Prove(
        LongfellowSumcheckCircuit circuit,
        LongfellowLigeroParameters parameters,
        ReadOnlySpan<byte> witnessColumn,
        int subfieldBoundary,
        LongfellowRandomByteSource random,
        LongfellowTranscript transcript,
        LongfellowRowEncoderFactory encoderFactory,
        LongfellowFieldProfile profile,
        LongfellowSubfieldRunCodec codec,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate leafHash,
        string hashAlgorithm,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        ScalarBroadcastMultiplyAccumulateDelegate? broadcastMultiplyAccumulate = null,
        ScalarBindQuadReduceDelegate? bindQuadReduce = null,
        ScalarGatherMultiplyAccumulateDelegate? gatherMultiplyAccumulate = null,
        ScalarBatchMultiplyDelegate? fp256BatchMultiply = null)
    {
        ArgumentNullException.ThrowIfNull(transcript);

        //The monolithic Prove is the reference's commit-then-prove on ONE transcript: commit (without the
        //root absorb), absorb the root, then finish the proof. The dual-field driver instead commits BOTH
        //circuits, absorbs BOTH roots, squeezes the shared MAC key, patches the public region, and proves
        //both — so the two halves are split into Commit + ProveFromCommitment and reused here.
        using LongfellowZkCommitment commitment = Commit(
            circuit, parameters, witnessColumn, subfieldBoundary, random, encoderFactory, profile, codec,
            add, subtract, multiply, merkleHash, leafHash, hashAlgorithm, curve, pool);

        transcript.AbsorbCommitmentRoot(commitment.RootSpan);

        return ProveFromCommitment(
            circuit, parameters, commitment, witnessColumn, transcript, encoderFactory, profile, codec,
            add, subtract, multiply, invert, merkleHash, leafHash, hashAlgorithm, curve, pool, broadcastMultiplyAccumulate, bindQuadReduce, gatherMultiplyAccumulate, fp256BatchMultiply);
    }


    /// <summary>
    /// The reference's <c>ZkProver::commit</c> (<c>lib/zk/zk_prover.h</c>) minus the transcript root absorb:
    /// draws the proof pad, assembles the committed witness <c>[private inputs ‖ pad]</c> from
    /// <paramref name="witnessColumn"/><c>[npub_in..]</c>, builds the <c>setup_lqc</c> claim-pad quadratics,
    /// and Merkle-commits the Ligero tableau. The returned <see cref="LongfellowZkCommitment"/> retains the
    /// commitment, the pad, the quadratics and the 32-byte root so a later
    /// <see cref="ProveFromCommitment"/> can finish the proof on a transcript the caller has driven (for the
    /// dual-field driver: commit both, absorb both roots, squeeze the MAC key, patch the public region,
    /// prove both). The caller absorbs <see cref="LongfellowZkCommitment.RootSpan"/> into the transcript
    /// (<see cref="LongfellowZkVerifier.RecvCommitment"/>) before <see cref="ProveFromCommitment"/>.
    /// </summary>
    /// <param name="circuit">The circuit shape with its per-layer Quad terms; must have <c>nc == 1</c>, <c>logc == 0</c>.</param>
    /// <param name="parameters">The circuit-derived Ligero parameters (<see cref="LongfellowZkVerifier.DeriveParameters(LongfellowSumcheckCircuit, int, int, int, int, int)"/>).</param>
    /// <param name="witnessColumn">The full input wire column <c>W</c> (one + public + private), <see cref="LongfellowSumcheckCircuit.InputCount"/> · 32 canonical bytes; only the private tail <c>[npub_in..]</c> is committed.</param>
    /// <param name="subfieldBoundary">The reference's <c>subfield_boundary</c> rebased to start at <c>npub_in</c>; the commit draws subfield padding for witness rows below it.</param>
    /// <param name="random">The raw-byte entropy source, consumed in the reference's fixed order (pad draws, then the Ligero commit draws).</param>
    /// <param name="encoderFactory">The field's systematic Reed–Solomon row encoder factory.</param>
    /// <param name="profile">The field profile: the on-wire element width, the third evaluation point and the <c>to_bytes_field</c> framing.</param>
    /// <param name="codec">The subfield-run codec for the field; consulted only for its subfield byte width at commit time.</param>
    /// <param name="add">Field addition.</param>
    /// <param name="subtract">Field subtraction.</param>
    /// <param name="multiply">Field multiplication.</param>
    /// <param name="merkleHash">The two-to-one <c>SHA256(L ‖ R)</c> Merkle compression.</param>
    /// <param name="leafHash">The one-shot SHA-256 over a contiguous span.</param>
    /// <param name="hashAlgorithm">The canonical hash-function name (SHA-256).</param>
    /// <param name="curve">The field the delegates operate over (<see cref="CurveParameterSet.None"/> for GF(2^128)).</param>
    /// <param name="pool">The pool the working buffers rent from.</param>
    /// <returns>The standing commitment holder; the caller disposes it.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the circuit has copies or a length is wrong.</exception>
    public static LongfellowZkCommitment Commit(
        LongfellowSumcheckCircuit circuit,
        LongfellowLigeroParameters parameters,
        ReadOnlySpan<byte> witnessColumn,
        int subfieldBoundary,
        LongfellowRandomByteSource random,
        LongfellowRowEncoderFactory encoderFactory,
        LongfellowFieldProfile profile,
        LongfellowSubfieldRunCodec codec,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate leafHash,
        string hashAlgorithm,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(circuit);
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(random);
        ArgumentNullException.ThrowIfNull(encoderFactory);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(codec);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(leafHash);
        ArgumentNullException.ThrowIfNull(hashAlgorithm);
        ArgumentNullException.ThrowIfNull(pool);

        if(circuit.CopyRounds != 0 || circuit.CopyCount != 1)
        {
            throw new ArgumentException($"The ZK prover requires nc == 1 and logc == 0; the circuit has nc = {circuit.CopyCount}, logc = {circuit.CopyRounds}.", nameof(circuit));
        }

        if(witnessColumn.Length != circuit.InputCount * ScalarSize)
        {
            throw new ArgumentException($"Expected {circuit.InputCount * ScalarSize} witness-column bytes; received {witnessColumn.Length}.", nameof(witnessColumn));
        }

        int subFieldBytes = codec.SubFieldBytes;
        int witnessCount = LongfellowZkVerifier.WitnessCount(circuit);
        int padSize = LongfellowZkVerifier.PadSize(circuit);

        //Draw the pad FIRST (the reference's fill_pad before the Ligero commit), then assemble the
        //committed witness [private inputs ‖ pad]. The pad transfers into the returned holder.
        LongfellowProofPad pad = LongfellowProofPad.Fill(circuit, random, profile, multiply, curve, pool);
        bool padTransferred = false;
        try
        {
            using IMemoryOwner<byte> witnessOwner = pool.Rent((witnessCount + padSize) * ScalarSize);
            Span<byte> committedWitness = witnessOwner.Memory.Span[..((witnessCount + padSize) * ScalarSize)];
            committedWitness.Clear();
            try
            {
                //The private inputs W[npub_in..ninputs) occupy [0, n_witness); the pad follows.
                witnessColumn.Slice(circuit.PublicInputCount * ScalarSize, witnessCount * ScalarSize).CopyTo(committedWitness);
                pad.CopyWitnessTo(committedWitness[(witnessCount * ScalarSize)..]);

                //setup_lqc: the per-layer claim-pad product triples (the quadratic constraints the commitment
                //binds at commit time and the Ligero prove carries through).
                LigeroQuadraticConstraint[] quadraticConstraints = new LigeroQuadraticConstraint[circuit.LayerCount];
                LongfellowZkVerifier.SetupLayerQuadraticConstraints(circuit, witnessCount, quadraticConstraints);

                //Commit to the witness and pad; the same random source continues from the pad draws. The
                //caller absorbs the root before any challenge (commit-then-challenge).
                LongfellowLigeroCommitment commitment = LongfellowLigeroCommitment.Commit(
                    parameters, committedWitness, quadraticConstraints, subFieldBytes, subfieldBoundary, random, encoderFactory, profile,
                    add, subtract, multiply, merkleHash, leafHash, hashAlgorithm, curve, pool);

                bool commitmentTransferred = false;
                try
                {
                    Span<byte> root = stackalloc byte[DigestLength];
                    commitment.CopyRoot(root);

                    var holder = new LongfellowZkCommitment(commitment, pad, quadraticConstraints, root);
                    commitmentTransferred = true;
                    padTransferred = true;

                    return holder;
                }
                finally
                {
                    if(!commitmentTransferred)
                    {
                        commitment.Dispose();
                    }
                }
            }
            finally
            {
                committedWitness.Clear();
            }
        }
        finally
        {
            if(!padTransferred)
            {
                pad.Dispose();
            }
        }
    }


    /// <summary>
    /// The reference's <c>ZkProver::prove</c> (<c>lib/zk/zk_prover.h</c>) starting AFTER the commitment root
    /// has been absorbed: the Fiat–Shamir setup, the sumcheck on a transcript clone, the
    /// <c>verifier_constraints</c> replay, the Ligero prove over the standing commitment, and the envelope
    /// serialize. Mirrors <see cref="LongfellowZkVerifier.VerifyFromAbsorbedRoot"/> on the prove side. The
    /// caller has already absorbed <paramref name="commitment"/>'s root into <paramref name="transcript"/>.
    /// </summary>
    /// <param name="circuit">The circuit shape with its per-layer Quad terms; must have <c>nc == 1</c>, <c>logc == 0</c>.</param>
    /// <param name="parameters">The circuit-derived Ligero parameters (<see cref="LongfellowZkVerifier.DeriveParameters(LongfellowSumcheckCircuit, int, int, int, int, int)"/>).</param>
    /// <param name="commitment">The standing commitment from <see cref="Commit"/>.</param>
    /// <param name="witnessColumn">The FULL input wire column <c>W</c>, with the public mac/av region already PATCHED by the driver; the FS setup and the circuit evaluation read the patched public region.</param>
    /// <param name="transcript">The shared transcript with the commitment root already absorbed.</param>
    /// <param name="encoderFactory">The field's systematic Reed–Solomon row encoder factory.</param>
    /// <param name="profile">The field profile: the on-wire element width, the third evaluation point and the <c>to_bytes_field</c> framing.</param>
    /// <param name="codec">The subfield-run codec the envelope serialize routes the run-length pass through.</param>
    /// <param name="add">Field addition.</param>
    /// <param name="subtract">Field subtraction.</param>
    /// <param name="multiply">Field multiplication.</param>
    /// <param name="invert">Field inversion.</param>
    /// <param name="merkleHash">The two-to-one <c>SHA256(L ‖ R)</c> Merkle compression.</param>
    /// <param name="leafHash">The one-shot SHA-256 over a contiguous span.</param>
    /// <param name="hashAlgorithm">The canonical hash-function name (SHA-256).</param>
    /// <param name="curve">The field the delegates operate over (<see cref="CurveParameterSet.None"/> for GF(2^128)).</param>
    /// <param name="pool">The pool the working buffers rent from.</param>
    /// <param name="broadcastMultiplyAccumulate">The optional broadcast-scalar fused multiply primitive the <c>filleq</c> eq-array fills in the constraint replay route their per-level scalar-times-vector products through; the GF(2^128) hash side supplies it, the Fp256 sig side leaves it <see langword="null"/> for the scalar fallback.</param>
    /// <param name="bindQuadReduce">The optional fused <c>bind_quad</c> per-term reduce primitive the constraint replay's <c>BindQuad</c> routes its three-multiply-per-term reduction through; the GF(2^128) hash side supplies it, the Fp256 sig side leaves it <see langword="null"/> for the scalar fallback.</param>
    /// <param name="gatherMultiplyAccumulate">The optional gather/scatter fused multiply-accumulate primitive the sumcheck prover's per-round <c>QW</c> corner precompute routes through; the GF(2^128) hash side supplies it, the Fp256 sig side leaves it <see langword="null"/> for the scalar fallback.</param>
    /// <param name="fp256BatchMultiply">The optional lane-parallel batch Montgomery multiply the constraint replay's <c>bind_quad</c> reduction routes its three-multiply-per-term chain through; the Fp256 sig side supplies it, the GF(2^128) hash side leaves it <see langword="null"/> (it supplies <paramref name="bindQuadReduce"/> instead).</param>
    /// <returns>The full proof envelope <c>com ‖ sc ‖ com_proof</c>; the caller owns the returned array.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a length is wrong.</exception>
    /// <exception cref="InvalidOperationException">When the patched witness does not satisfy the circuit.</exception>
    public static byte[] ProveFromCommitment(
        LongfellowSumcheckCircuit circuit,
        LongfellowLigeroParameters parameters,
        LongfellowZkCommitment commitment,
        ReadOnlySpan<byte> witnessColumn,
        LongfellowTranscript transcript,
        LongfellowRowEncoderFactory encoderFactory,
        LongfellowFieldProfile profile,
        LongfellowSubfieldRunCodec codec,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate leafHash,
        string hashAlgorithm,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        ScalarBroadcastMultiplyAccumulateDelegate? broadcastMultiplyAccumulate = null,
        ScalarBindQuadReduceDelegate? bindQuadReduce = null,
        ScalarGatherMultiplyAccumulateDelegate? gatherMultiplyAccumulate = null,
        ScalarBatchMultiplyDelegate? fp256BatchMultiply = null)
    {
        ArgumentNullException.ThrowIfNull(circuit);
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(commitment);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(encoderFactory);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(codec);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(leafHash);
        ArgumentNullException.ThrowIfNull(hashAlgorithm);
        ArgumentNullException.ThrowIfNull(pool);

        if(witnessColumn.Length != circuit.InputCount * ScalarSize)
        {
            throw new ArgumentException($"Expected {circuit.InputCount * ScalarSize} witness-column bytes; received {witnessColumn.Length}.", nameof(witnessColumn));
        }

        int witnessCount = LongfellowZkVerifier.WitnessCount(circuit);

        //initialize_sumcheck_fiat_shamir: id, public inputs, zero, nterms zero bytes.
        ReadOnlySpan<byte> publicInputs = witnessColumn[..(circuit.PublicInputCount * ScalarSize)];
        InitializeFiatShamir(circuit, witnessColumn, profile, transcript, pool);

        //The sumcheck runs on a CLONE of the transcript (the reference's tst = tsp.clone()); the
        //constraint build and the Ligero prove continue on the original.
        using LongfellowSumcheckProof sumcheckProof = new(circuit, pool);
        using(LongfellowTranscript sumcheckTranscript = transcript.Clone())
        using(LongfellowWireTables tables = LongfellowSumcheckProver.EvaluateCircuit(circuit, witnessColumn, multiply, add, curve, pool))
        {
            LongfellowSumcheckProver.Prove(circuit, tables, commitment.Pad, sumcheckProof, sumcheckTranscript, add, subtract, multiply, invert, profile, curve, pool, gatherMultiplyAccumulate, broadcastMultiplyAccumulate);
        }

        //verifier_constraints: replay the sumcheck on the original transcript, building A/b. The
        //public-input bytes the constraint build folds are the little-endian element framing.
        int elementBytes = profile.ElementBytes;
        using IMemoryOwner<byte> publicLittleEndianOwner = pool.Rent(Math.Max(circuit.PublicInputCount, 1) * elementBytes);
        Span<byte> publicLittleEndian = publicLittleEndianOwner.Memory.Span[..(circuit.PublicInputCount * elementBytes)];
        for(int i = 0; i < circuit.PublicInputCount; i++)
        {
            profile.ToBytesField(publicInputs.Slice(i * ScalarSize, ScalarSize), publicLittleEndian.Slice(i * elementBytes, elementBytes));
        }

        using LongfellowZkConstraintBuilder.ConstraintSystem system = LongfellowZkConstraintBuilder.Build(
            circuit, sumcheckProof, publicLittleEndian, witnessCount, transcript, add, subtract, multiply, invert, profile, curve, pool, bindQuadReduce: bindQuadReduce, broadcastMultiplyAccumulate: broadcastMultiplyAccumulate, fp256BatchMultiply: fp256BatchMultiply);

        //Ligero prove: continue the original transcript; the linear terms are the A system.
        LigeroLinearConstraint[] linearTerms = FlattenTerms(system);

        using LongfellowLigeroProof ligeroProof = LongfellowLigeroProver.Prove(
            commitment.Commitment, transcript, system.ConstraintCount, linearTerms, TheoremStatementHash, commitment.QuadraticConstraints,
            encoderFactory, profile, add, subtract, multiply, curve, pool);

        return SerializeEnvelope(circuit, commitment.RootSpan, sumcheckProof, ligeroProof, profile, codec);
    }


    //Serializes the full envelope com ‖ sc ‖ com_proof (the reference's ZkProof::write) under the field's
    //subfield-run codec — the same codec seam the Ligero proof serializer exposes (the GF path supplies the
    //GF basis codec, the Fp256 path the full-field identity codec).
    private static byte[] SerializeEnvelope(
        LongfellowSumcheckCircuit circuit,
        ReadOnlySpan<byte> root,
        LongfellowSumcheckProof sumcheckProof,
        LongfellowLigeroProof ligeroProof,
        LongfellowFieldProfile profile,
        LongfellowSubfieldRunCodec codec)
    {
        int scSize = LongfellowSumcheckProofSerializer.SerializedSize(circuit, profile);
        int comProofSize = LongfellowLigeroProofSerializer.SerializedSize(ligeroProof, profile, codec);

        byte[] envelope = new byte[DigestLength + scSize + comProofSize];
        root.CopyTo(envelope.AsSpan(0, DigestLength));
        LongfellowSumcheckProofSerializer.Write(circuit, sumcheckProof, profile, envelope.AsSpan(DigestLength, scSize));
        LongfellowLigeroProofSerializer.Write(ligeroProof, profile, codec, envelope.AsSpan(DigestLength + scSize, comProofSize));

        return envelope;
    }


    //ZkCommon::initialize_sumcheck_fiat_shamir: id [byte string], each public input [field element],
    //F.zero() [field element], nterms() zero bytes [byte string]. The input column is NOT absorbed; the
    //ZK prover absorbs only public inputs (the witness stays hidden behind the commitment).
    private static void InitializeFiatShamir(LongfellowSumcheckCircuit circuit, ReadOnlySpan<byte> witnessColumn, LongfellowFieldProfile profile, LongfellowTranscript transcript, BaseMemoryPool pool)
    {
        transcript.AbsorbByteString(circuit.Id.Span);

        int elementBytes = profile.ElementBytes;
        Span<byte> littleEndianBuffer = stackalloc byte[ScalarSize];
        Span<byte> littleEndian = littleEndianBuffer[..elementBytes];
        for(int i = 0; i < circuit.PublicInputCount; i++)
        {
            profile.ToBytesField(witnessColumn.Slice(i * ScalarSize, ScalarSize), littleEndian);
            transcript.AbsorbFieldElement(littleEndian, elementBytes);
        }

        Span<byte> zeroElement = stackalloc byte[ScalarSize];
        transcript.AbsorbFieldElement(zeroElement[..elementBytes], elementBytes);

        int termCount = circuit.TermCount;
        using IMemoryOwner<byte> zerosOwner = pool.Rent(Math.Max(termCount, 1));
        Span<byte> zeros = zerosOwner.Memory.Span[..termCount];
        zeros.Clear();
        transcript.AbsorbByteString(zeros);
    }


    private static LigeroLinearConstraint[] FlattenTerms(LongfellowZkConstraintBuilder.ConstraintSystem system)
    {
        IReadOnlyList<LigeroLinearConstraint> terms = system.Terms;
        var flat = new LigeroLinearConstraint[terms.Count];
        for(int i = 0; i < terms.Count; i++)
        {
            flat[i] = terms[i];
        }

        return flat;
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
