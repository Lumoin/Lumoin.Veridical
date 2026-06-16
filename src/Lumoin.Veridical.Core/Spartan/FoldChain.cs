using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Drives a Nova-style fold chain that aggregates a sequence of
/// satisfied relaxed R1CS statements into a single accumulator and
/// then compresses that accumulator to one zero-knowledge Spartan
/// proof. This is the consumer-facing entry point for Category B
/// fold-with-randomness.
/// </summary>
/// <remarks>
/// <para>
/// Lifecycle: <see cref="Start"/> seeds the chain with the
/// <em>blinding instance</em> — a randomly-sampled satisfied relaxed
/// instance over the same coefficient matrices as the statements to
/// be folded. The blinding instance is the construction's
/// zero-knowledge contribution: every later fold mixes the real
/// statements into a uniformly random accumulator, so the compressed
/// proof reveals nothing about the individual statements beyond their
/// joint satisfiability. <see cref="Step"/> folds one incoming
/// statement into the accumulator; <see cref="Finalize"/> compresses
/// the final accumulator with the masked Spartan prover.
/// </para>
/// <para>
/// Transcript discipline. The chain holds <em>one</em> fold transcript
/// across every <see cref="Step"/> so the fold challenges
/// <c>r₁, r₂, …</c> chain and are non-malleable across the sequence.
/// Compression in <see cref="Finalize"/> uses a <em>separate, fresh</em>
/// transcript: the Spartan verifier replays the compressed proof
/// against the final folded instance only — it does not re-derive the
/// fold challenges (that would be incremental-verification, out of
/// scope here). The fold challenges are already baked into the folded
/// instance (its <c>u</c>, public inputs, and error commitment), which
/// the compression prover re-absorbs.
/// </para>
/// <para>
/// Commitment-key consistency. A single commitment provider
/// (or byte-identical derivations of its key) must back every error,
/// cross-term, and witness commitment across the chain and the
/// compression, so the homomorphically-folded error commitment opens
/// under the same basis the compression prover uses. The chain holds
/// the key non-owningly; the caller owns its disposal and the fold
/// transcript's.
/// </para>
/// </remarks>
public sealed class FoldChain: IDisposable
{
    private RelaxedR1csAccumulator accumulator;
    private readonly PolynomialCommitmentProvider provider;
    private readonly FiatShamirTranscript foldTranscript;
    private bool disposed;


    private FoldChain(
        RelaxedR1csAccumulator accumulator,
        PolynomialCommitmentProvider provider,
        FiatShamirTranscript foldTranscript)
    {
        this.accumulator = accumulator;
        this.provider = provider;
        this.foldTranscript = foldTranscript;
    }


    /// <summary>
    /// The current accumulator — the running folded instance, witness,
    /// and error-commitment opening witness. After <see cref="Finalize"/>
    /// the caller verifies the compressed proof against
    /// <c>Accumulator.Instance</c>. The chain owns this accumulator's
    /// disposal; do not dispose it independently.
    /// </summary>
    /// <exception cref="ObjectDisposedException">When the chain has been disposed.</exception>
    public RelaxedR1csAccumulator Accumulator
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            return accumulator;
        }
    }


    /// <summary>
    /// Starts a fold chain by constructing the blinding accumulator: a
    /// random satisfied relaxed instance over <paramref name="template"/>'s
    /// coefficient matrices. The chain retains <paramref name="commitmentKey"/>
    /// and <paramref name="foldTranscript"/> (both non-owning) for the
    /// subsequent <see cref="Step"/> calls.
    /// </summary>
    /// <remarks>
    /// The blinding instance picks a random relaxation scalar <c>u</c>
    /// and a random witness, zeroes the public inputs (the accumulator
    /// carries no statement of its own; its hiding comes from the random
    /// <c>u</c>, witness, and error blinding), then sets the error vector
    /// to <c>E = (A·z) ∘ (B·z) − u · (C·z)</c> with <c>z = (u, 0, witness)</c>.
    /// By definition of <c>E</c> the relaxed identity
    /// <c>(A·z) ∘ (B·z) = u · (C·z) + E</c> holds, so the accumulator is a
    /// valid satisfied relaxed instance and can be folded against. The
    /// error vector is committed under Hyrax with random per-row
    /// blinding, yielding the error commitment carried in the instance
    /// and the opening witness carried in the accumulator.
    /// </remarks>
    /// <param name="template">Defines the constraint system (coefficient matrices, public-input count, dimensions) the chain folds over. Its public inputs and any witness are not used; only its matrices and shape are.</param>
    /// <param name="provider">The commitment provider backing every commitment in the chain and the compression. Retained non-owningly.</param>
    /// <param name="foldTranscript">The transcript the fold challenges are squeezed from across all steps. Retained non-owningly.</param>
    /// <param name="scalarAdd">Scalar-add backend (matrix-vector products).</param>
    /// <param name="scalarSubtract">Scalar-subtract backend (error vector).</param>
    /// <param name="scalarMultiply">Scalar-multiply backend (matrix-vector products, error vector).</param>
    /// <param name="scalarRandom">Scalar-random backend (the random <c>u</c>, witness, and error-commitment blinding).</param>
    /// <param name="g1Msm">G1 MSM backend (error commitment).</param>
    /// <param name="pool">The pool to rent every buffer from.</param>
    /// <returns>A fold chain seeded with the blinding accumulator.</returns>
    /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the template's row count is not a power of two.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "The blinding accumulator transfers ownership to the returned FoldChain, whose Dispose releases it.")]
    public static FoldChain Start(
        RawR1csInstance template,
        PolynomialCommitmentProvider provider,
        FiatShamirTranscript foldTranscript,
        ScalarAddDelegate scalarAdd,
        ScalarSubtractDelegate scalarSubtract,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarRandomDelegate scalarRandom,
        G1MultiScalarMultiplyDelegate g1Msm,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(template);
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(foldTranscript);
        ArgumentNullException.ThrowIfNull(scalarAdd);
        ArgumentNullException.ThrowIfNull(scalarSubtract);
        ArgumentNullException.ThrowIfNull(scalarMultiply);
        ArgumentNullException.ThrowIfNull(scalarRandom);
        ArgumentNullException.ThrowIfNull(g1Msm);
        ArgumentNullException.ThrowIfNull(pool);

        //Nova-style folding combines the accumulator's error commitment, the
        //cross-term commitment, and the incoming error commitment homomorphically
        //(C_folded = C_acc + r·C_cross + r²·C_in). That requires an additively
        //homomorphic commitment. A hash-based scheme (BaseFold) has no such
        //structure — its Merkle-root commitments cannot be combined — so the
        //chain rejects it up front rather than fail deep inside the first fold.
        //BaseFold serves the direct (non-folded) Spartan prove/verify paths
        //instead; see FOLDING.md and BASEFOLD.md.
        if(!provider.IsAdditivelyHomomorphic)
        {
            throw new ArgumentException(
                $"Fold chain requires an additively-homomorphic commitment provider; the supplied provider's scheme {provider.Scheme} is not homomorphic and cannot back Nova-style folding.",
                nameof(provider));
        }

        RelaxedR1csAccumulator blinding = BuildBlindingInstance(
            template, provider, scalarAdd, scalarSubtract, scalarMultiply, scalarRandom, g1Msm, pool);

        return new FoldChain(blinding, provider, foldTranscript);
    }


    /// <summary>
    /// Folds one incoming satisfied relaxed statement into the
    /// accumulator under a fresh fold challenge squeezed from the
    /// chain's fold transcript, then replaces and disposes the previous
    /// accumulator. The incoming triple is left intact for the caller to
    /// dispose; the fold copies every byte it needs.
    /// </summary>
    /// <param name="incomingInstance">The incoming relaxed instance (a prepared real statement, or any prior relaxed instance over the same constraint system).</param>
    /// <param name="incomingWitness">The incoming witness.</param>
    /// <param name="incomingErrorOpeningWitness">The incoming error-commitment opening witness.</param>
    /// <param name="hash">Fixed-output hash backend.</param>
    /// <param name="squeeze">XOF squeeze backend.</param>
    /// <param name="scalarReduce">Scalar-reduce backend.</param>
    /// <param name="scalarAdd">Scalar-add backend.</param>
    /// <param name="scalarSubtract">Scalar-subtract backend.</param>
    /// <param name="scalarMultiply">Scalar-multiply backend.</param>
    /// <param name="scalarRandom">Scalar-random backend (cross-term commitment blinding).</param>
    /// <param name="g1Add">G1-add backend (homomorphic commitment combination).</param>
    /// <param name="g1ScalarMultiply">G1 scalar-multiply backend.</param>
    /// <param name="g1Msm">G1 MSM backend (cross-term commitment).</param>
    /// <param name="pool">The pool to rent every buffer from.</param>
    /// <exception cref="ObjectDisposedException">When the chain has been disposed.</exception>
    /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the incoming statement disagrees with the accumulator on curve, dimensions, or public-input count.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "The folded triple transfers ownership to the new accumulator, which becomes the chain's state and is released by Dispose; the superseded accumulator is disposed here.")]
    public void Step(
        RelaxedR1csInstance incomingInstance,
        RelaxedR1csWitness incomingWitness,
        PolynomialCommitmentBlind incomingErrorOpeningWitness,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate scalarReduce,
        ScalarAddDelegate scalarAdd,
        ScalarSubtractDelegate scalarSubtract,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarRandomDelegate scalarRandom,
        G1AddDelegate g1Add,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1MultiScalarMultiplyDelegate g1Msm,
        BaseMemoryPool pool)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ArgumentNullException.ThrowIfNull(incomingInstance);
        ArgumentNullException.ThrowIfNull(incomingWitness);
        ArgumentNullException.ThrowIfNull(incomingErrorOpeningWitness);

        (RelaxedR1csInstance instance, RelaxedR1csWitness witness, PolynomialCommitmentBlind errorOpeningWitness) =
            RelaxedR1csFold.Fold(
                accumulator.Instance, accumulator.Witness, accumulator.ErrorOpeningWitness,
                incomingInstance, incomingWitness, incomingErrorOpeningWitness,
                provider, foldTranscript,
                hash, squeeze, scalarReduce, scalarAdd, scalarSubtract, scalarMultiply, scalarRandom,
                g1Add, g1ScalarMultiply, g1Msm, pool);

        RelaxedR1csAccumulator folded;
        try
        {
            folded = new RelaxedR1csAccumulator(instance, witness, errorOpeningWitness);
        }
        catch
        {
            instance.Dispose();
            witness.Dispose();
            errorOpeningWitness.Dispose();
            throw;
        }

        RelaxedR1csAccumulator previous = accumulator;
        accumulator = folded;
        previous.Dispose();
    }


    /// <summary>
    /// Compresses the current accumulator to a single masked Spartan
    /// proof using a fresh <paramref name="compressionTranscript"/>. The
    /// folded instance (matrices, <c>u</c>, public inputs, error
    /// commitment) is re-absorbed by the prover, so the verifier checks
    /// the proof against <see cref="Accumulator"/>'s instance from a
    /// matching fresh transcript. The chain is left intact (the
    /// accumulator is not consumed), so the instance remains available
    /// for verification until the chain is disposed.
    /// </summary>
    /// <param name="prover">The masked prover. Its commitment key must be byte-identical to the chain's so the folded error commitment opens correctly.</param>
    /// <param name="compressionTranscript">A fresh transcript, independent of the fold transcript, seeded with the Spartan domain label.</param>
    /// <param name="hash">Fixed-output hash backend.</param>
    /// <param name="squeeze">XOF squeeze backend.</param>
    /// <param name="scalarReduce">Scalar-reduce backend.</param>
    /// <param name="scalarAdd">Scalar-add backend.</param>
    /// <param name="scalarSubtract">Scalar-subtract backend.</param>
    /// <param name="scalarMultiply">Scalar-multiply backend.</param>
    /// <param name="scalarInvert">Scalar-invert backend.</param>
    /// <param name="scalarRandom">Scalar-random backend (masking-polynomial and opening blinding).</param>
    /// <param name="g1Add">G1-add backend.</param>
    /// <param name="g1ScalarMultiply">G1 scalar-multiply backend.</param>
    /// <param name="g1Msm">G1 MSM backend.</param>
    /// <param name="mleEvaluate">MLE point-evaluation backend.</param>
    /// <param name="mleFold">MLE fold backend.</param>
    /// <param name="pool">The pool to rent every buffer from.</param>
    /// <returns>The masked Spartan proof of the final folded instance.</returns>
    /// <exception cref="ObjectDisposedException">When the chain has been disposed.</exception>
    /// <exception cref="ArgumentNullException">When <paramref name="prover"/> or <paramref name="compressionTranscript"/> is <see langword="null"/>.</exception>
    public MaskedSpartanProof Finalize(
        MaskedSpartanProver prover,
        FiatShamirTranscript compressionTranscript,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate scalarReduce,
        ScalarAddDelegate scalarAdd,
        ScalarSubtractDelegate scalarSubtract,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarInvertDelegate scalarInvert,
        ScalarRandomDelegate scalarRandom,
        G1AddDelegate g1Add,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1MultiScalarMultiplyDelegate g1Msm,
        MleEvaluateDelegate mleEvaluate,
        MleFoldDelegate mleFold,
        BaseMemoryPool pool)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ArgumentNullException.ThrowIfNull(prover);
        ArgumentNullException.ThrowIfNull(compressionTranscript);

        return prover.Prove(
            accumulator.Instance, accumulator.Witness, accumulator.ErrorOpeningWitness,
            compressionTranscript,
            hash, squeeze, scalarReduce, scalarAdd, scalarSubtract, scalarMultiply,
            scalarInvert, scalarRandom, g1Add, g1ScalarMultiply, g1Msm,
            mleEvaluate, mleFold, pool);
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        //The commitment key and fold transcript are caller-owned; the
        //chain only disposes the accumulator it built and replaced.
        accumulator.Dispose();
        disposed = true;
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The error commitment and opening witness from CommitMultilinearExtension transfer ownership to the instance and the accumulator respectively; every exception path disposes them explicitly. The cloned matrices transfer to RelaxedR1csInstance.Create.")]
    private static RelaxedR1csAccumulator BuildBlindingInstance(
        RawR1csInstance template,
        PolynomialCommitmentProvider provider,
        ScalarAddDelegate scalarAdd,
        ScalarSubtractDelegate scalarSubtract,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarRandomDelegate scalarRandom,
        G1MultiScalarMultiplyDelegate g1Msm,
        BaseMemoryPool pool)
    {
        CurveParameterSet curve = template.Curve;
        int scalarSize = R1csMatrix.GetValueByteSize(curve);
        int m = template.A.RowCount;
        int n = template.A.ColumnCount;
        int publicInputCount = template.PublicInputCount;
        int witnessCount = n - 1 - publicInputCount;
        int rowVariableCount = BitOperations.Log2((uint)m);

        //Random relaxation scalar u.
        using IMemoryOwner<byte> uOwner = pool.Rent(scalarSize);
        Span<byte> uBytes = uOwner.Memory.Span[..scalarSize];
        _ = scalarRandom(uBytes, curve, WellKnownAlgebraicTags.ScalarFor(curve));

        //Zero public inputs — the blinding accumulator carries no
        //statement of its own.
        using IMemoryOwner<byte> publicOwner = pool.Rent(Math.Max(1, publicInputCount * scalarSize));
        Span<byte> publicBytes = publicOwner.Memory.Span[..(publicInputCount * scalarSize)];
        publicBytes.Clear();

        //Random witness.
        using IMemoryOwner<byte> witnessOwner = pool.Rent(witnessCount * scalarSize);
        Span<byte> witnessBytes = witnessOwner.Memory.Span[..(witnessCount * scalarSize)];
        for(int i = 0; i < witnessCount; i++)
        {
            _ = scalarRandom(witnessBytes.Slice(i * scalarSize, scalarSize), curve, WellKnownAlgebraicTags.ScalarFor(curve));
        }

        //z = (u, public = 0, witness).
        using IMemoryOwner<byte> zOwner = pool.Rent(n * scalarSize);
        Span<byte> z = zOwner.Memory.Span[..(n * scalarSize)];
        z.Clear();
        uBytes.CopyTo(z[..scalarSize]);
        publicBytes.CopyTo(z[scalarSize..]);
        int witnessOffset = (1 + publicInputCount) * scalarSize;
        witnessBytes.CopyTo(z[witnessOffset..]);

        //Matrix-vector products A·z, B·z, C·z over the template matrices.
        using IMemoryOwner<byte> azOwner = pool.Rent(m * scalarSize);
        using IMemoryOwner<byte> bzOwner = pool.Rent(m * scalarSize);
        using IMemoryOwner<byte> czOwner = pool.Rent(m * scalarSize);
        Span<byte> az = azOwner.Memory.Span[..(m * scalarSize)];
        Span<byte> bz = bzOwner.Memory.Span[..(m * scalarSize)];
        Span<byte> cz = czOwner.Memory.Span[..(m * scalarSize)];
        template.A.MatrixVectorProduct(z, az, scalarAdd, scalarMultiply, pool);
        template.B.MatrixVectorProduct(z, bz, scalarAdd, scalarMultiply, pool);
        template.C.MatrixVectorProduct(z, cz, scalarAdd, scalarMultiply, pool);

        //E[i] = az[i]·bz[i] − u·cz[i] so (A·z) ∘ (B·z) = u · (C·z) + E
        //holds by construction.
        using IMemoryOwner<byte> eOwner = pool.Rent(m * scalarSize);
        Span<byte> eBytes = eOwner.Memory.Span[..(m * scalarSize)];
        using IMemoryOwner<byte> termOwner = pool.Rent(scalarSize);
        Span<byte> term = termOwner.Memory.Span[..scalarSize];
        for(int i = 0; i < m; i++)
        {
            int o = i * scalarSize;
            Span<byte> ei = eBytes.Slice(o, scalarSize);
            scalarMultiply(az.Slice(o, scalarSize), bz.Slice(o, scalarSize), ei, curve);
            scalarMultiply(uBytes, cz.Slice(o, scalarSize), term, curve);
            scalarSubtract(ei, term, ei, curve);
        }

        //Commit E over the row variables; the opening witness is the
        //accumulator's error blinding.
        using MultilinearExtension eMle = MultilinearExtension.FromEvaluations(eBytes, rowVariableCount, curve, pool);
        (PolynomialCommitment errorCommitment, PolynomialCommitmentBlind errorOpeningWitness) =
            provider.Commit(eMle, pool);

        R1csMatrix aClone = CloneMatrix(template.A, pool);
        R1csMatrix bClone;
        R1csMatrix cClone;
        try
        {
            bClone = CloneMatrix(template.B, pool);
        }
        catch
        {
            aClone.Dispose();
            errorCommitment.Dispose();
            errorOpeningWitness.Dispose();
            throw;
        }

        try
        {
            cClone = CloneMatrix(template.C, pool);
        }
        catch
        {
            aClone.Dispose();
            bClone.Dispose();
            errorCommitment.Dispose();
            errorOpeningWitness.Dispose();
            throw;
        }

        RelaxedR1csInstance instance;
        try
        {
            instance = RelaxedR1csInstance.Create(aClone, bClone, cClone, publicBytes, uBytes, errorCommitment, pool);
        }
        catch
        {
            aClone.Dispose();
            bClone.Dispose();
            cClone.Dispose();
            errorCommitment.Dispose();
            errorOpeningWitness.Dispose();
            throw;
        }

        RelaxedR1csWitness witness;
        try
        {
            witness = RelaxedR1csWitness.FromCanonical(witnessBytes, eBytes, curve, pool);
        }
        catch
        {
            instance.Dispose();
            errorOpeningWitness.Dispose();
            throw;
        }

        try
        {
            return new RelaxedR1csAccumulator(instance, witness, errorOpeningWitness);
        }
        catch
        {
            instance.Dispose();
            witness.Dispose();
            errorOpeningWitness.Dispose();
            throw;
        }
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The cloned matrix transfers ownership to the caller (RelaxedR1csInstance.Create), whose Dispose chain releases it.")]
    private static R1csMatrix CloneMatrix(R1csMatrix source, BaseMemoryPool pool)
    {
        int nnz = source.NonzeroCount;
        int[] rows = new int[nnz];
        int[] columns = new int[nnz];
        for(int i = 0; i < nnz; i++)
        {
            (int row, int column) = source.GetTriplePosition(i);
            rows[i] = row;
            columns[i] = column;
        }

        return R1csMatrix.FromSortedTriples(
            rows, columns, source.GetValuesBytes(),
            source.RowCount, source.ColumnCount, source.Curve, pool);
    }
}