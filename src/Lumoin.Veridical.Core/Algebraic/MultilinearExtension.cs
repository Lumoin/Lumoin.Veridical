using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// A multilinear extension stored in dense form: the unique multilinear
/// polynomial that agrees with a function <c>{0,1}^n → F</c> on the
/// boolean hypercube, carried as <c>2^n</c> field-element evaluations.
/// </summary>
/// <remarks>
/// <para>
/// The type is intentionally broad: one
/// <see cref="MultilinearExtension"/> represents MLEs over any curve's
/// scalar field, with the field identity carried in the
/// <see cref="Tag"/> through <see cref="CurveParameterSet"/> rather
/// than encoded in the type name. Protocol logic — sumcheck rounds,
/// polynomial-commitment opens, R1CS construction — operates on
/// "MLE over some field" and the runtime tag dispatches arithmetic to
/// the right field-arithmetic backend.
/// </para>
/// <para>
/// Three entries always appear in the tag: an
/// <see cref="AlgebraicRole.MultilinearExtension"/> discriminator, the
/// <see cref="CurveParameterSet"/> identifying the field, and a
/// <see cref="MultilinearExtensionDimensions"/> value carrying the
/// variable count and evaluation count so consumers can read the
/// shape without unwrapping the leaf type.
/// </para>
/// <para>
/// Buffer layout is the dense evaluation form: evaluation at boolean
/// hypercube index <c>(b_1, b_2, ..., b_n)</c> lives at byte offset
/// <c>(b_1 + 2·b_2 + 4·b_3 + ... + 2^(n-1)·b_n) · fieldElementSize</c>.
/// One field element per slot, canonical big-endian bytes. The folding
/// formula (<see cref="MleFoldDelegate"/>) treats neighbouring
/// even/odd offsets as the <c>(f(0,...), f(1,...))</c> pair.
/// </para>
/// <para>
/// Like every leaf algebraic type, this one is narrow on responsibility:
/// it owns the buffer through the <see cref="SensitiveMemory"/> base and
/// validates its length. Arithmetic verbs and predicates surface through
/// <c>extension(MultilinearExtension)</c> blocks in separate extension
/// classes — broad inspection verbs in
/// <see cref="MultilinearExtensionInspectionExtensions"/>, BLS12-381
/// arithmetic verbs in
/// <c>MultilinearExtensionArithmeticExtensions</c>.
/// </para>
/// </remarks>
public sealed class MultilinearExtension: SensitiveMemory
{
    //Upper bound on variable count guards both the int-sized buffer-length
    //arithmetic (2^n * fieldSize must fit in int) and a reasonable memory
    //ceiling: at n=26 and 32-byte BLS12-381 scalars the buffer is 2 GiB,
    //already past the point where the pool architecture is the binding
    //constraint. Callers building larger MLEs should split into batches.
    private const int MaximumVariableCount = 26;


    /// <summary>The number of variables <c>n</c>; the MLE stores <c>2^n</c> evaluations.</summary>
    public int VariableCount { get; }

    /// <summary>The number of evaluations stored (<c>2^VariableCount</c>).</summary>
    public int EvaluationCount => 1 << VariableCount;

    /// <summary>The byte size of one field element in this MLE.</summary>
    public int FieldElementSizeBytes { get; }

    /// <summary>The curve identifying the field the MLE's coefficients live in.</summary>
    public CurveParameterSet Curve { get; }


    /// <summary>
    /// Constructs an MLE over a buffer the caller has already populated.
    /// The instance takes ownership of <paramref name="owner"/> and is
    /// responsible for clearing and returning it on disposal.
    /// </summary>
    /// <param name="owner">A pool-rented buffer whose first <c>2^variableCount * fieldElementSizeBytes</c> bytes hold the canonical big-endian evaluations.</param>
    /// <param name="variableCount">The number of variables <c>n</c>.</param>
    /// <param name="fieldElementSizeBytes">The byte size of one field element.</param>
    /// <param name="curve">The curve identifying the field.</param>
    /// <param name="tag">The runtime tag.</param>
    internal MultilinearExtension(
        IMemoryOwner<byte> owner,
        int variableCount,
        int fieldElementSizeBytes,
        CurveParameterSet curve,
        Tag tag)
        : base(owner, tag)
    {
        VariableCount = variableCount;
        FieldElementSizeBytes = fieldElementSizeBytes;
        Curve = curve;
    }


    /// <summary>
    /// Copies caller-supplied evaluations into a pool-rented buffer and
    /// returns an MLE wrapping it.
    /// </summary>
    /// <param name="evaluations">Exactly <c>2^variableCount * fieldElementSizeBytes</c> bytes carrying the dense evaluations in canonical big-endian order, one field element per slot.</param>
    /// <param name="variableCount">The number of variables <c>n</c>. Must be in <c>[0, 26]</c>.</param>
    /// <param name="curve">The curve identifying the field. Currently only <see cref="CurveParameterSet.Bls12Curve381"/> is supported.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries. The algebraic-identity entries are merged in unconditionally.</param>
    /// <returns>An MLE wrapping a pool-rented copy of the supplied evaluations.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="variableCount"/> is outside <c>[0, 26]</c>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="evaluations"/> has the wrong length for the requested shape.</exception>
    public static MultilinearExtension FromEvaluations(
        ReadOnlySpan<byte> evaluations,
        int variableCount,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ValidateVariableCount(variableCount);

        int fieldElementSize = GetFieldElementSizeBytes(curve);
        int evaluationCount = 1 << variableCount;
        int expectedLength = evaluationCount * fieldElementSize;
        if(evaluations.Length != expectedLength)
        {
            throw new ArgumentException(
                $"MLE with {variableCount} variable(s) over {curve} requires exactly {expectedLength} bytes ({evaluationCount} × {fieldElementSize}); received {evaluations.Length}.",
                nameof(evaluations));
        }

        IMemoryOwner<byte> owner = pool.Rent(expectedLength);
        evaluations.CopyTo(owner.Memory.Span);

        Tag effectiveTag = tag is null
            ? ComposeAlgebraicTag(variableCount, evaluationCount, curve)
            : MergeWithAlgebraicTag(tag, variableCount, evaluationCount, curve);

        return new MultilinearExtension(owner, variableCount, fieldElementSize, curve, effectiveTag);
    }


    /// <summary>
    /// Returns an all-zero MLE of the requested shape.
    /// </summary>
    /// <param name="variableCount">The number of variables <c>n</c>. Must be in <c>[0, 26]</c>.</param>
    /// <param name="curve">The curve identifying the field.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <returns>An MLE every one of whose <c>2^variableCount</c> evaluations is the field zero.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="variableCount"/> is outside <c>[0, 26]</c>.</exception>
    public static MultilinearExtension Zero(
        int variableCount,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ValidateVariableCount(variableCount);

        int fieldElementSize = GetFieldElementSizeBytes(curve);
        int evaluationCount = 1 << variableCount;
        int totalSize = evaluationCount * fieldElementSize;

        IMemoryOwner<byte> owner = pool.Rent(totalSize);

        //The pool clears buffers on dispose so freshly rented memory is usually
        //already zero, but the contract for a freshly rented buffer is "no
        //guarantee about content"; clear explicitly so callers see the field
        //zero regardless of pool reuse state.
        owner.Memory.Span[..totalSize].Clear();

        Tag tag = ComposeAlgebraicTag(variableCount, evaluationCount, curve);

        return new MultilinearExtension(owner, variableCount, fieldElementSize, curve, tag);
    }


    /// <summary>
    /// Returns a freshly randomised MLE: each of the <c>2^variableCount</c>
    /// evaluation slots holds an independent uniformly random scalar in
    /// the curve's scalar field.
    /// </summary>
    /// <param name="variableCount">The number of variables <c>n</c>. Must be in <c>[0, 26]</c>.</param>
    /// <param name="curve">The curve identifying the field.</param>
    /// <param name="random">The entropy-sourced scalar sampler. Called once per evaluation slot.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <returns>An MLE wrapping a pool-rented buffer whose slots are each independently sampled.</returns>
    /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="variableCount"/> is outside <c>[0, 26]</c>.</exception>
    /// <remarks>
    /// <para>
    /// This factory is the entry point the ZK Spartan fold uses for the
    /// fresh witness MLE that masks the prover's real witness. The
    /// uniformity contract sits on <paramref name="random"/>: a backend
    /// that returns biased or non-reduced bytes is non-conformant.
    /// </para>
    /// <para>
    /// Provenance: the per-slot tag returned by the first call to
    /// <paramref name="random"/> carries the backend's provenance entries;
    /// those entries are merged into the MLE-level tag. Subsequent calls'
    /// returned tags are ignored — every slot comes from the same backend
    /// so per-slot provenance recording would be redundant.
    /// </para>
    /// </remarks>
    public static MultilinearExtension Random(
        int variableCount,
        CurveParameterSet curve,
        ScalarRandomDelegate random,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(random);
        ArgumentNullException.ThrowIfNull(pool);
        ValidateVariableCount(variableCount);

        int fieldElementSize = GetFieldElementSizeBytes(curve);
        int evaluationCount = 1 << variableCount;
        int totalSize = evaluationCount * fieldElementSize;

        IMemoryOwner<byte> owner = pool.Rent(totalSize);
        Span<byte> buffer = owner.Memory.Span[..totalSize];

        //Fill slot 0 first to capture the backend's provenance entries from
        //the returned tag, then merge them under the MLE's algebraic-identity
        //entries via MergeWithAlgebraicTag — the MLE role and dimensions
        //override the scalar role the inbound tag carries while the
        //backend's provenance entries propagate up.
        Tag mleTag;
        if(evaluationCount > 0)
        {
            Tag firstSlotTag = random(buffer.Slice(0, fieldElementSize), curve, WellKnownAlgebraicTags.ScalarFor(curve));
            mleTag = MergeWithAlgebraicTag(firstSlotTag, variableCount, evaluationCount, curve);

            for(int i = 1; i < evaluationCount; i++)
            {
                _ = random(buffer.Slice(i * fieldElementSize, fieldElementSize), curve, WellKnownAlgebraicTags.ScalarFor(curve));
            }
        }
        else
        {
            //Zero-variable MLE: one constant slot. The factory still calls
            //random once so the provenance attaches; the loop above handles
            //it through the slot-0 branch when evaluationCount == 1, so the
            //evaluationCount == 0 case is unreachable in practice. Compose
            //the bare algebraic tag for defensiveness.
            mleTag = ComposeAlgebraicTag(variableCount, evaluationCount, curve);
        }


        return new MultilinearExtension(owner, variableCount, fieldElementSize, curve, mleTag);
    }


    /// <summary>
    /// Returns the canonical scalar-field byte size for the supplied
    /// curve. Throws for curves the polynomial layer does not yet wire.
    /// </summary>
    /// <exception cref="ArgumentException">When the curve is not supported by the polynomial layer.</exception>
    internal static int GetFieldElementSizeBytes(CurveParameterSet curve)
    {
        if(curve.Code == CurveParameterSet.Bls12Curve381.Code)
        {
            return WellKnownCurves.Bls12Curve381ScalarSizeBytes;
        }

        if(curve.Code == CurveParameterSet.Bn254.Code)
        {
            return WellKnownCurves.Bn254ScalarSizeBytes;
        }

        throw new ArgumentException(
            $"The multilinear-extension layer supports Bls12Curve381 or Bn254; received '{curve}'.",
            nameof(curve));
    }


    private static void ValidateVariableCount(int variableCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(variableCount);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(variableCount, MaximumVariableCount);
    }


    private static Tag ComposeAlgebraicTag(int variableCount, int evaluationCount, CurveParameterSet curve)
    {
        return Tag.Create(AlgebraicRole.MultilinearExtension)
            .With(curve)
            .With(new MultilinearExtensionDimensions(variableCount, evaluationCount));
    }


    private static Tag MergeWithAlgebraicTag(Tag tag, int variableCount, int evaluationCount, CurveParameterSet curve)
    {
        return tag.With(AlgebraicRole.MultilinearExtension)
            .With(curve)
            .With(new MultilinearExtensionDimensions(variableCount, evaluationCount));
    }
}