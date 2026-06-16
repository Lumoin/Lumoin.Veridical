using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// A bundle of one curve's scalar-field arithmetic operations as delegates,
/// plus the curve identity and a hardware-acceleration capability flag. It is
/// the composition seam for scalar backends: an application assembles one
/// backend at startup — choosing, per operation, a portable, SIMD-accelerated,
/// or future accelerator implementation — and passes the bundle's delegates into
/// the protocol code, which continues to accept individual delegates.
/// </summary>
/// <remarks>
/// <para>
/// This mirrors <c>PolynomialCommitmentProvider</c> (the polynomial-commitment
/// seam): a sealed delegate-bundle with an identity and capability flags. It does
/// not replace the established convention of passing individual scalar delegates
/// into protocol methods — that convention is deliberate, letting each operation
/// come from a different backend — it composes it, so a heterogeneous backend
/// (for example SIMD add/subtract with a portable multiply) is assembled once and
/// surfaced through one object.
/// </para>
/// <para>
/// <see cref="HashToScalar"/> is nullable because not every curve bakes in a
/// single expand-message function (BN254 takes it as a parameter), so a bundle
/// may omit it. <see cref="IsHardwareAccelerated"/> records whether the chosen
/// implementations use SIMD on the host — a wiring/telemetry hint, not a contract.
/// </para>
/// </remarks>
public sealed class ScalarArithmeticBackend: IDisposable
{
    private IDisposable? ownedResource;


    /// <summary>The curve whose scalar field these operations are over.</summary>
    public CurveParameterSet Curve { get; }

    /// <summary>Reduces wide canonical bytes into a canonical field element.</summary>
    public ScalarReduceDelegate Reduce { get; }

    /// <summary>Adds two scalars.</summary>
    public ScalarAddDelegate Add { get; }

    /// <summary>Subtracts two scalars.</summary>
    public ScalarSubtractDelegate Subtract { get; }

    /// <summary>Multiplies two scalars.</summary>
    public ScalarMultiplyDelegate Multiply { get; }

    /// <summary>Negates a scalar.</summary>
    public ScalarNegateDelegate Negate { get; }

    /// <summary>Inverts a scalar.</summary>
    public ScalarInvertDelegate Invert { get; }

    /// <summary>Samples a uniformly random scalar.</summary>
    public ScalarRandomDelegate Random { get; }

    /// <summary>Adds scalars element-wise in batch.</summary>
    public ScalarBatchAddDelegate BatchAdd { get; }

    /// <summary>Subtracts scalars element-wise in batch.</summary>
    public ScalarBatchSubtractDelegate BatchSubtract { get; }

    /// <summary>Multiplies scalars element-wise in batch (the lane-interleaved SIMD kernel when hardware-accelerated).</summary>
    public ScalarBatchMultiplyDelegate BatchMultiply { get; }

    /// <summary>Fused multiply-accumulate over sequential spans (<c>acc[i] += a[i]·b[i]</c>, deferred reduction in the binary-field backend); <see langword="null"/> when the backend does not supply it.</summary>
    public ScalarBatchMultiplyAccumulateDelegate? BatchMultiplyAccumulate { get; }

    /// <summary>Broadcast-scalar fused multiply-accumulate (<c>acc[i] += scalar·b[i]</c>); <see langword="null"/> when the backend does not supply it.</summary>
    public ScalarBroadcastMultiplyAccumulateDelegate? BroadcastMultiplyAccumulate { get; }

    /// <summary>Indexed (gather/scatter) fused multiply-accumulate (<c>acc[out[k]] += coeff[k]·data[in[k]]</c>); <see langword="null"/> when the backend does not supply it.</summary>
    public ScalarGatherMultiplyAccumulateDelegate? GatherMultiplyAccumulate { get; }

    /// <summary>One LCH14 additive-FFT forward butterfly across a twiddle-sharing group; <see langword="null"/> when the backend does not supply it (a binary-field-specific op).</summary>
    public Gf2kButterflyBatchDelegate? ButterflyBatch { get; }

    /// <summary>Hashes a message to a scalar, when the backend supplies a baked-in expand-message function; otherwise <see langword="null"/>.</summary>
    public ScalarHashToScalarDelegate? HashToScalar { get; }

    /// <summary>Whether the bundled operations use host SIMD acceleration. A hint for wiring and telemetry, not a behavioural contract.</summary>
    public bool IsHardwareAccelerated { get; }


    /// <summary>Bundles a curve's scalar operations.</summary>
    /// <param name="curve">The curve identity.</param>
    /// <param name="reduce">Reduce backend.</param>
    /// <param name="add">Add backend.</param>
    /// <param name="subtract">Subtract backend.</param>
    /// <param name="multiply">Multiply backend.</param>
    /// <param name="negate">Negate backend.</param>
    /// <param name="invert">Invert backend.</param>
    /// <param name="random">Random-sampling backend.</param>
    /// <param name="batchAdd">Batch-add backend.</param>
    /// <param name="batchSubtract">Batch-subtract backend.</param>
    /// <param name="hashToScalar">Optional hash-to-scalar backend; <see langword="null"/> when the curve has no baked-in expand-message function.</param>
    /// <param name="isHardwareAccelerated">Whether the bundled operations use host SIMD acceleration.</param>
    /// <param name="ownedResource">An optional resource the bundle disposes when disposed (for backends holding accelerator handles); <see langword="null"/> when the caller retains ownership.</param>
    /// <param name="batchMultiplyAccumulate">Optional fused multiply-accumulate backend; <see langword="null"/> when the backend does not supply it.</param>
    /// <param name="broadcastMultiplyAccumulate">Optional broadcast-scalar fused multiply-accumulate backend; <see langword="null"/> when the backend does not supply it.</param>
    /// <param name="gatherMultiplyAccumulate">Optional indexed fused multiply-accumulate backend; <see langword="null"/> when the backend does not supply it.</param>
    /// <param name="butterflyBatch">Optional LCH14 butterfly-batch backend; <see langword="null"/> when the backend does not supply it.</param>
    /// <exception cref="ArgumentNullException">When any non-optional delegate is <see langword="null"/>.</exception>
    public ScalarArithmeticBackend(
        CurveParameterSet curve,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarNegateDelegate negate,
        ScalarInvertDelegate invert,
        ScalarRandomDelegate random,
        ScalarBatchAddDelegate batchAdd,
        ScalarBatchSubtractDelegate batchSubtract,
        ScalarBatchMultiplyDelegate batchMultiply,
        ScalarHashToScalarDelegate? hashToScalar = null,
        bool isHardwareAccelerated = false,
        IDisposable? ownedResource = null,
        ScalarBatchMultiplyAccumulateDelegate? batchMultiplyAccumulate = null,
        ScalarBroadcastMultiplyAccumulateDelegate? broadcastMultiplyAccumulate = null,
        ScalarGatherMultiplyAccumulateDelegate? gatherMultiplyAccumulate = null,
        Gf2kButterflyBatchDelegate? butterflyBatch = null)
    {
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(negate);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(random);
        ArgumentNullException.ThrowIfNull(batchAdd);
        ArgumentNullException.ThrowIfNull(batchSubtract);
        ArgumentNullException.ThrowIfNull(batchMultiply);

        Curve = curve;
        Reduce = reduce;
        Add = add;
        Subtract = subtract;
        Multiply = multiply;
        Negate = negate;
        Invert = invert;
        Random = random;
        BatchAdd = batchAdd;
        BatchSubtract = batchSubtract;
        BatchMultiply = batchMultiply;
        BatchMultiplyAccumulate = batchMultiplyAccumulate;
        BroadcastMultiplyAccumulate = broadcastMultiplyAccumulate;
        GatherMultiplyAccumulate = gatherMultiplyAccumulate;
        ButterflyBatch = butterflyBatch;
        HashToScalar = hashToScalar;
        IsHardwareAccelerated = isHardwareAccelerated;
        this.ownedResource = ownedResource;
    }


    /// <summary>Disposes the resource the bundle owns, if any. Idempotent.</summary>
    public void Dispose()
    {
        ownedResource?.Dispose();
        ownedResource = null;
    }
}
