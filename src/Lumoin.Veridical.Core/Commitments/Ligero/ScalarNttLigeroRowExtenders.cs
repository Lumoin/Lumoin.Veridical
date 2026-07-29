using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Numerics;
using System.Threading;

namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// The NTT-convolution row-extender source for the wired scalar fields: a
/// <see cref="LigeroRowExtenderFactory"/> whose extenders produce the
/// byte-identical codeword of the barycentric reference path in
/// <c>O(L log L)</c> field multiplications per row instead of the reference's
/// <c>O(messageLength · extensionWidth)</c> multiplications and inversions.
/// Pass <see cref="Create"/> as the <c>rowExtenderFactory</c> of
/// <see cref="LigeroPolynomialCommitmentScheme.Create"/> to accelerate the
/// consecutive-integer Ligero encode path.
/// </summary>
/// <remarks>
/// One <see cref="ScalarNttReedSolomon"/> engine is built and cached per
/// distinct <c>(messageLength, codewordLength)</c> shape — the per-shape tables
/// are a one-time setup cost — and every cached engine is released when this
/// source is disposed. A shape whose transform domain would exceed the field's
/// 2-adic subgroup or byte-span addressability is declined so the caller falls
/// back to the barycentric path; every practical Ligero shape is far below both
/// bounds. The cache holds every shape it has seen until disposal, so a source
/// is scoped to one proving session rather than shared across unbounded shape
/// streams.
/// </remarks>
public sealed class ScalarNttLigeroRowExtenders: IDisposable
{
    private const int ScalarSize = Scalar.SizeBytes;

    private readonly Dictionary<(int MessageLength, int CodewordLength), ScalarNttReedSolomon> engines = [];
    private readonly Lock enginesLock = new();
    private readonly ScalarAddDelegate add;
    private readonly ScalarSubtractDelegate subtract;
    private readonly ScalarMultiplyDelegate multiply;
    private readonly ScalarInvertDelegate invert;
    private readonly CurveParameterSet curve;
    private readonly BaseMemoryPool pool;
    private readonly ScalarBatchMultiplyDelegate? batchMultiply;
    private bool disposed;


    /// <summary>
    /// Builds a row-extender source over a wired curve's scalar field.
    /// </summary>
    /// <param name="add">Scalar addition.</param>
    /// <param name="subtract">Scalar subtraction.</param>
    /// <param name="multiply">Scalar multiplication.</param>
    /// <param name="invert">Scalar inversion (per-shape table setup only).</param>
    /// <param name="curve">The wired curve the delegates route over.</param>
    /// <param name="pool">Pool the per-shape tables and per-row scratch rent from.</param>
    /// <param name="batchMultiply">Optional batched multiplication for the element-wise weight products.</param>
    /// <exception cref="ArgumentNullException">When a delegate or the pool is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the curve is not wired.</exception>
    public ScalarNttLigeroRowExtenders(
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        ScalarBatchMultiplyDelegate? batchMultiply = null)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(pool);
        WellKnownCurves.ThrowIfCurveNotWired(curve);

        this.add = add;
        this.subtract = subtract;
        this.multiply = multiply;
        this.invert = invert;
        this.curve = curve;
        this.pool = pool;
        this.batchMultiply = batchMultiply;
    }


    /// <summary>
    /// The <see cref="LigeroRowExtenderFactory"/>: returns the cached (or newly
    /// built) shape-bound extender, or declines a shape beyond the field's
    /// 2-adic subgroup.
    /// </summary>
    /// <param name="messageLength">The message length (the RS dimension); at least 1.</param>
    /// <param name="codewordLength">The codeword length (the RS block length); at least <paramref name="messageLength"/>.</param>
    /// <returns>The shape-bound extender, or <see langword="null"/> to use the barycentric path.</returns>
    /// <exception cref="ObjectDisposedException">When this source is disposed.</exception>
    public LigeroRowExtender? Create(int messageLength, int codewordLength)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ArgumentOutOfRangeException.ThrowIfLessThan(messageLength, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(codewordLength, messageLength);

        //Declines any shape the engine cannot serve — a padded transform domain
        //beyond the field's 2-adic subgroup or beyond byte-span addressability —
        //so the caller falls back to the barycentric path, which encodes every
        //byte-addressable codeword.
        uint paddedLength = BitOperations.RoundUpToPowerOf2((uint)codewordLength);
        if(paddedLength > int.MaxValue / ScalarSize || BitOperations.Log2(paddedLength) > ScalarNtt.TwoAdicity(curve))
        {
            return null;
        }

        ScalarNttReedSolomon engine;
        lock(enginesLock)
        {
            //Re-checked under the lock: a Create racing a Dispose must not cache
            //an engine nothing will ever release.
            ObjectDisposedException.ThrowIf(disposed, this);
            if(!engines.TryGetValue((messageLength, codewordLength), out ScalarNttReedSolomon? cached))
            {
                cached = new ScalarNttReedSolomon(messageLength, codewordLength, add, subtract, multiply, invert, WriteCanonicalUInt, curve, pool, batchMultiply);
                engines[(messageLength, codewordLength)] = cached;
            }

            engine = cached;
        }

        return engine.Interpolate;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        disposed = true;
        lock(enginesLock)
        {
            foreach(ScalarNttReedSolomon engine in engines.Values)
            {
                engine.Dispose();
            }

            engines.Clear();
        }
    }


    private static void WriteCanonicalUInt(uint value, Span<byte> destination)
    {
        destination.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(destination[(ScalarSize - sizeof(uint))..], value);
    }
}
