using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Threading;

namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// A <see cref="LigeroRowExtenderFactory"/> source backed by the
/// <see cref="Fp256ReedSolomon"/> FFT convolution engine: per
/// <c>(messageLength, codewordLength)</c> shape it builds one engine — whose
/// setup cost is one-time per shape — and hands out extenders that replace
/// the barycentric per-point loop with one convolution. Output is
/// byte-identical to the barycentric path: both compute the same integer-node
/// Lagrange extension, and field arithmetic is exact.
/// </summary>
/// <remarks>
/// The engines are owned by this instance; dispose it after the tableau or
/// matrix build completes. The supplied FFT holds no disposable state and
/// stays the caller's. Extenders assume rows of one shape are extended
/// sequentially, matching every encode loop in the library. The instance
/// works in whatever coordinate domain the supplied delegates and FFT share
/// — canonical or Montgomery — exactly like the engine itself.
/// </remarks>
internal sealed class Fp256LigeroRowExtenders: IDisposable
{
    private readonly Dictionary<(int MessageLength, int CodewordLength), Fp256ReedSolomon> engines = [];
    private readonly Lock enginesLock = new();
    private readonly Fp256RealFft fft;
    private readonly ScalarAddDelegate add;
    private readonly ScalarSubtractDelegate subtract;
    private readonly ScalarMultiplyDelegate multiply;
    private readonly ScalarInvertDelegate invert;
    private readonly Action<uint, Span<byte>> ofScalar;
    private readonly CurveParameterSet curve;
    private readonly BaseMemoryPool pool;
    private readonly ScalarBatchMultiplyDelegate? batchMultiply;
    private bool disposed;


    /// <summary>
    /// Wraps a working-domain FFT and its matching field backends.
    /// </summary>
    /// <param name="fft">The real FFT over the P-256 base field; must share the delegates' coordinate domain. Its lifetime stays the caller's.</param>
    /// <param name="add">Base-field addition.</param>
    /// <param name="subtract">Base-field subtraction.</param>
    /// <param name="multiply">Base-field multiplication in the working domain.</param>
    /// <param name="invert">Base-field inversion in the working domain.</param>
    /// <param name="ofScalar">The working-domain small-integer encoder.</param>
    /// <param name="curve">The curve tag the delegates route over.</param>
    /// <param name="pool">The pool engine tables rent from.</param>
    /// <param name="batchMultiply">Optional batched multiply the engines route their element-wise products through.</param>
    public Fp256LigeroRowExtenders(
        Fp256RealFft fft,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        Action<uint, Span<byte>> ofScalar,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        ScalarBatchMultiplyDelegate? batchMultiply = null)
    {
        ArgumentNullException.ThrowIfNull(fft);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(ofScalar);
        ArgumentNullException.ThrowIfNull(pool);

        this.fft = fft;
        this.add = add;
        this.subtract = subtract;
        this.multiply = multiply;
        this.invert = invert;
        this.ofScalar = ofScalar;
        this.curve = curve;
        this.pool = pool;
        this.batchMultiply = batchMultiply;
    }


    /// <summary>
    /// The factory method to install as a <see cref="LigeroRowExtenderFactory"/>:
    /// builds or reuses the shape's engine and returns its extender. Never
    /// declines — every consecutive-integer shape whose padded transform buffers
    /// are byte-addressable is supported, and larger shapes are argument errors.
    /// </summary>
    /// <param name="messageLength">The message length; at least 1.</param>
    /// <param name="codewordLength">The codeword length; at least <paramref name="messageLength"/>.</param>
    /// <returns>The shape-bound extender.</returns>
    public LigeroRowExtender? Create(int messageLength, int codewordLength)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ArgumentOutOfRangeException.ThrowIfLessThan(messageLength, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(codewordLength, messageLength);
        //The engine's padded FFT buffers are byte spans, so the PADDED domain
        //must stay byte-addressable; the guard also keeps the engine's
        //power-of-two padding search below its int wraparound.
        if(BitOperations.RoundUpToPowerOf2((uint)codewordLength) > int.MaxValue / Scalar.SizeBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(codewordLength),
                $"The codeword length {codewordLength} pads to a transform domain whose buffers cannot be addressed as byte spans.");
        }

        Fp256ReedSolomon engine;
        lock(enginesLock)
        {
            //Re-checked under the lock: a Create racing a Dispose must not cache
            //an engine nothing will ever release.
            ObjectDisposedException.ThrowIf(disposed, this);
            if(!engines.TryGetValue((messageLength, codewordLength), out Fp256ReedSolomon? cached))
            {
                cached = new Fp256ReedSolomon(messageLength, codewordLength, fft, add, subtract, multiply, invert, ofScalar, curve, pool, batchMultiply);
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
            foreach(Fp256ReedSolomon engine in engines.Values)
            {
                engine.Dispose();
            }

            engines.Clear();
        }
    }
}
