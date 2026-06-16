using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// The LCH14 additive-FFT Reed–Solomon interface, a faithful port of google/longfellow-zk's
/// <c>lib/gf2k/lch14_reed_solomon.h</c>. Given <c>N</c> evaluations at the first <c>N</c> LCH14
/// nodes <c>of_scalar(0), …, of_scalar(N−1)</c> of a polynomial of degree <c>&lt; N</c>, it
/// extends them to <c>M</c> evaluations at <c>of_scalar(0), …, of_scalar(M−1)</c> — so the <c>M</c>
/// points contain the original <c>N</c>. This is the <c>O(M log N)</c> systematic Reed–Solomon
/// encoder the reference's Ligero commits over (its codewords define the wire-format roots), the
/// fast path the generic <c>O(N²)</c> barycentric binary-domain encoder mirrors.
/// </summary>
/// <remarks>
/// <para>
/// The dimensions <c>N</c> and <c>M</c> are fixed at construction, matching the reference factory
/// surface (kept for interface compatibility with the prime-field Reed–Solomon class); the actual
/// work is in <see cref="Interpolate"/>, which adapts the reference's in-place <c>interpolate</c>
/// to a span the caller supplies sized for the full <c>M</c> outputs, holding the <c>N</c> inputs
/// in its prefix.
/// </para>
/// <para>
/// The algorithm: choose the smallest FFT dimension <c>l</c> with <c>2^l ≥ N</c>. Run the
/// bidirectional transform on the first coset to recover the novel-basis coefficients (the first
/// <c>N</c>) and the trailing evaluations (which fill the gap up to <c>min(M, 2^l)</c>). Then, for
/// every further coset that <c>M</c> reaches into, forward-transform the coefficients at that
/// coset's shift and copy the outputs — a full copy-and-transform when the coset fits entirely,
/// and a transform-then-partial-copy on the final straddling coset.
/// </para>
/// <para>
/// The transform engine (<see cref="Lch14AdditiveFft"/>) carries the precomputed basis table and
/// the field delegates; this type holds a reference to it and the two dimensions. Delegate-supplied
/// field arithmetic, 32-byte canonical scalars, caller-supplied pool for the coefficient scratch.
/// </para>
/// </remarks>
[System.Diagnostics.DebuggerDisplay("LCH14 RS (N={dimension}, M={blockLength})")]
internal sealed class Lch14ReedSolomon
{
    private const int ScalarSize = Scalar.SizeBytes;

    private readonly Lch14AdditiveFft fft;
    private readonly int dimension;
    private readonly int blockLength;
    private readonly BaseMemoryPool pool;


    /// <summary>
    /// Constructs the Reed–Solomon interface for the given <paramref name="dimension"/> (message
    /// length) and <paramref name="blockLength"/> — the <c>N</c> and <c>M</c> of the reference.
    /// </summary>
    /// <param name="dimension">The number of input evaluations (the RS dimension, the reference's <c>N</c>); <c>1 ≤ N ≤ M</c>.</param>
    /// <param name="blockLength">The number of output evaluations (the RS block length, the reference's <c>M</c>); at least <paramref name="dimension"/>.</param>
    /// <param name="fft">The additive-FFT engine carrying the precomputed table and field delegates.</param>
    /// <param name="pool">Pool the coefficient scratch is rented from.</param>
    public Lch14ReedSolomon(int dimension, int blockLength, Lch14AdditiveFft fft, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(fft);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfLessThan(dimension, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(blockLength, dimension);

        //The FFT dimension that covers N must stay within the subfield basis: 2^l ≤ 2^SubFieldBits.
        int fftDimension = FftDimension(dimension);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(fftDimension, fft.SubFieldBits);

        this.fft = fft;
        this.dimension = dimension;
        this.blockLength = blockLength;
        this.pool = pool;
    }


    /// <summary>The RS dimension (input evaluation count).</summary>
    public int Dimension => dimension;

    /// <summary>The RS block length (output evaluation count).</summary>
    public int BlockLength => blockLength;


    /// <summary>
    /// Extends the <c>N</c> input evaluations in the prefix of <paramref name="evaluations"/> to all
    /// <c>M</c> evaluations, in place. On entry <c>y[0..N)</c> holds the evaluations at
    /// <c>of_scalar(0), …, of_scalar(N−1)</c>; on return <c>y[0..M)</c> holds the evaluations at
    /// <c>of_scalar(0), …, of_scalar(M−1)</c>, the first <c>N</c> unchanged.
    /// </summary>
    /// <param name="evaluations"><c>M</c> scalars (<c>M · 32</c> bytes); the first <c>N</c> are the inputs — the reference's in-place <c>y</c>.</param>
    public void Interpolate(Span<byte> evaluations)
    {
        if(evaluations.Length != blockLength * ScalarSize)
        {
            throw new ArgumentException($"The evaluation buffer must be {blockLength * ScalarSize} bytes; received {evaluations.Length}.", nameof(evaluations));
        }

        int fftDimension = FftDimension(dimension);
        int fftLength = 1 << fftDimension;

        using IMemoryOwner<byte> coefficientOwner = pool.Rent(fftLength * ScalarSize);
        Span<byte> coefficients = coefficientOwner.Memory.Span[..(fftLength * ScalarSize)];

        //"Coefficients" under the assumption we know the n evaluations and the higher-order
        //(fftn − n) coefficients are zero: the bidirectional transform recovers the first n
        //coefficients and the trailing evaluations.
        evaluations[..(dimension * ScalarSize)].CopyTo(coefficients[..(dimension * ScalarSize)]);
        coefficients[(dimension * ScalarSize)..].Clear();
        fft.BidirectionalTransform(fftDimension, dimension, coefficients);

        //Fill the missing first-coset evaluations from the recovered C[[n, min(m, fftn))].
        int firstCosetEnd = Math.Min(blockLength, fftLength);
        for(int i = dimension; i < firstCosetEnd; i++)
        {
            coefficients.Slice(i * ScalarSize, ScalarSize).CopyTo(evaluations.Slice(i * ScalarSize, ScalarSize));
        }

        //Revert C to pure coefficients (zero the trailing slots the bidirectional pass evaluated).
        coefficients[(dimension * ScalarSize)..].Clear();

        //All remaining cosets.
        for(int coset = 1; (coset << fftDimension) < blockLength; coset++)
        {
            int cosetBase = coset << fftDimension;
            if(cosetBase + fftLength <= blockLength)
            {
                //The coset fits completely within y: copy the coefficients in and transform in place.
                Span<byte> target = evaluations.Slice(cosetBase * ScalarSize, fftLength * ScalarSize);
                coefficients.CopyTo(target);
                fft.ForwardTransform(fftDimension, cosetBase, target);
            }
            else
            {
                //Partial fit: transform a copy of C and copy out only what fits. This is the last
                //iteration, so destroying the copy is fine.
                using IMemoryOwner<byte> tailOwner = pool.Rent(fftLength * ScalarSize);
                Span<byte> tail = tailOwner.Memory.Span[..(fftLength * ScalarSize)];
                coefficients.CopyTo(tail);
                fft.ForwardTransform(fftDimension, cosetBase, tail);
                for(int i = 0; i + cosetBase < blockLength; i++)
                {
                    tail.Slice(i * ScalarSize, ScalarSize).CopyTo(evaluations.Slice((i + cosetBase) * ScalarSize, ScalarSize));
                }
            }
        }
    }


    //The smallest l with 2^l ≥ count (and l ≥ 0); count ≥ 1.
    private static int FftDimension(int count)
    {
        int dimension = 0;
        int size = 1;
        while(size < count)
        {
            size <<= 1;
            dimension++;
        }

        return dimension;
    }
}
