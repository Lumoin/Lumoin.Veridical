using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// The Lin–Chung–Han 2014 additive Fast Fourier Transform in the novel polynomial basis, the
/// <c>O(n log n)</c> transform Reed–Solomon encoding over a binary field rides on. A faithful port
/// of google/longfellow-zk's <c>lib/gf2k/lch14.h</c> — the algorithm of [LCH14] following
/// [DP24, Algorithm 2] — for the field <c>GF(2^128) = GF(2)[x]/(x^128 + x^7 + x^2 + x + 1)</c> over
/// a GF(2)-subfield chosen at construction by <see cref="Lch14Subfield"/>: the production mdoc path
/// commits over the <c>GF(2^16)</c> subfield (<see cref="Lch14Subfield.Production16"/>, the
/// reference's <c>GF2_128&lt;&gt;</c> default, <c>kSubFieldBits = 16</c>), so its codewords are the
/// wire-format conformant ones; the reference's LCH14 unit tests run over the <c>GF(2^32)</c>
/// subfield (<see cref="Lch14Subfield.TestParity32"/>, <c>GF2_128&lt;5&gt;</c>,
/// <c>kSubFieldBits = 32</c>), which the port pins for test parity.
/// </summary>
/// <remarks>
/// <para>
/// The transform is taken over the <em>subspace</em> spanned by the GF(2)-basis <c>β_j = g^j</c> of
/// the chosen subfield, where <c>g</c> is the subfield generator
/// <c>x^{(2^128−1)/(2^kSubFieldBits−1)}</c> the reference computes (an element of multiplicative
/// order exactly <c>2^kSubFieldBits − 1</c>). Evaluation node <c>k</c> is
/// <c>of_scalar(k) = Σ_{bit j of k} β_j</c> — the bit pattern of <c>k</c> read as coordinates
/// against that basis, <em>not</em> the field element whose raw bits are <c>k</c>. This is the
/// choice that distinguishes the LCH14 domain from the generic bit-pattern binary domain in
/// <see cref="BarycentricInterpolation.ComputeBinaryNodeWeights"/>; both are correct
/// Reed–Solomon domains, but a wire-format conformant codeword uses this one.
/// </para>
/// <para>
/// The forward <see cref="ForwardTransform"/> maps novel-basis "coefficients" to evaluations at the
/// nodes of a coset; the inverse <see cref="InverseTransform"/> goes the other way; the
/// <see cref="BidirectionalTransform"/> is the truncated-Fourier kernel that, given the first
/// <c>k</c> evaluations and the trailing <c>n − k</c> coefficients of a degree-<c>&lt; k</c>
/// polynomial, recovers the first <c>k</c> coefficients and the trailing <c>n − k</c> evaluations
/// in one pass — the interpolation primitive <see cref="Lch14ReedSolomon"/> builds on. R is
/// hardcoded to zero, exactly as the reference does, with an explicit coset parameter.
/// </para>
/// <para>
/// Delegate-supplied field arithmetic (add, subtract — which coincides with add in characteristic
/// two — multiply and invert), 32-byte canonical big-endian scalars, and a caller-supplied
/// <see cref="BaseMemoryPool"/> for the precomputed table and the per-transform twiddle
/// scratch. The normalized basis-vanishing-polynomial table <c>Ŵ_i(β_j)</c> is precomputed once at
/// construction (the only per-instance state) and held in a pooled buffer the instance owns and
/// returns on <see cref="Dispose"/>.
/// </para>
/// </remarks>
internal sealed class Lch14AdditiveFft: IDisposable
{
    private const int ScalarSize = Scalar.SizeBytes;

    //The field is GF(2^128), so kLogBits = 7 — the upper bound of the subfield-generator exponent
    //product, which runs over the field-bit-log range [kSubFieldLogBits, FieldLogBits).
    private const int FieldLogBits = 7;

    //The kSubFieldLogBits of each named subfield: GF(2^16) is 4, GF(2^32) is 5.
    private const int ProductionSubFieldLogBits = 4;
    private const int TestParitySubFieldLogBits = 5;

    //The subfield log-bits this instance transforms over — kSubFieldLogBits in the reference: 4 for
    //the GF(2^16) production subfield, 5 for the GF(2^32) test-parity subfield.
    private readonly int subFieldLogBits;

    //Ŵ_i(β_j): a SubFieldBits × SubFieldBits table of field elements, row-major (row i, column j).
    private readonly IMemoryOwner<byte> wHatOwner;
    private readonly Memory<byte> wHat;

    private readonly ScalarAddDelegate add;
    private readonly ScalarSubtractDelegate subtract;
    private readonly ScalarMultiplyDelegate multiply;
    private readonly ScalarInvertDelegate invert;
    private readonly CurveParameterSet curve;
    private readonly BaseMemoryPool pool;
    private bool disposed;


    /// <summary>
    /// Precomputes the normalized basis-vanishing-polynomial table <c>Ŵ_i(β_j)</c> over the chosen
    /// <paramref name="subfield"/> for the binary field the delegates operate over.
    /// </summary>
    /// <param name="subfield">The GF(2)-subfield to transform over — the production <c>GF(2^16)</c> or the test-parity <c>GF(2^32)</c>.</param>
    /// <param name="add">Scalar-add backend (XOR over a binary field).</param>
    /// <param name="subtract">Scalar-subtract backend (coincides with add in characteristic two).</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="invert">Scalar-invert backend.</param>
    /// <param name="curve">The field the delegates operate over.</param>
    /// <param name="pool">Pool the table and per-transform scratch are rented from.</param>
    public Lch14AdditiveFft(
        Lch14Subfield subfield,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(pool);
        subFieldLogBits = subfield switch
        {
            Lch14Subfield.Production16 => ProductionSubFieldLogBits,
            Lch14Subfield.TestParity32 => TestParitySubFieldLogBits,
            _ => throw new ArgumentOutOfRangeException(nameof(subfield), subfield, "The subfield must be the production GF(2^16) or the test-parity GF(2^32)."),
        };

        this.add = add;
        this.subtract = subtract;
        this.multiply = multiply;
        this.invert = invert;
        this.curve = curve;
        this.pool = pool;

        wHatOwner = pool.Rent(SubFieldBits * SubFieldBits * ScalarSize);
        wHat = wHatOwner.Memory[..(SubFieldBits * SubFieldBits * ScalarSize)];
        PrecomputeWHat();
    }


    /// <summary>
    /// The number of GF(2)-basis vectors of the subfield this instance transforms over —
    /// <c>kSubFieldBits</c> in the reference, <c>16</c> for the production <c>GF(2^16)</c> subfield
    /// and <c>32</c> for the test-parity <c>GF(2^32)</c> subfield. The transform supports any
    /// <c>l ≤ SubFieldBits</c>.
    /// </summary>
    public int SubFieldBits => 1 << subFieldLogBits;


    /// <summary>
    /// The maximum number of twiddle factors a transform of the given <paramref name="dimension"/>
    /// needs — the scratch <see cref="ForwardTransform"/> and friends require, sized
    /// <c>(2^{l−1}) · 32</c> bytes. The dimension must be at least 1.
    /// </summary>
    /// <param name="dimension">The transform dimension as a log2 block size — the <c>l</c> of [LCH14]; at least 1.</param>
    public static int TwiddleCount(int dimension)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(dimension, 1);

        return 1 << (dimension - 1);
    }


    /// <summary>
    /// The forward additive FFT: in place, transforms the <c>2^l</c> novel-basis coefficients in
    /// <paramref name="block"/> into the evaluations of that polynomial at the nodes of coset
    /// <paramref name="coset"/> (the nodes <c>of_scalar(coset·2^l + i)</c>, <c>0 ≤ i &lt; 2^l</c>).
    /// </summary>
    /// <param name="dimension">The transform dimension as a log2 block size — the <c>l</c> of [LCH14]; <c>0 ≤ l ≤ SubFieldBits</c>. <c>l = 0</c> is a no-op.</param>
    /// <param name="coset">The coset index (the reference's <c>coset</c> parameter; R is hardcoded to zero).</param>
    /// <param name="block"><c>2^l</c> scalars in place, transformed coefficients → evaluations.</param>
    public void ForwardTransform(int dimension, int coset, Span<byte> block)
    {
        ValidateTransform(dimension, coset, block);
        if(dimension == 0)
        {
            return;
        }

        using IMemoryOwner<byte> twiddleOwner = pool.Rent(TwiddleCount(dimension) * ScalarSize);
        Span<byte> twiddleScratch = twiddleOwner.Memory.Span[..(TwiddleCount(dimension) * ScalarSize)];

        //Layers from the highest stride down: i = l−1, …, 0.
        for(int i = dimension - 1; i >= 0; i--)
        {
            int stride = 1 << i;
            ComputeTwiddles(i, dimension, coset, twiddleScratch);
            for(int group = 0; (group << (i + 1)) < (1 << dimension); group++)
            {
                ReadOnlySpan<byte> twiddle = twiddleScratch.Slice(group * ScalarSize, ScalarSize);
                for(int offset = 0; offset < stride; offset++)
                {
                    ForwardButterfly(block, (group << (i + 1)) + offset, stride, twiddle);
                }
            }
        }
    }


    /// <summary>
    /// The inverse additive FFT: in place, transforms the <c>2^l</c> evaluations at coset
    /// <paramref name="coset"/>'s nodes back into the novel-basis coefficients.
    /// </summary>
    /// <param name="dimension">The transform dimension as a log2 block size — the <c>l</c> of [LCH14]; <c>0 ≤ l ≤ SubFieldBits</c>. <c>l = 0</c> is a no-op.</param>
    /// <param name="coset">The coset index.</param>
    /// <param name="block"><c>2^l</c> scalars in place, transformed evaluations → coefficients.</param>
    public void InverseTransform(int dimension, int coset, Span<byte> block)
    {
        ValidateTransform(dimension, coset, block);
        if(dimension == 0)
        {
            return;
        }

        using IMemoryOwner<byte> twiddleOwner = pool.Rent(TwiddleCount(dimension) * ScalarSize);
        Span<byte> twiddleScratch = twiddleOwner.Memory.Span[..(TwiddleCount(dimension) * ScalarSize)];

        //Layers from the lowest stride up: i = 0, …, l−1 — the reverse schedule of the forward FFT.
        for(int i = 0; i < dimension; i++)
        {
            int stride = 1 << i;
            ComputeTwiddles(i, dimension, coset, twiddleScratch);
            for(int group = 0; (group << (i + 1)) < (1 << dimension); group++)
            {
                ReadOnlySpan<byte> twiddle = twiddleScratch.Slice(group * ScalarSize, ScalarSize);
                for(int offset = 0; offset < stride; offset++)
                {
                    BackwardButterfly(block, (group << (i + 1)) + offset, stride, twiddle);
                }
            }
        }
    }


    /// <summary>
    /// The truncated Fourier kernel (van der Hoeven, ported to the LCH14 adaptive FFT). On entry
    /// <paramref name="block"/> holds, for a polynomial of degree <c>&lt; k</c>, the first
    /// <c>k</c> evaluations followed by the trailing <c>2^l − k</c> novel-basis coefficients; on
    /// return it holds the first <c>k</c> coefficients followed by the trailing <c>2^l − k</c>
    /// evaluations. Flips the known/unknown halves of time and frequency, in place.
    /// </summary>
    /// <param name="dimension">The transform dimension as a log2 block size — the <c>l</c> of [LCH14]; <c>0 ≤ l ≤ SubFieldBits</c>.</param>
    /// <param name="knownCount">The number of known leading evaluations — the <c>k</c> of [LCH14]; <c>0 ≤ k ≤ 2^l</c>.</param>
    /// <param name="block"><c>2^l</c> scalars in place.</param>
    public void BidirectionalTransform(int dimension, int knownCount, Span<byte> block)
    {
        ValidateTransform(dimension, coset: 0, block);
        ArgumentOutOfRangeException.ThrowIfNegative(knownCount);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(knownCount, 1 << dimension);

        BidirectionalRecurse(dimension, coset: 0, knownCount, block);
    }


    /// <summary>
    /// A single twiddle factor <c>Σ_{bit k of u} Ŵ_i(β_k)</c> — the <c>i</c> of [LCH14] is
    /// <paramref name="stage"/>, the <c>u</c> is <paramref name="index"/>. Exposed for the
    /// conformance gate that checks the linear-time table form against the per-index form.
    /// </summary>
    public void Twiddle(int stage, int index, Span<byte> result)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(stage);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(stage, SubFieldBits);
        if(result.Length != ScalarSize)
        {
            throw new ArgumentException($"A twiddle is {ScalarSize} bytes; received {result.Length}.", nameof(result));
        }

        TwiddleInto(stage, index, result);
    }


    /// <summary>
    /// Fills <paramref name="twiddleTable"/> (<c>2^{l−1} · 32</c> bytes) with all twiddles of the
    /// given <paramref name="stage"/> for the given <paramref name="dimension"/> and
    /// <paramref name="coset"/> via the linear-time doubling — the <c>i</c> of [LCH14] is
    /// <paramref name="stage"/>, the <c>l</c> is <paramref name="dimension"/>. Exposed for the
    /// conformance gate that checks this against <see cref="Twiddle"/> at the corresponding indices.
    /// </summary>
    public void ComputeTwiddleTable(int stage, int dimension, int coset, Span<byte> twiddleTable)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(stage);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(stage, dimension);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(dimension, SubFieldBits);
        ArgumentOutOfRangeException.ThrowIfNegative(coset);
        if(twiddleTable.Length != TwiddleCount(dimension) * ScalarSize)
        {
            throw new ArgumentException($"A stage-{stage} twiddle table for dimension {dimension} needs {TwiddleCount(dimension) * ScalarSize} bytes; received {twiddleTable.Length}.", nameof(twiddleTable));
        }

        ComputeTwiddles(stage, dimension, coset, twiddleTable);
    }


    /// <summary>
    /// Fills <paramref name="destination"/> with <c>of_scalar(index) = Σ_{bit j of index} β_j</c>
    /// — the LCH14 evaluation node at <paramref name="index"/> as the basis-coordinate combination,
    /// the mapping the interpolate contract assumes for its inputs and the conformance oracles need.
    /// <paramref name="index"/> is unsigned so the full 32-bit node range maps (the reference's
    /// <c>of_scalar</c> consumes up to <c>SubFieldBits</c> coordinate bits).
    /// </summary>
    public void NodeElement(uint index, Span<byte> destination)
    {
        if(destination.Length != ScalarSize)
        {
            throw new ArgumentException($"A node element is {ScalarSize} bytes; received {destination.Length}.", nameof(destination));
        }

        destination.Clear();
        Span<byte> accumulator = stackalloc byte[ScalarSize];
        accumulator.Clear();
        uint bits = index;
        for(int j = 0; bits != 0; j++, bits >>= 1)
        {
            if((bits & 1) != 0)
            {
                //β_j is Ŵ_0(β_j) — row 0 of the normalized table is exactly the basis (the
                //normalization of W_0(X) = X by W_0(β_0) = β_0 = 1 is the identity).
                add(accumulator, BasisVector(j), destination, curve);
                destination.CopyTo(accumulator);
            }
        }

        accumulator.CopyTo(destination);
    }


    /// <summary>
    /// Reads the GF(2)-basis vector <c>β_j = g^j</c> of the subfield, where <c>j</c> is
    /// <paramref name="index"/>. <c>β_j</c> is exactly <c>Ŵ_0(β_j)</c> — row 0 of the normalized
    /// table — since the normalization of <c>W_0(X) = X</c> by <c>W_0(β_0) = β_0 = 1</c> is the
    /// identity.
    /// </summary>
    public ReadOnlySpan<byte> BasisElement(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, SubFieldBits);

        return BasisVector(index);
    }


    /// <summary>
    /// Reads <c>Ŵ_i(β_j)</c> from the precomputed table — the <c>i</c> of [LCH14] is
    /// <paramref name="stage"/>, the <c>j</c> is <paramref name="index"/>. Exposed for the
    /// conformance gate against the slow direct definition.
    /// </summary>
    public ReadOnlySpan<byte> NormalizedWHat(int stage, int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(stage);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(stage, SubFieldBits);
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, SubFieldBits);

        return wHat.Span.Slice(((stage * SubFieldBits) + index) * ScalarSize, ScalarSize);
    }


    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        wHatOwner.Dispose();
        disposed = true;
    }


    //Computes Ŵ_i(β_j) for all i, j, mirroring the reference constructor.
    //Base case W_0(X) = X gives W[0][j] = β_j; the recursion
    //W_{i+1}(X) = W_i(X)·(W_i(X) + W_i(β_i)) builds the rest; then each row is scaled by
    //1/W_i(β_i) to normalize. The unnormalized W aliases the normalized table in the reference;
    //here the build happens in place in the same buffer in a single pass per stage.
    private void PrecomputeWHat()
    {
        Span<byte> table = wHat.Span;

        //β_j = g^j, where g is the subfield generator. Row 0 of W is the basis itself.
        Span<byte> g = stackalloc byte[ScalarSize];
        SubfieldGenerator(g);
        Span<byte> betaPrevious = stackalloc byte[ScalarSize];
        EncodeOne(table[..ScalarSize]);
        table[..ScalarSize].CopyTo(betaPrevious);
        for(int j = 1; j < SubFieldBits; j++)
        {
            multiply(betaPrevious, g, table.Slice(j * ScalarSize, ScalarSize), curve);
            table.Slice(j * ScalarSize, ScalarSize).CopyTo(betaPrevious);
        }

        //Inductive case W_{i+1}(β_j) = W_i(β_j)·(W_i(β_j) + W_i(β_i)).
        Span<byte> sum = stackalloc byte[ScalarSize];
        Span<byte> product = stackalloc byte[ScalarSize];
        for(int i = 0; i + 1 < SubFieldBits; i++)
        {
            ReadOnlySpan<byte> diagonal = RawWHat(table, i, i);
            for(int j = 0; j < SubFieldBits; j++)
            {
                Span<byte> current = RawWHatMutable(table, i, j);
                add(current, diagonal, sum, curve);
                multiply(current, sum, product, curve);
                product.CopyTo(RawWHatMutable(table, i + 1, j));
            }
        }

        //Normalize each row by 1/W_i(β_i). The diagonal entry W_i(β_i) must be read and inverted
        //before the row is scaled, since scaling overwrites it.
        Span<byte> scale = stackalloc byte[ScalarSize];
        Span<byte> scaled = stackalloc byte[ScalarSize];
        for(int i = 0; i < SubFieldBits; i++)
        {
            invert(RawWHat(table, i, i), scale, curve);
            for(int j = 0; j < SubFieldBits; j++)
            {
                multiply(scale, RawWHat(table, i, j), scaled, curve);
                scaled.CopyTo(RawWHatMutable(table, i, j));
            }
        }
    }


    //The subfield generator g = x^{(2^128−1)/(2^kSubFieldBits−1)}, computed as the product
    //x^{∏_{i=kSubFieldLogBits}^{6} (2^{2^i}+1)} via the reference's identity
    //(2^{2^n}−1)/(2^{2^k}−1) = ∏_{i=k}^{n−1} (2^{2^i}+1). Each factor 2^{2^i}+1 is applied as
    //r ← r^{2^{2^i}} · r, where r^{2^{2^i}} is i-th iterated squaring 2^i-fold.
    private void SubfieldGenerator(Span<byte> result)
    {
        //r starts at x (the field generator: bit 1 set).
        Span<byte> r = stackalloc byte[ScalarSize];
        r.Clear();
        EncodeX(r);

        Span<byte> s = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];
        for(int i = subFieldLogBits; i < FieldLogBits; i++)
        {
            //s ← r^{2^{2^i}}: square 2^i times.
            r.CopyTo(s);
            int squarings = 1 << i;
            for(int q = 0; q < squarings; q++)
            {
                multiply(s, s, scratch, curve);
                scratch.CopyTo(s);
            }

            //r ← r·s = r^{2^{2^i}+1}.
            multiply(r, s, scratch, curve);
            scratch.CopyTo(r);
        }

        r.CopyTo(result);
    }


    //Linear-time computation of all 2^{l−1} twiddles for stage i and coset, following the
    //reference: tw[0] = twiddle(i, coset), then each higher basis vector Ŵ_i(β_{(i+1)+k}) doubles
    //the populated prefix by XOR-adding into the next 2^k slots.
    private void ComputeTwiddles(int stage, int dimension, int coset, Span<byte> twiddleScratch)
    {
        TwiddleInto(stage, coset, twiddleScratch[..ScalarSize]);
        for(int k = 0; (stage + 1) + k < dimension; k++)
        {
            ReadOnlySpan<byte> shift = RawWHat(wHat.Span, stage, (stage + 1) + k);
            int half = 1 << k;
            for(int u = 0; u < half; u++)
            {
                add(twiddleScratch.Slice(u * ScalarSize, ScalarSize), shift, twiddleScratch.Slice((u + half) * ScalarSize, ScalarSize), curve);
            }
        }
    }


    //One twiddle factor: t = Σ_{bit k of u} Ŵ_i(β_k).
    private void TwiddleInto(int stage, int index, Span<byte> result)
    {
        result.Clear();
        Span<byte> accumulator = stackalloc byte[ScalarSize];
        accumulator.Clear();
        int bits = index;
        for(int k = 0; bits != 0; k++, bits >>= 1)
        {
            if((bits & 1) != 0)
            {
                add(accumulator, RawWHat(wHat.Span, stage, k), result, curve);
                result.CopyTo(accumulator);
            }
        }

        accumulator.CopyTo(result);
    }


    //The recursive truncated-Fourier kernel. Mirrors the reference bidir_recur with R = 0.
    private void BidirectionalRecurse(int dimension, int coset, int knownCount, Span<byte> block)
    {
        if(dimension == 0)
        {
            return;
        }

        dimension--;
        int stride = 1 << dimension;
        Span<byte> twiddle = stackalloc byte[ScalarSize];
        TwiddleInto(dimension, coset, twiddle);

        if(knownCount < stride)
        {
            for(int pairIndex = knownCount; pairIndex < stride; pairIndex++)
            {
                ForwardButterfly(block, pairIndex, stride, twiddle);
            }

            BidirectionalRecurse(dimension, coset, knownCount, block);

            for(int pairIndex = 0; pairIndex < knownCount; pairIndex++)
            {
                DiagonalButterfly(block, pairIndex, stride, twiddle);
            }

            ForwardTransform(dimension, coset + stride, block.Slice(stride * ScalarSize, stride * ScalarSize));
        }
        else
        {
            InverseTransform(dimension, coset, block[..(stride * ScalarSize)]);

            for(int pairIndex = knownCount - stride; pairIndex < stride; pairIndex++)
            {
                DiagonalButterfly(block, pairIndex, stride, twiddle);
            }

            BidirectionalRecurse(dimension, coset + stride, knownCount - stride, block.Slice(stride * ScalarSize, stride * ScalarSize));

            for(int pairIndex = 0; pairIndex < knownCount - stride; pairIndex++)
            {
                BackwardButterfly(block, pairIndex, stride, twiddle);
            }
        }
    }


    //B[uv] += twu·B[uv+s]; B[uv+s] += B[uv].
    private void ForwardButterfly(Span<byte> block, int pairIndex, int stride, ReadOnlySpan<byte> twiddle)
    {
        Span<byte> low = block.Slice(pairIndex * ScalarSize, ScalarSize);
        Span<byte> high = block.Slice((pairIndex + stride) * ScalarSize, ScalarSize);
        Span<byte> product = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];

        multiply(twiddle, high, product, curve);
        add(low, product, scratch, curve);
        scratch.CopyTo(low);
        add(high, low, scratch, curve);
        scratch.CopyTo(high);
    }


    //B[uv+s] −= B[uv]; B[uv] −= twu·B[uv+s].
    private void BackwardButterfly(Span<byte> block, int pairIndex, int stride, ReadOnlySpan<byte> twiddle)
    {
        Span<byte> low = block.Slice(pairIndex * ScalarSize, ScalarSize);
        Span<byte> high = block.Slice((pairIndex + stride) * ScalarSize, ScalarSize);
        Span<byte> product = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];

        subtract(high, low, scratch, curve);
        scratch.CopyTo(high);
        multiply(twiddle, high, product, curve);
        subtract(low, product, scratch, curve);
        scratch.CopyTo(low);
    }


    //Forward at [uv+s], backward at [uv]: b1 = B[uv+s]; B[uv+s] += B[uv]; B[uv] −= twu·b1.
    private void DiagonalButterfly(Span<byte> block, int pairIndex, int stride, ReadOnlySpan<byte> twiddle)
    {
        Span<byte> low = block.Slice(pairIndex * ScalarSize, ScalarSize);
        Span<byte> high = block.Slice((pairIndex + stride) * ScalarSize, ScalarSize);
        Span<byte> highInput = stackalloc byte[ScalarSize];
        high.CopyTo(highInput);
        Span<byte> product = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];

        add(high, low, scratch, curve);
        scratch.CopyTo(high);
        multiply(twiddle, highInput, product, curve);
        subtract(low, product, scratch, curve);
        scratch.CopyTo(low);
    }


    private ReadOnlySpan<byte> BasisVector(int j) => RawWHat(wHat.Span, 0, j);


    private void ValidateTransform(int dimension, int coset, ReadOnlySpan<byte> block)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ArgumentOutOfRangeException.ThrowIfNegative(dimension);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(dimension, SubFieldBits);
        ArgumentOutOfRangeException.ThrowIfNegative(coset);
        int size = 1 << dimension;
        if(block.Length != size * ScalarSize)
        {
            throw new ArgumentException($"A dimension-{dimension} block needs {size * ScalarSize} bytes; received {block.Length}.", nameof(block));
        }
    }


    private ReadOnlySpan<byte> RawWHat(ReadOnlySpan<byte> table, int i, int j) =>
        table.Slice(((i * SubFieldBits) + j) * ScalarSize, ScalarSize);


    private Span<byte> RawWHatMutable(Span<byte> table, int i, int j) =>
        table.Slice(((i * SubFieldBits) + j) * ScalarSize, ScalarSize);


    //The field element x (the generator of GF(2^128)): bit 1 of the trailing 128-bit value.
    private static void EncodeX(Span<byte> destination)
    {
        destination.Clear();
        destination[ScalarSize - 1] = 0b10;
    }


    //The field element 1: bit 0 set.
    private static void EncodeOne(Span<byte> destination)
    {
        destination.Clear();
        destination[ScalarSize - 1] = 1;
    }
}
