using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// A minimal, curve-agnostic assembler for the linear + quadratic constraint
/// surface that <see cref="LigeroProver"/> and <see cref="LigeroVerifier"/>
/// consume. Wires (witness positions) hold canonical big-endian field elements;
/// constraints are accumulated incrementally and emitted as
/// <see cref="LigeroParameters"/>, the witness/target byte vectors, and the
/// <see cref="LigeroLinearConstraint"/> / <see cref="LigeroQuadraticConstraint"/>
/// arrays.
/// </summary>
/// <remarks>
/// <para>
/// Field arithmetic is supplied as the canonical <see cref="ScalarAddDelegate"/>
/// family (add / subtract / multiply / invert / reduce), so the builder runs
/// over any field a backend exposes — for the Longfellow ECDSA circuits that is
/// the P-256 <em>base</em> field Fp256. The builder is the substrate the
/// higher-level elliptic-curve gadgets
/// (<see cref="Gadgets.WeierstrassGadgetExtensions"/>) compose from; it carries no curve
/// identity of its own.
/// </para>
/// <para>
/// Every <em>derived</em> wire (a product via <see cref="Multiply"/>, a linear
/// combination via <see cref="Combine"/>, a bit via <see cref="AddBit"/>) carries
/// its defining constraint, so a witness cannot satisfy the system unless each
/// intermediate equals the value its constraint names. The persistent scalars (the
/// witness, the linear-constraint targets, and the coefficients) are sub-allocated
/// from pooled arena slabs rented from the caller's <see cref="BaseMemoryPool"/>,
/// threaded in from the top, and zeroed back to the pool on <see cref="Dispose"/>;
/// transient per-call value buffers are stack-allocated.
/// </para>
/// <para>
/// The backing tier follows one reviewable rule: <em>a pooled region is
/// <see cref="AllocationKind.Pinned"/> exactly when it can hold a secret.</em> The scalar
/// arena (<see cref="RentScalar"/>) is Pinned because the wires include the witness — the
/// ECDSA nonce coordinates enter as wire values — so its zeroize-on-return wipe lands on the
/// exact bytes with no GC-relocation copy, matching how <see cref="LigeroProver"/> retains
/// its witness. The constant basis shares the scalar arena's lifetime. The wire-index arena
/// (<see cref="RentWireWord"/>) stays Managed: indices are public circuit structure, never
/// a secret. Pinned is the portable floor (pure managed pinned-object-heap, identical on
/// every platform including WASM), so the guarantee needs no native backing.
/// </para>
/// </remarks>
internal sealed class LigeroConstraintSystemBuilder: IDisposable
{
    /// <summary>The byte width of one canonical scalar, taken from the field's own representation.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The number of scalars held in one pooled arena slab; sized in the hundreds so a typical circuit build rents only a handful of slabs, amortizing the pool's per-rent cost across every wire, target, and coefficient scalar.</summary>
    private const int ScalarsPerSlab = 512;

    /// <summary>
    /// The byte size of one pooled wire-index slab. Wire-index words are byte-granular
    /// (<c>count * sizeof(int)</c>); a 64 KiB slab amortizes the many small words a circuit
    /// build produces, parallel to the scalar arena.
    /// </summary>
    private const int WireSlabBytes = 64 * 1024;

    /// <summary>The field's addition delegate, supplied by the caller so the builder runs over whichever field the backend exposes.</summary>
    private ScalarAddDelegate Add { get; }
    /// <summary>The field's subtraction delegate, supplied by the caller so the builder runs over whichever field the backend exposes.</summary>
    private ScalarSubtractDelegate Subtract { get; }
    /// <summary>The field's multiplication delegate, supplied by the caller so the builder runs over whichever field the backend exposes.</summary>
    private ScalarMultiplyDelegate MultiplyScalars { get; }
    /// <summary>The field's inversion delegate, supplied by the caller so the builder runs over whichever field the backend exposes.</summary>
    private ScalarInvertDelegate Invert { get; }
    /// <summary>The field's canonical-reduction delegate, supplied by the caller so the builder runs over whichever field the backend exposes.</summary>
    private ScalarReduceDelegate Reduce { get; }
    /// <summary>The curve parameters passed through to every field delegate call, identifying which field and modulus the delegates operate over.</summary>
    private CurveParameterSet Curve { get; }
    /// <summary>The Ligero inverse rate carried through unchanged into <see cref="BuildParameters"/>.</summary>
    private int InverseRate { get; }
    /// <summary>The number of Ligero columns opened per query, carried through unchanged into <see cref="BuildParameters"/>.</summary>
    private int OpenedColumnCount { get; }
    /// <summary>The Ligero block size carried through unchanged into <see cref="BuildParameters"/>.</summary>
    private int Block { get; }

    /// <summary>The canonical field-element value stored for each wire, indexed by wire number.</summary>
    private List<Memory<byte>> Wires { get; } = [];
    /// <summary>Every linear-constraint term accumulated so far, each naming the constraint it belongs to, the wire it reads, and its canonical coefficient.</summary>
    private List<(int Constraint, int Wire, Memory<byte> Coefficient)> LinearTerms { get; } = [];
    /// <summary>The target value of each linear constraint, indexed by constraint number.</summary>
    private List<Memory<byte>> Targets { get; } = [];
    /// <summary>Every quadratic constraint accumulated so far.</summary>
    private List<LigeroQuadraticConstraint> Quadratics { get; } = [];

    /// <summary>The pool every scalar and wire-index slab is rented from, threaded in from the top caller.</summary>
    private BaseMemoryPool MemoryPool { get; }
    /// <summary>Every pinned scalar slab rented so far, disposed back to the pool on <see cref="Dispose"/>.</summary>
    private List<IMemoryOwner<byte>> Slabs { get; } = [];
    /// <summary>The scalar slab <see cref="RentScalar"/> is currently sub-allocating from.</summary>
    private Memory<byte> currentSlab;
    /// <summary>The number of scalars already handed out of <see cref="currentSlab"/>.</summary>
    private int slabOffset;

    /// <summary>Every pooled wire-index slab rented so far, disposed back to the pool on <see cref="Dispose"/>.</summary>
    private List<IMemoryOwner<byte>> WireSlabs { get; } = [];
    /// <summary>The wire-index slab <see cref="RentWireWord"/> is currently sub-allocating from.</summary>
    private Memory<byte> currentWireSlab;
    /// <summary>The byte offset already handed out of <see cref="currentWireSlab"/>.</summary>
    private int wireSlabByteOffset;
    /// <summary>Whether <see cref="Dispose"/> has already run, so a repeated call is a harmless no-op.</summary>
    private bool disposed;

    /// <summary>The canonical zero in the owned scalar arena.</summary>
    private Memory<byte> Zero { get; }
    /// <summary>The canonical one in the owned scalar arena.</summary>
    private Memory<byte> One { get; }
    /// <summary>The field modulus in the owned scalar arena.</summary>
    private Memory<byte> Modulus { get; }

    /// <summary>The canonical negative one in the owned scalar arena, a repeated coefficient cached so bit-decomposition and recomposition constraints reuse it instead of re-deriving it per call.</summary>
    private Memory<byte> NegativeOne { get; }
    /// <summary>The canonical two in the owned scalar arena, a repeated coefficient cached so bit-decomposition and recomposition constraints reuse it instead of re-deriving it per call.</summary>
    private Memory<byte> Two { get; }
    /// <summary>The canonical negative two in the owned scalar arena, a repeated coefficient cached so bit-decomposition and recomposition constraints reuse it instead of re-deriving it per call.</summary>
    private Memory<byte> NegativeTwo { get; }

    /// <summary>Powers of two as canonical field elements, grown on demand and cached so the recomposition constraint reuses the table across every scalar instead of rebuilding it on each call.</summary>
    private List<Memory<byte>> PowerOfTwo { get; } = [];
    /// <summary>Negated powers of two as canonical field elements, grown on demand and cached alongside the un-negated table so the recomposition constraint reuses them across every scalar instead of rebuilding on each call.</summary>
    private List<Memory<byte>> NegativePowerOfTwo { get; } = [];

    /// <summary>The wire index a corruption test should perturb, or <c>-1</c> when no output has been recorded yet.</summary>
    private int lastOutputWire = -1;


    /// <summary>Creates a field-generic builder whose scalar storage belongs to the supplied pool.</summary>
    /// <remarks>Construction failures release any scalar slabs already rented for the constant basis.</remarks>
    public LigeroConstraintSystemBuilder(
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve,
        int inverseRate,
        int openedColumnCount,
        int block,
        BaseMemoryPool memoryPool)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(memoryPool);

        this.MemoryPool = memoryPool;
        this.Add = add;
        this.Subtract = subtract;
        this.MultiplyScalars = multiply;
        this.Invert = invert;
        this.Reduce = reduce;
        this.Curve = curve;
        this.InverseRate = inverseRate;
        this.OpenedColumnCount = openedColumnCount;
        this.Block = block;

        try
        {
            Zero = RentScalar();
            Zero.Span.Clear();
            One = RentScalar();
            EncodeConstant(1, One.Span);

            NegativeOne = RentScalar();
            NegativeOne.Span.Clear();
            Negate(One.Span, NegativeOne.Span);
            Two = RentScalar();
            EncodeConstant(2, Two.Span);
            NegativeTwo = RentScalar();
            NegativeTwo.Span.Clear();
            Negate(Two.Span, NegativeTwo.Span);

            //The field modulus p, derived once from the delegates as (0 − 1) + 1, so the
            //canonical-bits gadget can pin a decomposition to the unique integer in [0, p)
            //without the caller having to supply p separately.
            Modulus = RentScalar();
            Modulus.Span.Clear();
            Subtract(Zero.Span, One.Span, Modulus.Span, Curve);
            IncrementCanonical(Modulus.Span);
        }
        catch
        {
            Dispose();
            throw;
        }
    }


    /// <summary>The number of wires allocated so far.</summary>
    public int WireCount => Wires.Count;

    /// <summary>The number of linear constraints accumulated so far.</summary>
    public int LinearConstraintCount => Targets.Count;

    /// <summary>The number of quadratic constraints accumulated so far.</summary>
    public int QuadraticConstraintCount => Quadratics.Count;

    /// <summary>The wire index most recently recorded as the circuit's output, or <c>-1</c> when none has been recorded.</summary>
    public int LastOutputWire => lastOutputWire;


    /// <summary>
    /// Returns the canonical bytes backing a wire, for the gadget layer's value math. The
    /// span aliases the builder's storage and must not be mutated.
    /// </summary>
    /// <param name="wire">The wire index whose value to read.</param>
    /// <returns>The wire's canonical field-element value.</returns>
    public ReadOnlySpan<byte> Value(int wire) => Wires[wire].Span;


    /// <summary>Writes the canonical field sum <paramref name="a"/> + <paramref name="b"/>, exposing the field's addition delegate to the gadget layer.</summary>
    /// <param name="a">The first canonical addend.</param>
    /// <param name="b">The second canonical addend.</param>
    /// <param name="result">Receives the canonical sum.</param>
    public void AddValues(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result) => Add(a, b, result, Curve);

    /// <summary>Writes the canonical field difference <paramref name="a"/> − <paramref name="b"/>, exposing the field's subtraction delegate to the gadget layer.</summary>
    /// <param name="a">The canonical minuend.</param>
    /// <param name="b">The canonical subtrahend.</param>
    /// <param name="result">Receives the canonical difference.</param>
    public void SubtractValues(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result) => Subtract(a, b, result, Curve);

    /// <summary>Writes the canonical field product <paramref name="a"/>·<paramref name="b"/>, exposing the field's multiplication delegate to the gadget layer.</summary>
    /// <param name="a">The first canonical factor.</param>
    /// <param name="b">The second canonical factor.</param>
    /// <param name="result">Receives the canonical product.</param>
    public void MultiplyValues(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result) => MultiplyScalars(a, b, result, Curve);

    /// <summary>Writes the canonical multiplicative inverse of <paramref name="a"/>, exposing the field's inversion delegate to the gadget layer.</summary>
    /// <param name="a">The canonical value to invert; must be nonzero.</param>
    /// <param name="result">Receives the canonical inverse.</param>
    public void InvertValue(ReadOnlySpan<byte> a, Span<byte> result) => Invert(a, result, Curve);

    /// <summary>Writes the canonical field negation of <paramref name="a"/> as <c>0 − a</c>, matching the reference field's Subtract semantics.</summary>
    public void Negate(ReadOnlySpan<byte> a, Span<byte> result) => Subtract(Zero.Span, a, result, Curve);

    /// <summary>Encodes a small non-negative integer as a canonical big-endian scalar.</summary>
    /// <param name="value">The integer to encode.</param>
    /// <param name="destination">Receives the canonical big-endian encoding; must be at least <see cref="ScalarSize"/> bytes.</param>
    public static void EncodeConstant(uint value, Span<byte> destination)
    {
        destination.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(destination[(ScalarSize - sizeof(uint))..], value);
    }


    /// <summary>Allocates a wire holding the given value reduced into canonical form, backed by a pooled arena scalar.</summary>
    /// <param name="value">The value to reduce and store.</param>
    /// <returns>The index of the newly allocated wire.</returns>
    public int AddWire(ReadOnlySpan<byte> value)
    {
        Memory<byte> stored = RentScalar();
        Reduce(value, stored.Span, Curve);
        Wires.Add(stored);

        return Wires.Count - 1;
    }


    /// <summary>Allocates a wire pinned to the given value by a linear constraint, so a malicious prover cannot substitute another value.</summary>
    /// <param name="value">The value to pin the wire to.</param>
    /// <returns>The index of the newly allocated, pinned wire.</returns>
    public int AddConstant(ReadOnlySpan<byte> value)
    {
        int wire = AddWire(value);
        AddLinear(value, [new LinearTerm(wire, One)]);

        return wire;
    }


    /// <summary>
    /// Adds the linear constraint <c>Σ coefficient·W[wire] = target</c>. Coefficients and
    /// the target are reduced into canonical form and copied into builder-owned storage, so
    /// callers may reuse their buffers.
    /// </summary>
    /// <param name="target">The constraint's target value.</param>
    /// <param name="terms">The coefficient/wire terms summed on the constraint's left side.</param>
    public void AddLinear(ReadOnlySpan<byte> target, LinearTerm[] terms)
    {
        ArgumentNullException.ThrowIfNull(terms);

        int constraint = Targets.Count;
        Memory<byte> canonicalTarget = RentScalar();
        Reduce(target, canonicalTarget.Span, Curve);
        Targets.Add(canonicalTarget);

        foreach(LinearTerm term in terms)
        {
            Memory<byte> coefficient = RentScalar();
            Reduce(term.Coefficient.Span, coefficient.Span, Curve);
            LinearTerms.Add((constraint, term.Wire, coefficient));
        }
    }


    /// <summary>Adds the quadratic constraint <c>W[z] = W[x]·W[y]</c>.</summary>
    /// <param name="x">The first factor wire.</param>
    /// <param name="y">The second factor wire.</param>
    /// <param name="z">The product wire.</param>
    public void AddQuadratic(int x, int y, int z) => Quadratics.Add(new LigeroQuadraticConstraint(x, y, z));


    /// <summary>Allocates a product wire <c>W[w] = W[x]·W[y]</c> and emits its quadratic constraint.</summary>
    /// <param name="x">The first factor wire.</param>
    /// <param name="y">The second factor wire.</param>
    /// <returns>The index of the newly allocated product wire.</returns>
    public int Multiply(int x, int y)
    {
        Span<byte> product = stackalloc byte[ScalarSize];
        MultiplyScalars(Wires[x].Span, Wires[y].Span, product, Curve);
        int w = AddWire(product);
        AddQuadratic(x, y, w);

        return w;
    }


    /// <summary>
    /// Allocates a wire equal to <c>Σ coefficient·W[wire]</c>, with the value computed
    /// from the terms rather than supplied separately, and emits the defining linear
    /// constraint <c>w − Σ coefficient·W = 0</c>.
    /// </summary>
    public int Combine(LinearTerm[] terms)
    {
        ArgumentNullException.ThrowIfNull(terms);

        Span<byte> accumulator = stackalloc byte[ScalarSize];
        Span<byte> product = stackalloc byte[ScalarSize];
        Span<byte> next = stackalloc byte[ScalarSize];
        accumulator.Clear();
        foreach(LinearTerm term in terms)
        {
            MultiplyScalars(term.Coefficient.Span, Wires[term.Wire].Span, product, Curve);
            Add(accumulator, product, next, Curve);
            next.CopyTo(accumulator);
        }

        int w = AddWire(accumulator);

        var constraintTerms = new LinearTerm[terms.Length + 1];
        constraintTerms[0] = new LinearTerm(w, One);

        //An empty combination is the constant-zero wire (w = 0): no coefficients to negate, and a
        //zero-length pooled rent would throw — so emit its single defining term directly.
        if(terms.Length == 0)
        {
            AddLinear(Zero.Span, constraintTerms);

            return w;
        }

        //The negated coefficients are public constraint constants (never a witness value — the secret lives
        //in the wires they reference). They live only until AddLinear copies them into its own arena scalars,
        //so they are rented as one Managed block and returned (cleared) on scope exit — pooled, not
        //GC-reclaimed, but unpinned: there is no secret here to keep off a relocated heap block.
        using IMemoryOwner<byte> negatedOwner = MemoryPool.Rent(terms.Length * ScalarSize);
        Memory<byte> negatedBlock = negatedOwner.Memory[..(terms.Length * ScalarSize)];
        for(int i = 0; i < terms.Length; i++)
        {
            Memory<byte> negated = negatedBlock.Slice(i * ScalarSize, ScalarSize);
            Negate(terms[i].Coefficient.Span, negated.Span);
            constraintTerms[i + 1] = new LinearTerm(terms[i].Wire, negated);
        }

        AddLinear(Zero.Span, constraintTerms);

        return w;
    }


    /// <summary>Adds a wire constrained to a canonical boolean value, pinning it to <c>{0,1}</c> via the quadratic identity <c>b² = b</c>.</summary>
    public int AddBit(ReadOnlySpan<byte> value)
    {
        int b = AddWire(value);
        int bSquared = Multiply(b, b);
        AddLinear(Zero.Span, [new LinearTerm(bSquared, One), new LinearTerm(b, NegativeOne)]);

        return b;
    }


    /// <summary>
    /// Binds the least-significant-first bits to their recomposed scalar: a wire
    /// constrained to equal <c>Σ bit_i·2^i</c> by one linear constraint, with the
    /// <c>2^i</c> coefficients reduced mod the field so that, below the field order,
    /// the residue equals the integer value.
    /// </summary>
    public int AddRecomposedScalar(ReadOnlySpan<int> bitsLeastSignificantFirst)
    {
        EnsurePowersOfTwo(bitsLeastSignificantFirst.Length);

        Span<byte> accumulator = stackalloc byte[ScalarSize];
        Span<byte> product = stackalloc byte[ScalarSize];
        Span<byte> next = stackalloc byte[ScalarSize];
        accumulator.Clear();
        for(int i = 0; i < bitsLeastSignificantFirst.Length; i++)
        {
            MultiplyScalars(PowerOfTwo[i].Span, Wires[bitsLeastSignificantFirst[i]].Span, product, Curve);
            Add(accumulator, product, next, Curve);
            next.CopyTo(accumulator);
        }

        int w = AddWire(accumulator);

        var terms = new LinearTerm[bitsLeastSignificantFirst.Length + 1];
        terms[0] = new LinearTerm(w, One);
        for(int i = 0; i < bitsLeastSignificantFirst.Length; i++)
        {
            terms[i + 1] = new LinearTerm(bitsLeastSignificantFirst[i], NegativePowerOfTwo[i]);
        }

        AddLinear(Zero.Span, terms);

        return w;
    }


    /// <summary>
    /// Decomposes a wire into its boolean low bits, tied to its value, and constrains
    /// the result below the field modulus with a lexicographic proof that the bits
    /// represent the unique integer in <c>[0, p)</c>. Over a field with
    /// <c>p &lt; 2^bitCount</c>, a value below <c>2^bitCount − p</c> has two bit
    /// patterns recomposing to the same residue (<c>v</c> and <c>v + p</c>); the
    /// <c>&lt; p</c> chain pins the canonical one, so a malicious non-canonical
    /// representative is rejected. Returns the bits least-significant first.
    /// </summary>
    public WireWord AddCanonicalBits(int wire, int bitCount = 256)
    {
        WireWord bits = DecomposeAndBind(wire, bitCount);
        AddAssertLessThanConstant(bits, Modulus.Span);

        return bits;
    }


    /// <summary>
    /// Proves <c>W[wire] &lt; limit</c> for a constant limit ≤ p (canonical big-endian, itself
    /// &lt; 2^bitCount). Built on canonical bits — so the bits are the true integer, not an
    /// aliased representative — then a second lexicographic chain against the limit.
    /// </summary>
    /// <param name="wire">The wire whose value is bounded.</param>
    /// <param name="limit">The canonical big-endian limit the wire's value must fall strictly below.</param>
    /// <param name="bitCount">The number of low bits the value is decomposed into.</param>
    /// <returns>The canonical bits, least-significant first.</returns>
    public WireWord AddRangeBelow(int wire, ReadOnlySpan<byte> limit, int bitCount = 256)
    {
        WireWord bits = AddCanonicalBits(wire, bitCount);
        AddAssertLessThanConstant(bits, limit);

        return bits;
    }


    /// <summary>
    /// Proves a witnessed value is at least a public threshold: the difference <c>value −
    /// threshold</c> lies in <c>[0, 2^differenceBits)</c>. The bounded difference rejects
    /// <c>value &lt; threshold</c> — the difference wraps to a large field element no
    /// differenceBits-wide decomposition can represent — and caps value at <c>threshold +
    /// 2^differenceBits</c> (benign when the gap is small, for example an age over a legal
    /// threshold). A small <paramref name="differenceBits"/> needs no <c>&lt; p</c> canonicity
    /// chain: the alias <c>difference + p</c> exceeds <c>2^differenceBits</c>, so the
    /// recomposition pins the difference.
    /// </summary>
    /// <param name="valueWire">The wire holding the witnessed value.</param>
    /// <param name="threshold">The public, verifier-checked threshold the value must meet or exceed.</param>
    /// <param name="differenceBits">The number of bits the bounded difference is decomposed into.</param>
    public void AddAtLeast(int valueWire, ReadOnlySpan<byte> threshold, int differenceBits)
    {
        Span<byte> difference = stackalloc byte[ScalarSize];
        SubtractValues(Wires[valueWire].Span, threshold, difference);
        int differenceWire = AddWire(difference);

        //value − difference = threshold (threshold is the public, verifier-checked target).
        AddLinear(threshold, [new LinearTerm(valueWire, One), new LinearTerm(differenceWire, NegativeOne)]);

        //difference ∈ [0, 2^differenceBits) by a bounded bit-decomposition.
        DecomposeAndBind(differenceWire, differenceBits);
    }


    /// <summary>
    /// Bit-decomposes a wire into exactly <paramref name="bitCount"/> low bits
    /// (least-significant first), bound to the wire by recomposition. Sound for narrow widths
    /// with no canonicity chain — the <c>value + p</c> alias exceeds <c>2^bitCount</c> — so it
    /// serves the 32-bit word arithmetic of the hash gadgets. A wire whose value is ≥
    /// <c>2^bitCount</c> is unprovable.
    /// </summary>
    /// <param name="wire">The wire to decompose.</param>
    /// <param name="bitCount">The number of low bits to extract.</param>
    /// <returns>The canonical bits, least-significant first.</returns>
    public WireWord AddBits(int wire, int bitCount) => DecomposeAndBind(wire, bitCount);


    /// <summary>
    /// Constrains the value <c>Σ bit_i·2^i</c> of a boolean decomposition (bits
    /// least-significant first, each already pinned to <c>{0,1}</c>) to be strictly
    /// below the supplied constant, which must be <c>&lt; 2^bitCount</c>.
    /// </summary>
    /// <remarks>
    /// The comparison walks the literal bits most-significant first against the
    /// constant's known bits with a running prefix-equal flag: at a constant 1-bit the
    /// flag folds in the bit (a 0 there decides less-than, a 1 keeps the prefix equal);
    /// at a constant 0-bit the bit must be 0 while the prefix is still equal, else the
    /// value would exceed the constant at the top differing position. Every gate is on
    /// <c>{0,1}</c> operands, so no sum that could wrap mod p is ever formed — that is
    /// what makes the bound sound over Fp.
    /// </remarks>
    public void AddAssertLessThanConstant(ReadOnlySpan<int> bitsLeastSignificantFirst, ReadOnlySpan<byte> constant)
    {
        if(constant.Length != ScalarSize)
        {
            throw new ArgumentException($"Constant must be {ScalarSize} canonical bytes; received {constant.Length}.", nameof(constant));
        }

        //prefixEqual = "every bit above the current position equals the constant's".
        int prefixEqual = AddConstant(One.Span);
        for(int i = bitsLeastSignificantFirst.Length - 1; i >= 0; i--)
        {
            int bit = bitsLeastSignificantFirst[i];
            if(BitOfConstant(constant, i))
            {
                //Constant 1: the bit can only match (1) or decide less-than (0); fold
                //it into the prefix-equal flag.
                prefixEqual = Multiply(prefixEqual, bit);
            }
            else
            {
                //Constant 0: while still prefix-equal the bit must be 0; a 1 here would
                //make the value exceed the constant at the top differing position.
                int product = Multiply(prefixEqual, bit);
                AddAssertZero(product);
            }
        }

        //Equal-to-the-constant is not below it: forbid the all-equal prefix.
        AddAssertZero(prefixEqual);
    }


    /// <summary>
    /// Witnesses the wire's <paramref name="bitCount"/> low bits (least-significant
    /// first), pins each to <c>{0,1}</c>, and binds their recomposition
    /// <c>Σ bit_i·2^i</c> to the supplied wire by one linear constraint. Not canonical
    /// on its own: this is the building block that both <see cref="AddCanonicalBits"/>
    /// and the range gadget compose from.
    /// </summary>
    private WireWord DecomposeAndBind(int wire, int bitCount)
    {
        WireWord bits = RentWireWord(bitCount);
        Span<byte> bitValue = stackalloc byte[ScalarSize];
        for(int i = 0; i < bitCount; i++)
        {
            ExtractBit(Wires[wire].Span, i, bitValue);
            bits[i] = AddBit(bitValue);
        }

        int recomposed = AddRecomposedScalar(bits);
        AddLinear(Zero.Span, [new LinearTerm(recomposed, One), new LinearTerm(wire, NegativeOne)]);

        return bits;
    }


    /// <summary>
    /// Constrains a wire to have a multiplicative inverse, asserting <c>W[wire] ≠ 0</c>
    /// by witnessing its inverse and pinning the product to 1: a zero wire has no
    /// inverse, so no witness satisfies <c>wire·inv = 1</c>, and a zero value is
    /// rejected either way.
    /// </summary>
    public void AddNonzeroCheck(int wire)
    {
        Span<byte> inverse = stackalloc byte[ScalarSize];
        InvertValue(Wires[wire].Span, inverse);
        int inv = AddWire(inverse);
        int product = Multiply(wire, inv);
        AddLinear(One.Span, [new LinearTerm(product, One)]);
    }


    /// <summary>
    /// Pins a public scalar, proves it is canonical and <c>&lt; limit</c>, and returns its bits
    /// most-significant first for a double-and-add / Straus ladder. Because the bits are
    /// canonical, the integer the ladder consumes is exactly the pinned public scalar — a
    /// non-canonical representative (<c>scalar + p</c>) cannot be substituted to change the
    /// scalar the curve operation sees.
    /// </summary>
    /// <param name="scalar">The public scalar to pin.</param>
    /// <param name="limit">The canonical big-endian limit the scalar must fall strictly below.</param>
    /// <param name="bitCount">The number of low bits the scalar is decomposed into.</param>
    /// <returns>The pinned wire, and its bits most-significant first.</returns>
    public (int Wire, WireWord BitsMostSignificantFirst) AddPublicScalarBits(ReadOnlySpan<byte> scalar, ReadOnlySpan<byte> limit, int bitCount = 256)
    {
        int wire = AddConstant(scalar);
        WireWord leastSignificantFirst = AddRangeBelow(wire, limit, bitCount);
        WireWord mostSignificantFirst = ReverseInto(leastSignificantFirst);

        return (wire, mostSignificantFirst);
    }


    /// <summary>
    /// Binds a public <paramref name="reducedValue"/> to <c>(W[valueWire] mod modulus)</c>,
    /// where <paramref name="valueWire"/> holds a field element in <c>[0, p)</c> and
    /// <paramref name="modulus"/> satisfies <c>modulus &lt; p &lt; 2·modulus</c> (so the
    /// quotient is a single bit). Proves the integer identity <c>value = quotient·modulus +
    /// reducedValue</c> with a bit-serial ripple-carry adder whose every term is in
    /// <c>{0,1,2,3}</c> — never a sum that could wrap mod p — and a pinned zero carry-out. This
    /// is what rejects the mod-p alias <c>reducedValue + p − modulus</c>, which satisfies a
    /// naive field tie (it differs from the true value by exactly p).
    /// <paramref name="reducedValue"/> is range-checked canonical and <c>&lt; modulus</c> and
    /// returned most-significant first for reuse as the ladder scalar.
    /// </summary>
    /// <param name="valueWire">The wire holding the field element being reduced.</param>
    /// <param name="reducedValue">The claimed reduced value, canonical and below <paramref name="modulus"/>.</param>
    /// <param name="modulus">The modulus to reduce against; must satisfy <c>modulus &lt; p &lt; 2·modulus</c>.</param>
    /// <param name="bitCount">The number of bits the ripple-carry adder operates over.</param>
    /// <returns>The reduced-value wire, and its bits most-significant first.</returns>
    public (int Wire, WireWord BitsMostSignificantFirst) AddReduceModOrder(int valueWire, ReadOnlySpan<byte> reducedValue, ReadOnlySpan<byte> modulus, int bitCount = 256)
    {
        //quotient ∈ {0,1}: 1 iff value ≥ modulus (one subtraction suffices since the
        //value is below p < 2·modulus).
        bool quotientIsOne = CompareCanonical(Wires[valueWire].Span, modulus) >= 0;

        return AddReduceModOrderCore(valueWire, reducedValue, modulus, bitCount, quotientIsOne);
    }


    /// <summary>
    /// Builds the reduction binding with a chosen quotient bit — the witness a malicious
    /// prover would pick — so a test can check the integer identity's soundness against the
    /// mod-p alias, which needs the wrong quotient (the protocol-following path picks it from
    /// the value instead).
    /// </summary>
    /// <param name="valueWire">The wire holding the field element being reduced.</param>
    /// <param name="reducedValue">The claimed reduced value.</param>
    /// <param name="modulus">The modulus to reduce against.</param>
    /// <param name="quotient">The quotient bit to force into the binding, regardless of which one the value actually implies.</param>
    /// <param name="bitCount">The number of bits the ripple-carry adder operates over.</param>
    /// <returns>The reduced-value wire, and its bits most-significant first.</returns>
    internal (int Wire, WireWord BitsMostSignificantFirst) AddReduceModOrderWithQuotientForTesting(
        int valueWire, ReadOnlySpan<byte> reducedValue, ReadOnlySpan<byte> modulus, bool quotient, int bitCount = 256) =>
        AddReduceModOrderCore(valueWire, reducedValue, modulus, bitCount, quotient);


    /// <summary>Binds the reduced value through a boolean quotient and a carry-constrained integer sum.</summary>
    private (int Wire, WireWord BitsMostSignificantFirst) AddReduceModOrderCore(int valueWire, ReadOnlySpan<byte> reducedValue, ReadOnlySpan<byte> modulus, int bitCount, bool quotientIsOne)
    {
        int reducedWire = AddConstant(reducedValue);
        WireWord reducedBits = AddRangeBelow(reducedWire, modulus, bitCount);
        WireWord valueBits = AddCanonicalBits(valueWire, bitCount);

        Span<byte> scratch = stackalloc byte[ScalarSize];
        EncodeConstant(quotientIsOne ? 1u : 0u, scratch);
        int quotient = AddBit(scratch);

        //Ripple-carry addition reducedValue + quotient·modulus, asserting each column
        //equals value's bit with a carry, and the final carry is zero.
        int carryWire = AddConstant(Zero.Span);
        int carry = 0;
        for(int i = 0; i < bitCount; i++)
        {
            int reducedBit = BitOfConstant(reducedValue, i) ? 1 : 0;
            int modulusBit = BitOfConstant(modulus, i) ? 1 : 0;
            int columnSum = reducedBit + (quotientIsOne ? modulusBit : 0) + carry;
            int nextCarry = columnSum >> 1;

            int nextCarryWire;
            if(i == bitCount - 1)
            {
                //No carry past the top bit: pinning it to zero forbids an overflowing sum.
                nextCarryWire = AddConstant(Zero.Span);
            }
            else
            {
                EncodeConstant((uint)nextCarry, scratch);
                nextCarryWire = AddBit(scratch);
            }

            //reducedBits[i] + modulusBit·quotient + carry − valueBits[i] − 2·nextCarry = 0.
            LinearTerm[] terms;
            if(modulusBit == 1)
            {
                terms = [new LinearTerm(reducedBits[i], One), new LinearTerm(quotient, One), new LinearTerm(carryWire, One), new LinearTerm(valueBits[i], NegativeOne), new LinearTerm(nextCarryWire, NegativeTwo)];
            }
            else
            {
                terms = [new LinearTerm(reducedBits[i], One), new LinearTerm(carryWire, One), new LinearTerm(valueBits[i], NegativeOne), new LinearTerm(nextCarryWire, NegativeTwo)];
            }

            AddLinear(Zero.Span, terms);

            carryWire = nextCarryWire;
            carry = nextCarry;
        }

        WireWord mostSignificantFirst = ReverseInto(reducedBits);

        return (reducedWire, mostSignificantFirst);
    }


    /// <summary>Pins a wire to zero, asserting <c>W[wire] = 0</c> (for example a projective accumulator's <c>Z</c>, asserting it is <c>O</c>), and records it as the output.</summary>
    public void AddAssertZero(int wire)
    {
        AddLinear(Zero.Span, [new LinearTerm(wire, One)]);
        lastOutputWire = wire;
    }


    /// <summary>Records the wire a subsequent corruption test should perturb.</summary>
    /// <param name="wire">The wire index to record as the current output.</param>
    public void SetLastOutput(int wire) => lastOutputWire = wire;

    /// <summary>Perturbs the stored output so tests can reject an unsatisfied witness, corrupting the last output wire so it violates its defining constraint.</summary>
    public void CorruptLastOutputForTesting()
    {
        Span<byte> perturbed = stackalloc byte[ScalarSize];
        Add(Wires[lastOutputWire].Span, One.Span, perturbed, Curve);
        perturbed.CopyTo(Wires[lastOutputWire].Span);
    }


    /// <summary>
    /// Overwrites a wire's stored value so a malicious witness — one a protocol-following
    /// builder would never compute — can be fed to the prover or a constraint evaluator,
    /// exercising the soundness of the constraint system directly.
    /// </summary>
    /// <param name="wire">The wire index to overwrite.</param>
    /// <param name="value">The malicious value to store, copied verbatim without reduction.</param>
    internal void SetWireForTesting(int wire, ReadOnlySpan<byte> value)
    {
        Span<byte> stored = Wires[wire].Span;
        stored.Clear();
        value.CopyTo(stored);
    }


    /// <summary>Builds the immutable parameter summary — wire count, quadratic-constraint count, and the Ligero shape parameters — for <see cref="LigeroProver"/> and <see cref="LigeroVerifier"/> to consume.</summary>
    /// <returns>The parameters describing the accumulated constraint system.</returns>
    public LigeroParameters BuildParameters() => new(Wires.Count, Quadratics.Count, InverseRate, OpenedColumnCount, Block);

    /// <summary>Copies the current witness into an independently owned pooled buffer.</summary>
    /// <returns>The caller-disposed owner of exactly <see cref="WireCount"/> scalars, or <see langword="null"/> for an empty witness.</returns>
    public IMemoryOwner<byte>? WitnessBytes()
    {
        if(Wires.Count == 0)
        {
            return null;
        }

        int length = Wires.Count * ScalarSize;
        IMemoryOwner<byte>? owner = MemoryPool.Rent(length);
        try
        {
            Span<byte> bytes = owner.Memory.Span[..length];
            for(int i = 0; i < Wires.Count; i++)
            {
                Wires[i].Span.CopyTo(bytes.Slice(i * ScalarSize, ScalarSize));
            }

            IMemoryOwner<byte> result = owner;
            owner = null;

            return result;
        }
        finally
        {
            owner?.Dispose();
        }
    }


    /// <summary>Copies the current linear targets into an independently owned pooled buffer.</summary>
    /// <returns>The caller-disposed owner of exactly <see cref="LinearConstraintCount"/> scalars, or <see langword="null"/> for an empty target vector.</returns>
    public IMemoryOwner<byte>? TargetBytes()
    {
        if(Targets.Count == 0)
        {
            return null;
        }

        int length = Targets.Count * ScalarSize;
        IMemoryOwner<byte>? owner = MemoryPool.Rent(length);
        try
        {
            Span<byte> bytes = owner.Memory.Span[..length];
            for(int i = 0; i < Targets.Count; i++)
            {
                Targets[i].Span.CopyTo(bytes.Slice(i * ScalarSize, ScalarSize));
            }

            IMemoryOwner<byte> result = owner;
            owner = null;

            return result;
        }
        finally
        {
            owner?.Dispose();
        }
    }


    /// <summary>Materializes every accumulated linear-constraint term as an array.</summary>
    /// <returns>One <see cref="LigeroLinearConstraint"/> per term added through <see cref="AddLinear"/>.</returns>
    public LigeroLinearConstraint[] LinearConstraints()
    {
        var constraints = new LigeroLinearConstraint[LinearTerms.Count];
        for(int i = 0; i < LinearTerms.Count; i++)
        {
            constraints[i] = new LigeroLinearConstraint(LinearTerms[i].Constraint, LinearTerms[i].Wire, LinearTerms[i].Coefficient);
        }

        return constraints;
    }


    /// <summary>Materializes every accumulated quadratic constraint as an array.</summary>
    /// <returns>One <see cref="LigeroQuadraticConstraint"/> per constraint added through <see cref="AddQuadratic"/>.</returns>
    public LigeroQuadraticConstraint[] QuadraticConstraints() => [.. Quadratics];


    /// <summary>Writes bit number <paramref name="bitIndex"/> (0 = least significant) of a canonical big-endian value as a canonical <c>{0,1}</c> scalar.</summary>
    /// <param name="canonical">The canonical big-endian value to read the bit from.</param>
    /// <param name="bitIndex">The zero-based bit index, counting from the least significant bit.</param>
    /// <param name="destination">Receives the extracted bit as a canonical scalar.</param>
    private static void ExtractBit(ReadOnlySpan<byte> canonical, int bitIndex, Span<byte> destination)
    {
        destination.Clear();
        destination[ScalarSize - 1] = (byte)((canonical[ScalarSize - 1 - (bitIndex >> 3)] >> (bitIndex & 7)) & 1);
    }


    /// <summary>Reads bit number <paramref name="bitIndex"/> (0 = least significant) of a canonical big-endian constant.</summary>
    /// <param name="canonical">The canonical big-endian constant to read the bit from.</param>
    /// <param name="bitIndex">The zero-based bit index, counting from the least significant bit.</param>
    /// <returns><see langword="true"/> when the bit is set.</returns>
    private static bool BitOfConstant(ReadOnlySpan<byte> canonical, int bitIndex) =>
        ((canonical[ScalarSize - 1 - (bitIndex >> 3)] >> (bitIndex & 7)) & 1) != 0;


    /// <summary>Unsigned big-endian comparison of two canonical values: <c>-1</c> if <paramref name="a"/> &lt; <paramref name="b"/>, <c>0</c> if equal, <c>1</c> if <paramref name="a"/> &gt; <paramref name="b"/>.</summary>
    /// <param name="a">The first canonical value.</param>
    /// <param name="b">The second canonical value.</param>
    /// <returns>The comparison sign.</returns>
    private static int CompareCanonical(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        for(int i = 0; i < a.Length; i++)
        {
            if(a[i] != b[i])
            {
                return a[i] < b[i] ? -1 : 1;
            }
        }

        return 0;
    }


    /// <summary>Adds one to a canonical big-endian span in place (ripple carry), used once to derive the field modulus p from <c>p − 1</c>.</summary>
    /// <param name="canonical">The canonical big-endian value to increment in place.</param>
    private static void IncrementCanonical(Span<byte> canonical)
    {
        for(int i = canonical.Length - 1; i >= 0; i--)
        {
            if(canonical[i] != 0xFF)
            {
                canonical[i]++;

                return;
            }

            canonical[i] = 0;
        }
    }


    /// <summary>
    /// Extends both power caches with scalars owned until this builder is disposed, so
    /// that indices <c>[0, count)</c> are populated. Each power is twice the previous
    /// (<c>2^0 = 1</c>) as a canonical field element, computed once and reused across
    /// every recomposition instead of being rebuilt and negated per call.
    /// </summary>
    private void EnsurePowersOfTwo(int count)
    {
        while(PowerOfTwo.Count < count)
        {
            Memory<byte> power = RentScalar();
            power.Span.Clear();
            if(PowerOfTwo.Count == 0)
            {
                One.CopyTo(power);
            }
            else
            {
                Add(PowerOfTwo[^1].Span, PowerOfTwo[^1].Span, power.Span, Curve);
            }

            Memory<byte> negated = RentScalar();
            negated.Span.Clear();
            Negate(power.Span, negated.Span);
            PowerOfTwo.Add(power);
            NegativePowerOfTwo.Add(negated);
        }
    }


    /// <summary>Returns one scalar backed by a pinned slab owned by this builder, renting a fresh slab from the memory pool when the current one is exhausted.</summary>
    /// <remarks>
    /// Every handed-out scalar is fully overwritten by its caller before it is read, so no
    /// stale slab bytes leak into a wire, target, or coefficient; the accessor is internal
    /// so the gadgets rent their byte scratch and constants from this same arena instead of
    /// minting a naked <c>byte[]</c>. The arena is <see cref="AllocationKind.Pinned"/>: a
    /// witness scalar can hold a secret (the ECDSA nonce coordinates enter as wires), and
    /// pinning means the zeroize-on-return wipe lands on the exact bytes that held it, with
    /// no GC-relocation copy left behind. This matches how <see cref="LigeroProver"/>
    /// retains its secret witness; a witness-scale arena is too large for the native
    /// (locked) tier, so Pinned is the portable floor - pure managed, with an identical
    /// guarantee on every platform including WASM, needing no native backing.
    /// </remarks>
    internal Memory<byte> RentScalar()
    {
        if(Slabs.Count == 0 || slabOffset == ScalarsPerSlab)
        {
            IMemoryOwner<byte>? owner = MemoryPool.Rent(ScalarsPerSlab * ScalarSize, AllocationKind.Pinned);
            try
            {
                Memory<byte> memory = owner.Memory[..(ScalarsPerSlab * ScalarSize)];
                Slabs.Add(owner);
                owner = null;
                currentSlab = memory;
                slabOffset = 0;
            }
            finally
            {
                owner?.Dispose();
            }
        }

        Memory<byte> scalar = currentSlab.Slice(slabOffset * ScalarSize, ScalarSize);
        slabOffset++;

        return scalar;
    }


    /// <summary>
    /// Hands out a fixed-length wire word (<paramref name="count"/> wire indices) from the
    /// current pooled wire slab, renting a fresh slab when the current one cannot fit it. The
    /// returned <see cref="WireWord"/> reinterprets the bytes as ints; the builder owns the
    /// slab and the pool clears it on <see cref="Dispose"/>, so the word is valid for the whole
    /// circuit build and needs no separate disposal, replacing a naked <c>new int[]</c> wire
    /// array.
    /// </summary>
    /// <remarks>
    /// Unlike the scalar arena this stays <see cref="AllocationKind.Managed"/>: a wire word
    /// holds wire indices — public circuit structure, not secret values — so pinning would
    /// guard nothing here, and a circuit's index arenas run to megabytes that would
    /// needlessly pressure the non-compacting pinned-object heap. The reviewable rule is one
    /// line: scalars, which may hold secrets, are Pinned; indices, which are public structure,
    /// are Managed.
    /// </remarks>
    /// <param name="count">The number of wire indices the word holds.</param>
    /// <returns>A wire word of exactly <paramref name="count"/> indices, backed by pooled storage.</returns>
    internal WireWord RentWireWord(int count)
    {
        int byteCount = count * sizeof(int);
        if(WireSlabs.Count == 0 || wireSlabByteOffset + byteCount > currentWireSlab.Length)
        {
            int slabBytes = Math.Max(WireSlabBytes, byteCount);
            IMemoryOwner<byte> owner = MemoryPool.Rent(slabBytes);
            WireSlabs.Add(owner);
            currentWireSlab = owner.Memory[..slabBytes];
            wireSlabByteOffset = 0;
        }

        Memory<byte> backing = currentWireSlab.Slice(wireSlabByteOffset, byteCount);
        wireSlabByteOffset += byteCount;

        return new WireWord(backing, count);
    }


    /// <summary>Returns a fresh pooled wire word holding <paramref name="source"/> reversed (least-significant-first bits become most-significant-first for a double-and-add / Straus ladder), without minting a naked <c>int[]</c> clone.</summary>
    /// <param name="source">The wire word to reverse.</param>
    /// <returns>A freshly rented wire word holding the reversed indices.</returns>
    private WireWord ReverseInto(WireWord source)
    {
        WireWord reversed = RentWireWord(source.Length);
        for(int i = 0; i < source.Length; i++)
        {
            reversed[i] = source[source.Length - 1 - i];
        }

        return reversed;
    }


    /// <summary>Releases the wire, target, coefficient and constant-cache slabs to the pool.</summary>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        foreach(IMemoryOwner<byte> slab in Slabs)
        {
            slab.Dispose();
        }

        Slabs.Clear();

        foreach(IMemoryOwner<byte> wireSlab in WireSlabs)
        {
            wireSlab.Dispose();
        }

        WireSlabs.Clear();
        disposed = true;
    }
}
