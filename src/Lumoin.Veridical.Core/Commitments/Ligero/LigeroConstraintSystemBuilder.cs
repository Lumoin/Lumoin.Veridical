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
/// its witness. The wire-index arena (<see cref="RentWireWord"/>) and the fixed public
/// constant basis stay Managed: indices and coefficients are public circuit structure, never
/// a secret. Pinned is the portable floor (pure managed pinned-object-heap, identical on
/// every platform including WASM), so the guarantee needs no native backing.
/// </para>
/// </remarks>
internal sealed class LigeroConstraintSystemBuilder: IDisposable
{
    private const int ScalarSize = Scalar.SizeBytes;
    private const int ScalarsPerSlab = 512;

    //Wire-index words are byte-granular (count * sizeof(int)); a 64 KiB slab amortizes the many small
    //words a circuit build produces, parallel to the scalar arena.
    private const int WireSlabBytes = 64 * 1024;

    private readonly ScalarAddDelegate add;
    private readonly ScalarSubtractDelegate subtract;
    private readonly ScalarMultiplyDelegate multiply;
    private readonly ScalarInvertDelegate invert;
    private readonly ScalarReduceDelegate reduce;
    private readonly CurveParameterSet curve;
    private readonly int inverseRate;
    private readonly int openedColumnCount;
    private readonly int block;

    private readonly List<Memory<byte>> wires = [];
    private readonly List<(int Constraint, int Wire, Memory<byte> Coefficient)> linearTerms = [];
    private readonly List<Memory<byte>> targets = [];
    private readonly List<LigeroQuadraticConstraint> quadratics = [];

    private readonly BaseMemoryPool memoryPool;
    private readonly List<IMemoryOwner<byte>> slabs = [];
    private Memory<byte> currentSlab;
    private int slabOffset;

    private readonly List<IMemoryOwner<byte>> wireSlabs = [];
    private Memory<byte> currentWireSlab;
    private int wireSlabByteOffset;
    private bool disposed;

    private readonly byte[] zero = new byte[ScalarSize];
    private readonly byte[] one;
    private readonly byte[] modulus;

    //Repeated coefficient constants, derived once so the constraint-building hot paths
    //(bit decomposition, recomposition) reuse them instead of re-allocating per call.
    private readonly byte[] negativeOne;
    private readonly byte[] two;
    private readonly byte[] negativeTwo;

    //2^i and −2^i as canonical field elements, grown on demand and cached: the
    //recomposition constraint reuses them across every scalar instead of rebuilding the
    //table (and its negations) on each call.
    private readonly List<byte[]> powerOfTwo = [];
    private readonly List<byte[]> negativePowerOfTwo = [];

    private int lastOutputWire = -1;


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

        this.memoryPool = memoryPool;
        this.add = add;
        this.subtract = subtract;
        this.multiply = multiply;
        this.invert = invert;
        this.reduce = reduce;
        this.curve = curve;
        this.inverseRate = inverseRate;
        this.openedColumnCount = openedColumnCount;
        this.block = block;

        one = new byte[ScalarSize];
        EncodeConstant(1, one);

        negativeOne = new byte[ScalarSize];
        Negate(one, negativeOne);
        two = new byte[ScalarSize];
        EncodeConstant(2, two);
        negativeTwo = new byte[ScalarSize];
        Negate(two, negativeTwo);

        //The field modulus p, derived once from the delegates as (0 − 1) + 1, so the
        //canonical-bits gadget can pin a decomposition to the unique integer in [0, p)
        //without the caller having to supply p separately.
        modulus = new byte[ScalarSize];
        subtract(zero, one, modulus, curve);
        IncrementCanonical(modulus);
    }


    public int WireCount => wires.Count;

    public int LinearConstraintCount => targets.Count;

    public int QuadraticConstraintCount => quadratics.Count;

    public int LastOutputWire => lastOutputWire;


    //The canonical bytes backing a wire, for the gadget layer's value math. The
    //span aliases the builder's storage and must not be mutated.
    public ReadOnlySpan<byte> Value(int wire) => wires[wire].Span;


    //--- Field value helpers (delegate wrappers) used by the gadget layer ---

    public void AddValues(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result) => add(a, b, result, curve);

    public void SubtractValues(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result) => subtract(a, b, result, curve);

    public void MultiplyValues(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result) => multiply(a, b, result, curve);

    public void InvertValue(ReadOnlySpan<byte> a, Span<byte> result) => invert(a, result, curve);

    //−a = 0 − a (canonical); matches the reference field's Subtract semantics.
    public void Negate(ReadOnlySpan<byte> a, Span<byte> result) => subtract(zero, a, result, curve);

    //Encodes a small non-negative integer as a canonical big-endian scalar.
    public static void EncodeConstant(uint value, Span<byte> destination)
    {
        destination.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(destination[(ScalarSize - sizeof(uint))..], value);
    }


    //--- Constraint primitives ---

    //Allocates a wire holding the given value reduced into canonical form, backed by a
    //pooled arena scalar.
    public int AddWire(ReadOnlySpan<byte> value)
    {
        Memory<byte> stored = RentScalar();
        reduce(value, stored.Span, curve);
        wires.Add(stored);

        return wires.Count - 1;
    }


    //A wire pinned to the given value by a linear constraint, so a malicious
    //prover cannot substitute another value.
    public int AddConstant(ReadOnlySpan<byte> value)
    {
        int wire = AddWire(value);
        AddLinear(value, [new LinearTerm(wire, one)]);

        return wire;
    }


    //Adds the linear constraint Σ coefficient·W[wire] = target. Coefficients and
    //the target are reduced into canonical form and copied into builder-owned
    //storage, so callers may reuse their buffers.
    public void AddLinear(ReadOnlySpan<byte> target, LinearTerm[] terms)
    {
        ArgumentNullException.ThrowIfNull(terms);

        int constraint = targets.Count;
        Memory<byte> canonicalTarget = RentScalar();
        reduce(target, canonicalTarget.Span, curve);
        targets.Add(canonicalTarget);

        foreach(LinearTerm term in terms)
        {
            Memory<byte> coefficient = RentScalar();
            reduce(term.Coefficient.Span, coefficient.Span, curve);
            linearTerms.Add((constraint, term.Wire, coefficient));
        }
    }


    //Adds the quadratic constraint W[z] = W[x]·W[y].
    public void AddQuadratic(int x, int y, int z) => quadratics.Add(new LigeroQuadraticConstraint(x, y, z));


    //Allocates a product wire W[w] = W[x]·W[y] and emits its quadratic constraint.
    public int Multiply(int x, int y)
    {
        Span<byte> product = stackalloc byte[ScalarSize];
        multiply(wires[x].Span, wires[y].Span, product, curve);
        int w = AddWire(product);
        AddQuadratic(x, y, w);

        return w;
    }


    //Allocates a wire equal to Σ coefficient·W[wire] (value computed from the
    //terms — never a hand-supplied parallel value) and emits the defining linear
    //constraint w − Σ coefficient·W = 0.
    public int Combine(LinearTerm[] terms)
    {
        ArgumentNullException.ThrowIfNull(terms);

        Span<byte> accumulator = stackalloc byte[ScalarSize];
        Span<byte> product = stackalloc byte[ScalarSize];
        Span<byte> next = stackalloc byte[ScalarSize];
        accumulator.Clear();
        foreach(LinearTerm term in terms)
        {
            multiply(term.Coefficient.Span, wires[term.Wire].Span, product, curve);
            add(accumulator, product, next, curve);
            next.CopyTo(accumulator);
        }

        int w = AddWire(accumulator);

        var constraintTerms = new LinearTerm[terms.Length + 1];
        constraintTerms[0] = new LinearTerm(w, one);

        //An empty combination is the constant-zero wire (w = 0): no coefficients to negate, and a
        //zero-length pooled rent would throw — so emit its single defining term directly.
        if(terms.Length == 0)
        {
            AddLinear(zero, constraintTerms);

            return w;
        }

        //The negated coefficients are public constraint constants (never a witness value — the secret lives
        //in the wires they reference). They live only until AddLinear copies them into its own arena scalars,
        //so they are rented as one Managed block and returned (cleared) on scope exit — pooled, not
        //GC-reclaimed, but unpinned: there is no secret here to keep off a relocated heap block.
        using IMemoryOwner<byte> negatedOwner = memoryPool.Rent(terms.Length * ScalarSize);
        Memory<byte> negatedBlock = negatedOwner.Memory[..(terms.Length * ScalarSize)];
        for(int i = 0; i < terms.Length; i++)
        {
            Memory<byte> negated = negatedBlock.Slice(i * ScalarSize, ScalarSize);
            Negate(terms[i].Coefficient.Span, negated.Span);
            constraintTerms[i + 1] = new LinearTerm(terms[i].Wire, negated);
        }

        AddLinear(zero, constraintTerms);

        return w;
    }


    //Boolean constraint: pins W[b] to {0,1} via the quadratic identity b² = b.
    public int AddBit(ReadOnlySpan<byte> value)
    {
        int b = AddWire(value);
        int bSquared = Multiply(b, b);
        AddLinear(zero, [new LinearTerm(bSquared, one), new LinearTerm(b, negativeOne)]);

        return b;
    }


    //Scalar recomposition: a wire constrained to equal Σ bit_i·2^i (bits least-
    //significant first) by one linear constraint. The 2^i coefficients are reduced
    //mod the field; below the field order the residue equals the integer value.
    public int AddRecomposedScalar(ReadOnlySpan<int> bitsLeastSignificantFirst)
    {
        EnsurePowersOfTwo(bitsLeastSignificantFirst.Length);

        Span<byte> accumulator = stackalloc byte[ScalarSize];
        Span<byte> product = stackalloc byte[ScalarSize];
        Span<byte> next = stackalloc byte[ScalarSize];
        accumulator.Clear();
        for(int i = 0; i < bitsLeastSignificantFirst.Length; i++)
        {
            multiply(powerOfTwo[i], wires[bitsLeastSignificantFirst[i]].Span, product, curve);
            add(accumulator, product, next, curve);
            next.CopyTo(accumulator);
        }

        int w = AddWire(accumulator);

        var terms = new LinearTerm[bitsLeastSignificantFirst.Length + 1];
        terms[0] = new LinearTerm(w, one);
        for(int i = 0; i < bitsLeastSignificantFirst.Length; i++)
        {
            terms[i + 1] = new LinearTerm(bitsLeastSignificantFirst[i], negativePowerOfTwo[i]);
        }

        AddLinear(zero, terms);

        return w;
    }


    //Canonical bit-decomposition: the boolean low bits of the wire, tied to its
    //value, plus a lexicographic proof that they represent the unique integer in
    //[0, p). Over a field with p < 2^bitCount a value below 2^bitCount − p has two
    //bit patterns recomposing to the same residue (v and v + p); the < p chain pins
    //the canonical one, so a malicious non-canonical representative is rejected.
    //Returns the bits least-significant first.
    public WireWord AddCanonicalBits(int wire, int bitCount = 256)
    {
        WireWord bits = DecomposeAndBind(wire, bitCount);
        AddAssertLessThanConstant(bits, modulus);

        return bits;
    }


    //Proves W[wire] < limit for a constant limit ≤ p (canonical big-endian, itself
    //< 2^bitCount). Built on canonical bits — so the bits are the true integer, not
    //an aliased representative — then a second lexicographic chain against the
    //limit. Returns the canonical bits least-significant first.
    public WireWord AddRangeBelow(int wire, ReadOnlySpan<byte> limit, int bitCount = 256)
    {
        WireWord bits = AddCanonicalBits(wire, bitCount);
        AddAssertLessThanConstant(bits, limit);

        return bits;
    }


    //Proves a witnessed value is at least a public threshold: the difference
    //value − threshold lies in [0, 2^differenceBits). The bounded difference rejects
    //value < threshold — the difference wraps to a large field element no
    //differenceBits-wide decomposition can represent — and caps value at
    //threshold + 2^differenceBits (benign when the gap is small, e.g. an age over a
    //legal threshold). A small differenceBits needs no < p canonicity chain: the alias
    //difference + p exceeds 2^differenceBits, so the recomposition pins the difference.
    public void AddAtLeast(int valueWire, ReadOnlySpan<byte> threshold, int differenceBits)
    {
        Span<byte> difference = stackalloc byte[ScalarSize];
        SubtractValues(wires[valueWire].Span, threshold, difference);
        int differenceWire = AddWire(difference);

        //value − difference = threshold (threshold is the public, verifier-checked target).
        AddLinear(threshold, [new LinearTerm(valueWire, one), new LinearTerm(differenceWire, negativeOne)]);

        //difference ∈ [0, 2^differenceBits) by a bounded bit-decomposition.
        DecomposeAndBind(differenceWire, differenceBits);
    }


    //Bit-decomposes a wire into exactly bitCount low bits (least-significant first),
    //bound to the wire by recomposition. Sound for narrow widths with no canonicity
    //chain — the value + p alias exceeds 2^bitCount — so it serves the 32-bit word
    //arithmetic of the hash gadgets. A wire whose value is ≥ 2^bitCount is unprovable.
    public WireWord AddBits(int wire, int bitCount) => DecomposeAndBind(wire, bitCount);


    //Asserts the value Σ bit_i·2^i (bits least-significant first, each already pinned
    //to {0,1}) is strictly less than the constant. The comparison walks the literal
    //bits most-significant first against the constant's known bits with a running
    //prefix-equal flag: at a constant 1-bit the flag folds in the bit (a 0 there
    //decides less-than, a 1 keeps the prefix equal); at a constant 0-bit the bit must
    //be 0 while the prefix is still equal, else the value would exceed the constant at
    //the top differing position. Every gate is on {0,1} operands, so no sum that could
    //wrap mod p is ever formed — that is what makes the bound sound over Fp. The
    //constant must be < 2^bitCount.
    public void AddAssertLessThanConstant(ReadOnlySpan<int> bitsLeastSignificantFirst, ReadOnlySpan<byte> constant)
    {
        if(constant.Length != ScalarSize)
        {
            throw new ArgumentException($"Constant must be {ScalarSize} canonical bytes; received {constant.Length}.", nameof(constant));
        }

        //prefixEqual = "every bit above the current position equals the constant's".
        int prefixEqual = AddConstant(one);
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


    //Witnesses the wire's bitCount low bits (least-significant first), pins each to
    //{0,1}, and ties Σ bit_i·2^i to the wire by one linear constraint. NOT canonical
    //on its own (see AddCanonicalBits); the building block both it and the range
    //gadget compose from.
    private WireWord DecomposeAndBind(int wire, int bitCount)
    {
        WireWord bits = RentWireWord(bitCount);
        Span<byte> bitValue = stackalloc byte[ScalarSize];
        for(int i = 0; i < bitCount; i++)
        {
            ExtractBit(wires[wire].Span, i, bitValue);
            bits[i] = AddBit(bitValue);
        }

        int recomposed = AddRecomposedScalar(bits);
        AddLinear(zero, [new LinearTerm(recomposed, one), new LinearTerm(wire, negativeOne)]);

        return bits;
    }


    //Asserts W[wire] ≠ 0 by witnessing its inverse and pinning the product to 1: a
    //zero wire has no inverse (the honest prover cannot build the witness) and no
    //witness satisfies wire·inv = 1, so a zero value is rejected either way.
    public void AddNonzeroCheck(int wire)
    {
        Span<byte> inverse = stackalloc byte[ScalarSize];
        InvertValue(wires[wire].Span, inverse);
        int inv = AddWire(inverse);
        int product = Multiply(wire, inv);
        AddLinear(one, [new LinearTerm(product, one)]);
    }


    //Pins a public scalar, proves it is canonical and < limit, and returns its bits
    //MOST-significant first for a double-and-add / Straus ladder. Because the bits are
    //canonical, the integer the ladder consumes is exactly the pinned public scalar —
    //a non-canonical representative (scalar + p) cannot be substituted to change the
    //scalar the curve operation sees.
    public (int Wire, WireWord BitsMostSignificantFirst) AddPublicScalarBits(ReadOnlySpan<byte> scalar, ReadOnlySpan<byte> limit, int bitCount = 256)
    {
        int wire = AddConstant(scalar);
        WireWord leastSignificantFirst = AddRangeBelow(wire, limit, bitCount);
        WireWord mostSignificantFirst = ReverseInto(leastSignificantFirst);

        return (wire, mostSignificantFirst);
    }


    //Binds a public reducedValue to (W[valueWire] mod modulus), where valueWire holds a
    //field element in [0, p) and modulus satisfies modulus < p < 2·modulus (so the
    //quotient is a single bit). Proves the INTEGER identity
    //value = quotient·modulus + reducedValue with a bit-serial ripple-carry adder whose
    //every term is in {0,1,2,3} — never a sum that could wrap mod p — and a pinned
    //zero carry-out. This is what rejects the mod-p alias reducedValue + p − modulus,
    //which satisfies a naive field tie (it differs from the true value by exactly p).
    //reducedValue is range-checked canonical and < modulus and returned most-
    //significant first for reuse as the ladder scalar.
    public (int Wire, WireWord BitsMostSignificantFirst) AddReduceModOrder(int valueWire, ReadOnlySpan<byte> reducedValue, ReadOnlySpan<byte> modulus, int bitCount = 256)
    {
        //quotient ∈ {0,1}: 1 iff value ≥ modulus (one subtraction suffices since the
        //value is below p < 2·modulus).
        bool quotientIsOne = CompareCanonical(wires[valueWire].Span, modulus) >= 0;

        return AddReduceModOrderCore(valueWire, reducedValue, modulus, bitCount, quotientIsOne);
    }


    //Test-only: build the binding with a CHOSEN quotient bit — the witness a malicious
    //prover would pick — so the integer identity's soundness can be checked against the
    //mod-p alias, which needs the wrong quotient (the honest path picks it from value).
    internal (int Wire, WireWord BitsMostSignificantFirst) AddReduceModOrderWithQuotientForTesting(
        int valueWire, ReadOnlySpan<byte> reducedValue, ReadOnlySpan<byte> modulus, bool quotient, int bitCount = 256) =>
        AddReduceModOrderCore(valueWire, reducedValue, modulus, bitCount, quotient);


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
        int carryWire = AddConstant(zero);
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
                nextCarryWire = AddConstant(zero);
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
                terms = [new LinearTerm(reducedBits[i], one), new LinearTerm(quotient, one), new LinearTerm(carryWire, one), new LinearTerm(valueBits[i], negativeOne), new LinearTerm(nextCarryWire, negativeTwo)];
            }
            else
            {
                terms = [new LinearTerm(reducedBits[i], one), new LinearTerm(carryWire, one), new LinearTerm(valueBits[i], negativeOne), new LinearTerm(nextCarryWire, negativeTwo)];
            }

            AddLinear(zero, terms);

            carryWire = nextCarryWire;
            carry = nextCarry;
        }

        WireWord mostSignificantFirst = ReverseInto(reducedBits);

        return (reducedWire, mostSignificantFirst);
    }


    //Asserts W[wire] = 0 (e.g. a projective accumulator's Z, asserting it is O).
    public void AddAssertZero(int wire)
    {
        AddLinear(zero, [new LinearTerm(wire, one)]);
        lastOutputWire = wire;
    }


    //Records the wire a subsequent corruption test should perturb.
    public void SetLastOutput(int wire) => lastOutputWire = wire;

    //Corrupts the last output wire so its defining constraint no longer holds.
    public void CorruptLastOutputForTesting()
    {
        Span<byte> perturbed = stackalloc byte[ScalarSize];
        add(wires[lastOutputWire].Span, one, perturbed, curve);
        perturbed.CopyTo(wires[lastOutputWire].Span);
    }


    //Overwrites a wire's stored value (test-only) so a malicious witness — one the
    //honest builder would never compute — can be fed to the prover or a constraint
    //evaluator, exercising the soundness of the constraint system directly.
    internal void SetWireForTesting(int wire, ReadOnlySpan<byte> value)
    {
        Span<byte> stored = wires[wire].Span;
        stored.Clear();
        value.CopyTo(stored);
    }


    //--- Output for LigeroProver / LigeroVerifier ---

    public LigeroParameters BuildParameters() => new(wires.Count, quadratics.Count, inverseRate, openedColumnCount, block);

    public byte[] WitnessBytes()
    {
        byte[] bytes = new byte[wires.Count * ScalarSize];
        for(int i = 0; i < wires.Count; i++)
        {
            wires[i].Span.CopyTo(bytes.AsSpan(i * ScalarSize, ScalarSize));
        }

        return bytes;
    }


    public byte[] TargetBytes()
    {
        byte[] bytes = new byte[targets.Count * ScalarSize];
        for(int i = 0; i < targets.Count; i++)
        {
            targets[i].Span.CopyTo(bytes.AsSpan(i * ScalarSize, ScalarSize));
        }

        return bytes;
    }


    public LigeroLinearConstraint[] LinearConstraints()
    {
        var constraints = new LigeroLinearConstraint[linearTerms.Count];
        for(int i = 0; i < linearTerms.Count; i++)
        {
            constraints[i] = new LigeroLinearConstraint(linearTerms[i].Constraint, linearTerms[i].Wire, linearTerms[i].Coefficient);
        }

        return constraints;
    }


    public LigeroQuadraticConstraint[] QuadraticConstraints() => [.. quadratics];


    //Writes bit number bitIndex (0 = least significant) of a canonical big-endian
    //value as a canonical {0,1} scalar.
    private static void ExtractBit(ReadOnlySpan<byte> canonical, int bitIndex, Span<byte> destination)
    {
        destination.Clear();
        destination[ScalarSize - 1] = (byte)((canonical[ScalarSize - 1 - (bitIndex >> 3)] >> (bitIndex & 7)) & 1);
    }


    //Bit number bitIndex (0 = least significant) of a canonical big-endian constant.
    private static bool BitOfConstant(ReadOnlySpan<byte> canonical, int bitIndex) =>
        ((canonical[ScalarSize - 1 - (bitIndex >> 3)] >> (bitIndex & 7)) & 1) != 0;


    //Unsigned big-endian comparison of two canonical values: −1 if a < b, 0 if equal,
    //1 if a > b.
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


    //value + 1 over a canonical big-endian span (ripple carry), used once to derive
    //the field modulus p from p − 1.
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


    //Grows the cached 2^i and −2^i tables so indices [0, count) are populated. Each power
    //is twice the previous (2^0 = 1) as a canonical field element, computed once and reused
    //across every recomposition instead of being rebuilt and negated per call.
    private void EnsurePowersOfTwo(int count)
    {
        while(powerOfTwo.Count < count)
        {
            byte[] power = new byte[ScalarSize];
            if(powerOfTwo.Count == 0)
            {
                one.CopyTo(power);
            }
            else
            {
                add(powerOfTwo[^1], powerOfTwo[^1], power, curve);
            }

            byte[] negated = new byte[ScalarSize];
            Negate(power, negated);
            powerOfTwo.Add(power);
            negativePowerOfTwo.Add(negated);
        }
    }


    //Hands out one scalar (ScalarSize bytes) from the current pooled arena slab, renting
    //a fresh slab from the memory pool when the current one is exhausted. Every handed-out
    //scalar is fully overwritten by its caller before it is read, so no stale slab bytes
    //leak into a wire, target, or coefficient. Internal so the gadgets rent their byte
    //scratch and constants from the same arena instead of minting naked byte[].
    //
    //The arena is Pinned (pinned-object-heap): a witness scalar can hold a secret (the ECDSA
    //nonce coordinates enter as wires), and pinning means the zeroize-on-return wipe lands on
    //the exact bytes that held it, with no GC-relocation copy left behind. This matches how
    //LigeroProver retains its secret witness; a witness-scale arena is too large for the
    //native (locked) tier, so Pinned is the portable floor — pure managed, identical guarantee
    //on every platform including WASM, no native backing required.
    internal Memory<byte> RentScalar()
    {
        if(slabs.Count == 0 || slabOffset == ScalarsPerSlab)
        {
            IMemoryOwner<byte> owner = memoryPool.Rent(ScalarsPerSlab * ScalarSize, AllocationKind.Pinned);
            slabs.Add(owner);
            currentSlab = owner.Memory[..(ScalarsPerSlab * ScalarSize)];
            slabOffset = 0;
        }

        Memory<byte> scalar = currentSlab.Slice(slabOffset * ScalarSize, ScalarSize);
        slabOffset++;

        return scalar;
    }


    //Hands out a fixed-length wire word (count wire indices) from the current pooled wire slab, renting a
    //fresh slab when the current one cannot fit it. The returned WireWord reinterprets the bytes as ints;
    //the builder owns the slab and the pool clears it on Dispose, so the word is valid for the whole
    //circuit build and needs no separate disposal — replacing the gadgets' naked new int[] wire arrays.
    //
    //Unlike the scalar arena this stays Managed: a wire word holds wire INDICES — public circuit structure,
    //not secret values — so there is nothing to pin against a dump, and a circuit's index arenas run to
    //megabytes that would needlessly pressure the (non-compacting) pinned-object-heap. The reviewable rule
    //is one line: scalars (may hold secrets) are Pinned, indices (public structure) are Managed.
    internal WireWord RentWireWord(int count)
    {
        int byteCount = count * sizeof(int);
        if(wireSlabs.Count == 0 || wireSlabByteOffset + byteCount > currentWireSlab.Length)
        {
            int slabBytes = Math.Max(WireSlabBytes, byteCount);
            IMemoryOwner<byte> owner = memoryPool.Rent(slabBytes);
            wireSlabs.Add(owner);
            currentWireSlab = owner.Memory[..slabBytes];
            wireSlabByteOffset = 0;
        }

        Memory<byte> backing = currentWireSlab.Slice(wireSlabByteOffset, byteCount);
        wireSlabByteOffset += byteCount;

        return new WireWord(backing, count);
    }


    //A fresh pooled wire word holding source reversed (least-significant-first bits become most-significant
    //first for a double-and-add / Straus ladder), without minting a naked int[] clone.
    private WireWord ReverseInto(WireWord source)
    {
        WireWord reversed = RentWireWord(source.Length);
        for(int i = 0; i < source.Length; i++)
        {
            reversed[i] = source[source.Length - 1 - i];
        }

        return reversed;
    }


    //Returns the arena slabs to the pool, which zeroes them.
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        foreach(IMemoryOwner<byte> slab in slabs)
        {
            slab.Dispose();
        }

        slabs.Clear();

        foreach(IMemoryOwner<byte> wireSlab in wireSlabs)
        {
            wireSlab.Dispose();
        }

        wireSlabs.Clear();
        disposed = true;
    }
}
