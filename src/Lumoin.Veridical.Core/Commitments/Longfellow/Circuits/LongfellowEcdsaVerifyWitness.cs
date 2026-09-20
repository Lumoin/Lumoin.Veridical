using System;
using System.Buffers;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// Computes the advice column for one in-circuit ECDSA verification, a faithful port of
/// google/longfellow-zk's <c>VerifyWitness3&lt;EC, ScalarField&gt;</c>
/// (<c>circuits/ecdsa/verify_witness.h</c>): given the public key and the signature triple
/// <c>(e, r, s)</c> it recovers the signature point <c>R = (e/s)·G + (r/s)·Q</c>, builds the
/// four-entry precomputed sum table, walks the triple-scalar identity
/// <c>id = g·e + pk·r + R·(−s)</c> recording the packed advice digits and every unnormalized
/// projective intermediate, and emits the whole column in the exact order
/// <see cref="LongfellowEcdsaVerifyWitnessWires.Input"/> declares wires in.
/// </summary>
/// <remarks>
/// <para>
/// All arithmetic runs in the canonical domain over injected delegates: the base field through the
/// gadget layer's <see cref="LongfellowLogicFieldOperations"/> bundle, the order field through
/// canonical-in/out scalar delegates. The reference's Montgomery round-trips collapse away in this
/// domain; the emitted values are byte-for-byte the reference's <c>to_bytes_field</c> outputs. The
/// point arithmetic is the same Renes–Costello–Batina complete addition and doubling the circuit
/// emits, so the recorded intermediates match the circuit's computation exactly, unnormalized z
/// coordinates included.
/// </para>
/// <para>
/// Witness generation is variable-time, as the reference's is: it runs prover-side over the
/// prover's own credential. Inversion follows the Fermat convention that zero maps to zero (the
/// reference leaves the corresponding certificate at zero and lets the final identity check reject),
/// so a malformed signature makes <see cref="ComputeWitness"/> return <see langword="false"/> or
/// yields an unsatisfiable column rather than throwing.
/// </para>
/// </remarks>
internal sealed class LongfellowEcdsaVerifyWitness: IDisposable
{
    /// <summary>The packed digit's plucker-point domain: three exponent bits index an eight-entry table.</summary>
    private const int DigitTableLength = 8;

    /// <summary>The pretable workspace holds generator x/y, public-key x/y, and their shared affine z coordinate.</summary>
    private const int PreTableWorkspaceElements = 5;

    /// <summary>A projective point holds three scalar coordinates, x, y and z.</summary>
    private const int PointBytes = 3 * Scalar.SizeBytes;

    /// <summary>Addition needs six temporaries, three result coordinates and one nonoverlapping field-operation result.</summary>
    private const int ArithmeticWorkspaceElements = 10;

    /// <summary>The digit table and three recovery points share a fixed workspace with the arithmetic scratch.</summary>
    private const int WorkspaceBytes = ((DigitTableLength + 3) * PointBytes) + (ArithmeticWorkspaceElements * Scalar.SizeBytes);

    /// <summary>The borrowed base-field bundle and originating pool, kept alive until this generator is disposed.</summary>
    private LongfellowLogicFieldOperations Field { get; }
    /// <summary>The order-field multiplication delegate, canonical in and out.</summary>
    private ScalarMultiplyDelegate OrderMultiply { get; }
    /// <summary>The order-field subtraction delegate, canonical in and out.</summary>
    private ScalarSubtractDelegate OrderSubtract { get; }
    /// <summary>The order-field inversion delegate, canonical in and out.</summary>
    private ScalarInvertDelegate OrderInvert { get; }
    /// <summary>The curve parameter set the order-field delegates dispatch on.</summary>
    private CurveParameterSet OrderCurve { get; }
    /// <summary>The curve constants borrowed until this generator is disposed.</summary>
    private LongfellowEllipticCurveParameters Curve { get; }

    /// <summary>Owns every retained scalar and table through the field's caller pool.</summary>
    private LongfellowCircuitStorage Storage { get; }

    /// <summary>The canonical base prime, borrowed from storage.</summary>
    private Memory<byte> BasePrime { get; }

    /// <summary>The copied curve coefficient, borrowed from storage.</summary>
    private Memory<byte> CurveA { get; }

    /// <summary>The copied tripled curve coefficient, borrowed from storage.</summary>
    private Memory<byte> CurveBTimes3 { get; }

    /// <summary>The recovered signature point's x coordinate, borrowed from storage.</summary>
    private Memory<byte> Rx { get; }

    /// <summary>The recovered signature point's y coordinate, borrowed from storage.</summary>
    private Memory<byte> Ry { get; }

    /// <summary>The signature x-coordinate inverse, borrowed from storage.</summary>
    private Memory<byte> RxInverse { get; }

    /// <summary>The cross-field signature inverse, borrowed from storage.</summary>
    private Memory<byte> SInverse { get; }

    /// <summary>The public key x-coordinate inverse, borrowed from storage.</summary>
    private Memory<byte> PkInverse { get; }

    /// <summary>The flattened sum-table coordinates, borrowed from storage.</summary>
    private Memory<byte> Pre { get; }

    /// <summary>The flattened packed digits, borrowed from storage.</summary>
    private Memory<byte> Bi { get; }

    /// <summary>The flattened intermediate x coordinates, borrowed from storage.</summary>
    private Memory<byte> IntX { get; }

    /// <summary>The flattened intermediate y coordinates, borrowed from storage.</summary>
    private Memory<byte> IntY { get; }

    /// <summary>The flattened intermediate z coordinates, borrowed from storage.</summary>
    private Memory<byte> IntZ { get; }

    /// <summary>The column length in elements: the five scalars, the sum table, and per scalar bit the digit plus (all but the last step) the intermediate triple.</summary>
    public int ElementCount { get; }


    /// <summary>
    /// Constructs the generator over a base-field bundle, the order-field delegates, and the curve.
    /// </summary>
    /// <param name="field">The borrowed base-field bundle and originating pool, both kept alive until this generator is disposed.</param>
    /// <param name="orderMultiply">The order-field multiplication, canonical in and out.</param>
    /// <param name="orderSubtract">The order-field subtraction, canonical in and out.</param>
    /// <param name="orderInvert">The order-field inversion, canonical in and out.</param>
    /// <param name="orderCurve">The curve parameter set the order-field delegates dispatch on.</param>
    /// <param name="curve">The curve constants borrowed until this generator is disposed.</param>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    public LongfellowEcdsaVerifyWitness(
        LongfellowLogicFieldOperations field,
        ScalarMultiplyDelegate orderMultiply,
        ScalarSubtractDelegate orderSubtract,
        ScalarInvertDelegate orderInvert,
        CurveParameterSet orderCurve,
        LongfellowEllipticCurveParameters curve)
    {
        ArgumentNullException.ThrowIfNull(field);
        ArgumentNullException.ThrowIfNull(orderMultiply);
        ArgumentNullException.ThrowIfNull(orderSubtract);
        ArgumentNullException.ThrowIfNull(orderInvert);
        ArgumentNullException.ThrowIfNull(curve);

        this.Field = field;
        this.OrderMultiply = orderMultiply;
        this.OrderSubtract = orderSubtract;
        this.OrderInvert = orderInvert;
        this.OrderCurve = orderCurve;
        this.Curve = curve;
        Storage = new LongfellowCircuitStorage(field.Pool);
        try
        {
            CurveA = Storage.Copy(curve.A.Span);
            CurveBTimes3 = Storage.Copy(curve.BTimes3.Span);
            BasePrime = Storage.Allocate(Scalar.SizeBytes);
            DeriveBasePrime(field, BasePrime.Span);

            int bits = curve.ScalarBitCount;
            ElementCount = 5 + LongfellowEcdsaVerifyWitnessWires.PreTableLength + bits + (3 * (bits - 1));

            Rx = Storage.Allocate(Scalar.SizeBytes);
            Ry = Storage.Allocate(Scalar.SizeBytes);
            RxInverse = Storage.Allocate(Scalar.SizeBytes);
            SInverse = Storage.Allocate(Scalar.SizeBytes);
            PkInverse = Storage.Allocate(Scalar.SizeBytes);
            Pre = NewElementArray(LongfellowEcdsaVerifyWitnessWires.PreTableLength);
            Bi = NewElementArray(bits);
            IntX = NewElementArray(bits);
            IntY = NewElementArray(bits);
            IntZ = NewElementArray(bits);
        }
        catch
        {
            Storage.Dispose();
            throw;
        }
    }


    /// <summary>
    /// The reference's <c>compute_witness</c>: fills the advice for the signature triple, returning
    /// whether the triple-scalar walk terminated at the identity — the witness-side signature
    /// verification itself.
    /// </summary>
    /// <param name="pkX">The public key's x coordinate, canonical big-endian.</param>
    /// <param name="pkY">The public key's y coordinate, canonical big-endian.</param>
    /// <param name="e">The digest as a raw 256-bit big-endian value.</param>
    /// <param name="r">The signature's <c>r</c> as a raw 256-bit big-endian value.</param>
    /// <param name="s">The signature's <c>s</c> as a raw 256-bit big-endian value.</param>
    /// <returns>Whether the signature verified.</returns>
    /// <remarks>All transient points borrow a bounded rental disposed on every exit; only witness coordinates are copied into retained storage.</remarks>
    /// <exception cref="ArgumentException">When an input is not exactly <see cref="Scalar.SizeBytes"/> bytes.</exception>
    public bool ComputeWitness(ReadOnlySpan<byte> pkX, ReadOnlySpan<byte> pkY, ReadOnlySpan<byte> e, ReadOnlySpan<byte> r, ReadOnlySpan<byte> s)
    {
        if(pkX.Length != Scalar.SizeBytes || pkY.Length != Scalar.SizeBytes || e.Length != Scalar.SizeBytes
            || r.Length != Scalar.SizeBytes || s.Length != Scalar.SizeBytes)
        {
            throw new ArgumentException($"Witness inputs are canonical {Scalar.SizeBytes}-byte scalars.");
        }

        //Order-field copies of the raw inputs; the digit stream below keeps using the raw e and r
        //bits, exactly as the reference walks the unreduced naturals.
        Span<byte> eOrder = stackalloc byte[Scalar.SizeBytes];
        Span<byte> rOrder = stackalloc byte[Scalar.SizeBytes];
        Span<byte> sOrder = stackalloc byte[Scalar.SizeBytes];
        CanonicalScalarReduction.ReduceOnce(e, Curve.Order.Span, eOrder);
        CanonicalScalarReduction.ReduceOnce(r, Curve.Order.Span, rOrder);
        CanonicalScalarReduction.ReduceOnce(s, Curve.Order.Span, sOrder);

        //u1 = e/s and u2 = r/s in the order field; a zero s yields zero quotients under the
        //Fermat zero-maps-to-zero convention and the walk below rejects.
        Span<byte> sQuotient = stackalloc byte[Scalar.SizeBytes];
        InvertOrder(sOrder, sQuotient);
        Span<byte> u1 = stackalloc byte[Scalar.SizeBytes];
        Span<byte> u2 = stackalloc byte[Scalar.SizeBytes];
        OrderMultiply(eOrder, sQuotient, u1, OrderCurve);
        OrderMultiply(rOrder, sQuotient, u2, OrderCurve);

        //Recover R = u1·G + u2·Q; the base field has no square root here, exactly the reference's
        //reason for recomputing R instead of decompressing it from r.
        using IMemoryOwner<byte> owner = Field.Pool.Rent(WorkspaceBytes);
        Span<byte> buffer = owner.Memory.Span[..WorkspaceBytes];
        Span<byte> digitTable = buffer[..(DigitTableLength * PointBytes)];
        var generatorTerm = new ProjectivePoint(buffer.Slice(DigitTableLength * PointBytes, PointBytes));
        var keyTerm = new ProjectivePoint(buffer.Slice((DigitTableLength + 1) * PointBytes, PointBytes));
        var recovered = new ProjectivePoint(buffer.Slice((DigitTableLength + 2) * PointBytes, PointBytes));
        Span<byte> scratch = buffer[((DigitTableLength + 3) * PointBytes)..];
        ScalarMultiplyPoint(Curve.GeneratorX.Span, Curve.GeneratorY.Span, u1, generatorTerm, scratch);
        ScalarMultiplyPoint(pkX, pkY, u2, keyTerm, scratch);
        AddPoints(generatorTerm.Input, keyTerm.Input, recovered, scratch);
        Normalize(recovered, scratch);

        //rx is the signature scalar r read in the base field; ry is the recovered point's y.
        CanonicalScalarReduction.ReduceOnce(r, BasePrime.Span, Rx.Span);
        recovered.Y.CopyTo(Ry.Span);

        RxInverse.Span.Clear();
        if(!LongfellowCompilerFieldOperations.ElementIsZero(Rx.Span))
        {
            Field.Invert(Rx.Span, RxInverse.Span, Field.Compiler.Curve);
        }

        //The certificate for s is the BASE-field inverse of −s's canonical order-field value, the
        //reference's cross-field reinterpretation.
        Span<byte> negatedS = stackalloc byte[Scalar.SizeBytes];
        Span<byte> zeroOrder = stackalloc byte[Scalar.SizeBytes];
        OrderSubtract(zeroOrder, sOrder, negatedS, OrderCurve);
        SInverse.Span.Clear();
        if(!LongfellowCompilerFieldOperations.ElementIsZero(negatedS))
        {
            Field.Invert(negatedS, SInverse.Span, Field.Compiler.Curve);
        }

        PkInverse.Span.Clear();
        if(!LongfellowCompilerFieldOperations.ElementIsZero(pkX))
        {
            Field.Invert(pkX, PkInverse.Span, Field.Compiler.Curve);
        }

        FillPreTable(pkX, pkY, recovered, scratch);

        //Walk the triple-scalar identity from the identity point, recording digits and the
        //unnormalized intermediates the circuit re-anchors on.
        BuildDigitTable(pkX, pkY, digitTable);
        ProjectivePoint accumulator = generatorTerm;
        Identity(accumulator);
        int bits = Curve.ScalarBitCount;
        for(int i = 0; i < bits; i++)
        {
            int bitIndex = bits - i - 1;
            int digit = BitAt(e, bitIndex) + (2 * BitAt(r, bitIndex)) + (4 * BitAt(negatedS, bitIndex));

            LongfellowBitPlucker.PluckerPoint(Field, DigitTableLength, digit, Bi.Slice(i * Scalar.SizeBytes, Scalar.SizeBytes).Span);

            if(i > 0)
            {
                DoublePoint(accumulator.Input, accumulator, scratch);
            }

            var addend = new ProjectivePoint(digitTable.Slice(digit * PointBytes, PointBytes));
            AddPoints(accumulator.Input, addend.Input, accumulator, scratch);

            accumulator.X.CopyTo(IntX.Slice(i * Scalar.SizeBytes, Scalar.SizeBytes).Span);
            accumulator.Y.CopyTo(IntY.Slice(i * Scalar.SizeBytes, Scalar.SizeBytes).Span);
            accumulator.Z.CopyTo(IntZ.Slice(i * Scalar.SizeBytes, Scalar.SizeBytes).Span);
        }

        return LongfellowCompilerFieldOperations.ElementIsZero(accumulator.X)
            && LongfellowCompilerFieldOperations.ElementIsZero(accumulator.Z);
    }


    /// <summary>
    /// The reference's <c>fill_witness</c>: writes the column in declaration order — the five
    /// scalars, the sum table, then per scalar bit the digit followed by (all but the last step)
    /// the intermediate triple — as contiguous canonical elements.
    /// </summary>
    /// <param name="destination">Receives <see cref="ElementCount"/> elements of <see cref="Scalar.SizeBytes"/> bytes each.</param>
    /// <exception cref="ArgumentException">When <paramref name="destination"/> is not exactly the column's byte length.</exception>
    public void FillWitness(Span<byte> destination)
    {
        if(destination.Length != ElementCount * Scalar.SizeBytes)
        {
            throw new ArgumentException($"The column is exactly {ElementCount} elements of {Scalar.SizeBytes} bytes.", nameof(destination));
        }

        int cursor = 0;
        WriteElement(destination, ref cursor, Rx.Span);
        WriteElement(destination, ref cursor, Ry.Span);
        WriteElement(destination, ref cursor, RxInverse.Span);
        WriteElement(destination, ref cursor, SInverse.Span);
        WriteElement(destination, ref cursor, PkInverse.Span);
        for(int i = 0; i < Pre.Length / Scalar.SizeBytes; i++)
        {
            WriteElement(destination, ref cursor, Pre.Slice(i * Scalar.SizeBytes, Scalar.SizeBytes).Span);
        }

        int bits = Curve.ScalarBitCount;
        for(int i = 0; i < bits; i++)
        {
            WriteElement(destination, ref cursor, Bi.Slice(i * Scalar.SizeBytes, Scalar.SizeBytes).Span);
            if(i < bits - 1)
            {
                WriteElement(destination, ref cursor, IntX.Slice(i * Scalar.SizeBytes, Scalar.SizeBytes).Span);
                WriteElement(destination, ref cursor, IntY.Slice(i * Scalar.SizeBytes, Scalar.SizeBytes).Span);
                WriteElement(destination, ref cursor, IntZ.Slice(i * Scalar.SizeBytes, Scalar.SizeBytes).Span);
            }
        }
    }


    /// <summary>
    /// The reference's sum-table construction: <c>g+pk</c>, <c>g+r</c>, <c>r+pk</c> from the
    /// left-hand/right-hand coordinate sequences, each normalized by its z coordinate when nonzero,
    /// then <c>g+r+pk</c> from the normalized <c>g+r</c> entry.
    /// </summary>
    /// <remarks>Point inputs borrow one scope-bound workspace rental; normalized results are written into the witness's retained table.</remarks>
    /// <param name="pkX">The public key's x coordinate.</param>
    /// <param name="pkY">The public key's y coordinate.</param>
    /// <param name="sum">Receives each sum in caller-owned storage disjoint from the inputs and retained table.</param>
    /// <param name="scratch">The arithmetic workspace, disjoint from all point coordinates.</param>
    private void FillPreTable(ReadOnlySpan<byte> pkX, ReadOnlySpan<byte> pkY, ProjectivePoint sum, Span<byte> scratch)
    {
        using IMemoryOwner<byte> owner = Field.Pool.Rent(PreTableWorkspaceElements * Scalar.SizeBytes);
        Span<byte> buffer = owner.Memory.Span[..(PreTableWorkspaceElements * Scalar.SizeBytes)];
        buffer.Clear();
        Span<byte> generatorX = buffer.Slice(0 * Scalar.SizeBytes, Scalar.SizeBytes);
        Span<byte> generatorY = buffer.Slice(1 * Scalar.SizeBytes, Scalar.SizeBytes);
        Span<byte> keyX = buffer.Slice(2 * Scalar.SizeBytes, Scalar.SizeBytes);
        Span<byte> keyY = buffer.Slice(3 * Scalar.SizeBytes, Scalar.SizeBytes);
        Span<byte> one = buffer.Slice(4 * Scalar.SizeBytes, Scalar.SizeBytes);
        Field.Compiler.One.Span.CopyTo(one);
        Curve.GeneratorX.Span.CopyTo(generatorX);
        Curve.GeneratorY.Span.CopyTo(generatorY);
        pkX.CopyTo(keyX);
        pkY.CopyTo(keyY);

        var generator = new ProjectivePointInput(generatorX, generatorY, one);
        var key = new ProjectivePointInput(keyX, keyY, one);
        var signature = new ProjectivePointInput(Rx.Span, Ry.Span, one);

        AddPoints(generator, key, sum, scratch);
        NormalizeIntoPair(sum.Input, Pre.Slice(0 * Scalar.SizeBytes, Scalar.SizeBytes).Span, Pre.Slice(1 * Scalar.SizeBytes, Scalar.SizeBytes).Span);
        AddPoints(generator, signature, sum, scratch);
        NormalizeIntoPair(sum.Input, Pre.Slice(2 * Scalar.SizeBytes, Scalar.SizeBytes).Span, Pre.Slice(3 * Scalar.SizeBytes, Scalar.SizeBytes).Span);
        AddPoints(key, signature, sum, scratch);
        NormalizeIntoPair(sum.Input, Pre.Slice(4 * Scalar.SizeBytes, Scalar.SizeBytes).Span, Pre.Slice(5 * Scalar.SizeBytes, Scalar.SizeBytes).Span);

        var gr = new ProjectivePointInput(Pre.Slice(2 * Scalar.SizeBytes, Scalar.SizeBytes).Span, Pre.Slice(3 * Scalar.SizeBytes, Scalar.SizeBytes).Span, one);
        AddPoints(gr, key, sum, scratch);
        NormalizeIntoPair(sum.Input, Pre.Slice(6 * Scalar.SizeBytes, Scalar.SizeBytes).Span, Pre.Slice(7 * Scalar.SizeBytes, Scalar.SizeBytes).Span);
    }


    /// <summary>Scales a sum's x and y by its inverted z (the reference's per-entry table normalization: the inversion is skipped for a zero z but the multiplication is not, so an identity sum zeroes both coordinates and the proof fails downstream).</summary>
    /// <param name="point">The sum to normalize.</param>
    /// <param name="destinationX">Receives the x coordinate; disjoint from the point and y destination.</param>
    /// <param name="destinationY">Receives the y coordinate; disjoint from the point and x destination.</param>
    private void NormalizeIntoPair(ProjectivePointInput point, Span<byte> destinationX, Span<byte> destinationY)
    {
        Span<byte> scale = stackalloc byte[Scalar.SizeBytes];
        scale.Clear();
        if(!LongfellowCompilerFieldOperations.ElementIsZero(point.Z))
        {
            Field.Invert(point.Z, scale, Field.Compiler.Curve);
        }

        Field.Compiler.Multiply(point.X, scale, destinationX, Field.Compiler.Curve);
        Field.Compiler.Multiply(point.Y, scale, destinationY, Field.Compiler.Curve);
    }


    /// <summary>Builds the digit-indexed addend table: identity, <c>g</c>, <c>pk</c>, <c>g+pk</c>, <c>r</c>, <c>g+r</c>, <c>r+pk</c>, <c>g+r+pk</c>.</summary>
    /// <param name="pkX">The public key's x coordinate.</param>
    /// <param name="pkY">The public key's y coordinate.</param>
    /// <param name="destination">Receives eight contiguous points; disjoint from all inputs and retained witness storage.</param>
    private void BuildDigitTable(ReadOnlySpan<byte> pkX, ReadOnlySpan<byte> pkY, Span<byte> destination)
    {
        Identity(new ProjectivePoint(destination.Slice(0 * PointBytes, PointBytes)));
        WriteAffine(Curve.GeneratorX.Span, Curve.GeneratorY.Span, new ProjectivePoint(destination.Slice(1 * PointBytes, PointBytes)));
        WriteAffine(pkX, pkY, new ProjectivePoint(destination.Slice(2 * PointBytes, PointBytes)));
        WriteAffine(Pre.Slice(0 * Scalar.SizeBytes, Scalar.SizeBytes).Span, Pre.Slice(1 * Scalar.SizeBytes, Scalar.SizeBytes).Span, new ProjectivePoint(destination.Slice(3 * PointBytes, PointBytes)));
        WriteAffine(Rx.Span, Ry.Span, new ProjectivePoint(destination.Slice(4 * PointBytes, PointBytes)));
        WriteAffine(Pre.Slice(2 * Scalar.SizeBytes, Scalar.SizeBytes).Span, Pre.Slice(3 * Scalar.SizeBytes, Scalar.SizeBytes).Span, new ProjectivePoint(destination.Slice(5 * PointBytes, PointBytes)));
        WriteAffine(Pre.Slice(4 * Scalar.SizeBytes, Scalar.SizeBytes).Span, Pre.Slice(5 * Scalar.SizeBytes, Scalar.SizeBytes).Span, new ProjectivePoint(destination.Slice(6 * PointBytes, PointBytes)));
        WriteAffine(Pre.Slice(6 * Scalar.SizeBytes, Scalar.SizeBytes).Span, Pre.Slice(7 * Scalar.SizeBytes, Scalar.SizeBytes).Span, new ProjectivePoint(destination.Slice(7 * PointBytes, PointBytes)));
    }


    /// <summary>A writable non-owning point slot borrowing the caller's live workspace.</summary>
    /// <param name="buffer">Three contiguous, nonoverlapping scalar coordinates.</param>
    private readonly ref struct ProjectivePoint(Span<byte> buffer)
    {
        /// <summary>The writable x coordinate.</summary>
        public Span<byte> X { get; } = buffer[..Scalar.SizeBytes];

        /// <summary>The writable y coordinate.</summary>
        public Span<byte> Y { get; } = buffer.Slice(Scalar.SizeBytes, Scalar.SizeBytes);

        /// <summary>The writable z coordinate.</summary>
        public Span<byte> Z { get; } = buffer.Slice(2 * Scalar.SizeBytes, Scalar.SizeBytes);

        /// <summary>Returns a read-only input view borrowing these coordinates for synchronous arithmetic.</summary>
        public ProjectivePointInput Input => new(X, Y, Z);
    }


    /// <summary>Copies affine coordinates into a disjoint caller-owned projective slot with z equal to one.</summary>
    /// <param name="x">The affine x coordinate, disjoint from the destination.</param>
    /// <param name="y">The affine y coordinate, disjoint from the destination.</param>
    /// <param name="destination">Receives the point.</param>
    private void WriteAffine(ReadOnlySpan<byte> x, ReadOnlySpan<byte> y, ProjectivePoint destination)
    {
        destination.X.Clear();
        destination.Y.Clear();
        destination.Z.Clear();
        x.CopyTo(destination.X);
        y.CopyTo(destination.Y);
        Field.Compiler.One.Span.CopyTo(destination.Z);
    }


    /// <summary>A read-only point input borrowing caller-owned workspace or live point storage.</summary>
    /// <param name="x">The borrowed x coordinate.</param>
    /// <param name="y">The borrowed y coordinate.</param>
    /// <param name="z">The borrowed z coordinate.</param>
    private readonly ref struct ProjectivePointInput(ReadOnlySpan<byte> x, ReadOnlySpan<byte> y, ReadOnlySpan<byte> z)
    {
        /// <summary>The borrowed x coordinate.</summary>
        public ReadOnlySpan<byte> X { get; } = x;

        /// <summary>The borrowed y coordinate.</summary>
        public ReadOnlySpan<byte> Y { get; } = y;

        /// <summary>The borrowed z coordinate.</summary>
        public ReadOnlySpan<byte> Z { get; } = z;
    }


    /// <summary>The projective identity <c>(0 : 1 : 0)</c>.</summary>
    /// <param name="destination">Receives the identity in its caller-owned coordinates.</param>
    private void Identity(ProjectivePoint destination)
    {
        destination.X.Clear();
        destination.Y.Clear();
        destination.Z.Clear();
        Field.Compiler.One.Span.CopyTo(destination.Y);
    }


    /// <summary>Variable-time double-and-add over the scalar's bits, most significant first, from the projective identity.</summary>
    /// <param name="baseX">The base point's affine x coordinate.</param>
    /// <param name="baseY">The base point's affine y coordinate.</param>
    /// <param name="scalar">The canonical scalar.</param>
    /// <param name="destination">Receives the unnormalized product; disjoint from the base coordinates and scalar.</param>
    /// <param name="scratch">The arithmetic workspace, disjoint from the inputs and destination.</param>
    private void ScalarMultiplyPoint(ReadOnlySpan<byte> baseX, ReadOnlySpan<byte> baseY, ReadOnlySpan<byte> scalar, ProjectivePoint destination, Span<byte> scratch)
    {
        var basePoint = new ProjectivePointInput(baseX, baseY, Field.Compiler.One.Span);
        Identity(destination);
        for(int i = (Scalar.SizeBytes * 8) - 1; i >= 0; i--)
        {
            DoublePoint(destination.Input, destination, scratch);
            if(BitAt(scalar, i) != 0)
            {
                AddPoints(destination.Input, basePoint, destination, scratch);
            }
        }
    }


    /// <summary>Renes–Costello–Batina Algorithm 1 over concrete canonical elements, the same complete addition the circuit emits.</summary>
    /// <param name="p1">The first point's borrowed input view, consumed synchronously.</param>
    /// <param name="p2">The second point's borrowed input view, consumed synchronously.</param>
    /// <param name="destination">Receives the sum after all input reads, so it may overlap either input.</param>
    /// <param name="scratch">Ten scalar slots disjoint from both inputs and the destination.</param>
    private void AddPoints(ProjectivePointInput p1, ProjectivePointInput p2, ProjectivePoint destination, Span<byte> scratch)
    {
        Span<byte> t0 = scratch.Slice(0 * Scalar.SizeBytes, Scalar.SizeBytes);
        Span<byte> t1 = scratch.Slice(1 * Scalar.SizeBytes, Scalar.SizeBytes);
        Span<byte> t2 = scratch.Slice(2 * Scalar.SizeBytes, Scalar.SizeBytes);
        Span<byte> t3 = scratch.Slice(3 * Scalar.SizeBytes, Scalar.SizeBytes);
        Span<byte> t4 = scratch.Slice(4 * Scalar.SizeBytes, Scalar.SizeBytes);
        Span<byte> t5 = scratch.Slice(5 * Scalar.SizeBytes, Scalar.SizeBytes);
        Span<byte> x3 = scratch.Slice(6 * Scalar.SizeBytes, Scalar.SizeBytes);
        Span<byte> y3 = scratch.Slice(7 * Scalar.SizeBytes, Scalar.SizeBytes);
        Span<byte> z3 = scratch.Slice(8 * Scalar.SizeBytes, Scalar.SizeBytes);
        Span<byte> result = scratch.Slice((ArithmeticWorkspaceElements - 1) * Scalar.SizeBytes, Scalar.SizeBytes);

        Mul(p1.X, p2.X, t0, result);
        Mul(p1.Y, p2.Y, t1, result);
        Mul(p1.Z, p2.Z, t2, result);
        AddF(p1.X, p1.Y, t3, result);
        AddF(p2.X, p2.Y, t4, result);
        Mul(t3, t4, t3, result);
        AddF(t0, t1, t4, result);
        SubF(t3, t4, t3, result);
        AddF(p1.X, p1.Z, t4, result);
        AddF(p2.X, p2.Z, t5, result);
        Mul(t4, t5, t4, result);
        AddF(t0, t2, t5, result);
        SubF(t4, t5, t4, result);
        AddF(p1.Y, p1.Z, t5, result);
        AddF(p2.Y, p2.Z, x3, result);
        Mul(t5, x3, t5, result);
        AddF(t1, t2, x3, result);
        SubF(t5, x3, t5, result);
        Mul(CurveA.Span, t4, z3, result);
        Mul(CurveBTimes3.Span, t2, x3, result);
        AddF(x3, z3, z3, result);
        SubF(t1, z3, x3, result);
        AddF(t1, z3, z3, result);
        Mul(x3, z3, y3, result);
        AddF(t0, t0, t1, result);
        AddF(t1, t0, t1, result);
        Mul(CurveA.Span, t2, t2, result);
        Mul(CurveBTimes3.Span, t4, t4, result);
        AddF(t1, t2, t1, result);
        SubF(t0, t2, t2, result);
        Mul(CurveA.Span, t2, t2, result);
        AddF(t4, t2, t4, result);
        Mul(t1, t4, t0, result);
        AddF(y3, t0, y3, result);
        Mul(t5, t4, t0, result);
        Mul(t3, x3, x3, result);
        SubF(x3, t0, x3, result);
        Mul(t3, t1, t0, result);
        Mul(t5, z3, z3, result);
        AddF(z3, t0, z3, result);

        //All input reads finish before any destination coordinate is overwritten.
        x3.CopyTo(destination.X);
        y3.CopyTo(destination.Y);
        z3.CopyTo(destination.Z);
    }


    /// <summary>Renes–Costello–Batina Algorithm 3 over concrete canonical elements, the same complete doubling the circuit emits.</summary>
    /// <param name="p">The point to double.</param>
    /// <param name="destination">Receives the doubled point after all input reads, so it may overlap the input.</param>
    /// <param name="scratch">Ten scalar slots disjoint from the input and destination.</param>
    private void DoublePoint(ProjectivePointInput p, ProjectivePoint destination, Span<byte> scratch)
    {
        Span<byte> t0 = scratch.Slice(0 * Scalar.SizeBytes, Scalar.SizeBytes);
        Span<byte> t1 = scratch.Slice(1 * Scalar.SizeBytes, Scalar.SizeBytes);
        Span<byte> t2 = scratch.Slice(2 * Scalar.SizeBytes, Scalar.SizeBytes);
        Span<byte> t3 = scratch.Slice(3 * Scalar.SizeBytes, Scalar.SizeBytes);
        Span<byte> x3 = scratch.Slice(4 * Scalar.SizeBytes, Scalar.SizeBytes);
        Span<byte> y3 = scratch.Slice(5 * Scalar.SizeBytes, Scalar.SizeBytes);
        Span<byte> z3 = scratch.Slice(6 * Scalar.SizeBytes, Scalar.SizeBytes);
        Span<byte> result = scratch.Slice((ArithmeticWorkspaceElements - 1) * Scalar.SizeBytes, Scalar.SizeBytes);

        Mul(p.X, p.X, t0, result);
        Mul(p.Y, p.Y, t1, result);
        Mul(p.Z, p.Z, t2, result);
        Mul(p.X, p.Y, t3, result);
        AddF(t3, t3, t3, result);
        Mul(p.X, p.Z, z3, result);
        AddF(z3, z3, z3, result);
        Mul(CurveA.Span, z3, x3, result);
        Mul(CurveBTimes3.Span, t2, y3, result);
        AddF(x3, y3, y3, result);
        SubF(t1, y3, x3, result);
        AddF(t1, y3, y3, result);
        Mul(x3, y3, y3, result);
        Mul(t3, x3, x3, result);
        Mul(CurveBTimes3.Span, z3, z3, result);
        Mul(CurveA.Span, t2, t2, result);
        SubF(t0, t2, t3, result);
        Mul(CurveA.Span, t3, t3, result);
        AddF(t3, z3, t3, result);
        AddF(t0, t0, z3, result);
        AddF(z3, t0, t0, result);
        AddF(t0, t2, t0, result);
        Mul(t0, t3, t0, result);
        AddF(y3, t0, y3, result);
        Mul(p.Y, p.Z, t2, result);
        AddF(t2, t2, t2, result);
        Mul(t2, t3, t0, result);
        SubF(x3, t0, x3, result);
        Mul(t2, t1, z3, result);
        AddF(z3, z3, z3, result);
        AddF(z3, z3, z3, result);

        //All input reads finish before any destination coordinate is overwritten.
        x3.CopyTo(destination.X);
        y3.CopyTo(destination.Y);
        z3.CopyTo(destination.Z);
    }


    /// <summary>The reference's <c>normalize</c>: divides x and y by z in place when z is nonzero; the identity representation passes through untouched.</summary>
    /// <param name="point">The caller-owned point to normalize in place.</param>
    /// <param name="scratch">At least three scalar slots disjoint from the point, staging the inverse and both scaled coordinates.</param>
    private void Normalize(ProjectivePoint point, Span<byte> scratch)
    {
        if(LongfellowCompilerFieldOperations.ElementIsZero(point.Z))
        {
            return;
        }

        Span<byte> inverse = scratch[..Scalar.SizeBytes];
        Span<byte> x = scratch.Slice(Scalar.SizeBytes, Scalar.SizeBytes);
        Span<byte> y = scratch.Slice(2 * Scalar.SizeBytes, Scalar.SizeBytes);
        inverse.Clear();
        x.Clear();
        y.Clear();
        Field.Invert(point.Z, inverse, Field.Compiler.Curve);
        Field.Compiler.Multiply(point.X, inverse, x, Field.Compiler.Curve);
        Field.Compiler.Multiply(point.Y, inverse, y, Field.Compiler.Curve);
        x.CopyTo(point.X);
        y.CopyTo(point.Y);
        point.Z.Clear();
        Field.Compiler.One.Span.CopyTo(point.Z);
    }


    /// <summary>Order-field inversion under the Fermat zero-maps-to-zero convention.</summary>
    /// <param name="value">The canonical value to invert.</param>
    /// <param name="destination">Receives the inverse, or zero for a zero input.</param>
    private void InvertOrder(ReadOnlySpan<byte> value, Span<byte> destination)
    {
        if(LongfellowCompilerFieldOperations.ElementIsZero(value))
        {
            destination.Clear();

            return;
        }

        OrderInvert(value, destination, OrderCurve);
    }


    /// <summary>The base-field product of two elements.</summary>
    /// <param name="a">The first factor.</param>
    /// <param name="b">The second factor.</param>
    /// <param name="destination">Receives the product and may overlap either factor.</param>
    /// <param name="result">One scalar slot disjoint from both factors and the destination.</param>
    private void Mul(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> destination, Span<byte> result)
    {
        result.Clear();
        Field.Compiler.Multiply(a, b, result, Field.Compiler.Curve);
        result.CopyTo(destination);
    }


    /// <summary>The base-field sum of two elements.</summary>
    /// <param name="a">The first addend.</param>
    /// <param name="b">The second addend.</param>
    /// <param name="destination">Receives the sum and may overlap either addend.</param>
    /// <param name="result">One scalar slot disjoint from both addends and the destination.</param>
    private void AddF(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> destination, Span<byte> result)
    {
        result.Clear();
        Field.Compiler.Add(a, b, result, Field.Compiler.Curve);
        result.CopyTo(destination);
    }


    /// <summary>The base-field difference of two elements.</summary>
    /// <param name="a">The minuend.</param>
    /// <param name="b">The subtrahend.</param>
    /// <param name="destination">Receives the difference and may overlap either operand.</param>
    /// <param name="result">One scalar slot disjoint from both operands and the destination.</param>
    private void SubF(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> destination, Span<byte> result)
    {
        result.Clear();
        Field.Subtract(a, b, result, Field.Compiler.Curve);
        result.CopyTo(destination);
    }


    /// <summary>Reads bit <paramref name="index"/> of a canonical big-endian value, least significant bit first.</summary>
    /// <param name="value">The value.</param>
    /// <param name="index">The bit index.</param>
    /// <returns>The bit.</returns>
    private static int BitAt(ReadOnlySpan<byte> value, int index)
    {
        return (value[Scalar.SizeBytes - 1 - (index / 8)] >> (index % 8)) & 1;
    }


    /// <summary>
    /// The base prime as the bundle's minus-one constant plus one; deriving it from the bundle keeps
    /// every raw-value reduction in agreement with the delegates' own modulus.
    /// </summary>
    /// <param name="field">The base-field bundle.</param>
    /// <param name="prime">Receives the canonical big-endian prime in a scalar-sized destination owned by the caller.</param>
    internal static void DeriveBasePrime(LongfellowLogicFieldOperations field, Span<byte> prime)
    {
        prime.Clear();
        field.Compiler.MinusOne.Span.CopyTo(prime);
        for(int i = Scalar.SizeBytes - 1; i >= 0; i--)
        {
            prime[i]++;
            if(prime[i] != 0)
            {
                break;
            }
        }
    }


    /// <summary>Writes one element into the column and advances the cursor.</summary>
    /// <param name="destination">The column.</param>
    /// <param name="cursor">The element cursor.</param>
    /// <param name="element">The element to write.</param>
    private static void WriteElement(Span<byte> destination, ref int cursor, ReadOnlySpan<byte> element)
    {
        element.CopyTo(destination.Slice(cursor * Scalar.SizeBytes, Scalar.SizeBytes));
        cursor++;
    }


    /// <summary>Allocates a flattened table of zeroed canonical elements owned by this generator.</summary>
    /// <param name="count">The element count; zero needs no rental.</param>
    /// <returns>The table bytes borrowed until this generator is disposed.</returns>
    private Memory<byte> NewElementArray(int count)
    {
        if(count == 0)
        {
            return Memory<byte>.Empty;
        }

        return Storage.Allocate(checked(count * Scalar.SizeBytes));
    }


    /// <summary>Clears and releases every retained scalar and table. Repeated disposal has no effect.</summary>
    public void Dispose()
    {
        Storage.Dispose();
    }
}
