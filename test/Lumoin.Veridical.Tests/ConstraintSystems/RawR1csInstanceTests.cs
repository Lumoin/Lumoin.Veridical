using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Provenance;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Tests.ConstraintSystems;

/// <summary>
/// Pins the construction and ownership contract of <see cref="RawR1csInstance"/>. <see cref="RawR1csInstance.Create"/>
/// refuses a missing matrix or pool on that argument's own name, refuses matrices that disagree pairwise on curve or
/// on dimensions, and refuses public-input bytes that are not whole scalars or that leave no column for the constant;
/// each refusal is reached with an input that only that check rejects. A caller-supplied tag keeps its own entries
/// under the instance's role, curve and dimensions, and disposing the instance disposes the three matrices it took
/// ownership of together with its own public-input buffer. The canonicity of the public-input values is pinned in
/// <see cref="R1csInstanceCanonicityTests"/>.
/// </summary>
[TestClass]
internal sealed class RawR1csInstanceTests
{
    /// <summary>One constraint row, the smallest row count a matrix admits.</summary>
    private const int RowCount = 1;

    /// <summary>One row more than <see cref="RowCount"/>, the nearest row count that differs from it.</summary>
    private const int TallerRowCount = RowCount + 1;

    /// <summary>Four columns: the constant plus room for up to three public inputs.</summary>
    private const int ColumnCount = 4;

    /// <summary>One column more than <see cref="ColumnCount"/>, the nearest column count that differs from it.</summary>
    private const int WiderColumnCount = ColumnCount + 1;

    /// <summary>Every matrix holds its single entry in the first row, which every row count here has.</summary>
    private const int EntryRow = 0;

    /// <summary>Every matrix holds its single entry in the first column, which every column count here has.</summary>
    private const int EntryColumn = 0;

    /// <summary>The last byte of the entry value one, the only nonzero byte of its canonical big-endian encoding.</summary>
    private const byte EntryValueLowByte = 1;

    /// <summary>The row-index bytes of a single-entry matrix: one big-endian 32-bit index.</summary>
    private const int SingleEntryIndexBytes = sizeof(int);

    /// <summary>The 32-byte canonical scalar width of the BLS12-381 public inputs.</summary>
    private const int ScalarSize = WellKnownCurves.Bls12Curve381ScalarSizeBytes;

    /// <summary>The constant one occupies the first entry of <c>z</c>, ahead of the public inputs.</summary>
    private const int ConstantVariableCount = 1;

    /// <summary>No public inputs, the count the tag-merge instance is built with.</summary>
    private const int NoPublicInputs = 0;

    /// <summary>One public input, the count the disposal instance copies and the caller's stale dimensions record.</summary>
    private const int SinglePublicInputCount = 1;

    /// <summary>The byte length of <see cref="SinglePublicInputCount"/> whole scalars.</summary>
    private const int SinglePublicInputLength = SinglePublicInputCount * ScalarSize;

    /// <summary>As many public inputs as there are columns, so with the constant <c>z</c> needs one entry more than the matrices have.</summary>
    private const int OverfullPublicInputCount = ColumnCount;

    /// <summary>The byte length of <see cref="OverfullPublicInputCount"/> whole scalars.</summary>
    private const int OverfullPublicInputLength = OverfullPublicInputCount * ScalarSize;

    /// <summary>One byte past a whole scalar, which leaves the floored public-input count at one.</summary>
    private const int StrayByteCount = 1;

    /// <summary>One whole scalar followed by <see cref="StrayByteCount"/> stray byte, strictly between one and two scalars.</summary>
    private const int RaggedPublicInputLength = ScalarSize + StrayByteCount;

    /// <summary>A fixed fill stream selector, so every run builds the same canonical public inputs.</summary>
    private const int PublicInputFillSalt = 11;

    /// <summary>The instance composes three identity entries into its tag: its role, its curve and its dimensions.</summary>
    private const int IdentityTagEntryCount = 3;

    /// <summary>The caller's tag carries one entry that no identity entry replaces: its provider class.</summary>
    private const int CallerOnlyTagEntryCount = 1;

    /// <summary>The name of the <c>A</c> matrix parameter, which its null guard reports.</summary>
    private const string MatrixAParameterName = "a";

    /// <summary>The name of the <c>B</c> matrix parameter, which its null guard reports.</summary>
    private const string MatrixBParameterName = "b";

    /// <summary>The name of the <c>C</c> matrix parameter, which its null guard reports.</summary>
    private const string MatrixCParameterName = "c";

    /// <summary>The name of the pool parameter, which its null guard reports.</summary>
    private const string PoolParameterName = "pool";

    /// <summary>The name of the public-input parameter, which the length and count guards report.</summary>
    private const string PublicInputsParameterName = "publicInputs";

    /// <summary>The rule the curve refusal states, which no other refusal of the factory states.</summary>
    private const string SharedCurveRule = "must share a curve";

    /// <summary>The rule the dimension refusal states, which no other refusal of the factory states.</summary>
    private const string SharedDimensionsRule = "must share dimensions";

    /// <summary>The rule the public-input length refusal states, which no other refusal of the factory states.</summary>
    private const string WholeScalarsRule = "must be a multiple of the scalar size";

    /// <summary>The class name a caller records as the provider of the instance it builds.</summary>
    private const string CallerProviderClassName = "CircuitImporter";


    /// <summary>The curve every matrix is built over unless a test needs a second one.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;

    /// <summary>A second wired curve with the same 32-byte scalar width, on which the value one is canonical as well.</summary>
    private static CurveParameterSet OtherCurve { get; } = CurveParameterSet.Bn254;

    /// <summary>The BLS12-381 scalar-reduction backend that fills canonical public inputs.</summary>
    private static ScalarReduceDelegate Reduce { get; } = TestScalarBackends.Bls12Curve381.Reduce;

    /// <summary>
    /// The provider class a caller records in the tag it supplies. <see cref="ProviderClass"/> is a record struct, so
    /// it is held in a get-only property rather than a constant.
    /// </summary>
    private static ProviderClass CallerProviderClass { get; } = new(CallerProviderClassName);

    /// <summary>
    /// Dimensions a caller carried over from another instance into the tag it supplies. They differ from the built
    /// instance in every component, so the instance's own dimensions have to replace them.
    /// </summary>
    private static R1csDimensions CallerDimensions { get; } = new(TallerRowCount, WiderColumnCount, SinglePublicInputCount);


    /// <summary>The matrices, instances and pooled rentals a test opened, released together in cleanup.</summary>
    private List<IDisposable> Disposables { get; } = [];


    /// <summary>Disposes everything the test opened, most recent first.</summary>
    [TestCleanup]
    public void DisposeRentals()
    {
        for(int i = Disposables.Count - 1; i >= 0; i--)
        {
            Disposables[i].Dispose();
        }

        Disposables.Clear();
    }


    /// <summary>
    /// A missing <c>A</c> matrix is refused with an <see cref="ArgumentNullException"/> naming <c>a</c>. The
    /// <c>B</c> and <c>C</c> matrices and the pool are present, so no other null guard can answer, and the guard has
    /// to come before the curve comparison: that comparison reads the curve of <c>A</c> first, so without the guard
    /// the call fails with a <see cref="NullReferenceException"/>, which the exact exception type check rejects.
    /// </summary>
    [TestMethod]
    public void CreateRejectsANullAMatrix()
    {
        R1csMatrix b = Track(BuildOneEntryMatrix(RowCount, ColumnCount, Curve));
        R1csMatrix c = Track(BuildOneEntryMatrix(RowCount, ColumnCount, Curve));

        ArgumentNullException thrown = Assert.ThrowsExactly<ArgumentNullException>(
            () => RawR1csInstance.Create(null!, b, c, ReadOnlySpan<byte>.Empty, BaseMemoryPool.Shared).Dispose(),
            "An instance without an A matrix must be refused.");

        Assert.AreEqual(MatrixAParameterName, thrown.ParamName, "The refusal must name the A matrix parameter.");
    }


    /// <summary>
    /// A missing <c>B</c> matrix is refused with an <see cref="ArgumentNullException"/> naming <c>b</c>. <c>A</c> is
    /// present, so its guard passes, and <c>C</c> and the pool are present, so no later null guard can answer.
    /// Without the guard the curve comparison reads the curve of <c>B</c> right after that of <c>A</c>, and the call
    /// fails with a <see cref="NullReferenceException"/> instead.
    /// </summary>
    [TestMethod]
    public void CreateRejectsANullBMatrix()
    {
        R1csMatrix a = Track(BuildOneEntryMatrix(RowCount, ColumnCount, Curve));
        R1csMatrix c = Track(BuildOneEntryMatrix(RowCount, ColumnCount, Curve));

        ArgumentNullException thrown = Assert.ThrowsExactly<ArgumentNullException>(
            () => RawR1csInstance.Create(a, null!, c, ReadOnlySpan<byte>.Empty, BaseMemoryPool.Shared).Dispose(),
            "An instance without a B matrix must be refused.");

        Assert.AreEqual(MatrixBParameterName, thrown.ParamName, "The refusal must name the B matrix parameter.");
    }


    /// <summary>
    /// A missing <c>C</c> matrix is refused with an <see cref="ArgumentNullException"/> naming <c>c</c>. <c>A</c> and
    /// <c>B</c> are present and share a curve, so the first curve comparison finds no difference and the second one
    /// reads the curve of <c>C</c>: without the guard that read fails with a <see cref="NullReferenceException"/>.
    /// The pool is present, so its guard cannot answer instead.
    /// </summary>
    [TestMethod]
    public void CreateRejectsANullCMatrix()
    {
        R1csMatrix a = Track(BuildOneEntryMatrix(RowCount, ColumnCount, Curve));
        R1csMatrix b = Track(BuildOneEntryMatrix(RowCount, ColumnCount, Curve));

        ArgumentNullException thrown = Assert.ThrowsExactly<ArgumentNullException>(
            () => RawR1csInstance.Create(a, b, null!, ReadOnlySpan<byte>.Empty, BaseMemoryPool.Shared).Dispose(),
            "An instance without a C matrix must be refused.");

        Assert.AreEqual(MatrixCParameterName, thrown.ParamName, "The refusal must name the C matrix parameter.");
    }


    /// <summary>
    /// A missing pool is refused with an <see cref="ArgumentNullException"/> naming <c>pool</c>. The three matrices
    /// share a curve and a shape and there are no public inputs, so every check after the null guards admits the
    /// call, and without the guard it would first fail where the public-input buffer is rented, with a
    /// <see cref="NullReferenceException"/>.
    /// </summary>
    [TestMethod]
    public void CreateRejectsANullPool()
    {
        R1csMatrix a = Track(BuildOneEntryMatrix(RowCount, ColumnCount, Curve));
        R1csMatrix b = Track(BuildOneEntryMatrix(RowCount, ColumnCount, Curve));
        R1csMatrix c = Track(BuildOneEntryMatrix(RowCount, ColumnCount, Curve));

        ArgumentNullException thrown = Assert.ThrowsExactly<ArgumentNullException>(
            () => RawR1csInstance.Create(a, b, c, ReadOnlySpan<byte>.Empty, null!).Dispose(),
            "An instance without a pool must be refused.");

        Assert.AreEqual(PoolParameterName, thrown.ParamName, "The refusal must name the pool parameter.");
    }


    /// <summary>
    /// Matrices over different curves are refused with an <see cref="ArgumentException"/> that states the
    /// shared-curve rule, even when the mismatch is confined to one pair. <c>A</c> and <c>B</c> are over BLS12-381 and
    /// only <c>C</c> is over BN254, so the check has to reject when either compared pair disagrees, not only when
    /// both do. Both curves have 32-byte scalars and the value one is canonical on each, the shapes match and there
    /// are no public inputs, so without the check the call would return an instance.
    /// </summary>
    [TestMethod]
    public void CreateRejectsMatricesOverDifferentCurves()
    {
        R1csMatrix a = Track(BuildOneEntryMatrix(RowCount, ColumnCount, Curve));
        R1csMatrix b = Track(BuildOneEntryMatrix(RowCount, ColumnCount, Curve));
        R1csMatrix c = Track(BuildOneEntryMatrix(RowCount, ColumnCount, OtherCurve));

        ArgumentException thrown = Assert.ThrowsExactly<ArgumentException>(
            () => RawR1csInstance.Create(a, b, c, ReadOnlySpan<byte>.Empty, BaseMemoryPool.Shared).Dispose(),
            "Matrices over different curves must be refused.");

        Assert.Contains(SharedCurveRule, thrown.Message, StringComparison.Ordinal,
            "The refusal must state that the matrices must share a curve.");
    }


    /// <summary>
    /// Matrices whose column counts differ are refused with an <see cref="ArgumentException"/> that states the
    /// shared-dimension rule. <c>A</c> is one column wider than <c>B</c> and <c>C</c>, which agree with each other,
    /// and all three have one row, so the comparison of the <c>A</c> and <c>B</c> column counts is the only one of
    /// the four that finds a difference: any single disagreement has to be enough. The matrices share a curve, there
    /// are no public inputs and the constant fits either column count, so without the check the call would return an
    /// instance.
    /// </summary>
    [TestMethod]
    public void CreateRejectsMatricesWithDifferentColumnCounts()
    {
        R1csMatrix a = Track(BuildOneEntryMatrix(RowCount, WiderColumnCount, Curve));
        R1csMatrix b = Track(BuildOneEntryMatrix(RowCount, ColumnCount, Curve));
        R1csMatrix c = Track(BuildOneEntryMatrix(RowCount, ColumnCount, Curve));

        ArgumentException thrown = Assert.ThrowsExactly<ArgumentException>(
            () => RawR1csInstance.Create(a, b, c, ReadOnlySpan<byte>.Empty, BaseMemoryPool.Shared).Dispose(),
            "Matrices with different column counts must be refused.");

        Assert.Contains(SharedDimensionsRule, thrown.Message, StringComparison.Ordinal,
            "The refusal must state that the matrices must share dimensions.");
    }


    /// <summary>
    /// Matrices whose row counts differ are refused with an <see cref="ArgumentException"/> that states the
    /// shared-dimension rule, even when every column count agrees. <c>C</c> has one row more than <c>A</c> and
    /// <c>B</c>, which agree with each other, so the comparison of the <c>B</c> and <c>C</c> row counts is the only
    /// one of the four that finds a difference: a row mismatch confined to one pair has to be enough on its own. The
    /// matrices share a curve and there are no public inputs, so without the check the call would return an
    /// instance.
    /// </summary>
    [TestMethod]
    public void CreateRejectsMatricesWithDifferentRowCounts()
    {
        R1csMatrix a = Track(BuildOneEntryMatrix(RowCount, ColumnCount, Curve));
        R1csMatrix b = Track(BuildOneEntryMatrix(RowCount, ColumnCount, Curve));
        R1csMatrix c = Track(BuildOneEntryMatrix(TallerRowCount, ColumnCount, Curve));

        ArgumentException thrown = Assert.ThrowsExactly<ArgumentException>(
            () => RawR1csInstance.Create(a, b, c, ReadOnlySpan<byte>.Empty, BaseMemoryPool.Shared).Dispose(),
            "Matrices with different row counts must be refused.");

        Assert.Contains(SharedDimensionsRule, thrown.Message, StringComparison.Ordinal,
            "The refusal must state that the matrices must share dimensions.");
    }


    /// <summary>
    /// Public-input bytes that are not a whole number of scalars are refused with an <see cref="ArgumentException"/>
    /// on <c>publicInputs</c> that states the whole-scalar rule. One canonical scalar followed by a stray byte is an
    /// input only the length check rejects: the floored public-input count is one, which leaves room for the
    /// constant, and that input is canonical, so without the check the call would copy the stray byte into the
    /// instance and return it. The parameter name alone does not identify the check, because the count and
    /// canonicity refusals report the same parameter, so the stated rule is asserted as well.
    /// </summary>
    [TestMethod]
    public void CreateRejectsPublicInputBytesThatAreNotWholeScalars()
    {
        R1csMatrix a = Track(BuildOneEntryMatrix(RowCount, ColumnCount, Curve));
        R1csMatrix b = Track(BuildOneEntryMatrix(RowCount, ColumnCount, Curve));
        R1csMatrix c = Track(BuildOneEntryMatrix(RowCount, ColumnCount, Curve));

        IMemoryOwner<byte> inputOwner = Track(BaseMemoryPool.Shared.Rent(RaggedPublicInputLength));
        Memory<byte> publicInputs = inputOwner.Memory[..RaggedPublicInputLength];
        publicInputs.Span.Clear();
        DeterministicScalarFill.FillCanonical(publicInputs.Span[..ScalarSize], PublicInputFillSalt, Reduce, Curve);

        ArgumentException thrown = Assert.ThrowsExactly<ArgumentException>(
            () => RawR1csInstance.Create(a, b, c, publicInputs.Span, BaseMemoryPool.Shared).Dispose(),
            "Public-input bytes that are not whole scalars must be refused.");

        Assert.AreEqual(PublicInputsParameterName, thrown.ParamName, "The refusal must name the public-input parameter.");
        Assert.Contains(WholeScalarsRule, thrown.Message, StringComparison.Ordinal,
            "The refusal must state that the length must be a whole number of scalars.");
    }


    /// <summary>
    /// A public-input count that leaves no column for the constant is refused with an <see cref="ArgumentException"/>
    /// on <c>publicInputs</c> whose message reports the count plus the constant against the column count. As many
    /// inputs as columns is the smallest such count: <c>z</c> would need five entries on four columns, and the
    /// message has to report exactly that five, the count plus the one constant entry. The inputs are whole
    /// canonical scalars, so neither the length check before this one nor the canonicity check after it can reject
    /// them, and without the check the call would return an instance with no room for the constant.
    /// </summary>
    [TestMethod]
    public void CreateRejectsMorePublicInputsThanTheColumnsHold()
    {
        R1csMatrix a = Track(BuildOneEntryMatrix(RowCount, ColumnCount, Curve));
        R1csMatrix b = Track(BuildOneEntryMatrix(RowCount, ColumnCount, Curve));
        R1csMatrix c = Track(BuildOneEntryMatrix(RowCount, ColumnCount, Curve));

        IMemoryOwner<byte> inputOwner = Track(BaseMemoryPool.Shared.Rent(OverfullPublicInputLength));
        Memory<byte> publicInputs = inputOwner.Memory[..OverfullPublicInputLength];
        DeterministicScalarFill.FillCanonical(publicInputs.Span, PublicInputFillSalt, Reduce, Curve);

        ArgumentException thrown = Assert.ThrowsExactly<ArgumentException>(
            () => RawR1csInstance.Create(a, b, c, publicInputs.Span, BaseMemoryPool.Shared).Dispose(),
            "A public-input count that leaves no column for the constant must be refused.");

        Assert.AreEqual(PublicInputsParameterName, thrown.ParamName, "The refusal must name the public-input parameter.");
        Assert.Contains($"= {OverfullPublicInputCount + ConstantVariableCount} exceeds the variable count {ColumnCount}.", thrown.Message, StringComparison.Ordinal,
            "The refusal must report the count plus the constant against the column count.");
    }


    /// <summary>
    /// A caller-supplied tag is merged rather than replaced. The instance tag keeps the provider class the caller
    /// recorded, while the instance's own role, curve and dimensions replace the scalar role, the other curve and the
    /// stale dimensions the caller recorded, and nothing else is added. A tag composed from the identity entries
    /// alone has no provider class, so the provider-class assertion tells a merge from a rebuild.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000", Justification = "RawR1csInstance.Create takes ownership of the matrices and disposes them through its own Dispose chain.")]
    public void CreateKeepsCallerTagEntriesUnderTheInstanceIdentity()
    {
        Tag callerTag = Tag.Create(AlgebraicRole.Scalar)
            .With(OtherCurve)
            .With(CallerDimensions)
            .With(CallerProviderClass);

        using RawR1csInstance instance = RawR1csInstance.Create(
            BuildOneEntryMatrix(RowCount, ColumnCount, Curve),
            BuildOneEntryMatrix(RowCount, ColumnCount, Curve),
            BuildOneEntryMatrix(RowCount, ColumnCount, Curve),
            ReadOnlySpan<byte>.Empty,
            BaseMemoryPool.Shared,
            callerTag);

        Assert.IsTrue(instance.Tag.TryGet(out ProviderClass providerClass), "The caller's provider class must survive the merge.");
        Assert.AreEqual(CallerProviderClass, providerClass, "The merged provider class must be the one the caller recorded.");
        Assert.AreEqual(AlgebraicRole.RawR1csInstance, instance.Tag.Get<AlgebraicRole>(), "The instance role must replace the caller's scalar role.");
        Assert.AreEqual(Curve, instance.Tag.Get<CurveParameterSet>(), "The instance curve must replace the caller's curve.");
        Assert.AreEqual(new R1csDimensions(RowCount, ColumnCount, NoPublicInputs), instance.Tag.Get<R1csDimensions>(),
            "The instance dimensions must replace the caller's dimensions.");
        Assert.HasCount(IdentityTagEntryCount + CallerOnlyTagEntryCount, instance.Tag.Entries,
            "The merge must hold only the identity entries and the caller's provider class.");
    }


    /// <summary>
    /// Disposing an instance disposes the three matrices it took ownership of and releases its own public-input
    /// buffer. Every read below answers while the instance is live and is refused once it is disposed, and each
    /// refusal names the type whose own disposed check raised it: a matrix read can only be refused because that
    /// matrix was disposed, and the public-input read only because the instance released its buffer. A matrix the
    /// instance left undisposed would keep its pool slot rented after its owner is gone.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000", Justification = "RawR1csInstance.Create takes ownership of the matrices, and disposing the instance is the behaviour under test.")]
    public void DisposingTheInstanceDisposesItsMatricesAndItsPublicInputBuffer()
    {
        IMemoryOwner<byte> inputOwner = Track(BaseMemoryPool.Shared.Rent(SinglePublicInputLength));
        Memory<byte> publicInput = inputOwner.Memory[..SinglePublicInputLength];
        DeterministicScalarFill.FillCanonical(publicInput.Span, PublicInputFillSalt, Reduce, Curve);

        R1csMatrix a = BuildOneEntryMatrix(RowCount, ColumnCount, Curve);
        R1csMatrix b = BuildOneEntryMatrix(RowCount, ColumnCount, Curve);
        R1csMatrix c = BuildOneEntryMatrix(RowCount, ColumnCount, Curve);

        //The instance is tracked as well, so a failed live check still releases it; disposing it again does nothing.
        RawR1csInstance instance = Track(RawR1csInstance.Create(a, b, c, publicInput.Span, BaseMemoryPool.Shared));

        Assert.HasCount(SingleEntryIndexBytes, a.GetRowIndicesBytes(), "The A matrix must answer reads while the instance is live.");
        Assert.HasCount(SingleEntryIndexBytes, b.GetRowIndicesBytes(), "The B matrix must answer reads while the instance is live.");
        Assert.HasCount(SingleEntryIndexBytes, c.GetRowIndicesBytes(), "The C matrix must answer reads while the instance is live.");
        Assert.IsTrue(instance.GetPublicInputsBytes().SequenceEqual(publicInput.Span), "A live instance must return the public input it copied.");

        instance.Dispose();

        ObjectDisposedException aThrown = Assert.ThrowsExactly<ObjectDisposedException>(
            () => _ = a.GetRowIndicesBytes(),
            "Disposing the instance must dispose the A matrix.");
        Assert.AreEqual(typeof(R1csMatrix).FullName, aThrown.ObjectName, "The A matrix read must be refused by the matrix's own disposed check.");

        ObjectDisposedException bThrown = Assert.ThrowsExactly<ObjectDisposedException>(
            () => _ = b.GetRowIndicesBytes(),
            "Disposing the instance must dispose the B matrix.");
        Assert.AreEqual(typeof(R1csMatrix).FullName, bThrown.ObjectName, "The B matrix read must be refused by the matrix's own disposed check.");

        ObjectDisposedException cThrown = Assert.ThrowsExactly<ObjectDisposedException>(
            () => _ = c.GetRowIndicesBytes(),
            "Disposing the instance must dispose the C matrix.");
        Assert.AreEqual(typeof(R1csMatrix).FullName, cThrown.ObjectName, "The C matrix read must be refused by the matrix's own disposed check.");

        ObjectDisposedException instanceThrown = Assert.ThrowsExactly<ObjectDisposedException>(
            () => _ = instance.GetPublicInputsBytes(),
            "Disposing the instance must release its public-input buffer.");
        Assert.AreEqual(typeof(RawR1csInstance).FullName, instanceThrown.ObjectName, "The public-input read must be refused by the instance's own disposed check.");
    }


    /// <summary>
    /// Builds a matrix of the given shape over the given curve that holds a single entry, the value one at the first
    /// row and column. One is canonical on every wired curve, so the matrix factory accepts it whichever curve a test
    /// asks for, and the value is sized by the same per-curve scalar width the instance factory reads.
    /// </summary>
    /// <param name="rowCount">The number of rows.</param>
    /// <param name="columnCount">The number of columns.</param>
    /// <param name="curve">The curve whose scalar field the entry value lives in.</param>
    /// <returns>The matrix, owned by the caller until an instance takes it over.</returns>
    private static R1csMatrix BuildOneEntryMatrix(int rowCount, int columnCount, CurveParameterSet curve)
    {
        ReadOnlySpan<int> rows = [EntryRow];
        ReadOnlySpan<int> columns = [EntryColumn];
        Span<byte> one = stackalloc byte[R1csMatrix.GetValueByteSize(curve)];
        one.Clear();
        one[^1] = EntryValueLowByte;

        return R1csMatrix.FromSortedTriples(rows, columns, one, rowCount, columnCount, curve, BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Registers a disposable for release in <see cref="DisposeRentals"/> and returns it, so a test body holds its
    /// matrices and rentals without using declarations.
    /// </summary>
    /// <typeparam name="T">The disposable type.</typeparam>
    /// <param name="disposable">The disposable to release after the test.</param>
    /// <returns>The same disposable.</returns>
    private T Track<T>(T disposable) where T : IDisposable
    {
        Disposables.Add(disposable);

        return disposable;
    }
}
