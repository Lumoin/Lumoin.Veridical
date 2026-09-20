using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Provenance;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.ConstraintSystems;

/// <summary>
/// Pins the construction boundary of <see cref="RawR1csWitness.FromCanonical"/>. Each argument guard is reached with
/// an input that only that guard rejects, and each rejection is identified by its exact exception type, parameter
/// name and message: a missing pool, a byte length that is not a whole number of scalars, and a witness with no
/// variables. A caller-supplied tag is merged under the witness role and curve, so its other entries survive.
/// </summary>
[TestClass]
internal sealed class RawR1csWitnessTests
{
    /// <summary>The 32-byte canonical scalar width of the BLS12-381 witness material.</summary>
    private const int ScalarSize = WellKnownCurves.Bls12Curve381ScalarSizeBytes;

    /// <summary>A witness of one variable, the smallest variable count the construction accepts.</summary>
    private const int SingleWitnessVariable = 1;

    /// <summary>No bytes after the whole scalars, so the buffer length is an exact multiple of the scalar width.</summary>
    private const int NoTrailingBytes = 0;

    /// <summary>One byte past a whole scalar, which leaves the floored variable count at one.</summary>
    private const int TrailingPartialScalarBytes = 1;

    /// <summary>The length of one whole scalar and one trailing byte, strictly between one and two scalars.</summary>
    private const int ByteLengthBetweenWholeScalars = (SingleWitnessVariable * ScalarSize) + TrailingPartialScalarBytes;

    /// <summary>A fixed fill stream selector, so every run builds the same canonical witness scalars.</summary>
    private const int WitnessFillSalt = 7;

    /// <summary>The name of the pool parameter, which the null-pool guard reports.</summary>
    private const string PoolParameterName = "pool";

    /// <summary>The name of the witness bytes parameter, which the length and count guards report.</summary>
    private const string WitnessBytesParameterName = "witnessBytes";

    /// <summary>The operation name a caller records in the tag it supplies.</summary>
    private const string CallerOperationName = "ImportWitness";


    /// <summary>The curve whose scalar field holds the witness material.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;

    /// <summary>A curve other than the witness curve, recorded in the caller's tag so the merge has a curve entry to replace.</summary>
    private static CurveParameterSet CallerCurve { get; } = CurveParameterSet.Bn254;

    /// <summary>The BLS12-381 scalar-reduction backend that fills canonical witness scalars.</summary>
    private static ScalarReduceDelegate Reduce { get; } = TestScalarBackends.Bls12Curve381.Reduce;

    /// <summary>
    /// The provenance entry a caller records in the tag it supplies. <see cref="ProviderOperation"/> is a record
    /// struct, so it is held in a get-only property rather than a constant.
    /// </summary>
    private static ProviderOperation CallerOperation { get; } = new(CallerOperationName);


    /// <summary>The pooled rentals opened during a test, released together in cleanup.</summary>
    private List<IDisposable> Disposables { get; } = [];


    /// <summary>Disposes every rental the test opened, most recent first.</summary>
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
    /// A null pool is rejected with an <see cref="ArgumentNullException"/> naming the pool. The witness bytes are one
    /// whole canonical scalar, so the length, count and canonicity guards all admit them and only the pool guard can
    /// reject the call. Without that guard the call reaches the rental of the backing buffer and fails there with a
    /// <see cref="NullReferenceException"/>, which the exact exception type check rejects.
    /// </summary>
    [TestMethod]
    public void FromCanonicalRejectsNullPoolNamingThePool()
    {
        Memory<byte> bytes = RentCanonicalScalars(SingleWitnessVariable, NoTrailingBytes);

        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(
            () => RawR1csWitness.FromCanonical(bytes.Span, Curve, null!).Dispose());

        Assert.AreEqual(PoolParameterName, exception.ParamName);
    }


    /// <summary>
    /// A byte length strictly between one and two scalars is rejected with an <see cref="ArgumentException"/> on the
    /// witness bytes whose message states the length and the scalar width. The floored variable count of that length
    /// is one and its leading scalar is canonical, so the count and canonicity guards both admit it: only the length
    /// guard rejects it, and without that guard the call returns a witness whose buffer carries the partial trailing
    /// byte. A length below one scalar is not used, because the count guard would reject it as well.
    /// </summary>
    [TestMethod]
    public void FromCanonicalRejectsByteLengthBetweenWholeScalars()
    {
        Memory<byte> bytes = RentCanonicalScalars(SingleWitnessVariable, TrailingPartialScalarBytes);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => RawR1csWitness.FromCanonical(bytes.Span, Curve, BaseMemoryPool.Shared).Dispose());

        Assert.AreEqual(WitnessBytesParameterName, exception.ParamName);
        Assert.Contains($"Witness byte length {ByteLengthBetweenWholeScalars} must be a multiple of the scalar size {ScalarSize}.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// An empty witness is rejected with exactly an <see cref="ArgumentException"/> on the witness bytes whose message
    /// states that at least one witness variable is required. Zero bytes are a whole multiple of the scalar width and
    /// give the canonicity check no scalar to inspect, so only the count guard rejects the input. Without that guard
    /// the pool refuses the zero-byte rental with an <see cref="ArgumentOutOfRangeException"/>, a derived type that
    /// the exact exception type check rejects. The empty span is passed directly, because the pool cannot rent a
    /// zero-byte buffer.
    /// </summary>
    [TestMethod]
    public void FromCanonicalRejectsEmptyWitnessBytes()
    {
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => RawR1csWitness.FromCanonical(ReadOnlySpan<byte>.Empty, Curve, BaseMemoryPool.Shared).Dispose());

        Assert.AreEqual(WitnessBytesParameterName, exception.ParamName);
        Assert.Contains("RawR1csWitness requires at least one witness variable.", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A caller-supplied tag is merged rather than replaced: the witness tag keeps the caller's provenance entry, and
    /// the witness role and curve replace the scalar role and the other curve the caller recorded. A tag built from the
    /// role and curve alone has no provenance entry, so the provenance assertion tells a merge from a rebuild.
    /// </summary>
    [TestMethod]
    public void FromCanonicalMergesCallerTagUnderWitnessRoleAndCurve()
    {
        Memory<byte> bytes = RentCanonicalScalars(SingleWitnessVariable, NoTrailingBytes);
        Tag callerTag = Tag.Create(AlgebraicRole.Scalar)
            .With(CallerCurve)
            .With(CallerOperation);

        using RawR1csWitness witness = RawR1csWitness.FromCanonical(bytes.Span, Curve, BaseMemoryPool.Shared, callerTag);

        Assert.IsTrue(witness.Tag.TryGet(out ProviderOperation operation), "The caller's provenance entry must survive the merge.");
        Assert.AreEqual(CallerOperation, operation);
        Assert.AreEqual(AlgebraicRole.RawR1csWitness, witness.Tag.Get<AlgebraicRole>(), "The witness role must replace the caller's scalar role.");
        Assert.AreEqual(Curve, witness.Tag.Get<CurveParameterSet>(), "The witness curve must replace the caller's curve entry.");
    }


    /// <summary>
    /// Rents a pooled buffer of <paramref name="scalarCount"/> whole scalars followed by
    /// <paramref name="trailingBytes"/> further bytes, tracks the rental for cleanup, fills the whole scalars with
    /// deterministic canonical BLS12-381 scalars and clears the trailing bytes. The buffer is sliced to exactly the
    /// requested length, because the length guard reads the span length, and it is returned as
    /// <see cref="Memory{T}"/> because the assertion lambdas capture it where they cannot capture a stack span.
    /// </summary>
    /// <param name="scalarCount">The number of whole canonical scalars at the start of the buffer.</param>
    /// <param name="trailingBytes">The number of zero bytes after the whole scalars.</param>
    /// <returns>The filled buffer, exactly <paramref name="scalarCount"/> scalars and <paramref name="trailingBytes"/> bytes long.</returns>
    private Memory<byte> RentCanonicalScalars(int scalarCount, int trailingBytes)
    {
        int scalarBytes = scalarCount * ScalarSize;
        int length = scalarBytes + trailingBytes;
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        Disposables.Add(owner);

        Memory<byte> bytes = owner.Memory[..length];
        DeterministicScalarFill.FillCanonical(bytes.Span[..scalarBytes], WitnessFillSalt, Reduce, Curve);
        bytes.Span[scalarBytes..].Clear();

        return bytes;
    }
}
