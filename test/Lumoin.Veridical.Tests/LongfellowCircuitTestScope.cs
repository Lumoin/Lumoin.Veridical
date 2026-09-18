using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;
using System;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests;

/// <summary>Bounds compiler, circuit and witness rentals to one test, including failed assertions and discarded results.</summary>
internal sealed class LongfellowCircuitTestScope: IDisposable
{
    /// <summary>The test's independent pool, disposed after every owner.</summary>
    private BaseMemoryPool OwnedPool { get; } = new();

    /// <summary>The owners in creation order, released in reverse order.</summary>
    private List<IDisposable> Owners { get; } = [];

    /// <summary>Whether this scope's owners and pool have been released.</summary>
    private bool isDisposed;

    /// <summary>The test's independent pool, valid until scope disposal.</summary>
    public BaseMemoryPool Pool => OwnedPool;

    /// <summary>The lazily allocated owner of scalar expectations retained by this test.</summary>
    private LongfellowCircuitStorage? scalarStorage;

    /// <summary>Embeds a scalar into test-owned storage, including values retained by coefficient arrays.</summary>
    /// <param name="field">The live field defining the scalar embedding.</param>
    /// <param name="scalar">The scalar to embed.</param>
    /// <returns>The canonical scalar borrowed until scope disposal.</returns>
    public ReadOnlyMemory<byte> OfScalar(LongfellowLogicFieldOperations field, ulong scalar)
    {
        scalarStorage ??= Track(new LongfellowCircuitStorage(OwnedPool));
        Memory<byte> value = scalarStorage.Allocate(Scalar.SizeBytes);
        field.OfScalar(scalar, value.Span);

        return value;
    }

    /// <summary>Constructs and retains a compiler using this test's pool.</summary>
    /// <param name="field">The compiler field operations.</param>
    /// <returns>The compiler, disposed with this scope.</returns>
    public LongfellowQuadCircuitBuilder CreateBuilder(LongfellowCompilerFieldOperations field)
    {
        return Track(new LongfellowQuadCircuitBuilder(field));
    }

    /// <summary>Compiles and retains a circuit independently of the builder's lifetime.</summary>
    /// <param name="builder">The compiler producing the circuit.</param>
    /// <param name="copyCount">The circuit copy count.</param>
    /// <param name="hashFactory">The structural identifier hash factory.</param>
    /// <returns>The circuit, disposed with this scope.</returns>
    public LongfellowSumcheckCircuit Compile(LongfellowQuadCircuitBuilder builder, int copyCount, LongfellowIncrementalHashFactory hashFactory)
    {
        return Track(builder.MakeCircuit(copyCount, hashFactory));
    }

    /// <summary>Copies a fixture circuit's identifier and coefficients into test-owned pooled storage.</summary>
    /// <param name="outputCount">The output count.</param>
    /// <param name="outputLogCount">The output binding rounds.</param>
    /// <param name="copyCount">The copy count.</param>
    /// <param name="copyRounds">The copy binding rounds.</param>
    /// <param name="inputCount">The input count.</param>
    /// <param name="publicInputCount">The public input count.</param>
    /// <param name="id">The fixture identifier.</param>
    /// <param name="layers">The fixture layers.</param>
    /// <returns>The circuit, disposed with this scope.</returns>
    public LongfellowSumcheckCircuit CreateCircuit(int outputCount, int outputLogCount, int copyCount, int copyRounds, int inputCount, int publicInputCount, ReadOnlyMemory<byte> id, LongfellowSumcheckLayer[] layers)
    {
        return Track(new LongfellowSumcheckCircuit(outputCount, outputLogCount, copyCount, copyRounds, inputCount, publicInputCount, id, layers, OwnedPool));
    }

    /// <summary>Parses and retains any successful result, including results a rejection test discards.</summary>
    /// <param name="bytes">The serialized bytes.</param>
    /// <param name="fieldId">The expected field identifier.</param>
    /// <param name="elementBytes">The serialized element width.</param>
    /// <param name="circuit">Receives the parsed circuit, borrowed until scope disposal.</param>
    /// <param name="subfieldBoundary">Receives the subfield boundary.</param>
    /// <param name="bytesConsumed">Receives the consumed byte count.</param>
    /// <param name="constantRange">The optional canonical constant predicate.</param>
    /// <returns>Whether parsing succeeded.</returns>
    public bool TryRead(ReadOnlySpan<byte> bytes, int fieldId, int elementBytes, out LongfellowSumcheckCircuit? circuit, out int subfieldBoundary, out int bytesConsumed, LongfellowCanonicalRangeDelegate? constantRange = null)
    {
        bool parsed = LongfellowCircuitReader.TryRead(bytes, fieldId, elementBytes, OwnedPool, out circuit, out subfieldBoundary, out bytesConsumed, constantRange);
        if(circuit is not null)
        {
            Track(circuit);
        }

        return parsed;
    }

    /// <summary>Lifts and retains an independent circuit copy.</summary>
    /// <param name="circuit">The source circuit.</param>
    /// <param name="toWorking">The coefficient converter.</param>
    /// <returns>The lifted circuit, disposed with this scope.</returns>
    public LongfellowSumcheckCircuit Lift(LongfellowSumcheckCircuit circuit, LongfellowDomainConvertDelegate toWorking)
    {
        return Track(circuit.LiftCoefficientsToWorking(toWorking));
    }

    /// <summary>Constructs and retains a witness generator using the supplied field's originating pool.</summary>
    /// <param name="field">The field bundle borrowed for the generator's lifetime.</param>
    /// <param name="orderMultiply">The canonical order-field multiplication.</param>
    /// <param name="orderSubtract">The canonical order-field subtraction.</param>
    /// <param name="orderInvert">The canonical order-field inversion.</param>
    /// <param name="orderCurve">The order-field curve parameter set.</param>
    /// <param name="curve">The curve constants borrowed for the generator's lifetime.</param>
    /// <returns>The generator borrowed until this test scope is disposed.</returns>
    public LongfellowEcdsaVerifyWitness CreateEcdsaWitness(
        LongfellowLogicFieldOperations field,
        ScalarMultiplyDelegate orderMultiply,
        ScalarSubtractDelegate orderSubtract,
        ScalarInvertDelegate orderInvert,
        CurveParameterSet orderCurve,
        LongfellowEllipticCurveParameters curve)
    {
        LongfellowEcdsaVerifyWitness? owner = new(field, orderMultiply, orderSubtract, orderInvert, orderCurve, curve);
        try
        {
            LongfellowEcdsaVerifyWitness witness = Track(owner);
            owner = null;

            return witness;
        }
        finally
        {
            owner?.Dispose();
        }
    }

    /// <summary>Constructs and retains a witness generator using the supplied field's originating pool.</summary>
    /// <param name="field">The field bundle borrowed for the generator's lifetime.</param>
    /// <param name="orderMultiply">The canonical order-field multiplication.</param>
    /// <param name="orderSubtract">The canonical order-field subtraction.</param>
    /// <param name="orderInvert">The canonical order-field inversion.</param>
    /// <param name="orderCurve">The order-field curve parameter set.</param>
    /// <param name="curve">The curve constants borrowed for the generator's lifetime.</param>
    /// <param name="maxShaBlocks">The preimage capacity in SHA-256 blocks.</param>
    /// <returns>The generator borrowed until this test scope is disposed.</returns>
    public LongfellowJwtWitness CreateJwtWitness(
        LongfellowLogicFieldOperations field,
        ScalarMultiplyDelegate orderMultiply,
        ScalarSubtractDelegate orderSubtract,
        ScalarInvertDelegate orderInvert,
        CurveParameterSet orderCurve,
        LongfellowEllipticCurveParameters curve,
        int maxShaBlocks)
    {
        LongfellowJwtWitness? owner = new(field, orderMultiply, orderSubtract, orderInvert, orderCurve, curve, maxShaBlocks);
        try
        {
            LongfellowJwtWitness witness = Track(owner);
            owner = null;

            return witness;
        }
        finally
        {
            owner?.Dispose();
        }
    }

    /// <summary>Constructs and retains a witness generator using the supplied field's originating pool.</summary>
    /// <param name="field">The field bundle borrowed for the generator's lifetime.</param>
    /// <param name="orderMultiply">The canonical order-field multiplication.</param>
    /// <param name="orderSubtract">The canonical order-field subtraction.</param>
    /// <param name="orderInvert">The canonical order-field inversion.</param>
    /// <param name="orderCurve">The order-field curve parameter set.</param>
    /// <param name="curve">The curve constants borrowed for the generator's lifetime.</param>
    /// <returns>The generator borrowed until this test scope is disposed.</returns>
    public LongfellowMdocRevocationSpanWitness CreateRevocationSpanWitness(
        LongfellowLogicFieldOperations field,
        ScalarMultiplyDelegate orderMultiply,
        ScalarSubtractDelegate orderSubtract,
        ScalarInvertDelegate orderInvert,
        CurveParameterSet orderCurve,
        LongfellowEllipticCurveParameters curve)
    {
        LongfellowMdocRevocationSpanWitness? owner = new(field, orderMultiply, orderSubtract, orderInvert, orderCurve, curve);
        try
        {
            LongfellowMdocRevocationSpanWitness witness = Track(owner);
            owner = null;

            return witness;
        }
        finally
        {
            owner?.Dispose();
        }
    }

    /// <summary>Registers an owner or releases it if registration fails.</summary>
    /// <typeparam name="T">The disposable owner type.</typeparam>
    /// <param name="owner">The owner to register.</param>
    /// <returns>The registered owner.</returns>
    public T Track<T>(T owner) where T: IDisposable
    {
        try
        {
            ObjectDisposedException.ThrowIf(isDisposed, this);
            Owners.Add(owner);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>Releases every owner before disposing this test's pool. Repeated calls have no effect.</summary>
    public void Dispose()
    {
        if(isDisposed)
        {
            return;
        }

        isDisposed = true;
        for(int i = Owners.Count - 1; i >= 0; i--)
        {
            Owners[i].Dispose();
        }

        Owners.Clear();
        OwnedPool.Dispose();
    }
}
