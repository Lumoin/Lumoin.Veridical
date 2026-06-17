using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers.Binary;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// Test-project-only deterministic <see cref="ScalarRandomDelegate"/>
/// keyed by a fixed seed. Each call to the returned delegate consumes
/// the next 64 bytes of a BLAKE3-XOF stream and reduces them to a
/// canonical scalar for the operand's curve (the field order is selected
/// from the <see cref="CurveParameterSet"/> the delegate is invoked with).
/// </summary>
/// <remarks>
/// <para>
/// Used by the fixture tests so the prover's per-proof Hyrax blinding
/// factors are reproducible: two invocations with the same seed
/// produce byte-identical proofs. Production code never uses this —
/// the real <see cref="ScalarRandomDelegate"/> draws from
/// <see cref="System.Security.Cryptography.RandomNumberGenerator"/>.
/// </para>
/// <para>
/// Stream construction: for each call, hash <c>seed || counter_BE_4</c>
/// via BLAKE3 in XOF mode to produce 64 bytes, reduce modulo the
/// scalar field order. The counter increments per call so successive
/// scalars are independent.
/// </para>
/// </remarks>
internal sealed class DeterministicScalarRandom
{
    private readonly byte[] seed;
    private int counter;


    public DeterministicScalarRandom(ReadOnlySpan<byte> seed)
    {
        this.seed = seed.ToArray();
        this.counter = 0;
    }


    //The scalar field order is selected from the operand curve so the helper
    //reduces into the correct field for whichever wired curve invokes it.
    private static BigInteger FieldOrderFor(CurveParameterSet curve) =>
        curve.Code == CurveParameterSet.Bn254.Code
            ? Bn254BigIntegerScalarReference.FieldOrder
            : Bls12Curve381BigIntegerScalarReference.FieldOrder;


    /// <summary>Returns the delegate. Each call consumes one 32-byte scalar from the stream.</summary>
    public ScalarRandomDelegate AsDelegate() => Fill;


    private Tag Fill(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
    {
        //Produce 64 wide bytes via BLAKE3-XOF keyed by seed || counter.
        Span<byte> input = stackalloc byte[seed.Length + sizeof(int)];
        seed.AsSpan().CopyTo(input);
        BinaryPrimitives.WriteInt32BigEndian(input[seed.Length..], counter);
        counter++;

        Span<byte> wide = stackalloc byte[64];
        Lumoin.Veridical.Hashing.Blake3.Hash(input, wide);

        //Reduce the 64-byte stream to a canonical scalar via BigInteger
        //modular reduction; bias is bounded by 2^-256, negligible for
        //test-only use.
        BigInteger fieldOrder = FieldOrderFor(curve);
        BigInteger value = new(wide, isUnsigned: true, isBigEndian: true);
        BigInteger reduced = ((value % fieldOrder) + fieldOrder) % fieldOrder;

        destination.Clear();
        if(!reduced.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Reduced scalar did not fit in the canonical span.");
        }
        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }


        return inboundTag;
    }
}