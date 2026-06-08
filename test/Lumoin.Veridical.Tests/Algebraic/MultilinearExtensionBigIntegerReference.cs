using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Reference implementation of the BLS12-381 MLE delegates using
/// <see cref="BigInteger"/> arithmetic modulo the scalar field order
/// <c>r</c>. Serves as ground truth for cross-implementation tests.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="GetFold"/> returns the obvious scalar loop over the
/// <c>2^(n-1)</c> evaluation pairs. <see cref="GetEvaluate"/> rents a
/// scratch buffer from <see cref="SensitiveMemoryPool{T}.Shared"/> and
/// folds <c>n</c> times, copying the final element out to the result.
/// Operation counters are bumped at the entry of each delegate so
/// telemetry surfaces see the polynomial-layer cost.
/// </para>
/// <para>
/// The reference operates entirely in canonical big-endian byte form;
/// every read converts via <see cref="BigInteger(ReadOnlySpan{byte},
/// bool, bool)"/>, every write goes back through
/// <see cref="WriteCanonical"/>. The reference is not constant-time
/// and not intended to be — it is correctness-only, the standard
/// against which production backends are validated.
/// </para>
/// </remarks>
internal static class MultilinearExtensionBigIntegerReference
{
    //The MLE compute is curve-broad: the delegate carries the curve, and the
    //field order is selected from it. (The BLS12-381 reference and the BN254
    //reference both expose their scalar-field order as FieldOrder.)
    private static BigInteger FieldOrderFor(CurveParameterSet curve) =>
        curve.Code == CurveParameterSet.Bn254.Code
            ? Bn254BigIntegerScalarReference.FieldOrder
            : Bls12Curve381BigIntegerScalarReference.FieldOrder;


    /// <summary>Returns the reference MLE-fold delegate.</summary>
    public static MleFoldDelegate GetFold() => Fold;

    /// <summary>Returns the reference MLE-evaluate delegate.</summary>
    public static MleEvaluateDelegate GetEvaluate() => Evaluate;


    private static void Fold(
        ReadOnlySpan<byte> originalEvaluations,
        ReadOnlySpan<byte> challenge,
        Span<byte> foldedEvaluations,
        int variableCount,
        CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.MleFold, curve);

        ValidateFoldBuffers(originalEvaluations, challenge, foldedEvaluations, variableCount);

        int elementSize = Scalar.SizeBytes;
        BigInteger fieldOrder = FieldOrderFor(curve);
        BigInteger c = new(challenge, isUnsigned: true, isBigEndian: true);

        //(1 - c) mod r: compute as (r + 1 - c) mod r to keep intermediates non-negative.
        BigInteger oneMinusC = ((fieldOrder + BigInteger.One - c) % fieldOrder + fieldOrder) % fieldOrder;
        int pairCount = 1 << (variableCount - 1);

        for(int i = 0; i < pairCount; i++)
        {
            int leftOffset = 2 * i * elementSize;
            int rightOffset = (2 * i + 1) * elementSize;
            BigInteger left = new(originalEvaluations.Slice(leftOffset, elementSize), isUnsigned: true, isBigEndian: true);
            BigInteger right = new(originalEvaluations.Slice(rightOffset, elementSize), isUnsigned: true, isBigEndian: true);

            BigInteger folded = ((oneMinusC * left) + (c * right)) % fieldOrder;
            WriteCanonical(folded, foldedEvaluations.Slice(i * elementSize, elementSize));
        }
    }


    private static void Evaluate(
        ReadOnlySpan<byte> evaluations,
        ReadOnlySpan<byte> point,
        Span<byte> result,
        int variableCount,
        CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.MleEvaluate, curve);

        int elementSize = Scalar.SizeBytes;
        int evaluationCount = 1 << variableCount;
        if(evaluations.Length != evaluationCount * elementSize)
        {
            throw new ArgumentException(
                $"Evaluations span must be {evaluationCount * elementSize} bytes for variableCount = {variableCount}; received {evaluations.Length}.",
                nameof(evaluations));
        }

        if(point.Length != variableCount * elementSize)
        {
            throw new ArgumentException(
                $"Point span must be {variableCount * elementSize} bytes for variableCount = {variableCount}; received {point.Length}.",
                nameof(point));
        }

        if(result.Length != elementSize)
        {
            throw new ArgumentException(
                $"Result span must be {elementSize} bytes; received {result.Length}.",
                nameof(result));
        }

        if(variableCount == 0)
        {
            //An MLE in zero variables has a single evaluation; that is the answer.
            evaluations.CopyTo(result);
            return;
        }

        //Two ping-pong buffers: copy evaluations into one, fold variableCount
        //times alternating writes, copy the final single element out.
        int maxBufferSize = evaluationCount * elementSize;
        using IMemoryOwner<byte> bufferAOwner = SensitiveMemoryPool<byte>.Shared.Rent(maxBufferSize);
        using IMemoryOwner<byte> bufferBOwner = SensitiveMemoryPool<byte>.Shared.Rent(maxBufferSize / 2);

        Span<byte> bufferA = bufferAOwner.Memory.Span[..maxBufferSize];
        evaluations.CopyTo(bufferA);

        Span<byte> currentSource = bufferA;
        Span<byte> currentDestination = bufferBOwner.Memory.Span[..(maxBufferSize / 2)];
        int currentVariableCount = variableCount;
        BigInteger fieldOrder = FieldOrderFor(curve);

        for(int round = 0; round < variableCount; round++)
        {
            int roundedSourceLength = (1 << currentVariableCount) * elementSize;
            int roundedDestinationLength = (1 << (currentVariableCount - 1)) * elementSize;
            ReadOnlySpan<byte> challenge = point.Slice(round * elementSize, elementSize);

            FoldInternal(
                currentSource[..roundedSourceLength],
                challenge,
                currentDestination[..roundedDestinationLength],
                currentVariableCount,
                fieldOrder);

            //Swap: the new destination becomes the next source. Both buffers are
            //the same size class so a swap is just span juggling.
            Span<byte> next = currentSource;
            currentSource = currentDestination;
            currentDestination = next;
            currentVariableCount--;
        }

        //After variableCount rounds, currentSource holds one element — the result.
        currentSource[..elementSize].CopyTo(result);
    }


    /// <summary>The fold body without the counter increment, used by <see cref="Evaluate"/> so the per-element folds inside one MleEvaluate do not double-count.</summary>
    private static void FoldInternal(
        ReadOnlySpan<byte> originalEvaluations,
        ReadOnlySpan<byte> challenge,
        Span<byte> foldedEvaluations,
        int variableCount,
        BigInteger fieldOrder)
    {
        int elementSize = Scalar.SizeBytes;
        BigInteger c = new(challenge, isUnsigned: true, isBigEndian: true);
        BigInteger oneMinusC = ((fieldOrder + BigInteger.One - c) % fieldOrder + fieldOrder) % fieldOrder;
        int pairCount = 1 << (variableCount - 1);

        for(int i = 0; i < pairCount; i++)
        {
            int leftOffset = 2 * i * elementSize;
            int rightOffset = (2 * i + 1) * elementSize;
            BigInteger left = new(originalEvaluations.Slice(leftOffset, elementSize), isUnsigned: true, isBigEndian: true);
            BigInteger right = new(originalEvaluations.Slice(rightOffset, elementSize), isUnsigned: true, isBigEndian: true);

            BigInteger folded = ((oneMinusC * left) + (c * right)) % fieldOrder;
            WriteCanonical(folded, foldedEvaluations.Slice(i * elementSize, elementSize));
        }
    }


    private static void ValidateFoldBuffers(
        ReadOnlySpan<byte> originalEvaluations,
        ReadOnlySpan<byte> challenge,
        Span<byte> foldedEvaluations,
        int variableCount)
    {
        if(variableCount < 1)
        {
            throw new ArgumentException(
                $"Fold requires variableCount >= 1; received {variableCount}.",
                nameof(variableCount));
        }

        int elementSize = Scalar.SizeBytes;
        int originalCount = 1 << variableCount;
        int foldedCount = 1 << (variableCount - 1);

        if(originalEvaluations.Length != originalCount * elementSize)
        {
            throw new ArgumentException(
                $"Original-evaluations span must be {originalCount * elementSize} bytes for variableCount = {variableCount}; received {originalEvaluations.Length}.",
                nameof(originalEvaluations));
        }

        if(foldedEvaluations.Length != foldedCount * elementSize)
        {
            throw new ArgumentException(
                $"Folded-evaluations span must be {foldedCount * elementSize} bytes for variableCount = {variableCount}; received {foldedEvaluations.Length}.",
                nameof(foldedEvaluations));
        }

        if(challenge.Length != elementSize)
        {
            throw new ArgumentException(
                $"Challenge span must be {elementSize} bytes; received {challenge.Length}.",
                nameof(challenge));
        }
    }


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Reduced scalar did not fit in the canonical span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}