using Lumoin.Veridical.Core;
using System;
using System.Numerics;
using static Lumoin.Veridical.Core.Cryptography.ConstantTimeComparison;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The P-256 scalar and span validation shared by <see cref="SecdsaAlgorithm"/>,
/// <see cref="DlEqualityNizk"/>, and <see cref="EcdhMacAlgorithm"/>: one copy of the group-order
/// bytes and the <c>[1, n−1]</c> range check, so a fix or a curve generalization cannot land in a
/// subset of the protocol surfaces.
/// </summary>
/// <remarks>
/// The range check is branchless in the same sense as the callers document: <see cref="IsZero"/> and
/// <see cref="IsLess"/> inspect every byte with no data-dependent early exit, so a secret scalar does
/// not leak by where it first differs from the order.
/// </remarks>
internal static class P256ScalarValidation
{
    //The order n as a 32-byte big-endian scalar, used only for the public-order range checks. n is curve
    //definition data, not a secret.
    internal static byte[] OrderBytes { get; } = BuildOrderBytes();


    internal static void RequireScalarInRange(ReadOnlySpan<byte> scalar, string name)
    {
        if(IsZero(scalar) || !IsLess(scalar, OrderBytes))
        {
            throw new ArgumentException("The scalar must be in [1, n-1] for the P-256 group order.", name);
        }
    }


    internal static void RequireLength(ReadOnlySpan<byte> span, int expected, string name)
    {
        if(span.Length != expected)
        {
            throw new ArgumentException($"Expected {expected} bytes; received {span.Length}.", name);
        }
    }


    private static byte[] BuildOrderBytes()
    {
        BigInteger n = WellKnownCurves.GetScalarFieldOrder(CurveParameterSet.P256);
        byte[] big = n.ToByteArray(isUnsigned: true, isBigEndian: true);
        byte[] order = new byte[WellKnownCurves.P256ScalarSizeBytes];
        big.CopyTo(order.AsSpan(WellKnownCurves.P256ScalarSizeBytes - big.Length));

        return order;
    }
}
