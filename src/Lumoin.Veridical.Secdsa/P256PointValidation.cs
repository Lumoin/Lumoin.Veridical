using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Security.Cryptography;
using static Lumoin.Veridical.Secdsa.P256ScalarValidation;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The P-256 point validation shared by every SECDSA surface that accepts a point from a counterparty:
/// the ECDH-MAC and ECIES key-agreement preparation, the transferable-proof challenge and response, and the
/// signature-result conformity check. One copy of the canonical-encoding and not-infinity rules means a fix or a
/// curve generalisation lands in every surface at once.
/// </summary>
/// <remarks>
/// On-curve membership is the injected group delegate's SEC1 decode contract: multiplying by one decodes the
/// point and re-encodes it, so an <c>x</c>-coordinate with no point on the curve makes the backend throw, and a
/// non-canonical encoding of a valid point re-encodes to different bytes and is rejected. P-256 has cofactor one,
/// so a finite on-curve point is in the prime-order subgroup.
/// </remarks>
internal static class P256PointValidation
{
    /// <summary>The P-256 SEC1 compressed point length.</summary>
    internal const int CompressedPointSizeBytes = WellKnownCurves.P256CompressedSizeBytes;

    //The low byte of the scalar one, used to decode-validate a point by multiplying it by one.
    private const byte ScalarOneLowByte = 0x01;

    //The SEC1 compressed-point prefix of the point at infinity.
    private const byte InfinityPrefix = 0x00;

    //The SEC1 compressed-point prefixes of a finite point: the parity of the y-coordinate.
    private const byte EvenYPrefix = 0x02;
    private const byte OddYPrefix = 0x03;

    private static CurveParameterSet Curve { get; } = CurveParameterSet.P256;


    /// <summary>
    /// Realizes <c>E ∈ ⟨G⟩</c>: rejects the encoded point at infinity, leaving on-curve membership to the group
    /// delegate's decode contract.
    /// </summary>
    /// <param name="compressedPoint">The point; at least one byte.</param>
    /// <param name="name">The parameter name reported in the exception.</param>
    /// <exception cref="ArgumentException">When the point encodes the point at infinity.</exception>
    internal static void RequireNotInfinity(ReadOnlySpan<byte> compressedPoint, string name)
    {
        if(compressedPoint[0] == InfinityPrefix)
        {
            throw new ArgumentException("The point encodes the point at infinity, which is not a member of the prime-order subgroup <G>.", name);
        }
    }


    /// <summary>
    /// Whether a span has the shape of a finite SEC1 compressed P-256 point: exactly 33 bytes with a parity prefix
    /// of <c>0x02</c> or <c>0x03</c>. A structural check only; on-curve membership needs the group delegate.
    /// </summary>
    /// <param name="point">The candidate encoding.</param>
    /// <returns><see langword="true"/> when the shape is that of a finite compressed point.</returns>
    internal static bool HasFinitePointShape(ReadOnlySpan<byte> point)
    {
        return point.Length == CompressedPointSizeBytes && (point[0] == EvenYPrefix || point[0] == OddYPrefix);
    }


    /// <summary>
    /// Validates a counterparty point and writes its canonical encoding: length, not infinity, on-curve through
    /// the delegate's decode contract, and canonical (the re-encoding equals the input).
    /// </summary>
    /// <param name="point">The point, SEC1 compressed (33 bytes).</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication, whose decode contract rejects off-curve points.</param>
    /// <param name="canonical">Receives the validated canonical 33-byte encoding.</param>
    /// <param name="name">The parameter name reported in an exception.</param>
    /// <exception cref="ArgumentException">When a span has the wrong length, the point encodes infinity, or it is not the canonical encoding of its point.</exception>
    /// <exception cref="InvalidOperationException">When the point is not on the curve (the backend's decode contract).</exception>
    internal static void ValidateCanonical(
        ReadOnlySpan<byte> point,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        Span<byte> canonical,
        string name)
    {
        RequireLength(point, CompressedPointSizeBytes, name);
        RequireLength(canonical, CompressedPointSizeBytes, nameof(canonical));
        RequireNotInfinity(point, name);

        Span<byte> one = stackalloc byte[WellKnownCurves.P256ScalarSizeBytes];
        one[^1] = ScalarOneLowByte;
        Span<byte> decoded = stackalloc byte[CompressedPointSizeBytes];
        g1ScalarMultiply(point, one, decoded, Curve);
        if(decoded[0] == InfinityPrefix || !CryptographicOperations.FixedTimeEquals(decoded, point))
        {
            throw new ArgumentException("The point is not the canonical encoding of a finite point on the curve.", name);
        }

        decoded.CopyTo(canonical);
    }


    /// <summary>
    /// The rejecting form of <see cref="ValidateCanonical"/> for verifier paths: a malformed, off-curve, infinity,
    /// or non-canonical point returns <see langword="false"/> instead of throwing.
    /// </summary>
    /// <param name="point">The point from the wire.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication, whose decode contract rejects off-curve points.</param>
    /// <returns><see langword="true"/> when the point is a canonical finite on-curve point.</returns>
    internal static bool IsValidCanonical(ReadOnlySpan<byte> point, G1ScalarMultiplyDelegate g1ScalarMultiply)
    {
        if(!HasFinitePointShape(point))
        {
            return false;
        }

        Span<byte> canonical = stackalloc byte[CompressedPointSizeBytes];
        try
        {
            ValidateCanonical(point, g1ScalarMultiply, canonical, nameof(point));

            return true;
        }
        catch(InvalidOperationException)
        {
            return false;
        }
        catch(ArgumentException)
        {
            return false;
        }
    }
}
