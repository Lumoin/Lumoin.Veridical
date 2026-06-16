using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Core.Diagnostics;

/// <summary>
/// Reports structural and canonical-form facts about a
/// <see cref="Scalar"/> without performing arithmetic.
/// </summary>
/// <remarks>
/// <para>
/// The inspector is a pure read-only verb: it observes the scalar through
/// the public read-only span and returns a single
/// <see cref="ScalarInspectionReport"/>. No backend delegates are called,
/// so the inspector runs in nanoseconds and is safe to use inside test
/// assertions, debugger displays, and post-mortem dumps where calling a
/// full backend would be inappropriate.
/// </para>
/// <para>
/// The report bundles every fact a debugger typically wants to see at
/// once: byte length, identity predicates, canonical-range predicate, and
/// a lowercase hex rendering of the bytes. Bundling them as one
/// <c>record</c> means callers do not pay per-call inspection cost when
/// they want to log or assert against several at once.
/// </para>
/// </remarks>
public static class Bls12Curve381ScalarInspector
{
    // Canonical big-endian encoding of the BLS12-381 scalar field order
    // r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001.
    // Used by IsInCanonicalRange to compare a scalar's bytes against r
    // lexicographically without paying a BigInteger conversion.
    private static readonly byte[] ScalarFieldOrderBytes =
    [
        0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48,
        0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
        0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe,
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01
    ];


    /// <summary>
    /// Inspects <paramref name="scalar"/> and returns the bundled report.
    /// </summary>
    /// <param name="scalar">The scalar to inspect.</param>
    /// <returns>The inspection report.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="scalar"/> is <see langword="null"/>.</exception>
    public static ScalarInspectionReport Inspect(Scalar scalar)
    {
        ArgumentNullException.ThrowIfNull(scalar);

        ReadOnlySpan<byte> bytes = scalar.AsReadOnlySpan();

        return new ScalarInspectionReport(
            ByteLength: bytes.Length,
            IsZero: scalar.IsZero,
            IsOne: scalar.IsOne,
            IsInCanonicalRange: IsInCanonicalRange(bytes),
            CanonicalHex: scalar.ToHexString());
    }


    private static bool IsInCanonicalRange(ReadOnlySpan<byte> bytes)
    {
        // Canonical range is [0, r). Compare bytes against r lexicographically
        // big-endian: the first byte where they differ decides the order. Ties
        // through every byte mean value == r, which is out of range.
        if(bytes.Length != ScalarFieldOrderBytes.Length)
        {
            // Conservative on unexpected lengths: the leaf type validates this
            // at construction, so reaching here means a caller passed a torn
            // span. Better to report "not canonical" than to claim canonical.
            return false;
        }

        for(int i = 0; i < bytes.Length; i++)
        {
            if(bytes[i] < ScalarFieldOrderBytes[i])
            {
                return true;
            }

            if(bytes[i] > ScalarFieldOrderBytes[i])
            {
                return false;
            }
        }


        return false;
    }
}


/// <summary>
/// Bundled facts about a single <see cref="Scalar"/>.
/// </summary>
/// <param name="ByteLength">Length in bytes of the scalar's canonical encoding. Always <see cref="Scalar.SizeBytes"/> for well-formed inputs; reported for explicit safety.</param>
/// <param name="IsZero">True when the scalar is the additive identity.</param>
/// <param name="IsOne">True when the scalar is the multiplicative identity.</param>
/// <param name="IsInCanonicalRange">True when the scalar's value is strictly less than the field order r. A scalar produced by a correct backend always satisfies this; a false result is a strong signal of a non-conformant entry path.</param>
/// <param name="CanonicalHex">Lowercase hexadecimal rendering of the canonical big-endian bytes.</param>
public sealed record ScalarInspectionReport(
    int ByteLength,
    bool IsZero,
    bool IsOne,
    bool IsInCanonicalRange,
    string CanonicalHex);