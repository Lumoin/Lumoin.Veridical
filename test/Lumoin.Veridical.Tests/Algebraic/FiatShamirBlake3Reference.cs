using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Reference backend for the Fiat-Shamir transcript's hash and squeeze
/// delegates, wrapping the managed <see cref="Lumoin.Veridical.Hashing.Blake3"/>
/// implementation. Earlier batches wrapped the xoofx <c>Blake3</c>
/// NuGet package; the managed implementation is byte-faithful with the
/// upstream reference, so the swap is transparent to every transcript
/// consumer.
/// </summary>
/// <remarks>
/// <para>
/// Both delegates dispatch to the same
/// <see cref="Lumoin.Veridical.Hashing.Blake3.Hash(System.ReadOnlySpan{byte}, System.Span{byte})"/>
/// overload. When the destination is exactly 32 bytes that overload
/// computes the standard fixed-output BLAKE3 hash; for any other length
/// it switches to the XOF mode internally. The transcript treats the
/// two as a logical hash and squeeze pair, but the API does not
/// distinguish them — a 32-byte squeeze and a 32-byte hash of the same
/// input return the same bytes, exactly as the BLAKE3 spec requires.
/// </para>
/// <para>
/// Backends for other hash functions land later as parallel reference
/// implementations; this one fails fast with
/// <see cref="System.NotSupportedException"/> for anything other than
/// BLAKE3 so a mis-wired test surfaces the misconfiguration immediately.
/// </para>
/// </remarks>
internal static class FiatShamirBlake3Reference
{
    //Promoted to production as Lumoin.Veridical.Backends.Managed
    //.Blake3FiatShamirBackend; this test alias forwards so the suite keeps
    //its established name while exercising the shipped implementation.

    /// <summary>Returns the fixed-output hash delegate.</summary>
    public static FiatShamirHashDelegate GetHash() => Lumoin.Veridical.Backends.Managed.Blake3FiatShamirBackend.GetHash();

    /// <summary>Returns the XOF-mode squeeze delegate.</summary>
    public static FiatShamirSqueezeDelegate GetSqueeze() => Lumoin.Veridical.Backends.Managed.Blake3FiatShamirBackend.GetSqueeze();
}