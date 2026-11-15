using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Secdsa;
using System;

namespace Lumoin.Veridical.Tests.Secdsa;

/// <summary>
/// Span-shaped entry points over the typed split-sign API of <see cref="SecdsaAlgorithm"/>: each method wraps its span
/// arguments in the tagged protocol values, calls the typed entry point, and copies the result out. The tests keep their
/// fixed byte vectors and call these, so every test exercises the typed API and the validation of the typed values.
/// </summary>
internal static class SecdsaTypedCalls
{
    private static BaseMemoryPool Pool { get; } = BaseMemoryPool.Shared;


    /// <summary>The typed phase one, with the blinded hash copied into <paramref name="blindedHash"/>.</summary>
    public static void PrepareSplitSign(
        ReadOnlySpan<byte> pinKey,
        ReadOnlySpan<byte> messageHash,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarInvertDelegate scalarInvert,
        ScalarReduceDelegate scalarReduce,
        Span<byte> blindedHash)
    {
        using PinKey pin = PinKey.FromCanonical(pinKey, Pool);
        using MessageHash hash = MessageHash.FromCanonical(messageHash, Pool);
        using BlindedHash blinded = SecdsaAlgorithm.PrepareSplitSign(pin, hash, scalarMultiply, scalarInvert, scalarReduce, Pool);
        blinded.AsReadOnlySpan().CopyTo(blindedHash);
    }


    /// <summary>The typed phase two, with the signature component <c>s</c> copied into <paramref name="s"/> and cleared when the completion is rejected.</summary>
    public static void CompleteSplitSign(
        ReadOnlySpan<byte> pinKey,
        ReadOnlySpan<byte> messageHash,
        ReadOnlySpan<byte> publicKeyCompressed,
        ReadOnlySpan<byte> r,
        ReadOnlySpan<byte> rawS,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarInvertDelegate scalarInvert,
        ScalarReduceDelegate scalarReduce,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1AddDelegate g1Add,
        Span<byte> s)
    {
        try
        {
            using PinKey pin = PinKey.FromCanonical(pinKey, Pool);
            using MessageHash hash = MessageHash.FromCanonical(messageHash, Pool);
            using G1Point publicKey = G1Point.FromCanonical(publicKeyCompressed, CurveParameterSet.P256, Pool);
            Span<byte> raw = stackalloc byte[RawSignature.SizeBytes];
            r.CopyTo(raw);
            rawS.CopyTo(raw[RawSignature.RawSOffset..]);
            using RawSignature rawSignature = RawSignature.FromCanonical(raw, Pool);
            using SecdsaSignature signature = SecdsaAlgorithm.CompleteSplitSign(
                pin, hash, publicKey, rawSignature, scalarMultiply, scalarInvert, scalarReduce, g1ScalarMultiply, g1Add, Pool);
            signature.GetSBytes().CopyTo(s);
        }
        catch
        {
            s.Clear();
            throw;
        }
    }


    /// <summary>The typed software split sign, with <c>(r, s)</c> copied into the output spans and cleared on a failure.</summary>
    public static void SplitSign(
        ReadOnlySpan<byte> pinKey,
        ReadOnlySpan<byte> hardwareKey,
        ReadOnlySpan<byte> messageHash,
        SecdsaNonceSource nonceSource,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarAddDelegate scalarAdd,
        ScalarInvertDelegate scalarInvert,
        ScalarReduceDelegate scalarReduce,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1AddDelegate g1Add,
        Span<byte> r,
        Span<byte> s)
    {
        try
        {
            using SecdsaSignature signature = SplitSign(
                pinKey, hardwareKey, messageHash, nonceSource, scalarMultiply, scalarAdd, scalarInvert, scalarReduce, g1ScalarMultiply, g1Add, Pool);
            signature.GetRBytes().CopyTo(r);
            signature.GetSBytes().CopyTo(s);
        }
        catch
        {
            r.Clear();
            s.Clear();
            throw;
        }
    }


    /// <summary>The typed software split sign returning the pooled signature.</summary>
    public static SecdsaSignature SplitSign(
        ReadOnlySpan<byte> pinKey,
        ReadOnlySpan<byte> hardwareKey,
        ReadOnlySpan<byte> messageHash,
        SecdsaNonceSource nonceSource,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarAddDelegate scalarAdd,
        ScalarInvertDelegate scalarInvert,
        ScalarReduceDelegate scalarReduce,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1AddDelegate g1Add,
        BaseMemoryPool pool)
    {
        using PinKey pin = PinKey.FromCanonical(pinKey, pool);
        using PrivateScalar hardware = PrivateScalar.FromCanonical(hardwareKey, pool);
        using MessageHash hash = MessageHash.FromCanonical(messageHash, pool);

        return SecdsaAlgorithm.SplitSign(pin, hardware, hash, nonceSource, scalarMultiply, scalarAdd, scalarInvert, scalarReduce, g1ScalarMultiply, g1Add, pool);
    }


    /// <summary>The typed split sign over a raw-sign seam, with <c>(r, s)</c> copied into the output spans and cleared on a failure.</summary>
    public static void SplitSign(
        ReadOnlySpan<byte> pinKey,
        ReadOnlySpan<byte> messageHash,
        ReadOnlySpan<byte> publicKeyCompressed,
        SecdsaRawEcdsaSign rawSign,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarInvertDelegate scalarInvert,
        ScalarReduceDelegate scalarReduce,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1AddDelegate g1Add,
        Span<byte> r,
        Span<byte> s)
    {
        try
        {
            using PinKey pin = PinKey.FromCanonical(pinKey, Pool);
            using MessageHash hash = MessageHash.FromCanonical(messageHash, Pool);
            using G1Point publicKey = G1Point.FromCanonical(publicKeyCompressed, CurveParameterSet.P256, Pool);
            using SecdsaSignature signature = SecdsaAlgorithm.SplitSign(
                pin, hash, publicKey, rawSign, scalarMultiply, scalarInvert, scalarReduce, g1ScalarMultiply, g1Add, Pool);
            signature.GetRBytes().CopyTo(r);
            signature.GetSBytes().CopyTo(s);
        }
        catch
        {
            r.Clear();
            s.Clear();
            throw;
        }
    }
}
