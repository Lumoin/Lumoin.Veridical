using CsCheck;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core.Algebraic;
using System;
using OsShake256 = System.Security.Cryptography.Shake256;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Tests for the managed <see cref="ManagedShake256"/> XOF that backs the
/// <c>BLS12-381-SHAKE-256</c> ciphersuite on platforms whose native
/// cryptography provider lacks SHA-3 (notably macOS).
/// </summary>
/// <remarks>
/// Two gates. <see cref="EmptyInputMatchesFips202KnownAnswer"/> pins the
/// implementation to a published FIPS 202 vector and runs on every host.
/// <see cref="AgreesWithOsShakeOnRandomInputs"/> asserts byte-identity with
/// the OS XOF across random message and output lengths (so the multi-block
/// absorb and squeeze paths are covered); it runs only where the OS XOF
/// exists and is Inconclusive elsewhere — on those hosts the RFC 9380 K.6
/// and IETF BBS SHAKE-256 vectors exercise this path instead.
/// </remarks>
[TestClass]
internal sealed class ManagedShake256Tests
{
    //Largest random case sized so both outputs stay on the stack and the
    //input spans several 136-byte rate blocks.
    private const int MaximumRandomInputBytes = 400;
    private const int MaximumRandomOutputBytes = 400;
    private const int AgreementSampleCount = 100;


    [TestMethod]
    public void EmptyInputMatchesFips202KnownAnswer()
    {
        //FIPS 202 / NIST SHAKE256 of the empty message, first 32 squeezed bytes.
        const string ExpectedHex = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f";

        Span<byte> output = stackalloc byte[ExpectedHex.Length / 2];
        ManagedShake256.HashData(ReadOnlySpan<byte>.Empty, output);

        Assert.AreEqual(ExpectedHex, Convert.ToHexStringLower(output));
    }


    [TestMethod]
    public void EmptyInputMultiBlockSqueezeMatchesFips202KnownAnswer()
    {
        //Same empty message, squeezed past the 136-byte rate boundary to
        //exercise the squeeze-time permutation. First 64 bytes.
        const string ExpectedHex =
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f" +
            "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be";

        Span<byte> output = stackalloc byte[ExpectedHex.Length / 2];
        ManagedShake256.HashData(ReadOnlySpan<byte>.Empty, output);

        Assert.AreEqual(ExpectedHex, Convert.ToHexStringLower(output));
    }


    [TestMethod]
    public void AgreesWithOsShakeOnRandomInputs()
    {
        if(!OsShake256.IsSupported)
        {
            Assert.Inconclusive("The OS SHAKE-256 XOF is not available on this host; the managed path is gated by the FIPS 202 and IETF BBS vectors instead.");
        }

        Gen.Select(Gen.Byte.Array[0, MaximumRandomInputBytes], Gen.Int[1, MaximumRandomOutputBytes])
            .Sample(((byte[] message, int outputLength) t) =>
            {
                Span<byte> managed = stackalloc byte[MaximumRandomOutputBytes];
                Span<byte> os = stackalloc byte[MaximumRandomOutputBytes];

                ManagedShake256.HashData(t.message, managed[..t.outputLength]);
                OsShake256.HashData(t.message, os[..t.outputLength]);

                return managed[..t.outputLength].SequenceEqual(os[..t.outputLength]);
            }, iter: AgreementSampleCount);
    }
}
