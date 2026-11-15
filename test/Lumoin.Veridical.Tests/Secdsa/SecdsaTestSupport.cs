using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Cryptography;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Secdsa;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers.Binary;
using System.Text;

namespace Lumoin.Veridical.Tests.Secdsa;

/// <summary>
/// The delegates and small helpers the SECDSA protocol tests share: the BigInteger reference scalar and group
/// arithmetic, SHA-256 as the Fiat-Shamir hash, RFC 6979 as the nonce source, and scalar and point derivation that
/// write into caller-supplied spans so the tests do not allocate buffers of their own.
/// </summary>
internal static class SecdsaTestSupport
{
    /// <summary>The P-256 scalar width in bytes.</summary>
    public const int ScalarSize = 32;

    /// <summary>The P-256 compressed point width in bytes.</summary>
    public const int PointSize = 33;

    /// <summary>The SHA-256 digest width in bytes.</summary>
    public const int DigestSize = 32;

    /// <summary>Scalar multiplication mod n.</summary>
    public static ScalarMultiplyDelegate ScalarMultiply { get; } = P256BigIntegerScalarReference.GetMultiply();

    /// <summary>Scalar addition mod n.</summary>
    public static ScalarAddDelegate ScalarAdd { get; } = P256BigIntegerScalarReference.GetAdd();

    /// <summary>Scalar inversion mod n.</summary>
    public static ScalarInvertDelegate ScalarInvert { get; } = P256BigIntegerScalarReference.GetInvert();

    /// <summary>Reduction mod n.</summary>
    public static ScalarReduceDelegate ScalarReduce { get; } = P256BigIntegerScalarReference.GetReduce();

    /// <summary>G1 scalar multiplication.</summary>
    public static G1ScalarMultiplyDelegate G1ScalarMultiply { get; } = P256BigIntegerG1Reference.GetScalarMultiply();

    /// <summary>G1 addition.</summary>
    public static G1AddDelegate G1Add { get; } = P256BigIntegerG1Reference.GetAdd();

    /// <summary>G1 negation.</summary>
    public static G1NegateDelegate G1Negate { get; } = P256BigIntegerG1Reference.GetNegate();

    /// <summary>The RFC 6979 nonce source over HMAC-SHA-256.</summary>
    public static SecdsaNonceSource NonceSource { get; } = Rfc6979SecdsaNonceSource.Create(Sha256Hmac.Compute);

    /// <summary>SHA-256 as the Fiat-Shamir hash.</summary>
    public static FiatShamirHashDelegate Hash { get; } = Sha256FiatShamir;

    /// <summary>HMAC-SHA-256.</summary>
    public static HmacSha256Delegate Hmac { get; } = Sha256Hmac.Compute;


    /// <summary>Derives a scalar in [1, n-1] from a label by hashing it and reducing mod n.</summary>
    /// <param name="label">The label.</param>
    /// <param name="scalar">Receives the 32-byte scalar.</param>
    public static void DeriveScalar(ReadOnlySpan<byte> label, Span<byte> scalar)
    {
        Span<byte> digest = stackalloc byte[DigestSize];
        Sha256.HashData(label, digest);
        ScalarReduce(digest, scalar, CurveParameterSet.P256);
        digest.Clear();
    }


    /// <summary>Computes the compressed public point <c>scalar·G</c>.</summary>
    /// <param name="scalar">The scalar.</param>
    /// <param name="point">Receives the 33-byte point.</param>
    public static void PublicPoint(ReadOnlySpan<byte> scalar, Span<byte> point)
    {
        Span<byte> generator = stackalloc byte[PointSize];
        WellKnownCurves.GetG1GeneratorCompressed(CurveParameterSet.P256).CopyTo(generator);
        G1ScalarMultiply(generator, scalar, point, CurveParameterSet.P256);
    }


    /// <summary>Computes <c>scalar·point</c>.</summary>
    /// <param name="point">The compressed point.</param>
    /// <param name="scalar">The scalar.</param>
    /// <param name="result">Receives the 33-byte product.</param>
    public static void Multiply(ReadOnlySpan<byte> point, ReadOnlySpan<byte> scalar, Span<byte> result)
    {
        G1ScalarMultiply(point, scalar, result, CurveParameterSet.P256);
    }


    /// <summary>Hashes a label with SHA-256 into a 32-byte message representative.</summary>
    /// <param name="label">The message.</param>
    /// <param name="digest">Receives the 32-byte digest.</param>
    public static void MessageHash(ReadOnlySpan<byte> label, Span<byte> digest)
    {
        Sha256.HashData(label, digest);
    }


    private static void Sha256FiatShamir(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction)
    {
        Sha256.HashData(input, output);
    }


    /// <summary>
    /// A deterministic entropy stream for tests: the blocks are <c>SHA-256(label ‖ counter)</c> for a counter that
    /// advances with every block, so a test that injects the same label obtains the same bytes. It is not a random
    /// source and exists only to make protocol output reproducible.
    /// </summary>
    internal sealed class DeterministicEntropy
    {
        private const int CounterSize = sizeof(int);

        private string Label { get; }

        private int Counter { get; set; }


        /// <summary>Creates a stream for a label.</summary>
        /// <param name="label">The label that fixes the stream.</param>
        public DeterministicEntropy(string label)
        {
            Label = label;
        }


        /// <summary>Fills the destination from the stream.</summary>
        /// <param name="destination">Receives the bytes.</param>
        public void Fill(Span<byte> destination)
        {
            Span<byte> input = stackalloc byte[Encoding.UTF8.GetMaxByteCount(Label.Length) + CounterSize];
            Span<byte> block = stackalloc byte[DigestSize];
            int written = 0;
            while(written < destination.Length)
            {
                int labelLength = Encoding.UTF8.GetBytes(Label, input);
                BinaryPrimitives.WriteInt32BigEndian(input.Slice(labelLength, CounterSize), Counter);
                Counter++;
                Sha256.HashData(input[..(labelLength + CounterSize)], block);
                int take = Math.Min(DigestSize, destination.Length - written);
                block[..take].CopyTo(destination[written..]);
                written += take;
            }
        }


        /// <summary>The entropy source delegate over this stream.</summary>
        public SecdsaEntropySource Source => Fill;
    }
}
