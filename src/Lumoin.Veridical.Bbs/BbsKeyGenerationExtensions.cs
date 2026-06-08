using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Provenance;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// BBS+ key generation as an extension on <see cref="BbsCiphersuite"/>.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class BbsKeyGenerationExtensions
{
    extension(BbsCiphersuite ciphersuite)
    {
        /// <summary>
        /// Derives a fresh BBS+ key pair from <paramref name="keyMaterial"/>
        /// (the entropy source) and an optional <paramref name="keyInfo"/>
        /// (a domain-separation string the same key material can be
        /// re-used under), per IETF
        /// <c>draft-irtf-cfrg-bbs-signatures-10</c> Section 3.4.1.
        /// </summary>
        /// <param name="keyMaterial">The secret entropy bytes (at least 32 bytes per the spec).</param>
        /// <param name="keyInfo">An optional key-info string (up to 65535 bytes).</param>
        /// <param name="hashToScalar">Backend implementation of hash-to-scalar (reference: <c>Bls12Curve381BigIntegerScalarReference.GetHashToScalar()</c>).</param>
        /// <param name="g2ScalarMultiply">Backend implementation of G2 scalar multiplication.</param>
        /// <param name="pool">The pool to rent destination buffers from.</param>
        /// <returns>A freshly derived BBS+ key pair. The caller is responsible for disposing it.</returns>
        /// <exception cref="ArgumentNullException">When any required argument is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When <paramref name="keyMaterial"/> is shorter than 32 bytes or <paramref name="keyInfo"/> is longer than 65535 bytes.</exception>
        /// <remarks>
        /// KeyGen is deterministic: given the same <paramref name="keyMaterial"/>
        /// and <paramref name="keyInfo"/>, the same key pair is produced.
        /// The caller is responsible for sourcing sufficient entropy in
        /// <paramref name="keyMaterial"/>.
        /// </remarks>
        public BbsKeyPair Generate(
            ReadOnlySpan<byte> keyMaterial,
            ReadOnlySpan<byte> keyInfo,
            ScalarHashToScalarDelegate hashToScalar,
            G2ScalarMultiplyDelegate g2ScalarMultiply,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(hashToScalar);
            ArgumentNullException.ThrowIfNull(g2ScalarMultiply);
            ArgumentNullException.ThrowIfNull(pool);

            if(keyMaterial.Length < 32)
            {
                throw new ArgumentException("BBS+ key material must be at least 32 bytes per draft Section 3.4.1.", nameof(keyMaterial));
            }
            if(keyInfo.Length > 65535)
            {
                throw new ArgumentException("BBS+ key info must be at most 65535 bytes per draft Section 3.4.1.", nameof(keyInfo));
            }

            CryptographicOperationCounters.Increment(CryptographicOperationKind.BbsGenerate, CurveParameterSet.Bls12Curve381);

            //derive_input = key_material || I2OSP(length(key_info), 2) || key_info
            int deriveInputLength = keyMaterial.Length + 2 + keyInfo.Length;
            using IMemoryOwner<byte> deriveInputOwner = pool.Rent(deriveInputLength);
            Span<byte> deriveInput = deriveInputOwner.Memory.Span[..deriveInputLength];
            Span<byte> cursor = deriveInput;
            keyMaterial.CopyTo(cursor);
            cursor = cursor[keyMaterial.Length..];
            BinaryPrimitives.WriteUInt16BigEndian(cursor, (ushort)keyInfo.Length);
            cursor = cursor[2..];
            keyInfo.CopyTo(cursor);

            byte[] keyDst = BbsAlgorithm.ComputeDst(ciphersuite.Identifier, WellKnownBbsDomainSeparationTags.KeygenDstSuffix);
            using Scalar skScalar = Scalar.FromHashToScalar(deriveInput, keyDst, hashToScalar, CurveParameterSet.Bls12Curve381, pool);

            //Public key: PK = SK · BP2 (G2 generator).
            using G2Point g2 = G2Point.Generator(CurveParameterSet.Bls12Curve381, pool);
            using G2Point publicKeyPoint = g2.ScalarMultiply(skScalar, g2ScalarMultiply, pool);

            //Per IETF Section 3.4.1, both SK and PK are produced by a single
            //KeyGen call; both receive the same SignatureKeyGeneration
            //provenance stamping. The algebraic tag is keyed by the
            //ciphersuite (receiver) so the ciphersuite identifier travels
            //with the produced material.
            Tag skTag = ProviderInstrumentation.StampTag(
                BbsSecretKey.GetAlgebraicTag(ciphersuite),
                WellKnownBbsProviderIdentities.Library,
                WellKnownBbsProviderIdentities.Crypto,
                WellKnownBbsProviderIdentities.Class,
                ProviderOperation.SignatureKeyGeneration);
            Tag pkTag = ProviderInstrumentation.StampTag(
                BbsPublicKey.GetAlgebraicTag(ciphersuite),
                WellKnownBbsProviderIdentities.Library,
                WellKnownBbsProviderIdentities.Crypto,
                WellKnownBbsProviderIdentities.Class,
                ProviderOperation.SignatureKeyGeneration);

            //Wrap the SK bytes into a BbsSecretKey, the PK bytes into a BbsPublicKey.
            //Ownership transfers to the returned BbsKeyPair, whose Dispose releases both.
#pragma warning disable CA2000 //Disposed by the returned BbsKeyPair.
            IMemoryOwner<byte> skOwner = pool.Rent(BbsSecretKey.SizeBytes);
            skScalar.AsReadOnlySpan().CopyTo(skOwner.Memory.Span[..BbsSecretKey.SizeBytes]);
            BbsSecretKey secretKey = new(skOwner, skTag);

            IMemoryOwner<byte> pkOwner = pool.Rent(BbsPublicKey.SizeBytes);
            publicKeyPoint.AsReadOnlySpan().CopyTo(pkOwner.Memory.Span[..BbsPublicKey.SizeBytes]);
            BbsPublicKey publicKey = new(pkOwner, pkTag);
#pragma warning restore CA2000

            return new BbsKeyPair(secretKey, publicKey);
        }
    }
}