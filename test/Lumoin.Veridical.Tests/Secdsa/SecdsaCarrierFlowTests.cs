using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Secdsa;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Text;

namespace Lumoin.Veridical.Tests.Secdsa;

/// <summary>
/// End-to-end SECDSA gate over P-256 driven through the broad, Tag-disciplined leaf carriers a real consumer uses
/// (<see cref="Scalar"/>, <see cref="G1Point"/>, <see cref="SecdsaSignature"/>, <see cref="DlEqualityProof"/>),
/// rather than the raw <c>byte[]</c> the other SECDSA gates use. The carrier construction factories
/// (<see cref="Scalar.FromRandom"/>, <see cref="Scalar.FromBytesReduced"/>, <see cref="G1Point.Generator"/>,
/// <see cref="G1Point.FromCanonical(System.ReadOnlySpan{byte}, CurveParameterSet, Lumoin.Base.BaseMemoryPool, Tag?)"/>)
/// resolve a per-curve algebraic-identity tag from <see cref="WellKnownAlgebraicTags"/>; this gate exercises that
/// path for P-256, which the raw-span gates never did — the omission that let a missing P-256 tag entry ship.
/// </summary>
/// <remarks>
/// <para>
/// This gate carries the full EUDI Wallet SECDSA flow narrative (Verheul, "An HSM-based EUDI wallet using
/// Split-ECDSA (SECDSA) providing verifiable sole control", version 11 October 2026 — the paper-map numbering below
/// follows that revision; the underlying construction is Verheul's "SECDSA: Mobile signing and authentication
/// under classical sole control", eprint 2021/910), so the cryptographic steps below read against the protocol
/// they implement. Every value crosses the WSCA surface as a tagged broad carrier; the mod-<c>n</c> scalar and group
/// arithmetic is wired from the BigInteger references, the same reuse-by-injection the other SECDSA gates use.
/// This library implements the WSCA-side cryptography only; the device raw-sign of <c>u</c>, the relying-party
/// exchange (OID4VP), and the application orchestration are out of scope (the boundary is stated in
/// <see cref="SecdsaEvidence"/>).
/// </para>
/// <code>
///  -- KEY TERMS -------------------------------------------------------------
///
///   SCI  = Secure Cryptographic Interface: the authenticated channel between the Wallet APP and the WSCA.
///   WSCA = Wallet Secure Cryptographic Application: the wallet provider's server-side trusted process that
///          authenticates signing instructions and gates the WSCD. A software container; no bespoke HSM firmware.
///   WSCD = Wallet Secure Cryptographic Device: the hardware holding the user blinding key aU (a PKCS#11 HSM or
///          a TPM with wrapped keys).
///   NCH  = Native Cryptographic Hardware: the on-device key store holding the user's signing key u (TPM on
///          Windows/Linux, Secure Enclave on iOS, StrongBox on Android).
///   PID  = Person Identification Data: the foundational identity credential a national authority issues to the
///          user, stored as a Verifiable Credential on the phone.
///   OID4VP = OpenID for Verifiable Presentations: how a relying party requests credentials from a wallet.
///   DCQL = Digital Credentials Query Language: the query inside an OID4VP request naming the wanted attributes.
///   KYC  = Know Your Customer: the regulatory duty to verify a customer's identity.
///
///  -- SYSTEM ARCHITECTURE ---------------------------------------------------
///
///   +---------------------------+              +--------------------------------+
///   |       Wallet APP          |     SCI      |        Wallet Provider         |
///   |                           |==============|  +----------+   +-----------+  |
///   |  PID credential           |              |  |  WSCA    |   |   WSCD    |  |
///   |  Internal Certificate     |              |  | (server, |   | (hardware)|  |
///   |  Transaction Log          |              |  | this lib)|   |  holds aU |  |
///   |  NCH holds u (possession) |              |  +----------+   +-----------+  |
///   |  PIN -> P     (knowledge) |              |  Transaction Log               |
///   +---------------------------+              +--------------------------------+
///
///   The wallet provider may be a government body (issues PID and runs the WSCA) or a private company (the state
///   issues PID, the company runs the WSCA). This library provides the WSCA-side implementation; a provider wires
///   its own device delegates and transport.
///
///  -- PARTIES IN THE SCENARIO ----------------------------------------------
///
///   +------------------+   issues PID    +------------------+
///   | National PID     | --------------- | Alice's wallet   |
///   | issuer (state)   |   (one-time,    | (Wallet APP +    |
///   | signs credential |    at issuance) |  NCH on phone)   |
///   +------------------+                 +--------+---------+
///                                                 | SCI (signing instruction)
///                                        +--------+---------+
///                                        | Wallet Provider  |
///                                        | (WSCA + WSCD)    |
///                                        +--------+---------+
///                                                 | InstructionTranscript
///                                                 v
///   +------------------+  OID4VP req     +------------------+   OID4VP VP    +-----------+
///   | Relying party    | --------------- | Alice's wallet   | -------------- | Relying   |
///   | (e.g. EudiBank,  |  (DCQL query    | assembles VP:    |               | party     |
///   |  KYC onboarding) |   for PID)      | PID + holder sig |               | verifies  |
///   +------------------+                 +------------------+               +-----------+
///
///  -- eIDAS HIGH: TWO-FACTOR AUTHENTICATION (factors must be independent) ---
///
///   Possession (required) : NCH-bound key u. Never leaves the NCH; proven by key attestation (EK/AK chain).
///                           TPM, Secure Enclave, HBK, StrongBox all qualify.
///   Knowledge (option A)  : PIN-key P, derived from the user's PIN + an NCH-bound binder key KP (Annex B
///                           Algorithms 24/25/27). One NCH call per attempt enforces lockout. Independent: the
///                           PIN alone cannot produce P without the NCH. (Spec 3.1)
///   Inherence (option B)  : P stored under biometric access control (Face ID / Touch ID / BiometricPrompt); the
///                           biometric unlocks P, the SECDSA math is identical. (Spec 3.2)
///
///  -- FLOW (what this gate exercises) --------------------------------------
///
///   SETUP step 1  PID issuance (state to wallet, one-time): NCH generates (u, U=u*G); wallet sends U plus a key
///                 attestation; the state signs { name, dob, nationality, holderPublicKey: U }. Wallet stores it.
///   SETUP step 2  WSCA activation (Protocol 1): wallet derives P and Y = P*U = P*u*G, blinds it (Ybl=t*Y), the
///                 WSCD blinds with aU (Y'bl=aU*Ybl), the wallet removes t (Y'=t^-1*Y'bl=aU*Y). The WSCA issues
///                 the Internal Certificate { AliceId, U, H, H'=aU*H, Y'=aU*Y } with H a wallet-specific base point.
///                 The raw Y is never stored.
///   SIGNING       (Algorithm 2) e=H(I); e'=P^-1*e; NCH raw-signs e' with u -> (r,s0); s=P*s0. The result (r,s)
///                 is ordinary ECDSA under Y though the NCH never saw P (Proposition 3.1). Recover R=k*G; from the
///                 certificate G''=s^-1*G, Y''=s^-1*Y'; a DL-equality proof shows they share s^-1 (Alg 3 Steps 6-7).
///   WSCA VERIFY   W = R - e*G'' and W' = r*Y'' = r*s^-1*aU*Y = aU*W (Algorithm 3 Step 8, Proposition 3.3). Equality holds
///                 exactly when the correct PIN was used: the AES-GCM key is derived from W', so a wrong PIN gives
///                 a wrong W', a wrong key, a failed tag, and the instruction is rejected without the WSCA ever
///                 learning the PIN.
///   CONTROL       A control DL-equality proof ZKP[(H,H'),(W,W'),H(T_I)] binds H'=aU*H and W'=aU*W to the
///                 transaction-record context N=H(T_I) (Equation 7, Algorithms 9/10): the irrefutable evidence of
///                 sole control.
///   TRANSCRIPT    The WSCA returns the signed transaction record carrying the instruction, R, G'', Y'' and the
///                 proofs; the transfer of such records to third parties is the application layer.
///
///   WHAT THE TRANSCRIPT PROVES: anyone holding the transcript and the Internal Certificate can verify, without
///   WSCD access, the WSCA signature, the ZKP that G''/Y'' are well formed, and W'=aU*W with W=R-e*G'' -- establishing
///   sole control and non-repudiation at eIDAS High.
///
///  -- TRANSACTION-LOG INTEGRITY (pluggable, beyond this gate) ----------------
///
///   The transcript has the shape of a signed append-only log entry. The chain-integrity backend is a delegate:
///     hash-chain  : each entry stores H(previous canonical bytes); replay verifies linearly (DID event logs).
///     Merkle tree : a batch commits to one root; inclusion proofs verify one entry (RFC 9162 CT).
///     TPM quote   : the chain head is extended into a PCR and TPM_Quote signs it (TCG firmware event logs).
///   All three share one fold structure; only the integrity-proof delegate differs.
///
///  -- VERHEUL SECDSA PAPER MAP ----------------------------------------------
///
///   Algorithm 1             Y = (P*u)*G                        DeriveSplitPublicKey
///   Algorithm 2 / Prop 3.1  split-sign is valid ECDSA under Y  SplitSign + Verify
///   Protocol 1              Internal Certificate issuance       activation (H', Y')
///   Algorithms 3 / 4        blind-signing relation ZKP          ProveBlindingRelation
///   Alg 3 Step 8 / Prop 3.3 W' = r*Y'' = aU*W, W = R - e*G''    ComputeBlindedPoint
///   Equation 7 / Alg 9-10   control relation evidence           ProveControlRelation
///   Algorithms 20 / 21      DL-equality NIZK on Statement (9)   DlEqualityNizk
///   Algorithms 22-24        transferable Protocol 2 proof       application layer
///   Section 4 / Alg 11      split-key architecture              separate gate (SplitKey...)
///
///   Scalars:  P = PIN-key,  u = NCH hardware key,  t = wallet one-time blinding,  aU = HSM/WSCD blinding key.
/// </code>
/// </remarks>
[TestClass]
internal sealed class SecdsaCarrierFlowTests
{
    private const int ScalarSize = 32;
    private const int CompressedSize = 33;
    private static CurveParameterSet Curve => CurveParameterSet.P256;

    private static ScalarMultiplyDelegate ScalarMultiply { get; } = P256BigIntegerScalarReference.GetMultiply();
    private static ScalarAddDelegate ScalarAdd { get; } = P256BigIntegerScalarReference.GetAdd();
    private static ScalarInvertDelegate ScalarInvert { get; } = P256BigIntegerScalarReference.GetInvert();
    private static ScalarReduceDelegate ScalarReduce { get; } = P256BigIntegerScalarReference.GetReduce();
    private static ScalarRandomDelegate ScalarRandom { get; } = P256BigIntegerScalarReference.GetRandom();
    private static G1ScalarMultiplyDelegate G1ScalarMultiply { get; } = P256BigIntegerG1Reference.GetScalarMultiply();
    private static G1AddDelegate G1Add { get; } = P256BigIntegerG1Reference.GetAdd();
    private static G1NegateDelegate G1Negate { get; } = P256BigIntegerG1Reference.GetNegate();

    private static SecdsaNonceSource NonceSource { get; } = Rfc6979SecdsaNonceSource.Create(Sha256Hmac.Compute);
    private static FiatShamirHashDelegate Hash { get; } = Sha256FiatShamir;


    [TestMethod]
    public void FullSecdsaFlowOverP256HoldsThroughTaggedBroadCarriers()
    {
        using var pool = new BaseMemoryPool();

        //Activation: mint the keys as tagged P-256 scalars from the entropy boundary factory.
        //        //FromRandom is the factory that first surfaced the missing P-256 tag entry. P is the PIN-key,
        //u the NCH hardware key, t the wallet's one-time blinding scalar, aU the HSM-bound blinding key.
        using Scalar pinKey = Scalar.FromRandom(ScalarRandom, Curve, pool);
        using Scalar hardwareKey = Scalar.FromRandom(ScalarRandom, Curve, pool);
        using Scalar blinding = Scalar.FromRandom(ScalarRandom, Curve, pool);
        using Scalar walletProviderKey = Scalar.FromRandom(ScalarRandom, Curve, pool);

        Assert.AreEqual(Curve, pinKey.Curve, "A scalar minted for P-256 must carry the P-256 curve tag.");

        using G1Point generator = G1Point.Generator(Curve, pool);

        //Y = (P*u)*G, the raw SECDSA public key, as a tagged compressed point.
        using G1Point publicKey = DeriveSplitPublicKey(pinKey, hardwareKey, pool);
        Assert.AreEqual(Curve, publicKey.Curve, "The derived public key must carry the P-256 curve tag.");

        //Internal certificate: H is a wallet-specific base point, H' = aU*H. Blinding round-trip: Ybl = t*Y,
        //Y'bl = aU*Ybl, Y' = t^-1*Y'bl. The result must equal aU*Y.
        using Scalar baseScalar = Scalar.FromRandom(ScalarRandom, Curve, pool);
        using G1Point walletBase = Mul(generator, baseScalar, pool);                       //H
        using G1Point blindedWalletBase = Mul(walletBase, walletProviderKey, pool);        //H' = aU*H
        using G1Point blindSecdsaPublicKey = BlindRoundTrip(publicKey, blinding, walletProviderKey, pool);
        using(G1Point expected = Mul(publicKey, walletProviderKey, pool))
        {
            Assert.IsTrue(PointsEqual(expected, blindSecdsaPublicKey),
                "Y' = t^-1*aU*t*Y must equal aU*Y after the blinding round-trip.");
        }

        //Signing: the pool overload returns a tagged SecdsaSignature carrier (Algorithm 2).
        byte[] messageHash = Digest("present-pid-attributes SN=1");
        using SecdsaSignature signature = SecdsaAlgorithm.SplitSign(
            pinKey.AsReadOnlySpan(), hardwareKey.AsReadOnlySpan(), messageHash, NonceSource,
            ScalarMultiply, ScalarAdd, ScalarInvert, ScalarReduce, G1ScalarMultiply, G1Add, pool);

        Assert.IsTrue(
            SecdsaAlgorithm.Verify(
                publicKey.AsReadOnlySpan(), messageHash, signature.GetRBytes(), signature.GetSBytes(),
                ScalarMultiply, ScalarInvert, ScalarReduce, G1ScalarMultiply, G1Add),
            "The split signature must verify under Y as ordinary ECDSA (Algorithm 14).");

        //Recover the full nonce point R = k*G the WSCA verification equation needs.
        Span<byte> noncePointBytes = stackalloc byte[CompressedSize];
        Assert.IsTrue(
            SecdsaAlgorithm.RecoverNoncePoint(
                publicKey.AsReadOnlySpan(), messageHash, signature.GetRBytes(), signature.GetSBytes(),
                ScalarMultiply, ScalarInvert, ScalarReduce, G1ScalarMultiply, G1Add, noncePointBytes),
            "The signature must yield a finite nonce point R.");
        using G1Point noncePoint = G1Point.FromCanonical(noncePointBytes, Curve, pool);

        //G'' = s^-1*G, Y'' = s^-1*Y' as tagged points; the blinding ZKP shares the witness s^-1 (Algorithm 3 Steps 6-7).
        using Scalar signatureScalar = Scalar.FromCanonical(signature.GetSBytes(), Curve, pool);
        using Scalar signatureInverse = Invert(signatureScalar, pool);
        using G1Point gDoublePrime = Mul(generator, signatureInverse, pool);
        using G1Point yDoublePrime = Mul(blindSecdsaPublicKey, signatureInverse, pool);

        using DlEqualityProof blindingProof = SecdsaEvidence.ProveBlindingRelation(
            generator.AsReadOnlySpan(), gDoublePrime.AsReadOnlySpan(),
            blindSecdsaPublicKey.AsReadOnlySpan(), yDoublePrime.AsReadOnlySpan(),
            signatureInverse.AsReadOnlySpan(), NonceSource, Hash, ScalarMultiply, ScalarAdd, ScalarReduce, G1ScalarMultiply, pool);

        Assert.IsTrue(
            SecdsaEvidence.VerifyBlindingRelation(
                generator.AsReadOnlySpan(), gDoublePrime.AsReadOnlySpan(),
                blindSecdsaPublicKey.AsReadOnlySpan(), yDoublePrime.AsReadOnlySpan(),
                blindingProof.GetRBytes(), blindingProof.GetSBytes(), Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate),
            "The blind-signing relation proof must verify.");

        //WSCA verification: W = R - e*G'' and W' = r*Y'' must satisfy W' = aU*W (Algorithm 3 Step 8, Proposition 3.3).
        //e is reduced from the message hash through FromBytesReduced; r is the signature component as a scalar.
        using Scalar e = Scalar.FromBytesReduced(messageHash, ScalarReduce, Curve, pool);
        using Scalar r = Scalar.FromCanonical(signature.GetRBytes(), Curve, pool);
        using G1Point w = ComputeInstructionPoint(noncePoint, e, gDoublePrime, pool);
        using G1Point wPrime = Mul(yDoublePrime, r, pool);
        using(G1Point expectedWPrime = Mul(w, walletProviderKey, pool))
        {
            Assert.IsTrue(PointsEqual(expectedWPrime, wPrime),
                "W' = r*Y'' must equal aU*W — the invariant proving the correct PIN was used.");
        }

        //Control evidence: H' = aU*H and W' = aU*W share aU, bound to N = H(T_I) (Equation 7, Algorithm 9 Step 6, Algorithm 10 Step 6).
        byte[] recordContext = Digest("transaction-record T_I for instruction #1");
        using DlEqualityProof controlProof = SecdsaEvidence.ProveControlRelation(
            walletBase.AsReadOnlySpan(), w.AsReadOnlySpan(), blindedWalletBase.AsReadOnlySpan(), wPrime.AsReadOnlySpan(),
            walletProviderKey.AsReadOnlySpan(), recordContext, NonceSource, Hash, ScalarMultiply, ScalarAdd, ScalarReduce, G1ScalarMultiply, pool);

        Assert.IsTrue(
            SecdsaEvidence.VerifyControlRelation(
                walletBase.AsReadOnlySpan(), w.AsReadOnlySpan(), blindedWalletBase.AsReadOnlySpan(), wPrime.AsReadOnlySpan(),
                recordContext, controlProof.GetRBytes(), controlProof.GetSBytes(), Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate),
            "A third party must accept the wallet-provider control evidence bound to the transaction record.");
    }


    /// <summary>Derives <c>Y = (P·u)·G</c> as a tagged compressed point (Algorithm 1).</summary>
    private static G1Point DeriveSplitPublicKey(Scalar pinKey, Scalar hardwareKey, BaseMemoryPool pool)
    {
        Span<byte> publicKey = stackalloc byte[CompressedSize];
        SecdsaAlgorithm.DeriveSplitPublicKey(
            pinKey.AsReadOnlySpan(), hardwareKey.AsReadOnlySpan(), ScalarMultiply, G1ScalarMultiply, publicKey);

        return G1Point.FromCanonical(publicKey, Curve, pool);
    }


    /// <summary>Runs the blinding round-trip <c>Y' = t^-1·(aU·(t·Y))</c>, returning the blind SECDSA public key.</summary>
    private static G1Point BlindRoundTrip(G1Point publicKey, Scalar blinding, Scalar walletProviderKey, BaseMemoryPool pool)
    {
        using G1Point blinded = Mul(publicKey, blinding, pool);
        using G1Point blindedPrime = Mul(blinded, walletProviderKey, pool);
        using Scalar blindingInverse = Invert(blinding, pool);

        return Mul(blindedPrime, blindingInverse, pool);
    }


    /// <summary>Computes <c>W = R − e·G''</c> (Algorithm 3 Step 8) as a fresh tagged compressed point.</summary>
    private static G1Point ComputeInstructionPoint(G1Point noncePoint, Scalar e, G1Point gDoublePrime, BaseMemoryPool pool)
    {
        using G1Point scaled = Mul(gDoublePrime, e, pool);
        using G1Point negated = Negate(scaled, pool);

        return Add(noncePoint, negated, pool);
    }


    /// <summary>Computes <c>−point</c> as a fresh tagged compressed point.</summary>
    private static G1Point Negate(G1Point point, BaseMemoryPool pool)
    {
        Span<byte> result = stackalloc byte[CompressedSize];
        G1Negate(point.AsReadOnlySpan(), result, Curve);

        return G1Point.FromCanonical(result, Curve, pool);
    }


    /// <summary>Computes <c>factor·point</c> as a fresh tagged compressed point.</summary>
    private static G1Point Mul(G1Point point, Scalar factor, BaseMemoryPool pool)
    {
        Span<byte> result = stackalloc byte[CompressedSize];
        G1ScalarMultiply(point.AsReadOnlySpan(), factor.AsReadOnlySpan(), result, Curve);

        return G1Point.FromCanonical(result, Curve, pool);
    }


    /// <summary>Computes the curve sum <c>a + b</c> as a fresh tagged compressed point.</summary>
    private static G1Point Add(G1Point a, G1Point b, BaseMemoryPool pool)
    {
        Span<byte> result = stackalloc byte[CompressedSize];
        G1Add(a.AsReadOnlySpan(), b.AsReadOnlySpan(), result, Curve);

        return G1Point.FromCanonical(result, Curve, pool);
    }


    /// <summary>Computes <c>a^-1 mod n</c> as a fresh tagged scalar.</summary>
    private static Scalar Invert(Scalar a, BaseMemoryPool pool)
    {
        Span<byte> result = stackalloc byte[ScalarSize];
        ScalarInvert(a.AsReadOnlySpan(), result, Curve);

        return Scalar.FromCanonical(result, Curve, pool);
    }


    /// <summary>Compares two points by their canonical SEC1-compressed encoding.</summary>
    private static bool PointsEqual(G1Point left, G1Point right) =>
        left.AsReadOnlySpan().SequenceEqual(right.AsReadOnlySpan());


    /// <summary>SHA-256 of an ASCII label, the 32-byte digest a message hash or transaction-record context needs.</summary>
    private static byte[] Digest(string label)
    {
        byte[] digest = new byte[ScalarSize];
        Sha256.HashData(Encoding.ASCII.GetBytes(label), digest);

        return digest;
    }


    /// <summary>The Fiat-Shamir hash the DL-equality evidence binds with — SHA-256.</summary>
    private static void Sha256FiatShamir(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction) =>
        Sha256.HashData(input, output);
}
