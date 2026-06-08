using System;
using System.Globalization;
using System.Numerics;
using System.Runtime.CompilerServices;

namespace Lumoin.Veridical.Core;

/// <summary>
/// Well-known elliptic curve identifiers, byte sizes for their scalar and group
/// elements, and conversion utilities.
/// </summary>
/// <remarks>
/// <para>
/// The constants in this class drive length validation in the library's leaf
/// algebraic types. A <c>Scalar</c> validates its memory length
/// against <see cref="Bls12Curve381ScalarSizeBytes"/>; a <c>Bn254G1Point</c>
/// validates against <see cref="Bn254G1CompressedSizeBytes"/> or
/// <see cref="Bn254G1UncompressedSizeBytes"/> depending on its encoding flag.
/// </para>
/// <para>
/// The canonical wire-format names — <c>"BLS12-381"</c>, <c>"BN254"</c> — are
/// string constants here; the runtime routing keys with .NET-compliant
/// identifier names live in <see cref="CurveParameterSet"/>.
/// </para>
/// <para>
/// JOSE <c>crv</c> values are provided for curves where the IETF JOSE working
/// group has standardised one. COSE numeric curve identifiers, multibase
/// did:key prefixes, and other wire-format codes will be added in
/// <c>Lumoin.Veridical.Cbor</c> and <c>Lumoin.Veridical.Json</c> when those
/// projects are introduced.
/// </para>
/// <para>
/// All sizes assume the canonical big-endian byte layout declared in
/// <see cref="WellKnownEncodings"/>.
/// </para>
/// </remarks>
public static class WellKnownCurves
{
    /// <summary>BLS12-381 (Barreto-Lynn-Scott curve, 381-bit base field).</summary>
    /// <remarks>
    /// Pairing-friendly. Used by BBS+, the BLS signature scheme, KZG-based
    /// proof systems, and the Ethereum 2.0 consensus layer.
    /// </remarks>
    public const string Bls12Curve381 = "BLS12-381";

    /// <summary>BN254 (Barreto-Naehrig curve, 254-bit field). Also called alt_bn128.</summary>
    /// <remarks>
    /// Pairing-friendly. Used by the Ethereum precompiles and many earlier
    /// SNARK deployments.
    /// </remarks>
    public const string Bn254 = "BN254";

    /// <summary>Pallas curve (Pasta cycle, paired with Vesta).</summary>
    /// <remarks>
    /// Not pairing-friendly. Forms a 2-cycle with Vesta — the scalar field of
    /// each is the base field of the other — which enables efficient
    /// recursive proof composition without pairings. Used by Halo2.
    /// </remarks>
    public const string Pallas = "Pallas";

    /// <summary>Vesta curve (Pasta cycle, paired with Pallas).</summary>
    /// <remarks>
    /// Not pairing-friendly. Other half of the Pasta 2-cycle.
    /// </remarks>
    public const string Vesta = "Vesta";

    /// <summary>Grumpkin curve (cycle with BN254).</summary>
    /// <remarks>
    /// Not pairing-friendly. The scalar field of Grumpkin equals the base
    /// field of BN254, completing a 2-cycle used for pairing-free recursion.
    /// </remarks>
    public const string Grumpkin = "Grumpkin";

    /// <summary>secp256k1 curve.</summary>
    /// <remarks>
    /// Used by Bitcoin, Ethereum signing, and many decentralised identity
    /// schemes. JOSE <c>crv</c> value is <c>secp256k1</c> per RFC 8812.
    /// </remarks>
    public const string Secp256k1 = "secp256k1";

    /// <summary>Ed25519 (Edwards curve over the 25519 prime).</summary>
    /// <remarks>
    /// Used by EdDSA signatures (RFC 8032). JOSE <c>crv</c> value is
    /// <c>Ed25519</c> per RFC 8037.
    /// </remarks>
    public const string Ed25519 = "Ed25519";

    /// <summary>NIST P-256 (secp256r1, prime256v1).</summary>
    public const string P256 = "P-256";

    /// <summary>NIST P-384 (secp384r1).</summary>
    public const string P384 = "P-384";

    /// <summary>NIST P-521 (secp521r1).</summary>
    public const string P521 = "P-521";


    /// <summary>JOSE <c>crv</c> value for secp256k1 (RFC 8812).</summary>
    public const string Secp256k1JoseCrv = "secp256k1";

    /// <summary>JOSE <c>crv</c> value for Ed25519 (RFC 8037).</summary>
    public const string Ed25519JoseCrv = "Ed25519";

    /// <summary>JOSE <c>crv</c> value for P-256 (RFC 7518).</summary>
    public const string P256JoseCrv = "P-256";

    /// <summary>JOSE <c>crv</c> value for P-384 (RFC 7518).</summary>
    public const string P384JoseCrv = "P-384";

    /// <summary>JOSE <c>crv</c> value for P-521 (RFC 7518).</summary>
    public const string P521JoseCrv = "P-521";


    /// <summary>BLS12-381 scalar field element size: 255-bit prime, 32 bytes when laid out big-endian.</summary>
    public const int Bls12Curve381ScalarSizeBytes = 32;

    /// <summary>BLS12-381 base field element size: 381-bit prime, 48 bytes.</summary>
    public const int Bls12Curve381BaseFieldSizeBytes = 48;

    /// <summary>BLS12-381 G1 compressed point size: one base-field x-coordinate plus three flag bits in the most-significant byte.</summary>
    public const int Bls12Curve381G1CompressedSizeBytes = 48;

    /// <summary>BLS12-381 G1 uncompressed point size: x and y as base-field elements.</summary>
    public const int Bls12Curve381G1UncompressedSizeBytes = 96;

    /// <summary>BLS12-381 G2 compressed point size: one Fp2 x-coordinate (two base-field elements) plus flag bits.</summary>
    public const int Bls12Curve381G2CompressedSizeBytes = 96;

    /// <summary>BLS12-381 G2 uncompressed point size: x and y as Fp2 elements.</summary>
    public const int Bls12Curve381G2UncompressedSizeBytes = 192;

    /// <summary>BLS12-381 GT element size: one Fp12 element, 12 base-field elements.</summary>
    public const int Bls12Curve381GtSizeBytes = 576;


    /// <summary>BN254 scalar field element size: 254-bit prime, 32 bytes.</summary>
    public const int Bn254ScalarSizeBytes = 32;

    /// <summary>BN254 base field element size: 254-bit prime, 32 bytes.</summary>
    public const int Bn254BaseFieldSizeBytes = 32;

    /// <summary>BN254 G1 compressed point size.</summary>
    public const int Bn254G1CompressedSizeBytes = 32;

    /// <summary>BN254 G1 uncompressed point size.</summary>
    public const int Bn254G1UncompressedSizeBytes = 64;

    /// <summary>BN254 G2 compressed point size.</summary>
    public const int Bn254G2CompressedSizeBytes = 64;

    /// <summary>BN254 G2 uncompressed point size.</summary>
    public const int Bn254G2UncompressedSizeBytes = 128;

    /// <summary>BN254 GT element size: one Fp12 element, 12 base-field elements.</summary>
    public const int Bn254GtSizeBytes = 384;


    /// <summary>Pallas scalar field element size: 32 bytes (Pasta scalar field).</summary>
    public const int PallasScalarSizeBytes = 32;

    /// <summary>Pallas base field element size: 32 bytes (Pasta base field).</summary>
    public const int PallasBaseFieldSizeBytes = 32;

    /// <summary>Pallas G1 compressed point size.</summary>
    public const int PallasG1CompressedSizeBytes = 32;

    /// <summary>Pallas G1 uncompressed point size.</summary>
    public const int PallasG1UncompressedSizeBytes = 64;


    /// <summary>Vesta scalar field element size: 32 bytes (Pasta cycle counterpart of Pallas).</summary>
    public const int VestaScalarSizeBytes = 32;

    /// <summary>Vesta base field element size: 32 bytes.</summary>
    public const int VestaBaseFieldSizeBytes = 32;

    /// <summary>Vesta G1 compressed point size.</summary>
    public const int VestaG1CompressedSizeBytes = 32;

    /// <summary>Vesta G1 uncompressed point size.</summary>
    public const int VestaG1UncompressedSizeBytes = 64;


    /// <summary>Grumpkin scalar field element size: 32 bytes.</summary>
    public const int GrumpkinScalarSizeBytes = 32;

    /// <summary>Grumpkin base field element size: 32 bytes.</summary>
    public const int GrumpkinBaseFieldSizeBytes = 32;

    /// <summary>Grumpkin G1 compressed point size.</summary>
    public const int GrumpkinG1CompressedSizeBytes = 32;

    /// <summary>Grumpkin G1 uncompressed point size.</summary>
    public const int GrumpkinG1UncompressedSizeBytes = 64;


    /// <summary>secp256k1 scalar size: 32 bytes.</summary>
    public const int Secp256k1ScalarSizeBytes = 32;

    /// <summary>secp256k1 base field element size: 32 bytes.</summary>
    public const int Secp256k1BaseFieldSizeBytes = 32;

    /// <summary>secp256k1 compressed point size: 0x02/0x03 prefix plus x-coordinate.</summary>
    public const int Secp256k1CompressedSizeBytes = 33;

    /// <summary>secp256k1 uncompressed point size: 0x04 prefix plus x and y.</summary>
    public const int Secp256k1UncompressedSizeBytes = 65;


    /// <summary>Ed25519 scalar size: 32 bytes.</summary>
    public const int Ed25519ScalarSizeBytes = 32;

    /// <summary>Ed25519 compressed point size: y-coordinate with sign bit folded into the most-significant byte.</summary>
    public const int Ed25519CompressedSizeBytes = 32;


    /// <summary>P-256 scalar size: 32 bytes.</summary>
    public const int P256ScalarSizeBytes = 32;

    /// <summary>P-256 base field element size: 32 bytes.</summary>
    public const int P256BaseFieldSizeBytes = 32;

    /// <summary>P-256 compressed point size: 0x02/0x03 prefix plus x.</summary>
    public const int P256CompressedSizeBytes = 33;

    /// <summary>P-256 uncompressed point size: 0x04 prefix plus x and y.</summary>
    public const int P256UncompressedSizeBytes = 65;


    /// <summary>P-384 scalar size: 48 bytes.</summary>
    public const int P384ScalarSizeBytes = 48;

    /// <summary>P-384 base field element size: 48 bytes.</summary>
    public const int P384BaseFieldSizeBytes = 48;

    /// <summary>P-384 compressed point size.</summary>
    public const int P384CompressedSizeBytes = 49;

    /// <summary>P-384 uncompressed point size.</summary>
    public const int P384UncompressedSizeBytes = 97;


    /// <summary>P-521 scalar size: 66 bytes (521 bits rounded up to byte boundary).</summary>
    public const int P521ScalarSizeBytes = 66;

    /// <summary>P-521 base field element size: 66 bytes.</summary>
    public const int P521BaseFieldSizeBytes = 66;

    /// <summary>P-521 compressed point size.</summary>
    public const int P521CompressedSizeBytes = 67;

    /// <summary>P-521 uncompressed point size.</summary>
    public const int P521UncompressedSizeBytes = 133;


    /// <summary>Determines whether the specified value identifies BLS12-381.</summary>
    /// <remarks>
    /// Accepted aliases include the canonical <c>"BLS12-381"</c> wire form,
    /// the lowercase joined form <c>"bls12381"</c>, and the legacy underscored
    /// form <c>"bls12_381"</c> — both appear in JSON-LD contexts, did:key
    /// payloads, and other ecosystem files.
    /// </remarks>
    public static bool IsBls12Curve381(string? value)
    {
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }


        return string.Equals(value, Bls12Curve381, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "bls12381", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "bls12_381", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Determines whether the specified value identifies BN254.</summary>
    public static bool IsBn254(string? value)
    {
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }


        return string.Equals(value, Bn254, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "alt_bn128", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "bn128", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Determines whether the specified value identifies Pallas.</summary>
    public static bool IsPallas(string? value) =>
        !string.IsNullOrEmpty(value)
            && string.Equals(value, Pallas, StringComparison.OrdinalIgnoreCase);

    /// <summary>Determines whether the specified value identifies Vesta.</summary>
    public static bool IsVesta(string? value) =>
        !string.IsNullOrEmpty(value)
            && string.Equals(value, Vesta, StringComparison.OrdinalIgnoreCase);

    /// <summary>Determines whether the specified value identifies Grumpkin.</summary>
    public static bool IsGrumpkin(string? value) =>
        !string.IsNullOrEmpty(value)
            && string.Equals(value, Grumpkin, StringComparison.OrdinalIgnoreCase);

    /// <summary>Determines whether the specified value identifies secp256k1.</summary>
    public static bool IsSecp256k1(string? value) =>
        !string.IsNullOrEmpty(value)
            && string.Equals(value, Secp256k1, StringComparison.OrdinalIgnoreCase);

    /// <summary>Determines whether the specified value identifies Ed25519.</summary>
    public static bool IsEd25519(string? value) =>
        !string.IsNullOrEmpty(value)
            && string.Equals(value, Ed25519, StringComparison.OrdinalIgnoreCase);

    /// <summary>Determines whether the specified value identifies NIST P-256.</summary>
    public static bool IsP256(string? value)
    {
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }


        return string.Equals(value, P256, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "secp256r1", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "prime256v1", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "nistP256", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Determines whether the specified value identifies NIST P-384.</summary>
    public static bool IsP384(string? value)
    {
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }


        return string.Equals(value, P384, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "secp384r1", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "nistP384", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Determines whether the specified value identifies NIST P-521.</summary>
    public static bool IsP521(string? value)
    {
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }


        return string.Equals(value, P521, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "secp521r1", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "nistP521", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Determines whether the specified curve is pairing-friendly. BLS12-381
    /// and BN254 are; the others are not.
    /// </summary>
    public static bool IsPairingFriendly(string? value) =>
        IsBls12Curve381(value) || IsBn254(value);

    /// <summary>
    /// Determines whether the specified curve participates in a 2-cycle used
    /// for pairing-free recursive composition. Pallas, Vesta, and Grumpkin do.
    /// </summary>
    public static bool ParticipatesInCurveCycle(string? value) =>
        IsPallas(value) || IsVesta(value) || IsGrumpkin(value);

    /// <summary>
    /// Determines whether the specified curve is a NIST P-curve.
    /// </summary>
    public static bool IsNistPCurve(string? value) =>
        IsP256(value) || IsP384(value) || IsP521(value);


    /// <summary>
    /// Returns the canonical name of the curve cycle partner if the curve
    /// participates in a 2-cycle, or <see langword="null"/> otherwise.
    /// </summary>
    public static string? GetCycleCounterpart(string? value) => value switch
    {
        _ when IsPallas(value) => Vesta,
        _ when IsVesta(value) => Pallas,
        _ when IsGrumpkin(value) => Bn254,
        _ when IsBn254(value) => Grumpkin,
        _ => null
    };


    /// <summary>
    /// Converts a curve identifier to its JOSE <c>crv</c> value when one is
    /// standardised, throwing for curves that have no JOSE registration.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown for curves with no JOSE <c>crv</c> value.</exception>
    public static string ToJoseCrv(string value) => value switch
    {
        _ when IsSecp256k1(value) => Secp256k1JoseCrv,
        _ when IsEd25519(value) => Ed25519JoseCrv,
        _ when IsP256(value) => P256JoseCrv,
        _ when IsP384(value) => P384JoseCrv,
        _ when IsP521(value) => P521JoseCrv,
        _ => throw new ArgumentException($"No JOSE crv value standardised for curve '{value}'.", nameof(value))
    };


    /// <summary>
    /// Returns the scalar field byte size for the specified curve.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown when the curve is not recognised.</exception>
    public static int GetScalarSizeBytes(string value) => value switch
    {
        _ when IsBls12Curve381(value) => Bls12Curve381ScalarSizeBytes,
        _ when IsBn254(value) => Bn254ScalarSizeBytes,
        _ when IsPallas(value) => PallasScalarSizeBytes,
        _ when IsVesta(value) => VestaScalarSizeBytes,
        _ when IsGrumpkin(value) => GrumpkinScalarSizeBytes,
        _ when IsSecp256k1(value) => Secp256k1ScalarSizeBytes,
        _ when IsEd25519(value) => Ed25519ScalarSizeBytes,
        _ when IsP256(value) => P256ScalarSizeBytes,
        _ when IsP384(value) => P384ScalarSizeBytes,
        _ when IsP521(value) => P521ScalarSizeBytes,
        _ => throw new ArgumentException($"Unknown curve: '{value}'.", nameof(value))
    };

    /// <summary>
    /// Returns the base field byte size for the specified curve.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown when the curve is not recognised or has no separate base field constant.</exception>
    public static int GetBaseFieldSizeBytes(string value) => value switch
    {
        _ when IsBls12Curve381(value) => Bls12Curve381BaseFieldSizeBytes,
        _ when IsBn254(value) => Bn254BaseFieldSizeBytes,
        _ when IsPallas(value) => PallasBaseFieldSizeBytes,
        _ when IsVesta(value) => VestaBaseFieldSizeBytes,
        _ when IsGrumpkin(value) => GrumpkinBaseFieldSizeBytes,
        _ when IsSecp256k1(value) => Secp256k1BaseFieldSizeBytes,
        _ when IsP256(value) => P256BaseFieldSizeBytes,
        _ when IsP384(value) => P384BaseFieldSizeBytes,
        _ when IsP521(value) => P521BaseFieldSizeBytes,
        _ => throw new ArgumentException($"No base field size known for curve '{value}'.", nameof(value))
    };


    /// <summary>
    /// Returns the compressed G1-point byte size for the specified curve.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown when the curve is not recognised or not yet wired.</exception>
    public static int GetG1CompressedSizeBytes(CurveParameterSet curve) =>
        curve.Code == CurveParameterSet.Bls12Curve381.Code
            ? Bls12Curve381G1CompressedSizeBytes
            : curve.Code == CurveParameterSet.Bn254.Code
                ? Bn254G1CompressedSizeBytes
                : curve.Code == CurveParameterSet.P256.Code
                    ? P256CompressedSizeBytes
                    : throw new ArgumentException($"No G1 compressed size known for {curve}; add a WellKnownCurves entry when wiring this curve.", nameof(curve));


    /// <summary>
    /// Returns the compressed G2-point byte size for the specified curve.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown when the curve is not recognised or has no G2 group.</exception>
    public static int GetG2CompressedSizeBytes(CurveParameterSet curve) =>
        curve.Code == CurveParameterSet.Bls12Curve381.Code
            ? Bls12Curve381G2CompressedSizeBytes
            : curve.Code == CurveParameterSet.Bn254.Code ? Bn254G2CompressedSizeBytes : throw new ArgumentException($"No G2 compressed size known for {curve}; add a WellKnownCurves entry when wiring this curve.", nameof(curve));


    /// <summary>
    /// BLS12-381 scalar field order
    /// <c>r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001</c>.
    /// </summary>
    private static readonly BigInteger Bls12Curve381ScalarFieldOrderValue = BigInteger.Parse(
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);

    /// <summary>
    /// BN254 (alt_bn128) scalar field order
    /// <c>r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001</c>.
    /// </summary>
    private static readonly BigInteger Bn254ScalarFieldOrderValue = BigInteger.Parse(
        "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);

    /// <summary>
    /// NIST P-256 (secp256r1) group order
    /// <c>n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551</c>.
    /// The leading <c>"0"</c> keeps the <c>0xff</c> top byte from parsing as a
    /// negative two's-complement value. Source: NIST SP 800-186 (2023) Curve
    /// P-256, value <c>n</c>; SEC 2 v2.0 §2.4.2 secp256r1; FIPS 186-4 Appendix
    /// D.1.2.3.
    /// </summary>
    private static readonly BigInteger P256ScalarFieldOrderValue = BigInteger.Parse(
        "0ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);


    /// <summary>
    /// Returns the scalar field order (the prime modulus <c>r</c> the witness
    /// elements and coefficients are reduced modulo) for the specified curve.
    /// Used by the in-process constraint-system compiler to reduce
    /// arbitrary-precision builder coefficients into canonical field elements.
    /// </summary>
    /// <exception cref="ArgumentException">When the curve is not wired.</exception>
    public static BigInteger GetScalarFieldOrder(CurveParameterSet curve) =>
        curve.Code == CurveParameterSet.Bls12Curve381.Code
            ? Bls12Curve381ScalarFieldOrderValue
            : curve.Code == CurveParameterSet.Bn254.Code
                ? Bn254ScalarFieldOrderValue
                : curve.Code == CurveParameterSet.P256.Code
                    ? P256ScalarFieldOrderValue
                    : throw new ArgumentException($"No scalar field order known for {curve}; add a WellKnownCurves entry when wiring this curve.", nameof(curve));


    /// <summary>
    /// Throws <see cref="ArgumentException"/> when <paramref name="curve"/> is not
    /// one of the curves wired with reference/backend support. A single source of
    /// truth for the wired set: wiring a new curve updates this method, not every
    /// guard. Reaching an unwired curve here is a programmer error (the
    /// construction code routed a curve the layer never supported), so this is
    /// fail-fast, not a recoverable condition.
    /// </summary>
    /// <exception cref="ArgumentException">When the curve is not Bls12Curve381 or Bn254.</exception>
    public static void ThrowIfCurveNotWired(
        CurveParameterSet curve,
        [CallerArgumentExpression(nameof(curve))] string? paramName = null)
    {
        if(curve.Code != CurveParameterSet.Bls12Curve381.Code
            && curve.Code != CurveParameterSet.Bn254.Code)
        {
            throw new ArgumentException(
                $"Curve '{curve}' is not wired; the wired curves are Bls12Curve381 and Bn254.",
                paramName);
        }
    }


    /// <summary>
    /// Throws <see cref="ArgumentException"/> when <paramref name="curve"/> and
    /// <paramref name="other"/> are different curves. For binary operations that
    /// require both operands to share a curve.
    /// </summary>
    /// <exception cref="ArgumentException">When the two curves differ.</exception>
    public static void ThrowIfCurvesDiffer(
        CurveParameterSet curve,
        CurveParameterSet other,
        [CallerArgumentExpression(nameof(other))] string? paramName = null)
    {
        if(curve.Code != other.Code)
        {
            throw new ArgumentException(
                $"Operation requires both operands to share a curve; received {curve} and {other}.",
                paramName);
        }
    }


    //Canonical compressed encodings of the distinguished group constants.
    //These are curve-definition data (fixed by the curve standard / RFC 9380),
    //the same kind of constant as the size and modulus values above; the broad
    //G1Point/G2Point wrapper types look them up rather than embedding any one
    //curve's bytes. Per-curve entries are added as each curve is wired.

    private static readonly byte[] Bls12Curve381G1GeneratorCompressed =
    [
        0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94,
        0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9, 0xac, 0x0f,
        0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05,
        0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b, 0xac, 0x58,
        0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef,
        0xfb, 0x3a, 0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb
    ];

    private static readonly byte[] Bls12Curve381G1IdentityCompressed =
    [
        0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];

    private static readonly byte[] Bls12Curve381G2GeneratorCompressed =
    [
        0x93, 0xe0, 0x2b, 0x60, 0x52, 0x71, 0x9f, 0x60,
        0x7d, 0xac, 0xd3, 0xa0, 0x88, 0x27, 0x4f, 0x65,
        0x59, 0x6b, 0xd0, 0xd0, 0x99, 0x20, 0xb6, 0x1a,
        0xb5, 0xda, 0x61, 0xbb, 0xdc, 0x7f, 0x50, 0x49,
        0x33, 0x4c, 0xf1, 0x12, 0x13, 0x94, 0x5d, 0x57,
        0xe5, 0xac, 0x7d, 0x05, 0x5d, 0x04, 0x2b, 0x7e,
        0x02, 0x4a, 0xa2, 0xb2, 0xf0, 0x8f, 0x0a, 0x91,
        0x26, 0x08, 0x05, 0x27, 0x2d, 0xc5, 0x10, 0x51,
        0xc6, 0xe4, 0x7a, 0xd4, 0xfa, 0x40, 0x3b, 0x02,
        0xb4, 0x51, 0x0b, 0x64, 0x7a, 0xe3, 0xd1, 0x77,
        0x0b, 0xac, 0x03, 0x26, 0xa8, 0x05, 0xbb, 0xef,
        0xd4, 0x80, 0x56, 0xc8, 0xc1, 0x21, 0xbd, 0xb8
    ];

    private static readonly byte[] Bls12Curve381G2IdentityCompressed =
    [
        0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];


    //BN254 G1 distinguished constants in the gnark big-endian compressed
    //convention (gnark bn254/marshal.go): the most-significant two bits of
    //byte 0 tag the point (0b10 = smaller-y, 0b11 = larger-y, 0b01 = infinity)
    //and the remaining 254 bits hold the big-endian x-coordinate. The generator
    //is the affine point (1, 2); y = 2 is the smaller root, so its tag is 0b10
    //(0x80) and the encoding is 0x80 followed by x = 1. The identity carries
    //the 0b01 (0x40) infinity tag with all x bits zero.

    private static readonly byte[] Bn254G1GeneratorCompressed =
    [
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    ];

    private static readonly byte[] Bn254G1IdentityCompressed =
    [
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];


    //BN254 G2 distinguished constants in the same gnark big-endian compressed
    //convention as G1 (64 bytes): the imaginary component x.c1 first, then the
    //real component x.c0, with the 2-bit tag in byte 0. The generator is the
    //canonical alt_bn128 G2 point (py_ecc / EIP-197); its y is the smaller root,
    //so its tag is 0b10 (0x80). The identity carries the 0b01 (0x40) tag.

    private static readonly byte[] Bn254G2GeneratorCompressed = Convert.FromHexString(
        "998e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"
        + "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed");

    private static readonly byte[] Bn254G2IdentityCompressed = Convert.FromHexString(
        "40" + new string('0', 126));


    //P-256 (secp256r1) G1 distinguished constants in the SEC1 compressed
    //convention (33 bytes): a 0x02/0x03 prefix carrying the y-parity followed
    //by the 32-byte big-endian x, or a 0x00 prefix with zero padding for the
    //point at infinity. The generator's y (SEC 2 v2.0 §2.4.2) is odd, so its
    //prefix is 0x03; x is the standard P-256 Gx.
    private static byte[] P256G1GeneratorCompressed { get; } = Convert.FromHexString(
        "03" + "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");

    private static byte[] P256G1IdentityCompressed { get; } = Convert.FromHexString(
        "00" + new string('0', 64));


    /// <summary>Returns the canonical compressed encoding of the G1 generator for the specified curve.</summary>
    /// <exception cref="ArgumentException">Thrown when the curve's generator is not wired.</exception>
    public static ReadOnlySpan<byte> GetG1GeneratorCompressed(CurveParameterSet curve) =>
        curve.Code == CurveParameterSet.Bls12Curve381.Code
            ? Bls12Curve381G1GeneratorCompressed
            : curve.Code == CurveParameterSet.Bn254.Code
                ? Bn254G1GeneratorCompressed
                : curve.Code == CurveParameterSet.P256.Code
                    ? P256G1GeneratorCompressed
                    : throw new ArgumentException($"No G1 generator wired for {curve}.", nameof(curve));


    /// <summary>Returns the canonical compressed encoding of the G1 identity (point at infinity) for the specified curve.</summary>
    /// <exception cref="ArgumentException">Thrown when the curve's identity encoding is not wired.</exception>
    public static ReadOnlySpan<byte> GetG1IdentityCompressed(CurveParameterSet curve) =>
        curve.Code == CurveParameterSet.Bls12Curve381.Code
            ? Bls12Curve381G1IdentityCompressed
            : curve.Code == CurveParameterSet.Bn254.Code
                ? Bn254G1IdentityCompressed
                : curve.Code == CurveParameterSet.P256.Code
                    ? P256G1IdentityCompressed
                    : throw new ArgumentException($"No G1 identity wired for {curve}.", nameof(curve));


    /// <summary>Returns the canonical compressed encoding of the G2 generator for the specified curve.</summary>
    /// <exception cref="ArgumentException">Thrown when the curve's generator is not wired.</exception>
    public static ReadOnlySpan<byte> GetG2GeneratorCompressed(CurveParameterSet curve) =>
        curve.Code == CurveParameterSet.Bls12Curve381.Code
            ? Bls12Curve381G2GeneratorCompressed
            : curve.Code == CurveParameterSet.Bn254.Code
                ? Bn254G2GeneratorCompressed
                : throw new ArgumentException($"No G2 generator wired for {curve}.", nameof(curve));


    /// <summary>Returns the canonical compressed encoding of the G2 identity (point at infinity) for the specified curve.</summary>
    /// <exception cref="ArgumentException">Thrown when the curve's identity encoding is not wired.</exception>
    public static ReadOnlySpan<byte> GetG2IdentityCompressed(CurveParameterSet curve) =>
        curve.Code == CurveParameterSet.Bls12Curve381.Code
            ? Bls12Curve381G2IdentityCompressed
            : curve.Code == CurveParameterSet.Bn254.Code
                ? Bn254G2IdentityCompressed
                : throw new ArgumentException($"No G2 identity wired for {curve}.", nameof(curve));


    //Field-tower element byte sizes: Fp_k = k * base-field size. The
    //pairing tower for BLS12-381 is Fp ⊂ Fp2 ⊂ Fp6 ⊂ Fp12; Fp12 equals the
    //GT element size.

    /// <summary>BLS12-381 Fp2 element size: two base-field components.</summary>
    public const int Bls12Curve381Fp2SizeBytes = 2 * Bls12Curve381BaseFieldSizeBytes;

    /// <summary>BLS12-381 Fp6 element size: three Fp2 components.</summary>
    public const int Bls12Curve381Fp6SizeBytes = 3 * Bls12Curve381Fp2SizeBytes;

    /// <summary>BLS12-381 Fp12 element size: two Fp6 components (equals the GT element size).</summary>
    public const int Bls12Curve381Fp12SizeBytes = 2 * Bls12Curve381Fp6SizeBytes;


    /// <summary>Returns the base field (Fp) element byte size for the specified curve.</summary>
    /// <exception cref="ArgumentException">Thrown when the curve is not wired.</exception>
    public static int GetBaseFieldSizeBytes(CurveParameterSet curve) =>
        curve.Code == CurveParameterSet.Bls12Curve381.Code
            ? Bls12Curve381BaseFieldSizeBytes
            : curve.Code == CurveParameterSet.Bn254.Code
                ? Bn254BaseFieldSizeBytes
                : curve.Code == CurveParameterSet.P256.Code
                    ? P256BaseFieldSizeBytes
                    : throw new ArgumentException($"No base field size known for {curve}; add a WellKnownCurves entry when wiring this curve.", nameof(curve));


    /// <summary>Returns the Fp2 element byte size for the specified curve.</summary>
    /// <exception cref="ArgumentException">Thrown when the curve is not wired.</exception>
    public static int GetFp2SizeBytes(CurveParameterSet curve) =>
        curve.Code == CurveParameterSet.Bls12Curve381.Code
            ? Bls12Curve381Fp2SizeBytes
            : curve.Code == CurveParameterSet.Bn254.Code ? (2 * Bn254BaseFieldSizeBytes) : throw new ArgumentException($"No Fp2 size known for {curve}; add a WellKnownCurves entry when wiring this curve.", nameof(curve));


    /// <summary>Returns the Fp6 element byte size for the specified curve.</summary>
    /// <exception cref="ArgumentException">Thrown when the curve is not wired.</exception>
    public static int GetFp6SizeBytes(CurveParameterSet curve) =>
        curve.Code == CurveParameterSet.Bls12Curve381.Code
            ? Bls12Curve381Fp6SizeBytes
            : curve.Code == CurveParameterSet.Bn254.Code ? (6 * Bn254BaseFieldSizeBytes) : throw new ArgumentException($"No Fp6 size known for {curve}; add a WellKnownCurves entry when wiring this curve.", nameof(curve));


    /// <summary>Returns the Fp12 element byte size for the specified curve.</summary>
    /// <exception cref="ArgumentException">Thrown when the curve is not wired.</exception>
    public static int GetFp12SizeBytes(CurveParameterSet curve) =>
        curve.Code == CurveParameterSet.Bls12Curve381.Code
            ? Bls12Curve381Fp12SizeBytes
            : curve.Code == CurveParameterSet.Bn254.Code ? (12 * Bn254BaseFieldSizeBytes) : throw new ArgumentException($"No Fp12 size known for {curve}; add a WellKnownCurves entry when wiring this curve.", nameof(curve));
}