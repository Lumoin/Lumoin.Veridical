using Lumoin.Veridical.Backends.Managed;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Lumoin.Veridical.Tests.Cryptography.Wycheproof;

/// <summary>
/// Gates the in-repo <see cref="P256EcdsaReference"/> against the C2SP/wycheproof
/// secp256r1 ASN.1/DER signature catalogue. The library deliberately ships no ASN.1/DER
/// parsing surface: signatures cross its API as fixed-width <c>r, s</c> spans (32 bytes
/// each), so a caller consuming DER-encoded signatures owns the DER decode. This harness
/// pins the STRICT-DER contract that caller must implement: the private
/// <see cref="TryParseStrictDerSignature"/> follows X.690 minimal-encoding rules with
/// no exceptions. The gate is fail-closed — a lenient decoder would accept
/// BER-encoded-but-semantically-valid vectors and incorrectly make the test pass.
/// </summary>
[TestClass]
internal sealed class WycheproofEcdsaAsn1Tests
{
    //SHA-256 output is 256 bits.
    private const int DigestSizeBytes = 32;

    //P-256 coordinate is 32 bytes; r and s each occupy exactly this width.
    private const int ScalarSizeBytes = 32;

    //Mismatches list cap for the failure message; avoids enormous output on widespread breakage.
    private const int MaxPrintedMismatches = 20;

    //DER tag bytes.
    private const byte DerTagSequence = 0x30;
    private const byte DerTagInteger = 0x02;

    //DER length-field boundary values.
    private const int DerShortFormMaxLength = 0x7F;
    private const int DerLongForm1ByteMarker = 0x81;
    private const int DerMinimalLongFormThreshold = 0x80;


    [TestMethod]
    public void EveryAsn1VectorMatchesTheReferenceVerifier()
    {
        WycheproofFileResult? file = WycheproofEcdsaFixtures.TryLoadAsn1();
        if(file is null)
        {
            Assert.Inconclusive(
                "ASN.1/DER fixture file not found. See Cryptography/Wycheproof/Fixtures/FIXTURES.md for provenance and regeneration instructions.");
        }

        var mismatches = new List<string>();
        int processed = 0;

        Span<byte> r = stackalloc byte[ScalarSizeBytes];
        Span<byte> s = stackalloc byte[ScalarSizeBytes];
        Span<byte> digest = stackalloc byte[DigestSizeBytes];

        foreach(WycheproofVector v in file.Vectors)
        {
            //The DER parser left-pads into r and s; clear both before each vector
            //so a short value from a prior iteration cannot bleed into the high bytes.
            r.Clear();
            s.Clear();

            bool parsed = TryParseStrictDerSignature(v.Signature, r, s);
            if(!parsed)
            {
                //Strict DER rejected the encoding.  This is correct when the vector is
                //expected-invalid; if the vector is expected-valid our decoder has a bug.
                if(v.ExpectedValid)
                {
                    string flags = string.Join(", ", v.Flags);
                    mismatches.Add(
                        $"tcId {v.TcId}: \"{v.Comment}\" (flags: [{flags}]) — strict DER parser rejected a Wycheproof-valid signature (harness bug)");
                }

                processed++;

                continue;
            }

            SHA256.HashData(v.Message, digest);

            bool actual;
            try
            {
                actual = P256EcdsaReference.Verify(v.CompressedKey, digest, r, s);
            }
            catch(ArgumentException)
            {
                actual = false;
            }

            if(actual != v.ExpectedValid)
            {
                string flags = string.Join(", ", v.Flags);
                mismatches.Add(
                    $"tcId {v.TcId}: \"{v.Comment}\" (flags: [{flags}]) — expected {(v.ExpectedValid ? "valid" : "invalid")}, got {(actual ? "valid" : "invalid")}");
            }

            processed++;
        }

        Assert.AreEqual(file.DeclaredNumberOfTests, processed,
            $"Processed vector count {processed} does not match the fixture's declared numberOfTests {file.DeclaredNumberOfTests}.");

        if(mismatches.Count == 0)
        {
            return;
        }

        var sb = new StringBuilder();
        sb.AppendLine(CultureInfo.InvariantCulture, $"{mismatches.Count} mismatch(es) against P256EcdsaReference (ASN.1/DER):");
        foreach(string entry in mismatches.Take(MaxPrintedMismatches))
        {
            sb.AppendLine(entry);
        }

        int extra = mismatches.Count - MaxPrintedMismatches;
        if(extra > 0)
        {
            sb.AppendLine(CultureInfo.InvariantCulture, $"...and {extra} more.");
        }

        Assert.IsEmpty(mismatches, sb.ToString());
    }


    /// <summary>
    /// Parses a strict-DER SEQUENCE { INTEGER r, INTEGER s } into 32-byte big-endian
    /// <paramref name="r32"/> and <paramref name="s32"/>. Returns <see langword="false"/>
    /// on any encoding violation including non-minimal lengths, negative integers,
    /// non-minimal padding, trailing bytes, or values that exceed 32 bytes after stripping
    /// the single allowed sign byte.
    /// </summary>
    private static bool TryParseStrictDerSignature(
        ReadOnlySpan<byte> der,
        Span<byte> r32,
        Span<byte> s32)
    {
        //SEQUENCE tag.
        if(der.IsEmpty || der[0] != DerTagSequence)
        {
            return false;
        }

        int pos = 1;
        if(!TryReadDerLength(der, ref pos, out int contentLen))
        {
            return false;
        }

        //No trailing bytes after the SEQUENCE content.
        if(pos + contentLen != der.Length)
        {
            return false;
        }

        int contentEnd = pos + contentLen;

        if(!TryReadDerInteger(der, contentEnd, ref pos, r32))
        {
            return false;
        }

        if(!TryReadDerInteger(der, contentEnd, ref pos, s32))
        {
            return false;
        }

        //Must have consumed exactly the SEQUENCE content — no extra elements.
        return pos == contentEnd;
    }


    /// <summary>
    /// Reads a DER length at <paramref name="pos"/> in <paramref name="buffer"/> and
    /// advances <paramref name="pos"/>. Enforces the minimal-encoding rule: short form
    /// when length &lt; 128, long-form-1-byte (0x81) with a byte ≥ 0x80 when 128–255.
    /// Returns <see langword="false"/> for indefinite form (0x80), multi-byte long form
    /// (≥ 0x82), or non-minimal long form (0x81 followed by a byte &lt; 0x80).
    /// </summary>
    private static bool TryReadDerLength(ReadOnlySpan<byte> buffer, ref int pos, out int length)
    {
        length = 0;
        if(pos >= buffer.Length)
        {
            return false;
        }

        byte first = buffer[pos++];
        if(first <= DerShortFormMaxLength)
        {
            //Short form: length is encoded directly.
            length = first;
            return true;
        }

        if(first != DerLongForm1ByteMarker)
        {
            //0x80 = indefinite; 0x82..0xFF = multi-byte long form → all rejected.
            return false;
        }

        //Long form, 1-byte length.
        if(pos >= buffer.Length)
        {
            return false;
        }

        byte lenByte = buffer[pos++];
        if(lenByte < DerMinimalLongFormThreshold)
        {
            //Non-minimal: lengths < 128 must use short form.
            return false;
        }

        length = lenByte;

        return true;
    }


    /// <summary>
    /// Reads one DER INTEGER at <paramref name="pos"/>, validates its encoding,
    /// strips at most one 0x00 sign byte, rejects negative values and non-minimal
    /// padding, rejects values that exceed 32 bytes, and left-pads the canonical
    /// value into <paramref name="dest32"/>.
    /// </summary>
    private static bool TryReadDerInteger(
        ReadOnlySpan<byte> buffer,
        int contentEnd,
        ref int pos,
        Span<byte> dest32)
    {
        //INTEGER tag.
        if(pos >= contentEnd || buffer[pos] != DerTagInteger)
        {
            return false;
        }

        pos++;

        if(!TryReadDerLength(buffer, ref pos, out int valueLen))
        {
            return false;
        }

        //Content must be at least 1 byte and must not exceed the SEQUENCE boundary.
        if(valueLen < 1 || pos + valueLen > contentEnd)
        {
            return false;
        }

        ReadOnlySpan<byte> value = buffer.Slice(pos, valueLen);
        pos += valueLen;

        //Reject negative integers: the high bit of the first byte must be clear.
        //r and s are unsigned; a legitimate encoder cannot produce a negative value.
        if((value[0] & 0x80) != 0)
        {
            return false;
        }

        //Reject non-minimal padding: a leading 0x00 is valid only when the next byte
        //has its high bit set (to distinguish a positive integer from a negative one).
        //0x00 followed by a byte with high bit clear is non-minimal.
        if(valueLen > 1 && value[0] == 0x00 && (value[1] & 0x80) == 0)
        {
            return false;
        }

        //Strip at most one 0x00 sign byte (the only valid case: high bit of the next
        //byte is 1, so the encoder prepended a zero to keep the value positive).
        ReadOnlySpan<byte> canonical = (value[0] == 0x00 && valueLen > 1)
            ? value[1..]
            : value;

        //A scalar that exceeds 32 bytes is necessarily ≥ 2^256 and therefore outside
        //[1, n−1] for P-256 regardless of the bit pattern: reject without allocating.
        if(canonical.Length > ScalarSizeBytes)
        {
            return false;
        }

        //Left-pad into the 32-byte destination (big-endian, zero-fill the high bytes).
        dest32.Clear();
        canonical.CopyTo(dest32[(ScalarSizeBytes - canonical.Length)..]);

        return true;
    }
}
