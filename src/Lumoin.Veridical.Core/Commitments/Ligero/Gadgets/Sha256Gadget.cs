using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Buffers.Binary;

namespace Lumoin.Veridical.Core.Commitments.Ligero.Gadgets;

/// <summary>
/// SHA-256 building blocks expressed as Ligero constraints over a prime field. A
/// 32-bit word is held as 32 boolean bit wires, least-significant first; the bitwise
/// operations (XOR / AND / NOT / OR) are per-bit, the rotations and shifts are free
/// rewirings, and modular addition recomposes the operands to the field, adds, and
/// re-decomposes the low bits (cheaper than a ripple-carry of full adders). Every
/// derived bit is forced to {0,1} by its defining constraint, so only witnessed input
/// bits carry an explicit boolean constraint.
/// </summary>
/// <remarks>
/// <para>
/// This is the Fp256 prototype of the hashing half of the Longfellow binding (proving
/// <c>e = SHA-256(message)</c> in-circuit so the signed message is tied to its hash).
/// The production path runs the same logic over GF(2^128), where XOR is field addition
/// and so is free; here each XOR bit costs one multiplication. Words are integers in
/// <c>[0, 2^32)</c>; rotations and shifts follow the SHA-256 convention on the 32-bit
/// integer value.
/// </para>
/// <para>
/// Unlike the EC, ECDSA and CBOR gadgets — which are extension methods on
/// <see cref="LigeroConstraintSystemBuilder"/> over data POCOs — this stays a stateful
/// class: it caches shared constant wires (a 0-bit and a 1-bit) and a power-of-two table
/// once per construction and threads them across a cohesive, individually-tested word
/// primitive surface (XOR/AND/NOT/OR, the rotations and shifts, modular addition). That
/// shared per-build state is the same justification the codebase's <c>R1csBuilder</c>
/// family carries; expressing the primitives as stateless builder extensions would either
/// re-emit those constant wires per call or lose the primitive-level tests.
/// </para>
/// </remarks>
internal sealed class Sha256Gadget
{
    private const int WordBits = 32;
    private const int ScalarSize = Scalar.SizeBytes;

    private readonly LigeroConstraintSystemBuilder builder;
    private readonly byte[][] powerOfTwo;
    private readonly byte[] one;
    private readonly byte[] negativeOne;
    private readonly byte[] negativeTwo;
    private readonly int zeroBit;
    private readonly int oneBit;


    public Sha256Gadget(LigeroConstraintSystemBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        this.builder = builder;

        one = Encode(1);
        negativeOne = Negate(one);
        negativeTwo = Negate(Encode(2));

        powerOfTwo = new byte[WordBits][];
        for(int i = 0; i < WordBits; i++)
        {
            byte[] power = new byte[ScalarSize];
            power[ScalarSize - 1 - (i >> 3)] = (byte)(1 << (i & 7));
            powerOfTwo[i] = power;
        }

        zeroBit = builder.AddConstant(Encode(0));
        oneBit = builder.AddConstant(one);
    }


    //A witnessed 32-bit word: 32 boolean bit wires (least-significant first) holding
    //the bits of value.
    public int[] WitnessWord(uint value)
    {
        int[] bits = new int[WordBits];
        Span<byte> bit = stackalloc byte[ScalarSize];
        for(int i = 0; i < WordBits; i++)
        {
            bit.Clear();
            bit[ScalarSize - 1] = (byte)((value >> i) & 1);
            bits[i] = builder.AddBit(bit);
        }

        return bits;
    }


    //A pinned constant 32-bit word (each bit fixed by a public target), for the round
    //constants and initial hash values.
    public int[] ConstantWord(uint value)
    {
        int[] bits = new int[WordBits];
        Span<byte> bit = stackalloc byte[ScalarSize];
        for(int i = 0; i < WordBits; i++)
        {
            bit.Clear();
            bit[ScalarSize - 1] = (byte)((value >> i) & 1);
            bits[i] = builder.AddConstant(bit);
        }

        return bits;
    }


    //Bitwise XOR: a ⊕ b = a + b − 2·(a·b) per bit (∈ {0,1} for boolean a, b).
    public int[] Xor(int[] a, int[] b)
    {
        int[] result = new int[WordBits];
        for(int i = 0; i < WordBits; i++)
        {
            int product = builder.Multiply(a[i], b[i]);
            result[i] = builder.Combine([Term(a[i], one), Term(b[i], one), Term(product, negativeTwo)]);
        }

        return result;
    }


    //Bitwise AND: a · b per bit.
    public int[] And(int[] a, int[] b)
    {
        int[] result = new int[WordBits];
        for(int i = 0; i < WordBits; i++)
        {
            result[i] = builder.Multiply(a[i], b[i]);
        }

        return result;
    }


    //Bitwise NOT: 1 − a per bit.
    public int[] Not(int[] a)
    {
        int[] result = new int[WordBits];
        for(int i = 0; i < WordBits; i++)
        {
            result[i] = builder.Combine([Term(oneBit, one), Term(a[i], negativeOne)]);
        }

        return result;
    }


    //Bitwise OR: a + b − a·b per bit.
    public int[] Or(int[] a, int[] b)
    {
        int[] result = new int[WordBits];
        for(int i = 0; i < WordBits; i++)
        {
            int product = builder.Multiply(a[i], b[i]);
            result[i] = builder.Combine([Term(a[i], one), Term(b[i], one), Term(product, negativeOne)]);
        }

        return result;
    }


    //Right rotation by n (SHA-256 ROTR): result bit j is input bit (j + n) mod 32.
    public static int[] RotateRight(int[] a, int n)
    {
        int[] result = new int[WordBits];
        for(int j = 0; j < WordBits; j++)
        {
            result[j] = a[(j + n) % WordBits];
        }

        return result;
    }


    //Logical right shift by n (SHA-256 SHR): result bit j is input bit j + n, or 0 once
    //that runs off the top.
    public int[] ShiftRight(int[] a, int n)
    {
        int[] result = new int[WordBits];
        for(int j = 0; j < WordBits; j++)
        {
            result[j] = (j + n) < WordBits ? a[j + n] : zeroBit;
        }

        return result;
    }


    //Addition modulo 2^32: recompose every operand to the field, sum, and keep the low
    //32 bits of the decomposition (the overflow bits are dropped).
    public int[] AddMod32(params int[][] words)
    {
        ArgumentNullException.ThrowIfNull(words);

        var terms = new LinearTerm[words.Length * WordBits];
        int t = 0;
        foreach(int[] word in words)
        {
            for(int i = 0; i < WordBits; i++)
            {
                terms[t++] = Term(word[i], powerOfTwo[i]);
            }
        }

        int sum = builder.Combine(terms);

        //Enough bits to hold the sum of all operands without wrap, then take the low 32.
        int extra = 0;
        while((1 << extra) < words.Length)
        {
            extra++;
        }

        int[] sumBits = builder.AddBits(sum, WordBits + extra);

        return sumBits[..WordBits];
    }


    //Reads a word's integer value from its bit wires (for gating against a reference).
    public uint WordValue(int[] word)
    {
        uint value = 0;
        for(int i = 0; i < WordBits; i++)
        {
            if((builder.Value(word[i])[ScalarSize - 1] & 1) != 0)
            {
                value |= 1u << i;
            }
        }

        return value;
    }


    //SHA-256 round constants (first 32 bits of the fractional parts of the cube roots of the
    //first 64 primes).
    private static readonly uint[] RoundConstants =
    [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    //SHA-256 initial hash values (first 32 bits of the fractional parts of the square roots of
    //the first 8 primes).
    private static readonly uint[] InitialHash =
    [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];


    //SHA-256 of an arbitrary-length message: pads (message ‖ 0x80 ‖ zeros ‖ 64-bit big-endian
    //bit length) to a multiple of 512 bits and chains the compression across the blocks. The
    //message bytes are witnessed; returns the eight digest words.
    public int[][] Hash(ReadOnlySpan<byte> message)
    {
        //Smallest multiple of 64 with room for the message, the 0x80 terminator, and 8 length bytes.
        int paddedLength = ((message.Length + 72) / 64) * 64;
        int blockCount = paddedLength / 64;

        int[][] hash = InitialHashState();
        Span<byte> block = stackalloc byte[64];
        for(int b = 0; b < blockCount; b++)
        {
            block.Clear();
            int start = b * 64;
            for(int i = 0; i < 64 && start + i < message.Length; i++)
            {
                block[i] = message[start + i];
            }

            //The 0x80 terminator sits one byte past the message (in whichever block holds it).
            if(message.Length >= start && message.Length < start + 64)
            {
                block[message.Length - start] = 0x80;
            }

            //The 64-bit length occupies the final eight bytes of the last block.
            if(b == blockCount - 1)
            {
                BinaryPrimitives.WriteUInt64BigEndian(block[56..], (ulong)message.Length * 8);
            }

            int[][] words = new int[16][];
            for(int t = 0; t < 16; t++)
            {
                words[t] = WitnessWord(BinaryPrimitives.ReadUInt32BigEndian(block.Slice(t * 4, 4)));
            }

            hash = CompressBlock(hash, words);
        }

        return hash;
    }


    //SHA-256 over a message already witnessed as one wire per byte. The same witnessed message
    //can then be shared with another gadget (e.g. CBOR disclosure), so a disclosed attribute is
    //provably in the hashed bytes. The padding (0x80, zeros, the 64-bit length) is added as
    //constants; assembling the words bit-decomposes each byte, which also pins it to [0,255].
    public int[][] Hash(int[] messageByteWires)
    {
        ArgumentNullException.ThrowIfNull(messageByteWires);

        int n = messageByteWires.Length;
        int paddedLength = ((n + 72) / 64) * 64;
        int blockCount = paddedLength / 64;

        Span<byte> lengthBytes = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(lengthBytes, (ulong)n * 8);

        int[] padded = new int[paddedLength];
        Span<byte> value = stackalloc byte[ScalarSize];
        for(int p = 0; p < paddedLength; p++)
        {
            if(p < n)
            {
                padded[p] = messageByteWires[p];
                continue;
            }

            byte padByte = p == n ? (byte)0x80 : p >= paddedLength - 8 ? lengthBytes[p - (paddedLength - 8)] : (byte)0;
            LigeroConstraintSystemBuilder.EncodeConstant(padByte, value);
            padded[p] = builder.AddConstant(value);
        }

        int[][] hash = InitialHashState();
        for(int b = 0; b < blockCount; b++)
        {
            int[][] words = new int[16][];
            for(int t = 0; t < 16; t++)
            {
                int baseIndex = (b * 64) + (t * 4);
                words[t] = WordFromBytes(padded[baseIndex], padded[baseIndex + 1], padded[baseIndex + 2], padded[baseIndex + 3]);
            }

            hash = CompressBlock(hash, words);
        }

        return hash;
    }


    //The eight initial hash words as pinned constants.
    private int[][] InitialHashState()
    {
        int[][] hash = new int[8][];
        for(int i = 0; i < 8; i++)
        {
            hash[i] = ConstantWord(InitialHash[i]);
        }

        return hash;
    }


    //Assembles a big-endian 32-bit word from four byte wires (byte0 most significant). Bit-
    //decomposing each byte also constrains it to [0,255].
    private int[] WordFromBytes(int byte0, int byte1, int byte2, int byte3)
    {
        int[] bits3 = builder.AddBits(byte3, 8);
        int[] bits2 = builder.AddBits(byte2, 8);
        int[] bits1 = builder.AddBits(byte1, 8);
        int[] bits0 = builder.AddBits(byte0, 8);

        int[] word = new int[WordBits];
        for(int i = 0; i < 8; i++)
        {
            word[i] = bits3[i];
            word[8 + i] = bits2[i];
            word[16 + i] = bits1[i];
            word[24 + i] = bits0[i];
        }

        return word;
    }


    //One SHA-256 compression: the message schedule (extending the first 16 words to 64), the 64
    //rounds, and the add-back of the input state.
    private int[][] CompressBlock(int[][] hashState, int[][] first16Words)
    {
        int[][] w = new int[64][];
        for(int t = 0; t < 16; t++)
        {
            w[t] = first16Words[t];
        }

        for(int t = 16; t < 64; t++)
        {
            w[t] = AddMod32(w[t - 16], LowerSigma0(w[t - 15]), w[t - 7], LowerSigma1(w[t - 2]));
        }

        int[] a = hashState[0], b = hashState[1], c = hashState[2], d = hashState[3], e = hashState[4], f = hashState[5], g = hashState[6], h = hashState[7];
        for(int t = 0; t < 64; t++)
        {
            int[] t1 = AddMod32(h, BigSigma1(e), Choose(e, f, g), ConstantWord(RoundConstants[t]), w[t]);
            int[] t2 = AddMod32(BigSigma0(a), Majority(a, b, c));
            h = g;
            g = f;
            f = e;
            e = AddMod32(d, t1);
            d = c;
            c = b;
            b = a;
            a = AddMod32(t1, t2);
        }

        int[][] result = new int[8][];
        result[0] = AddMod32(hashState[0], a);
        result[1] = AddMod32(hashState[1], b);
        result[2] = AddMod32(hashState[2], c);
        result[3] = AddMod32(hashState[3], d);
        result[4] = AddMod32(hashState[4], e);
        result[5] = AddMod32(hashState[5], f);
        result[6] = AddMod32(hashState[6], g);
        result[7] = AddMod32(hashState[7], h);

        return result;
    }


    //Writes the 32-byte big-endian digest from the eight hash words (for gating).
    public void DigestBytes(int[][] hashWords, Span<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(hashWords);
        for(int i = 0; i < 8; i++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(i * 4, 4), WordValue(hashWords[i]));
        }
    }


    //The 32 digest bytes as wires (each in [0,255]), big-endian, for use as a derived match
    //pattern — e.g. proving an outer message (an MSO) contains this digest of an inner item.
    public int[] DigestByteWires(int[][] hashWords)
    {
        ArgumentNullException.ThrowIfNull(hashWords);

        int[] digestBytes = new int[32];
        int index = 0;
        for(int word = 0; word < 8; word++)
        {
            for(int byteIndex = 0; byteIndex < 4; byteIndex++)
            {
                //Big-endian: the most significant byte (word bits 24..31) comes first.
                int baseBit = (3 - byteIndex) * 8;
                int[] eightBits = hashWords[word][baseBit..(baseBit + 8)];
                digestBytes[index++] = builder.AddRecomposedScalar(eightBits);
            }
        }

        return digestBytes;
    }


    //Σ0(a) = ROTR(a,2) ⊕ ROTR(a,13) ⊕ ROTR(a,22).
    private int[] BigSigma0(int[] a) => Xor(Xor(RotateRight(a, 2), RotateRight(a, 13)), RotateRight(a, 22));

    //Σ1(e) = ROTR(e,6) ⊕ ROTR(e,11) ⊕ ROTR(e,25).
    private int[] BigSigma1(int[] e) => Xor(Xor(RotateRight(e, 6), RotateRight(e, 11)), RotateRight(e, 25));

    //σ0(x) = ROTR(x,7) ⊕ ROTR(x,18) ⊕ SHR(x,3).
    private int[] LowerSigma0(int[] x) => Xor(Xor(RotateRight(x, 7), RotateRight(x, 18)), ShiftRight(x, 3));

    //σ1(x) = ROTR(x,17) ⊕ ROTR(x,19) ⊕ SHR(x,10).
    private int[] LowerSigma1(int[] x) => Xor(Xor(RotateRight(x, 17), RotateRight(x, 19)), ShiftRight(x, 10));

    //Ch(e,f,g) = (e ∧ f) ⊕ (¬e ∧ g).
    private int[] Choose(int[] e, int[] f, int[] g) => Xor(And(e, f), And(Not(e), g));

    //Maj(a,b,c) = (a ∧ b) ⊕ (a ∧ c) ⊕ (b ∧ c).
    private int[] Majority(int[] a, int[] b, int[] c) => Xor(Xor(And(a, b), And(a, c)), And(b, c));


    private static LinearTerm Term(int wire, ReadOnlyMemory<byte> coefficient) => new(wire, coefficient);


    private byte[] Negate(ReadOnlySpan<byte> value)
    {
        byte[] negated = new byte[ScalarSize];
        builder.Negate(value, negated);

        return negated;
    }


    private static byte[] Encode(uint value)
    {
        byte[] bytes = new byte[ScalarSize];
        LigeroConstraintSystemBuilder.EncodeConstant(value, bytes);

        return bytes;
    }
}
