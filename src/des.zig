const std = @import("std");
const builtin = @import("builtin");

const DesError = error {
    InvalidCipherDescription,
    SrcDstSizeMismatch,
    InvalidSrcLenght,
};

pub const Mode = enum {
    CBC,
};

const CipherDescr = struct {
    key: u64,
    mode: Mode,
    iv: ?u64 = undefined,
};

pub const Cipher = struct {
    key: u64,
    subkeys: [16]u48,
    inv_subkeys: [16]u48,
    mode: Mode,
    iv: ?u64,

    pub const Action = enum { decrypt, encrypt };

    pub fn init(descr: CipherDescr) !Cipher {
        const key = descr.key;
        const subkeys = generateSubkeys(descr.key);
        var inv_subkeys = subkeys;
        std.mem.reverse(u48, inv_subkeys[0..]);

        const mode = descr.mode;
        const iv = descr.iv;

        return Cipher {
            .key = key,
            .subkeys = subkeys,
            .inv_subkeys = inv_subkeys,
            .mode = mode,
            .iv = iv,
        };
    }

    fn performCBC(self: *const Cipher, comptime action: Action, dst: []u8, src: []u8) !void {
        const lenght = src.len / 8;
        const subkeys = if (action == .encrypt) self.subkeys else self.inv_subkeys;
        const iv = self.iv;

        var i: usize = 0;
        var last_block = Block { .repr = iv.? };
        var block: Block = undefined;
        var result: Block = undefined;
        while (i < lenght) : (i += 1) {
            if (action == .encrypt) {
                block = Block.fromBytes(src[8 * i ..][0..8].*);
                result = block.xor(last_block).encode(&subkeys);
                last_block = result;
            }
            else {
                block = Block.fromBytes(src[8 * i ..][0..8].*);
                result = block.encode(&subkeys).xor(last_block);
                last_block = block;
            }

            @memcpy(dst[8 * i ..][0..8], &result.toBytes());
        }
    }

    pub fn perform(self: *const Cipher, comptime action: Action, dst: []u8, src: []u8) !void {
        if (dst.len != src.len) return DesError.SrcDstSizeMismatch;
        if (src.len % 8 != 0) return DesError.InvalidSrcLenght;

        try self.performCBC(action, dst, src);
    }
};

pub const Block = struct {
    repr: u64,

    pub fn xor(a: Block, b: Block) Block {
        return Block { .repr = a.repr ^ b.repr };
    }

    pub fn fromBytes(bytes: [8]u8) Block {
        const repr = std.mem.readInt(u64, &bytes, .big);
        return Block { .repr = repr };
    }

    pub fn toBytes(block: Block) [8]u8 {
        var result = std.mem.toBytes(block.repr);
        if (builtin.cpu.arch.endian() == .little) {
            std.mem.reverse(u8, &result);
        }
        return result;
    }

    pub fn encode(block: *const Block, subkeys: *const [16]u48) Block {
        var out: u64 = 0;
        for (&IP, 0..) |p, i| {
            out |= @as(u64,@intCast(((@as(u64, @as(u64, 1) << (63-(@as(u6,@intCast(p-1))))) & block.repr) >> (63-@as(u6,@intCast(p-1)))) << @as(u6,@intCast(63 - i))));
        }

        var lhs: u32 = @as(u32,@truncate( (out >> 32)));
        var rhs: u32 = @as(u32,@truncate( out));

        var i: usize = 0;
        while (i < 16) : (i += 1) {
            const subkey = subkeys[i];

            const tmp = lhs; 
            lhs = rhs;
            rhs = tmp ^ feistel(rhs, subkey);
        }

        const R16L16: u64 = (@as(u64, rhs) << 32) | @as(u64, lhs);
        out = 0;
        for (&IP_1, 0..) |p, j| {
            out |= (((@as(u64, 1) << @as(u6,@intCast(63-(p-1)))) & R16L16) >> @as(u6,@intCast(63-(p-1)))) << @as(u6,@intCast(63 - j));
        }

        return Block { .repr = out };
    }
};

fn feistel(Rn: u32, key: u48) u32 {
    var expanded_rn: u48 = 0;
    for (&E_BIT_SELECTION, 0..) |p, i| {
        expanded_rn |= (@as(u48, ((@as(u32, 1) << @as(u5,@intCast(31-(p-1)))) & Rn) >> @as(u5,@intCast(31-(p-1)))) << @as(u6,@intCast(47 - i)));
    }

    const xored_expanded_rn: u48 = expanded_rn ^ key;

    var result: u32 = 0;
    var i: usize = 0;
    while (i < S_TABLES.len) : (i += 1) {
        const index: u6 = @as(u6,@truncate( xored_expanded_rn >> @as(u6,@intCast(6 * ((S_TABLES.len - 1) - i)))));

        const normalized_index: u6 = (@as(u6, 0xF) & index >> 1) + 16 * ((index & @as(u6, 0x1)) | ((index >> 4) & @as(u6, 0x2)));

        result |= (@as(u32, S_TABLES[i][@as(usize, normalized_index)]) << @as(u5,@intCast(4 * ((S_TABLES.len - 1) - i))));
    }

    var permuted_result: u32 = 0; 
    for (&P, 0..) |p, j| {
        permuted_result |= (((@as(u32, 1) << @as(u5,@intCast(31-(p-1)))) & result) >> @as(u5,@intCast(31-(p-1)))) << @as(u5,@intCast(31 - j));
    }

    return permuted_result;
}

fn generateSubkeys(key: u64) [16]u48 {
    var subkeys: [16]u48 = .{0}**16;
    var stripped_key: u56 = 0;
    for (&PC1, 0..) |p, i| {
        stripped_key |= @as(u56,@intCast(((@as(u64, @as(u64, 1) << (63-(p-1))) & key) >> (63-(p-1))) << @as(u6,@intCast(55 - i))));
    }

    var key_lhs: u28 = @as(u28,@intCast((stripped_key & @as(u56, 0xF_FF_FF_FF) << @as(u6,@intCast(28))) >> @as(u6,@intCast(28))));
    var key_rhs: u28 = @as(u28,@intCast(stripped_key & @as(u56, 0xF_FF_FF_FF)));

    var i: usize = 0;
    while (i < 16) : (i += 1) {
        var k: u2 = 0;
        while (k < ROTATIONS[i]) : (k += 1) {
            key_lhs = (key_lhs << 1) | (key_lhs & @as(u28, 1 << 27)) >> 27;
            key_rhs = (key_rhs << 1) | (key_rhs & @as(u28, 1 << 27)) >> 27;
        }

        const subkey: u56 = (@as(u56,@intCast(key_lhs)) << @as(u6,@intCast(28))) | @as(u56,@intCast(key_rhs));
        var permutated_subkey: u48 = 0;    
        for (&PC2, 0..) |p, j| {
            permutated_subkey |= @as(u48,@intCast((((@as(u56, 1) << (55-(p-1))) & subkey) >> (55-(p-1))) << @as(u6,@intCast(47 - j))));
        }
        subkeys[i] = permutated_subkey;
    }

    return subkeys;
}

// KEY GEN
const PC1 = [_]u6{
    57, 49, 41, 33, 25, 17, 9 ,	1,
    58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3,
    60,	52, 44, 36, 63, 55, 47, 39,
    31,	23, 15, 7 , 62, 54, 46, 38,
    30,	22, 14, 6 , 61, 53, 45, 37,
    29,	21, 13, 5 , 28, 20, 12, 4 
};

const PC2 = [_]u6{
    14, 17, 11, 24,  1,  5,  3, 28,
    15,  6, 21, 10, 23, 19, 12,  4,
    26,  8, 16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
};

const ROTATIONS = [_]u2{
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 
};

// ENCRYPTION
const IP = [_]u7{
    58,    50,   42,    34,    26,   18,    10,    2, 
    60,    52,   44,    36,    28,   20,    12,    4,
    62,    54,   46,    38,    30,   22,    14,    6,
    64,    56,   48,    40,    32,   24,    16,    8,
    57,    49,   41,    33,    25,   17,     9,    1,
    59,    51,   43,    35,    27,   19,    11,    3,
    61,    53,   45,    37,    29,   21,    13,    5,
    63,    55,   47,    39,    31,   23,    15,    7,
};

const P = [_]u6 {
    16,   7,  20,  21, 
    29,  12,  28,  17,
     1,  15,  23,  26,
     5,  18,  31,  10,
     2,   8,  24,  14,
    32,  27,   3,   9,
    19,  13,  30,   6,
    22,  11,   4,  25,
};

const E_BIT_SELECTION = [_]u7{
    32,     1,    2,     3,     4,    5, 
     4,     5,    6,     7,     8,    9,
     8,     9,   10,    11,    12,   13,
    12,    13,   14,    15,    16,   17,
    16,    17,   18,    19,    20,   21,
    20,    21,   22,    23,    24,   25,
    24,    25,   26,    27,    28,   29,
    28,    29,   30,    31,    32,    1,
};

const IP_1 = [_]u7{
    40,     8,   48,    16,    56,   24,    64,   32, 
    39,     7,   47,    15,    55,   23,    63,   31,
    38,     6,   46,    14,    54,   22,    62,   30,
    37,     5,   45,    13,    53,   21,    61,   29,
    36,     4,   44,    12,    52,   20,    60,   28,
    35,     3,   43,    11,    51,   19,    59,   27,
    34,     2,   42,    10,    50,   18,    58,   26,
    33,     1,   41,     9,    49,   17,    57,   25,
};

const S_TABLES = [8][64]u4{
    .{
     14,  4,  13,  1,   2, 15,  11,  8,   3, 10,   6, 12,   5,  9,   0,  7, 
      0, 15,   7,  4,  14,  2,  13,  1,  10,  6,  12, 11,   9,  5,   3,  8,
      4,  1,  14,  8,  13,  6,   2, 11,  15, 12,   9,  7,   3, 10,   5,  0,
     15, 12,   8,  2,   4,  9,   1,  7,   5, 11,   3, 14,  10,  0,   6, 13,
    },
    .{    
     15,  1,   8, 14,   6, 11,   3,  4,   9,  7,   2, 13,  12,  0,   5, 10, 
      3, 13,   4,  7,  15,  2,   8, 14,  12,  0,   1, 10,   6,  9,  11,  5,
      0, 14,   7, 11,  10,  4,  13,  1,   5,  8,  12,  6,   9,  3,   2, 15,
     13,  8,  10,  1,   3, 15,   4,  2,  11,  6,   7, 12,   0,  5,  14,  9,
    },
    .{
     10,  0,   9, 14,   6,  3,  15,  5,   1, 13,  12,  7,  11,  4,   2,  8, 
     13,  7,   0,  9,   3,  4,   6, 10,   2,  8,   5, 14,  12, 11,  15,  1,
     13,  6,   4,  9,   8, 15,   3,  0,  11,  1,   2, 12,   5, 10,  14,  7,
      1, 10,  13,  0,   6,  9,   8,  7,   4, 15,  14,  3,  11,  5,   2, 12,
    },
    .{
      7, 13,  14,  3,   0,  6,   9, 10,   1,  2,   8,  5,  11, 12,   4, 15, 
     13,  8,  11,  5,   6, 15,   0,  3,   4,  7,   2, 12,   1, 10,  14,  9,
     10,  6,   9,  0,  12, 11,   7, 13,  15,  1,   3, 14,   5,  2,   8,  4,
      3, 15,   0,  6,  10,  1,  13,  8,   9,  4,   5, 11,  12,  7,   2, 14,
    },
    .{
      2, 12,   4,  1,   7, 10,  11,  6,   8,  5,   3, 15,  13,  0,  14,  9, 
     14, 11,   2, 12,   4,  7,  13,  1,   5,  0,  15, 10,   3,  9,   8,  6,
      4,  2,   1, 11,  10, 13,   7,  8,  15,  9,  12,  5,   6,  3,   0, 14,
     11,  8,  12,  7,   1, 14,   2, 13,   6, 15,   0,  9,  10,  4,   5,  3,
    },
    .{
     12,  1,  10, 15,   9,  2,   6,  8,   0, 13,   3,  4,  14,  7,   5, 11, 
     10, 15,   4,  2,   7, 12,   9,  5,   6,  1,  13, 14,   0, 11,   3,  8,
      9, 14,  15,  5,   2,  8,  12,  3,   7,  0,   4, 10,   1, 13,  11,  6,
      4,  3,   2, 12,   9,  5,  15, 10,  11, 14,   1,  7,   6,  0,   8, 13,
    },
    .{
      4, 11,   2, 14,  15,  0,   8, 13,   3, 12,   9,  7,   5, 10,   6,  1, 
     13,  0,  11,  7,   4,  9,   1, 10,  14,  3,   5, 12,   2, 15,   8,  6,
      1,  4,  11, 13,  12,  3,   7, 14,  10, 15,   6,  8,   0,  5,   9,  2,
      6, 11,  13,  8,   1,  4,  10,  7,   9,  5,   0, 15,  14,  2,   3, 12,
    },
    .{
     13,  2,   8,  4,   6, 15,  11,  1,  10,  9,   3, 14,   5,  0,  12,  7, 
      1, 15,  13,  8,  10,  3,   7,  4,  12,  5,   6, 11,   0, 14,   9,  2,
      7, 11,   4,  1,   9, 12,  14,  2,   0,  6,  10, 13,  15,  3,   5,  8,
      2,  1,  14,  7,   4, 10,   8, 13,  15, 12,   9,  0,   3,  5,   6, 11,
    }
};

// TESTS //
test "Subkeys generation" {
    const key: u64 = 0x133457799BBCDFF1;
    const subkeys: [16]u48 = generateSubkeys(key);
    const correct_subkeys = [_]u48{
        0b000110110000001011101111111111000111000001110010,
        0b011110011010111011011001110110111100100111100101,
        0b010101011111110010001010010000101100111110011001,
        0b011100101010110111010110110110110011010100011101,
        0b011111001110110000000111111010110101001110101000,
        0b011000111010010100111110010100000111101100101111,
        0b111011001000010010110111111101100001100010111100,
        0b111101111000101000111010110000010011101111111011,
        0b111000001101101111101011111011011110011110000001,
        0b101100011111001101000111101110100100011001001111,
        0b001000010101111111010011110111101101001110000110,
        0b011101010111000111110101100101000110011111101001,
        0b100101111100010111010001111110101011101001000001,
        0b010111110100001110110111111100101110011100111010,
        0b101111111001000110001101001111010011111100001010,
        0b110010110011110110001011000011100001011111110101,
    };

    for (subkeys, correct_subkeys) |subkey, correct_subkey| {
        try std.testing.expect(subkey == correct_subkey);
    } 
}

test "Block encode" {
    const key: u64 = 0x133457799BBCDFF1;
    const subkeys: [16]u48 = generateSubkeys(key);

    const src_bytes: [8]u8 = .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    const src_block = Block.fromBytes(src_bytes);

    const dst_block = src_block.encode(&subkeys);
    const dst_bytes = dst_block.toBytes();
    const expected_dst_bytes: [8]u8 = .{ 0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a, 0xb4, 0x05 };

    try std.testing.expect(std.mem.eql(u8, &dst_bytes, &expected_dst_bytes));
}

test "CBC encryption/decryption" {
    const key: u64 = 0x133457799BBCDFF1;
    const iv: u64 = 0x0101010101010101;

    const cipher = try Cipher.init(.{
        .key = key,
        .mode = .CBC,
        .iv = iv,
    });

    const plaintext: [16]u8 = .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } ** 2;
    const ciphertext: [16]u8 = .{ 0xb7, 0x8d, 0x73, 0xc8, 0x4a, 0x4c, 0x2f, 0xc5,
                                  0x78, 0xdb, 0x61, 0x6c, 0x4e, 0x3a, 0xe4, 0xbb };

    var src: [16]u8 = plaintext;
    var dst: [16]u8 = .{0} ** 16;
    try cipher.perform(.encrypt, &dst, &src);
    try std.testing.expect(std.mem.eql(u8, &dst, &ciphertext));

    src = ciphertext;
    dst = .{0} ** 16;
    try cipher.perform(.decrypt, &dst, &src);
    try std.testing.expect(std.mem.eql(u8, &dst, &plaintext));
}
