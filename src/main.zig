const std = @import("std");
const des = @import("des");
const args = @import("args");

const Error = error {
    WrongArgsNum,
    WrongKey,
    WrongIv,
    WrongHex,
    WrongInputFile,
    WrongOutputFile,
    WrongArg,
    FileWritingError
};

fn printHelp() void {
    std.log.info(
        "[usage] DES [-d] -k <key:[8B/16B]> <input_file_path> <output_file_path>\n" ++
        "   -d    : decrypt(default encrypt)\n" ++
        "   -i    : iv (for CBC mode)\n" ++
        "  --help : print this message", .{}
    );
}

//fn parseArgs(args: [][:0]u8) Error!anytype {
//    if (args.len > 8 or args.len < 7) {
//        printHelp();
//        return error.WrongArgsNum;
//    }
//
//    const mode: des.Mode = if(std.mem.eql(u8, args[1], "-d")) .decrypt else .encrypt;
//
//    if (mode == .decrypt and args.len != 8) {
//        printHelp();
//        return error.WrongArgsNum;
//    }
//
//    if (!std.mem.eql(u8, args[1 + @as(usize, @intFromBool(mode == .decrypt))][0..2], "-k")) {
//        printHelp();
//        return error.WrongArg;
//    }
//
//    const key_in_hex = std.mem.eql(u8, args[1 + @as(usize, @intFromBool(mode == .decrypt))], "-kx");
//
//    const key_str = args[2 + @as(usize, @intFromBool(mode == .decrypt))];
//    if ((!key_in_hex and key_str.len != 8) and key_str.len != 16) {
//        printHelp();
//        return error.WrongKey;
//    }
//
//    var key: u64 = 0; 
//    if (key_in_hex) {
//        var i: u6 = 0;
//        while (i < 16) : (i += 1) {
//            const key_char = key_str[@as(usize, i)];
//            var offset: u8 = 0;
//            if (key_char >= '0' and key_char <= '9') {
//                offset = '0';
//            } else if (key_char >= 'A' and key_char <= 'F') {
//                offset = 'A' - 10;
//            } else if (key_char >= 'a' and key_char <= 'f') {
//                offset = 'a' - 10;                 
//            } else {
//                printHelp();
//                return error.WrongKey;
//            }
//
//            key |= (@as(u64, @as(u4,@truncate( key_char - offset))) << ((15 - i) * 4));
//        }
//    } else {
//        var i: u6 = 0;
//        while (i < 8) : (i += 1) {
//            key |= (@as(u64, key_str[@as(usize, i)]) << (i * 8));
//        }
//    }
//
//    const intput_file = std.fs.cwd().openFileZ(
//        args[4 + @as(usize, @intFromBool(decrypt))],
//        .{ .mode = .read_only }
//    ) catch {
//        printHelp();
//        return error.WrongInputFile;
//    };
//
//    if (!std.mem.eql(u8, args[5 + @as(usize, @intFromBool(decrypt))], "-o")) {
//        printHelp();
//        return error.WrongArg;
//    }
//
//    const output_file = std.fs.cwd().createFileZ(
//        args[6 + @as(usize, @intFromBool(decrypt))],
//        .{ .truncate = true }
//    ) catch {
//        printHelp();
//        return error.WrongOutputFile;
//    };
//
//    return .{
//        .cipher = des.Cipher.init(.{
//            .key = key,
//            .mode = .CBC,
//            .iv = iv,
//            }),
//        .action = action,
//        .input_file = intput_file,
//        .output_file = output_file
//    };
//}

fn parseHex(str: []const u8) !u64 {
    var i: u6 = 0;
    var out: u64 = 0;

    while (i < 16) : (i += 1) {
        const char = str[@as(u6, i)];
        var offset: u8 = 0;
        if (char >= '0' and char <= '9') {
            offset = '0';
        } else if (char >= 'A' and char <= 'F') {
            offset = 'A' - 10;
        } else if (char >= 'a' and char <= 'f') {
            offset = 'a' - 10;                 
        } else {
            printHelp();
            return error.WrongHex;
        }

        out |= (@as(u64, @as(u4,@truncate(char - offset))) << ((15 - i) * 4));
    }
    return out;
}

pub fn main() !u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const options = args.parseForCurrentProcess(struct {
        decrypt: bool = false,
        key: []const u8 = undefined,
        iv: []const u8 = undefined,
        help: bool = false,

        pub const shorthands = .{
            .d = "decrypt",
            .k = "key",
            .i = "iv",
            .h = "help",
        };
    }, allocator, .print) catch return 1;
    defer options.deinit();

    if (options.options.help) {
        printHelp();
        return 0;
    }

    if (options.options.key.len != 16) return Error.WrongKey;
    if (options.options.iv.len != 16) return Error.WrongIv;

    const key: u64 = try parseHex(options.options.key);
    const iv: u64 = try parseHex(options.options.iv);
    const action: des.Cipher.Action = if(options.options.decrypt) .decrypt else .encrypt;

    const src_filepath = options.positionals[0];
    const dst_filepath = options.positionals[1];

    const src = try std.fs.cwd().readFileAlloc(allocator, src_filepath, 4096);
    defer allocator.free(src);

    const dst = try allocator.alloc(u8, src.len);
    defer allocator.free(dst);

    const cipher = try des.Cipher.init(.{
        .key = key,
        .mode = .CBC,
        .iv = iv,
    });

    switch (action) {
        .decrypt => try cipher.perform(.decrypt, dst, src),
        .encrypt => try cipher.perform(.encrypt, dst, src),
    }

    try std.fs.cwd().writeFile(dst_filepath, dst);

    return 0;
}
