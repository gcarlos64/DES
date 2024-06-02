const std = @import("std");
const des = @import("des");

const Error = error {
    WrongArgsNum,
    WrongKey,
    WrongInputFile,
    WrongOutputFile,
    WrongArg,
    FileWritingError
};

fn printHelp() void {
    std.log.info(
        "[usage] DES [-d] -k[x] <key:[8B/16B]> -i <input_file_path> -o <output_file_path\n" ++
        "   -x    : key in hex format\n" ++
        "   -d    : decrypt(default encrypt)\n" ++
        "  --help : print this message", .{}
    );
}

fn parseArgs(args: [][:0]u8) Error!des.AlgorithmDescriptor {
    if (args.len > 8 or args.len < 7) {
        printHelp();
        return error.WrongArgsNum;
    }

    const decrypt = std.mem.eql(u8, args[1], "-d");

    if (decrypt and args.len != 8) {
        printHelp();
        return error.WrongArgsNum;
    }

    if (!std.mem.eql(u8, args[1 + @as(usize, @intFromBool(decrypt))][0..2], "-k")) {
        printHelp();
        return error.WrongArg;
    }

    const key_in_hex = std.mem.eql(u8, args[1 + @as(usize, @intFromBool(decrypt))], "-kx");

    const key_str = args[2 + @as(usize, @intFromBool(decrypt))];
    if ((!key_in_hex and key_str.len != 8) and key_str.len != 16) {
        printHelp();
        return error.WrongKey;
    }

    var key: u64 = 0; 
    if (key_in_hex) {
        var i: u6 = 0;
        while (i < 16) : (i += 1) {
            const key_char = key_str[@as(usize, i)];
            var offset: u8 = 0;
            if (key_char >= '0' and key_char <= '9') {
                offset = '0';
            } else if (key_char >= 'A' and key_char <= 'F') {
                offset = 'A' - 10;
            } else if (key_char >= 'a' and key_char <= 'f') {
                offset = 'a' - 10;                 
            } else {
                printHelp();
                return error.WrongKey;
            }

            key |= (@as(u64, @as(u4,@truncate( key_char - offset))) << ((15 - i) * 4));
        }
    } else {
        var i: u6 = 0;
        while (i < 8) : (i += 1) {
            key |= (@as(u64, key_str[@as(usize, i)]) << (i * 8));
        }
    }

    if (!std.mem.eql(u8, args[3 + @as(usize, @intFromBool(decrypt))], "-i")) {
        printHelp();
        return error.WrongArg;
    }
    
    const intput_file = std.fs.cwd().openFileZ(
        args[4 + @as(usize, @intFromBool(decrypt))],
        .{ .mode = .read_only }
    ) catch {
        printHelp();
        return error.WrongInputFile;
    };

    if (!std.mem.eql(u8, args[5 + @as(usize, @intFromBool(decrypt))], "-o")) {
        printHelp();
        return error.WrongArg;
    }

    const output_file = std.fs.cwd().createFileZ(
        args[6 + @as(usize, @intFromBool(decrypt))],
        .{ .truncate = true }
    ) catch {
        printHelp();
        return error.WrongOutputFile;
    };

    return des.AlgorithmDescriptor{
        .key = key,
        .decrypt = decrypt,
        .input_file = intput_file,
        .output_file = output_file
    };
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if ((args.len == 2 and std.mem.eql(u8, args[1], "--help"))) {
        printHelp();
        return;
    }
    var alg_descriptor = try parseArgs(args);

    des.generateKeys(alg_descriptor.key, &alg_descriptor.subkeys);

    if (alg_descriptor.decrypt) {
        std.mem.reverse(u48, alg_descriptor.subkeys[0..]);
    } 

    try des.perform(alg_descriptor);
    alg_descriptor.input_file.close();
    alg_descriptor.output_file.close();
}
