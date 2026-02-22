const SHA = @This();

const std = @import("std");
const Io = std.Io;
const print = std.debug.print;

// type aliases
const word = u32;

pub const ShaAlgos = enum {
    sha1,
    sha256,
    sha384,
    sha512,
};

// fields
allocator: std.mem.Allocator,
init: std.process.Init,

pub fn initSHA(init: std.process.Init, allocator: std.mem.Allocator) SHA {
    return SHA{
        .allocator = allocator,
        .init = init,
    };
}

pub fn getHash(self: SHA, file: []const u8, algo: ShaAlgos) ![]const u8 {
    const data = try std.Io.Dir.cwd().readFileAlloc(self.init.io, file, self.allocator, std.Io.Limit.unlimited);
    return switch (algo) {
        .sha1 => SHA1.SHA1(data, self.allocator),
        .sha256 => unreachable,
        .sha384 => unreachable,
        .sha512 => unreachable,
    };
}

const SHAUtils = struct {
    fn shr(n: word, x: word) word {
        return std.math.shr(word, x, n);
    }

    fn rotr(n: u5, x: word) word {
        return std.math.rotr(word, x, n);
    }

    fn rotl(n: u5, x: word) word {
        return std.math.rotl(word, x, n);
    }

    fn ch(x: word, y: word, z: word) word {
        return (x & y) ^ (~x & z);
    }

    fn parity(x: word, y: word, z: word) word {
        return x ^ y ^ z;
    }

    fn maj(x: word, y: word, z: word) word {
        return (x & y) ^ (x & z) ^ (y & z);
    }
};

const SHA256: type = struct {
    fn SIGMA0(x: word) word {
        return SHAUtils.rotr(2, x) ^ SHAUtils.rotr(13, x) ^ SHAUtils.rotr(22, x);
    }

    fn SIGMA1(x: word) word {
        return SHAUtils.rotr(6, x) ^ SHAUtils.rotr(11, x) ^ SHAUtils.rotr(25, x);
    }

    fn sigma0(x: word) word {
        return SHAUtils.rotr(7, x) ^ SHAUtils.rotr(18, x) ^ SHAUtils.shr(3, x);
    }

    fn sigma1(x: word) word {
        return SHAUtils.rotr(17, x) ^ SHAUtils.rotr(19, x) ^ SHAUtils.shr(10, x);
    }
    const sha256Constants: [256]word = .{
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };

    pub fn getSHA256Constants(t: word) word {
        return sha256Constants[t];
    }

    fn SHA256Preprocessing(message: []const u8, allocator: std.mem.Allocator) ![]const u8 {
        return SHA1.SHA1Preprocessing(message, allocator);
    }

    fn SHA256Parsing(message: []const u8, allocator: std.mem.Allocator) ![][16]word {
        return SHA1.SHA1Parsing(message, allocator);
    }

    pub fn SHA256(message: []const u8, allocator: std.mem.Allocator) ![]const u8 {
        const preprocessedData = try SHA256Preprocessing(message, allocator);
        const parsedData = try SHA256Parsing(message, allocator);
        _ = preprocessedData;
        _ = parsedData;

        // TODO(Aniket): To be implemented
    }
};

const SHA1 = struct {
    fn getSHA1Constants(t: word) word {
        if (t >= 0 and t <= 19) {
            return 0x5A827999;
        } else if (t >= 20 and t <= 39) {
            return 0x6ED9EBA1;
        } else if (t >= 40 and t <= 59) {
            return 0x8F1BBCDC;
        } else {
            return 0xCA62C1D6;
        }
    }

    pub fn SHA1Function(t: word, x: word, y: word, z: word) word {
        if (t >= 0 and t <= 19) {
            return SHAUtils.ch(x, y, z);
        } else if (t >= 20 and t <= 39) {
            return SHAUtils.parity(x, y, z);
        } else if (t >= 40 and t <= 59) {
            return SHAUtils.maj(x, y, z);
        } else {
            return SHAUtils.parity(x, y, z);
        }
    }
    pub fn SHA1Preprocessing(message: []const u8, allocator: std.mem.Allocator) ![]const u8 {
        const length: u64 = message.len * 8;
        const k = (447 - length % 512) % 512;
        const additionalBytesRequired = (k + 1) / 8;
        var newByteArray = try allocator.alloc(u8, message.len + additionalBytesRequired + @sizeOf(u64));

        @memset(newByteArray, 0);
        std.mem.copyForwards(u8, newByteArray, message);
        newByteArray[message.len] = 0x80;
        newByteArray[newByteArray.len - 1] = @intCast((length & 0x00000000000000FF));
        newByteArray[newByteArray.len - 2] = @intCast((length & 0x000000000000FF00) >> 8);
        newByteArray[newByteArray.len - 3] = @intCast((length & 0x0000000000FF0000) >> 16);
        newByteArray[newByteArray.len - 4] = @intCast((length & 0x00000000FF000000) >> 24);
        newByteArray[newByteArray.len - 5] = @intCast((length & 0x000000FF00000000) >> 32);
        newByteArray[newByteArray.len - 6] = @intCast((length & 0x0000FF0000000000) >> 40);
        newByteArray[newByteArray.len - 7] = @intCast((length & 0x00FF000000000000) >> 48);
        newByteArray[newByteArray.len - 8] = @intCast((length & 0xFF00000000000000) >> 56);

        return newByteArray;
    }

    pub fn SHA1Parsing(message: []const u8, allocator: std.mem.Allocator) ![][16]word {
        const noOfBlocks = (message.len * 8) / 512;
        const parsedMessage = try allocator.alloc([16]word, noOfBlocks);
        var i: u64 = 0;
        while (i < noOfBlocks) : (i += 1) {
            var j: u64 = 0;
            while (j < 16) : (j += 1) {
                const idxIntoMessage = i * 64 + j * 4;
                const bytes: [4]u8 = .{ message[idxIntoMessage], message[idxIntoMessage + 1], message[idxIntoMessage + 2], message[idxIntoMessage + 3] };
                parsedMessage[i][j] = std.mem.readInt(u32, &bytes, .big);
            }
        }

        //for (parsedMessage) |arr| {
        //    for (arr) |elem| {
        //        print("0x{x:0>8} \n", .{elem});
        //    }
        //    print("\n", .{});
        //}

        return parsedMessage;
    }

    pub fn SHA1(message: []const u8, allocator: std.mem.Allocator) ![]const u8 {
        const preprocessedData = try SHA1Preprocessing(message, allocator);
        const parsedData = try SHA1Parsing(preprocessedData, allocator);
        const noOfSteps = parsedData.len;

        var hashes: [][5]word = try allocator.alloc([5]word, noOfSteps + 1);
        for (hashes) |*hash| {
            hash[0] = 0;
            hash[1] = 0;
            hash[2] = 0;
            hash[3] = 0;
            hash[4] = 0;
        }

        hashes[0][0] = 0x67452301;
        hashes[0][1] = 0xefcdab89;
        hashes[0][2] = 0x98badcfe;
        hashes[0][3] = 0x10325476;
        hashes[0][4] = 0xc3d2e1f0;

        var idx: usize = 1;
        while (idx <= noOfSteps) : (idx += 1) {
            var w: []word = try allocator.alloc(word, 80);
            @memset(w, 0);

            var i: usize = 0;
            while (i < w.len) : (i += 1) {
                if (i >= 0 and i <= 15) {
                    w[i] = parsedData[idx - 1][i];
                } else {
                    w[i] = SHAUtils.rotl(1, w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]);
                }
            }

            var a = hashes[idx - 1][0];
            var b = hashes[idx - 1][1];
            var c = hashes[idx - 1][2];
            var d = hashes[idx - 1][3];
            var e = hashes[idx - 1][4];

            var t: word = 0;
            while (t < 80) : (t += 1) {
                const T = SHAUtils.rotl(5, a) +% SHA1Function(t, b, c, d) +% e +% getSHA1Constants(t) +% w[t];
                e = d;
                d = c;
                c = SHAUtils.rotl(30, b);
                b = a;
                a = T;
            }

            hashes[idx][0] = a +% hashes[idx - 1][0];
            hashes[idx][1] = b +% hashes[idx - 1][1];
            hashes[idx][2] = c +% hashes[idx - 1][2];
            hashes[idx][3] = d +% hashes[idx - 1][3];
            hashes[idx][4] = e +% hashes[idx - 1][4];
        }

        const buffer: []u8 = try allocator.alloc(u8, 40);
        _ = try std.fmt.bufPrint(buffer, "{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}", .{ hashes[noOfSteps][0], hashes[noOfSteps][1], hashes[noOfSteps][2], hashes[noOfSteps][3], hashes[noOfSteps][4] });

        return buffer;
    }
};

test "SHA1" {
    const hash = try SHA1("abc", std.testing.allocator);
    try std.testing.expect(std.mem.eql(u8, "a9993e364706816aba3e25717850c26c9cd0d89d", hash));
}
