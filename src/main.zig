const std = @import("std");
const Io = std.Io;
const print = std.debug.print;
const assert = std.debug.assert;
const shatool = @import("shatool");

pub fn main(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena.allocator();
    const SHA = shatool.initSHA(init, allocator);
    const hash = try SHA.getHash("test.txt", shatool.ShaAlgos.sha1);
    print("{s}\n", .{hash});
}
