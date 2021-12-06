const std = @import("std");
const math = std.math;

const Ip4Address = std.net.Ip4Address;

fn permuteFwd(state: *[4]u8) void {
    state[0] +%= state[1];
    state[2] +%= state[3];
    state[1] = math.rotl(u8, state[1], 2) ^ state[0];
    state[3] = math.rotl(u8, state[3], 5) ^ state[2];
    state[0] = math.rotl(u8, state[0], 4) +% state[3];
    state[2] +%= state[1];
    state[1] = math.rotl(u8, state[1], 3) ^ state[2];
    state[3] = math.rotl(u8, state[3], 7) ^ state[0];
    state[2] = math.rotl(u8, state[2], 4);
}

fn permuteBwd(state: *[4]u8) void {
    state[2] = math.rotl(u8, state[2], 4);
    state[1] = math.rotl(u8, state[1] ^ state[2], 5);
    state[3] = math.rotl(u8, state[3] ^ state[0], 1);
    state[2] -%= state[1];
    state[0] = math.rotl(u8, state[0] -% state[3], 4);
    state[1] = math.rotl(u8, state[1] ^ state[0], 6);
    state[3] = math.rotl(u8, state[3] ^ state[2], 3);
    state[0] -%= state[1];
    state[2] -%= state[3];
}

fn xor4(dst: *[4]u8, a: *const [4]u8, b: *const [4]u8) void {
    for (dst) |_, i| {
        dst[i] = a[i] ^ b[i];
    }
}

pub fn encrypt(key: *const [16]u8, ip: Ip4Address) Ip4Address {
    const bytes = @ptrCast(*const [4]u8, &ip.sa.addr);
    var out: [4]u8 = undefined;
    xor4(&out, bytes, key[0..4]);
    permuteFwd(&out);
    xor4(&out, &out, key[4..8]);
    permuteFwd(&out);
    xor4(&out, &out, key[8..12]);
    permuteFwd(&out);
    xor4(&out, &out, key[12..16]);
    return Ip4Address.init(out, 0);
}

pub fn decrypt(key: *const [16]u8, ip: Ip4Address) Ip4Address {
    const bytes = @ptrCast(*const [4]u8, &ip.sa.addr);
    var out: [4]u8 = undefined;
    xor4(&out, bytes, key[12..16]);
    permuteBwd(&out);
    xor4(&out, &out, key[8..12]);
    permuteBwd(&out);
    xor4(&out, &out, key[4..8]);
    permuteBwd(&out);
    xor4(&out, &out, key[0..4]);
    return Ip4Address.init(out, 0);
}

test "ipcrypt" {
    const key = "some 16-byte key";
    const TestVector = struct {
        in: Ip4Address,
        out: Ip4Address,
    };
    const test_vectors = [_]TestVector{
        .{
            .in = try Ip4Address.parse("127.0.0.1", 0),
            .out = try Ip4Address.parse("114.62.227.59", 0),
        },
        .{
            .in = try Ip4Address.parse("8.8.8.8", 0),
            .out = try Ip4Address.parse("46.48.51.50", 0),
        },
        .{
            .in = try Ip4Address.parse("1.2.3.4", 0),
            .out = try Ip4Address.parse("171.238.15.199", 0),
        },
    };
    for (test_vectors) |tv| {
        const in_bytes = @ptrCast(*const [4]u8, &tv.in.sa.addr);
        const out_bytes = @ptrCast(*const [4]u8, &tv.out.sa.addr);

        const ip_enc = encrypt(key, tv.in);
        const enc_bytes = @ptrCast(*const [4]u8, &ip_enc.sa.addr);
        try std.testing.expect(std.mem.eql(u8, enc_bytes, out_bytes));

        const ip_dec = decrypt(key, ip_enc);
        const dec_bytes = @ptrCast(*const [4]u8, &ip_dec.sa.addr);
        try std.testing.expect(std.mem.eql(u8, dec_bytes, in_bytes));
    }
}
