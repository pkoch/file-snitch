const std = @import("std");

pub const Error = error{InvalidRfc3339Utc};

/// Parse an RFC 3339 UTC timestamp in the form `YYYY-MM-DDTHH:MM:SSZ`.
pub fn parseUtcSeconds(value: []const u8) Error!i64 {
    if (value.len != "2006-01-02T15:04:05Z".len) return error.InvalidRfc3339Utc;
    if (value[4] != '-' or value[7] != '-' or value[10] != 'T' or
        value[13] != ':' or value[16] != ':' or value[19] != 'Z')
    {
        return error.InvalidRfc3339Utc;
    }
    try requireDigits(value[0..4]);
    try requireDigits(value[5..7]);
    try requireDigits(value[8..10]);
    try requireDigits(value[11..13]);
    try requireDigits(value[14..16]);
    try requireDigits(value[17..19]);

    const year = std.fmt.parseInt(i64, value[0..4], 10) catch return error.InvalidRfc3339Utc;
    const month = std.fmt.parseInt(u8, value[5..7], 10) catch return error.InvalidRfc3339Utc;
    const day = std.fmt.parseInt(u8, value[8..10], 10) catch return error.InvalidRfc3339Utc;
    const hour = std.fmt.parseInt(u8, value[11..13], 10) catch return error.InvalidRfc3339Utc;
    const minute = std.fmt.parseInt(u8, value[14..16], 10) catch return error.InvalidRfc3339Utc;
    const second = std.fmt.parseInt(u8, value[17..19], 10) catch return error.InvalidRfc3339Utc;

    if (month < 1 or month > 12) return error.InvalidRfc3339Utc;
    if (day < 1 or day > daysInMonth(year, month)) return error.InvalidRfc3339Utc;
    if (hour > 23 or minute > 59 or second > 59) return error.InvalidRfc3339Utc;

    const days = daysSinceUnixEpoch(year, month, day) catch return error.InvalidRfc3339Utc;
    const day_seconds = @as(i64, hour) * std.time.s_per_hour +
        @as(i64, minute) * std.time.s_per_min +
        second;
    return std.math.add(i64, days * 86400, day_seconds) catch return error.InvalidRfc3339Utc;
}

/// Format a Unix timestamp in seconds as an RFC 3339 UTC string (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn formatUtcAlloc(allocator: std.mem.Allocator, unix_seconds: i64) ![]u8 {
    if (unix_seconds < 0) return error.InvalidTimestamp;
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(unix_seconds) };
    const epoch_day = epoch_seconds.getEpochDay();
    const day_seconds = epoch_seconds.getDaySeconds();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    return std.fmt.allocPrint(
        allocator,
        "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z",
        .{
            year_day.year,
            month_day.month.numeric(),
            month_day.day_index + 1,
            day_seconds.getHoursIntoDay(),
            day_seconds.getMinutesIntoHour(),
            day_seconds.getSecondsIntoMinute(),
        },
    );
}

fn requireDigits(value: []const u8) Error!void {
    for (value) |byte| {
        if (byte < '0' or byte > '9') return error.InvalidRfc3339Utc;
    }
}

fn daysSinceUnixEpoch(year: i64, month: u8, day: u8) !i64 {
    var adjusted_year = year;
    if (month <= 2) adjusted_year -= 1;

    const era = @divFloor(if (adjusted_year >= 0) adjusted_year else adjusted_year - 399, 400);
    const year_of_era = adjusted_year - era * 400;
    const adjusted_month: i64 = if (month > 2) month - 3 else month + 9;
    const day_of_year = @divFloor(153 * adjusted_month + 2, 5) + day - 1;
    const day_of_era = year_of_era * 365 + @divFloor(year_of_era, 4) - @divFloor(year_of_era, 100) + day_of_year;
    return try std.math.sub(i64, era * 146097 + day_of_era, 719468);
}

fn daysInMonth(year: i64, month: u8) u8 {
    return switch (month) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if (isLeapYear(year)) 29 else 28,
        else => 0,
    };
}

fn isLeapYear(year: i64) bool {
    return (@mod(year, 4) == 0 and @mod(year, 100) != 0) or @mod(year, 400) == 0;
}

test "parse and format round-trip" {
    const allocator = std.testing.allocator;

    try std.testing.expectEqual(@as(i64, 0), try parseUtcSeconds("1970-01-01T00:00:00Z"));
    try std.testing.expectEqual(@as(i64, 951_782_400), try parseUtcSeconds("2000-02-29T00:00:00Z"));
    const ts = try parseUtcSeconds("2100-01-01T00:00:00Z");
    try std.testing.expectEqual(@as(i64, 4_102_444_800), ts);

    const formatted = try formatUtcAlloc(allocator, ts);
    defer allocator.free(formatted);
    try std.testing.expectEqualStrings("2100-01-01T00:00:00Z", formatted);
}

test "parse rejects malformed timestamps" {
    try std.testing.expectError(error.InvalidRfc3339Utc, parseUtcSeconds(""));
    try std.testing.expectError(error.InvalidRfc3339Utc, parseUtcSeconds("later-ish"));
    try std.testing.expectError(error.InvalidRfc3339Utc, parseUtcSeconds("4102444800"));
    try std.testing.expectError(error.InvalidRfc3339Utc, parseUtcSeconds("2026-13-01T00:00:00Z"));
    try std.testing.expectError(error.InvalidRfc3339Utc, parseUtcSeconds("2026-01-01T-1:00:00Z"));
    try std.testing.expectError(error.InvalidRfc3339Utc, parseUtcSeconds("2026-01-01T00:-1:00Z"));
    try std.testing.expectError(error.InvalidRfc3339Utc, parseUtcSeconds("2026-01-01T00:00:-1Z"));
    try std.testing.expectError(error.InvalidRfc3339Utc, parseUtcSeconds("2100-02-29T00:00:00Z"));
    try std.testing.expectError(error.InvalidRfc3339Utc, parseUtcSeconds("2100-01-01 00:00:00Z"));
    try std.testing.expectError(error.InvalidRfc3339Utc, parseUtcSeconds("2100-01-01T00:00:00"));
}

test "format rejects negative timestamps" {
    try std.testing.expectError(error.InvalidTimestamp, formatUtcAlloc(std.testing.allocator, -1));
}
