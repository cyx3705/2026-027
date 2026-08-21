using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using HistoryPortunus.Web;
using HistoryVulcan.Core.Commands;
using HistoryVulcan.Core.Logging;
using HistoryVulcan.Core.Storage;
using Xunit;

namespace HistoryPortunus.Contracts;

/// <summary>
/// Web 航线的边界合同。随网关一同从 HistoryVulcan 的 FreezeBlockerTests 迁入（4.3.0）。
/// </summary>
/// <remarks>
/// 这三条守的都是活的边界，不是历史包袱：删掉任何一条，对应的收紧就变成无人看守的放宽。
/// 同批迁移中被删除的是 <c>SessionSourceRoundTripsArbitraryIdsAndNames</c>——
/// 它测的解码半边（<c>SessionIdFromSource</c>）随进程外前端中继一起退役，
/// 生产代码里已无调用方，只剩那条测试在维持它活着。
/// </remarks>
public sealed class WebGatewayContractTests
{
    /// <summary>
    /// 回环与请求头都可以被任意本机进程伪造，真正的边界只有一次性凭据。
    ///
    /// 局域网面删除后鉴权只剩「回环 + 声明 Shell + 持券」三条，前两条是形状检查。
    /// 必须显式验证，否则删除 scope 判定就成了无人看守的放宽。
    /// </summary>
    [Fact]
    public async Task GatewayAcceptsOnlyTheLoopbackShellSession()
    {
        var registry = new CommandRegistry();
        registry.Register(new CommandDescriptor
        {
            Name = "unsafe.write",
            Summary = "write",
            Handler = CommandDescriptor.Sync(_ => CommandResult.Ok("must-not-run")),
        });
        var log = new MemoryLog();
        var bus = new CommandBus(registry, log);
        using var gateway = new WebGateway(() => bus, new MemorySettings(), log);
        Assert.True(gateway.Start(FreePort()).Success);

        // 不声明 X-HistoryVulcan-Client: Shell 的回环调用方一律 401。
        using var plain = NewClient(gateway.Port);
        plain.DefaultRequestHeaders.Add("X-Session-Id", Guid.NewGuid().ToString("N"));
        plain.DefaultRequestHeaders.Add("X-Client-Name", "PlainWeb");
        using var rejected = await PostCommandAsync(plain, "unsafe.write");
        Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);

        // 携带过去的设备鉴权头也不再有任何特权路径可走。
        using var device = NewClient(gateway.Port);
        device.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "read-token");
        device.DefaultRequestHeaders.Add("X-Device-Id", "read-device");
        device.DefaultRequestHeaders.Add("X-Session-Id", Guid.NewGuid().ToString("N"));
        using var deviceRejected = await PostCommandAsync(device, "unsafe.write");
        Assert.Equal(HttpStatusCode.Unauthorized, deviceRejected.StatusCode);

        // 只伪造 Shell 头、不持券的本机进程必须被挡下。这是本条用例的核心。
        using var forged = NewClient(gateway.Port);
        forged.DefaultRequestHeaders.Add("X-HistoryVulcan-Client", "Shell");
        forged.DefaultRequestHeaders.Add("X-Session-Id", Guid.NewGuid().ToString("N"));
        forged.DefaultRequestHeaders.Add("X-Client-Name", "ForgedFrontend");
        using var forgedRejected = await PostCommandAsync(forged, "unsafe.write");
        Assert.Equal(HttpStatusCode.Unauthorized, forgedRejected.StatusCode);

        // 持错券同样被挡下。
        using var wrongToken = NewClient(gateway.Port);
        wrongToken.DefaultRequestHeaders.Add("X-HistoryVulcan-Client", "Shell");
        wrongToken.DefaultRequestHeaders.Add("X-Session-Id", Guid.NewGuid().ToString("N"));
        wrongToken.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", gateway.AccessToken + "x");
        using var wrongRejected = await PostCommandAsync(wrongToken, "unsafe.write");
        Assert.Equal(HttpStatusCode.Unauthorized, wrongRejected.StatusCode);

        // 持本次监听凭据的同机前端畅通。
        using var shell = NewClient(gateway.Port);
        shell.DefaultRequestHeaders.Add("X-HistoryVulcan-Client", "Shell");
        shell.DefaultRequestHeaders.Add("X-Session-Id", Guid.NewGuid().ToString("N"));
        shell.DefaultRequestHeaders.Add("X-Client-Name", "Frontend");
        shell.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", gateway.AccessToken);
        using var accepted = await PostCommandAsync(shell, "unsafe.write");
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
    }

    /// <summary>
    /// 凭据必须每次监听换发，否则 endpoint.json 的残留值会在重启后继续有效。
    ///
    /// 迁入模块后这条比原先更要紧：网关随每轮热重载重启，换发频率从「每次宿主启动」
    /// 变成「每次模块重载」，客户端因此必须每次调用前重读 endpoint.json。
    /// </summary>
    [Fact]
    public void AccessTokenIsRegeneratedPerListenAndClearedOnStop()
    {
        var log = new MemoryLog();
        using var gateway = new WebGateway(
            () => new CommandBus(new CommandRegistry(), log), new MemorySettings(), log);

        Assert.True(gateway.Start(FreePort()).Success);
        var first = gateway.AccessToken;
        Assert.False(string.IsNullOrWhiteSpace(first));
        Assert.True(first.Length >= 32);

        Assert.True(gateway.Stop().Success);
        Assert.Equal("", gateway.AccessToken);

        Assert.True(gateway.Start(FreePort()).Success);
        Assert.NotEqual(first, gateway.AccessToken);
    }

    /// <summary>超限请求体必须在反序列化之前就被拒绝，而不是先读进内存再判断。</summary>
    [Fact]
    public async Task RejectsRequestBodiesOverOneMiBBeforeDeserialization()
    {
        var gateway = new WebGateway(
            () => new CommandBus(new CommandRegistry(), new MemoryLog()),
            new MemorySettings(),
            new MemoryLog());
        using (gateway)
        {
            Assert.True(gateway.Start(FreePort()).Success);
            using var client = NewClient(gateway.Port);
            client.DefaultRequestHeaders.Add("X-HistoryVulcan-Client", "Shell");
            client.DefaultRequestHeaders.Add("X-Client-Name", "LargeBodyTest");
            client.DefaultRequestHeaders.Add("X-Session-Id", Guid.NewGuid().ToString("N"));
            client.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", gateway.AccessToken);
            using var body = new StringContent(
                new string('x', 1_048_577), Encoding.UTF8, "application/json");

            using var response = await client.PostAsync("api/command", body);

            Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        }
    }

    private static HttpClient NewClient(int port)
        => new() { BaseAddress = new Uri($"http://127.0.0.1:{port}/") };

    private static async Task<HttpResponseMessage> PostCommandAsync(HttpClient client, string command)
    {
        using var body = new StringContent(
            JsonSerializer.Serialize(new { text = command }), Encoding.UTF8, "application/json");
        return await client.PostAsync("api/command", body);
    }

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private sealed class MemorySettings : ISettingsService
    {
        private readonly Dictionary<string, string> _values = new(StringComparer.OrdinalIgnoreCase);

        public string? Get(string key) => _values.GetValueOrDefault(key);

        public int GetInt(string key, int fallback) => int.TryParse(Get(key), out var value) ? value : fallback;

        public void Set(string key, string value) => _values[key] = value;

        public IReadOnlyList<KeyValuePair<string, string>> All() => _values.ToList();
    }

    private sealed class MemoryLog : IShellLog
    {
        private readonly List<ShellLogEntry> _entries = [];

        public void Log(ShellLogLevel level, string category, string message)
        {
            var entry = new ShellLogEntry(DateTime.UtcNow, level, category, message);
            lock (_entries)
                _entries.Add(entry);
            EntryAdded?.Invoke(this, entry);
        }

        public event EventHandler<ShellLogEntry>? EntryAdded;

        public IReadOnlyList<ShellLogEntry> Snapshot()
        {
            lock (_entries)
                return _entries.ToList();
        }
    }
}
