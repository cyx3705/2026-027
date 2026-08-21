using Xunit;

namespace HistoryPortunus.Contracts;

/// <summary>
/// 测试集合按「争用哪种独占资源」划分。随 MCP 与 Web 用例一同从 HistoryVulcan.Tests 迁入。
/// </summary>
/// <remarks>
/// 本仓只保留网关一组：Portunus 没有界面，不存在 WPF 前台激活与焦点的争用。
/// 组内串行保住确定性（真实端口绑定与进程级网关状态无法并发），
/// 未标注集合的纯逻辑用例各自并行。
/// </remarks>
public static class TestCollections
{
    /// <summary>争用真实端口绑定与进程级网关状态的用例。</summary>
    public const string Gateway = "network-gateway";
}

/// <summary>网关用例串行执行：真实端口与进程级 mutex 无法并发。</summary>
[CollectionDefinition(TestCollections.Gateway, DisableParallelization = true)]
public sealed class NetworkGatewayCollection;
