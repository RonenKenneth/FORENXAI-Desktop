using System;
using System.ComponentModel;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Windows.Controls;
using System.Windows.Data;
using FORENXAI.Desktop.Services;

namespace FORENXAI.Desktop.Views;

public partial class InvestigationView : UserControl
{
    private readonly ObservableCollection<PacketDisplayRow> rows = new();
    private ICollectionView? packetView;
    public InvestigationView(AnalysisResponse analysis)
    {
        InitializeComponent();
        SummaryText.Text = $"{analysis.FileName}  •  {analysis.Packets.Count:N0} packets  •  {analysis.TotalFlows:N0} flows";
        foreach (var packet in analysis.Packets)
        {
            rows.Add(new PacketDisplayRow(packet));
        }
        PacketGrid.ItemsSource = rows;
        packetView = CollectionViewSource.GetDefaultView(rows);
        UpdateFilterStatus();
    }

    private void ApplyFilter_Click(object sender, System.Windows.RoutedEventArgs e)
    {
        string expression = FilterTextBox.Text.Trim();
        string protocol = (ProtocolComboBox.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "All protocols";
        string flag = (FlagsComboBox.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "All flags";
        packetView!.Filter = item => Matches((PacketDisplayRow)item, expression, protocol, flag);
        packetView.Refresh();
        UpdateFilterStatus();
    }

    private void ClearFilter_Click(object sender, System.Windows.RoutedEventArgs e)
    {
        FilterTextBox.Clear(); ProtocolComboBox.SelectedIndex = 0; FlagsComboBox.SelectedIndex = 0;
        packetView!.Filter = null; packetView.Refresh(); UpdateFilterStatus();
    }

    private bool Matches(PacketDisplayRow row, string expression, string protocol, string flag)
    {
        if (protocol != "All protocols" && !row.Protocol.Equals(protocol, StringComparison.OrdinalIgnoreCase)) return false;
        if (flag != "All flags" && !row.Info.Contains(flag, StringComparison.OrdinalIgnoreCase)) return false;
        if (string.IsNullOrWhiteSpace(expression)) return true;
        string[] parts = expression.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3) return row.SearchText.Contains(expression, StringComparison.OrdinalIgnoreCase);
        string value = string.Join(' ', parts, 2, parts.Length - 2).Trim('"', '\'');
        string actual = row.GetField(parts[0]);
        return parts[1] switch
        {
            "==" or "=" => actual.Equals(value, StringComparison.OrdinalIgnoreCase),
            "contains" => actual.Contains(value, StringComparison.OrdinalIgnoreCase),
            ">" => double.TryParse(actual, out var a) && double.TryParse(value, out var b) && a > b,
            "<" => double.TryParse(actual, out var c) && double.TryParse(value, out var d) && c < d,
            _ => false
        };
    }

    private void UpdateFilterStatus() => FilterStatusText.Text = $"Showing {(packetView?.Cast<object>().Count() ?? rows.Count):N0} of {rows.Count:N0} packets";
}

public sealed class PacketDisplayRow
{
    private readonly PacketRecord packet;
    public PacketDisplayRow(PacketRecord packet) => this.packet = packet;
    public int PacketNumber => packet.PacketNumber;
    public string Timestamp => DateTimeOffset.FromUnixTimeMilliseconds((long)(packet.Timestamp * 1000.0)).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture);
    public string SourceDisplay => packet.SourceIp + (packet.SourcePort.HasValue ? ":" + packet.SourcePort : "");
    public string DestinationDisplay => packet.DestinationIp + (packet.DestinationPort.HasValue ? ":" + packet.DestinationPort : "");
    public string Protocol => packet.Protocol ?? "OTHER";
    public int PacketLength => packet.PacketLength;
    public string Info => string.IsNullOrWhiteSpace(packet.TcpFlags) ? "" : "TCP flags: " + packet.TcpFlags;
    public string SearchText => $"{PacketNumber} {SourceDisplay} {DestinationDisplay} {Protocol} {PacketLength} {Info}";
    public string GetField(string field) => field.ToLowerInvariant() switch
    {
        "source_ip" or "source" => packet.SourceIp ?? "",
        "destination_ip" or "destination" => packet.DestinationIp ?? "",
        "protocol" => Protocol,
        "source_port" => packet.SourcePort?.ToString() ?? "",
        "destination_port" => packet.DestinationPort?.ToString() ?? "",
        "packet_length" or "length" => PacketLength.ToString(),
        "packet_number" or "number" => PacketNumber.ToString(),
        "tcp_flags" => packet.TcpFlags ?? "",
        _ => ""
    };
}
