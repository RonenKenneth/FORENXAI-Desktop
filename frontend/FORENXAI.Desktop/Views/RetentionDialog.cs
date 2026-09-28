using System;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace FORENXAI.Desktop.Views;

/// <summary>
/// Asks for the date and time at which a case is deleted automatically.
/// Result: Scheduled (DeleteAfter set), Cleared (schedule removed), or
/// null when cancelled.
/// </summary>
public class RetentionDialog : Window
{
    public enum Outcome { Scheduled, Cleared }

    public Outcome? Result { get; private set; }
    public DateTimeOffset DeleteAfter { get; private set; }

    private readonly DatePicker datePicker = new();
    private readonly ComboBox hourBox = new();
    private readonly ComboBox minuteBox = new();
    private readonly TextBlock errorText = new();

    private static readonly Brush Text = new SolidColorBrush(Color.FromRgb(0xCB, 0xD5, 0xE1));
    private static readonly Brush Muted = new SolidColorBrush(Color.FromRgb(0x94, 0xA3, 0xB8));

    public RetentionDialog(Window owner, string caseId, DateTimeOffset? current)
    {
        Owner = owner;
        Title = "Schedule Case Deletion";
        Width = 460;
        SizeToContent = SizeToContent.Height;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = new SolidColorBrush(Color.FromRgb(0x0F, 0x17, 0x2A));

        DateTime initial = (current?.LocalDateTime ?? DateTime.Now.AddDays(30)).Date
            .AddHours(current?.LocalDateTime.Hour ?? 17)
            .AddMinutes(current?.LocalDateTime.Minute / 5 * 5 ?? 0);

        datePicker.SelectedDate = initial.Date;
        datePicker.DisplayDateStart = DateTime.Today;
        datePicker.Width = 150;
        hourBox.ItemsSource = Enumerable.Range(0, 24).Select(h => h.ToString("00")).ToList();
        hourBox.SelectedIndex = initial.Hour;
        hourBox.Width = 60;
        minuteBox.ItemsSource = Enumerable.Range(0, 12).Select(m => (m * 5).ToString("00")).ToList();
        minuteBox.SelectedIndex = initial.Minute / 5;
        minuteBox.Width = 60;

        var panel = new StackPanel { Margin = new Thickness(20) };
        panel.Children.Add(new TextBlock
        {
            Text = $"Delete case {caseId} automatically at:",
            Foreground = Brushes.White, FontSize = 14, FontWeight = FontWeights.SemiBold,
        });
        panel.Children.Add(new TextBlock
        {
            Text = "The whole case folder is removed at that time: the evidence copy, flow records, "
                 + "analysis, Suricata logs and investigator reviews. Export any report you need "
                 + "before then. If FORENXAI is closed at that time, the case is deleted when it next starts.",
            Foreground = Muted, FontSize = 12, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 14),
        });

        var row = new StackPanel { Orientation = Orientation.Horizontal };
        row.Children.Add(datePicker);
        row.Children.Add(new TextBlock { Text = "Time", Foreground = Text, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(14, 0, 6, 0) });
        row.Children.Add(hourBox);
        row.Children.Add(new TextBlock { Text = ":", Foreground = Text, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(4, 0, 4, 0) });
        row.Children.Add(minuteBox);
        panel.Children.Add(row);

        errorText.Foreground = new SolidColorBrush(Color.FromRgb(0xFC, 0xA5, 0xA5));
        errorText.FontSize = 12;
        errorText.Margin = new Thickness(0, 8, 0, 0);
        errorText.TextWrapping = TextWrapping.Wrap;
        panel.Children.Add(errorText);

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 16, 0, 0) };
        if (current != null)
        {
            buttons.Children.Add(MakeButton("Remove Schedule", () => { Result = Outcome.Cleared; DialogResult = true; }));
        }
        buttons.Children.Add(MakeButton("Cancel", () => DialogResult = false));
        buttons.Children.Add(MakeButton("Schedule", Schedule, primary: true));
        panel.Children.Add(buttons);

        Content = panel;
    }

    private Button MakeButton(string label, Action onClick, bool primary = false)
    {
        var button = new Button
        {
            Content = label,
            MinWidth = 96,
            Height = 32,
            Padding = new Thickness(14, 0, 14, 0),
            Margin = new Thickness(8, 0, 0, 0),
            Foreground = Brushes.White,
            Background = new SolidColorBrush(primary ? Color.FromRgb(0x25, 0x63, 0xEB) : Color.FromRgb(0x1E, 0x29, 0x3B)),
            BorderThickness = new Thickness(0),
            IsDefault = primary,
            IsCancel = label == "Cancel",
        };
        button.Click += (_, _) => onClick();
        return button;
    }

    private void Schedule()
    {
        if (datePicker.SelectedDate is not DateTime date)
        {
            errorText.Text = "Choose a date.";
            return;
        }

        var local = date.Date.AddHours(hourBox.SelectedIndex).AddMinutes(minuteBox.SelectedIndex * 5);
        var when = new DateTimeOffset(local, TimeZoneInfo.Local.GetUtcOffset(local));
        if (when <= DateTimeOffset.Now)
        {
            errorText.Text = "Choose a time in the future. To delete the case now, use Delete Case.";
            return;
        }

        DeleteAfter = when;
        Result = Outcome.Scheduled;
        DialogResult = true;
    }
}
