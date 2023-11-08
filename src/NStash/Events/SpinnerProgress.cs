using System.Collections.Concurrent;
using Kurukuru;

namespace NStash.Events;

public sealed class SpinnerProgress : IProgress<FileEncryptionEventArgs>, IDisposable
{
    private readonly Spinner spinner;

    private readonly IDictionary<string, SpinnerProgress> progresses;

    public SpinnerProgress(string text)
    {
        this.spinner = new Spinner(text);
        this.progresses = new ConcurrentDictionary<string, SpinnerProgress>();
        this.spinner.Start();
    }

    public void Report(FileEncryptionEventArgs value)
    {
        if (this.progresses.TryGetValue(value.SourceFilePath, out var progress) is false)
        {
            progress = new SpinnerProgress($"{value.Percentage,3}% {value.SourceFilePath}");
            this.progresses.Add(value.SourceFilePath, progress);
        }

        progress.spinner.Text = $"{value.Percentage,3}% {value.SourceFilePath}";

        if (value.Percentage >= 100)
        {
            progress.Dispose();
            this.progresses.Remove(value.SourceFilePath);
        }
    }

    public void Dispose()
    {
        this.spinner.Succeed();
        this.spinner.Dispose();

        foreach (var progress in this.progresses.Values)
        {
            progress.Dispose();
        }

        this.progresses.Clear();
    }
}