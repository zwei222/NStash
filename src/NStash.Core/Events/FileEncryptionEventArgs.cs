namespace NStash.Core.Events;

public sealed class FileEncryptionEventArgs : EventArgs
{
    public FileEncryptionEventArgs(
        string sourceFilePath,
        string destinationFilePath,
        int percentage)
    {
        this.SourceFilePath = sourceFilePath;
        this.DestinationFilePath = destinationFilePath;
        this.Percentage = percentage;
    }

    public string SourceFilePath { get; }

    public string DestinationFilePath { get; }

    public int Percentage { get; set; }
}