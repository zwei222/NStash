using System;

namespace NStash.Events;

public sealed class FileEncryptionEventArgs : EventArgs
{
    public FileEncryptionEventArgs(string sourceFilePath, string destinationFilePath)
    {
        this.SourceFilePath = sourceFilePath;
        this.DestinationFilePath = destinationFilePath;
    }

    public string SourceFilePath { get; }

    public string DestinationFilePath { get; }
}