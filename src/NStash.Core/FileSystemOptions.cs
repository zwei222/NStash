namespace NStash.Core;

public readonly struct FileSystemOptions
{
    public string Path { get; init; }

    public bool IsFile { get; init; }
}