namespace NStash.Commands;

public readonly struct FileSystemOptions
{
    public required string Path { get; init; }

    public required bool IsFile { get; init; }
}