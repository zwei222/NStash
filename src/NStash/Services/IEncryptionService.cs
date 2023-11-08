using NStash.Commands;
using NStash.Events;

namespace NStash.Services;

public interface IEncryptionService
{
    public bool AfterDelete { get; set; }

    public bool Compress { get; set; }

    public IAsyncEnumerable<ValueTask> EncryptAsync(
        FileSystemOptions fileSystemOptions,
        string password,
        bool dryRun,
        IProgress<FileEncryptionEventArgs> progress,
        CancellationToken cancellationToken = default);

    public IAsyncEnumerable<ValueTask> DecryptAsync(
        FileSystemOptions fileSystemOptions,
        string password,
        bool dryRun,
        IProgress<FileEncryptionEventArgs> progress,
        CancellationToken cancellationToken = default);
}