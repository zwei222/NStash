using System;
using System.Threading.Tasks;
using System.Threading;
using NStash.Commands;
using NStash.Events;

namespace NStash.Services;

public interface IEncryptionService
{
    public event EventHandler<FileEncryptionEventArgs>? FileEncrypting;

    public event EventHandler<FileEncryptionEventArgs>? FileDecrypting;

    public ValueTask EncryptAsync(
        FileSystemOptions fileSystemOptions,
        string password,
        bool dryRun,
        CancellationToken cancellationToken = default);

    public ValueTask DecryptAsync(
        FileSystemOptions fileSystemOptions,
        string password,
        bool dryRun,
        CancellationToken cancellationToken = default);
}