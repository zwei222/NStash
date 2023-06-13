using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Threading;
using NStash.Commands;
using NStash.Events;

namespace NStash.Services;

public interface IEncryptionService
{
    public event EventHandler<FileEncryptionEventArgs>? FileEncrypting;

    public event EventHandler<FileEncryptionEventArgs>? FileDecrypting;

    public bool AfterDelete { get; set; }

    public bool Compress { get; set; }

    public IAsyncEnumerable<Task> EncryptAsync(
        FileSystemOptions fileSystemOptions,
        string password,
        bool dryRun,
        CancellationToken cancellationToken = default);

    public IAsyncEnumerable<Task> DecryptAsync(
        FileSystemOptions fileSystemOptions,
        string password,
        bool dryRun,
        CancellationToken cancellationToken = default);
}