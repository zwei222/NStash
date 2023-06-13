using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Threading;
using NStash.Commands;
using NStash.Events;

namespace NStash.Services;

public interface IEncryptionService
{
    public bool AfterDelete { get; set; }

    public bool Compress { get; set; }

    public IAsyncEnumerable<Task> EncryptAsync(
        FileSystemOptions fileSystemOptions,
        string password,
        bool dryRun,
        IProgress<FileEncryptionEventArgs> progress,
        CancellationToken cancellationToken = default);

    public IAsyncEnumerable<Task> DecryptAsync(
        FileSystemOptions fileSystemOptions,
        string password,
        bool dryRun,
        IProgress<FileEncryptionEventArgs> progress,
        CancellationToken cancellationToken = default);
}