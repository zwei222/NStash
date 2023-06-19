using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using NStash.Commands;
using NStash.Events;
using NStash.Services;
using NStash.Services.Implementations;
using Xunit;

namespace NStash.Test.Services.Implementations;

public sealed class EncryptionServiceTest
{
    private readonly IEncryptionService encryptionService;

    public EncryptionServiceTest()
    {
        this.encryptionService = new EncryptionService();
        this.Initialize();
    }

    [Theory(DisplayName = "Encrypt & Decrypt")]
    [InlineData("sample01.txt", "password")]
    public async Task EncryptAsyncTest(
        string fileName,
        string encryptPassword)
    {
        var encryptFileSystemOptions = new FileSystemOptions
        {
            IsFile = true,
            Path = Path.Combine(AppContext.BaseDirectory, "Resources", fileName),
        };

        this.encryptionService.AfterDelete = true;

        await foreach (var task in this.encryptionService.EncryptAsync(
                           encryptFileSystemOptions,
                           encryptPassword,
                           false,
                           new Progress<FileEncryptionEventArgs>()).ConfigureAwait(false))
        {
            await task.ConfigureAwait(false);
        }

        await Task.Delay(1000).ConfigureAwait(false);

        Assert.True(File.Exists($"{encryptFileSystemOptions.Path}.nstash"));
        Assert.False(File.Exists(encryptFileSystemOptions.Path));
    }

    private void Initialize()
    {
        foreach (var nstashFile in Directory.EnumerateFiles(
                     $"{Path.Combine(AppContext.BaseDirectory, "Resources")}",
                     "*.nstash",
                     SearchOption.AllDirectories))
        {
            File.Delete(nstashFile);
        }
    }
}