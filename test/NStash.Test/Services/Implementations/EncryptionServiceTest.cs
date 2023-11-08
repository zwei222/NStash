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
    [InlineData("sample01.txt", "password1")]
    [InlineData("sample02.txt", "password2")]
    [InlineData("1KB.bin", "password1KB")]
    [InlineData("100KB.bin", "password100KB")]
    [InlineData("100MB.bin", "password100MB")]
    [InlineData("186245.bin", "passw0rd")]
    public async Task EncryptAsyncTest(
        string fileName,
        string encryptPassword)
    {
        var encryptFileSystemOptions = new FileSystemOptions
        {
            IsFile = true,
            Path = Path.Combine(AppContext.BaseDirectory, "Resources", fileName),
        };
        var expected = await File.ReadAllBytesAsync(encryptFileSystemOptions.Path);

        this.encryptionService.AfterDelete = true;

        await foreach (var task in this.encryptionService.EncryptAsync(
                           encryptFileSystemOptions,
                           encryptPassword,
                           false,
                           new Progress<FileEncryptionEventArgs>()))
        {
            await task;
        }

        await Task.Delay(1000);

        Assert.True(File.Exists($"{encryptFileSystemOptions.Path}.nstash"));
        Assert.False(File.Exists(encryptFileSystemOptions.Path));

        var decryptFileSystemOptions = new FileSystemOptions
        {
            IsFile = true,
            Path = $"{encryptFileSystemOptions.Path}.nstash",
        };

        await foreach (var task in this.encryptionService.DecryptAsync(
                           decryptFileSystemOptions,
                           encryptPassword,
                           false,
                           new Progress<FileEncryptionEventArgs>()))
        {
            await task;
        }

        await Task.Delay(1000);

        Assert.True(File.Exists(encryptFileSystemOptions.Path));
        Assert.False(File.Exists($"{encryptFileSystemOptions.Path}.nstash"));

        var actual = await File.ReadAllBytesAsync(encryptFileSystemOptions.Path);

        Assert.Equal(expected, actual);
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