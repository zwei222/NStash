using NStash.Core.Events;
using Xunit;

namespace NStash.Core.Test;

public sealed class EncryptorTest
{
    public EncryptorTest()
    {
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

        await foreach (var task in Encryptor.EncryptAsync(
                           encryptFileSystemOptions,
                           encryptPassword,
                           false,
                           false,
                           true,
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

        await foreach (var task in Encryptor.DecryptAsync(
                           decryptFileSystemOptions,
                           encryptPassword,
                           false,
                           true,
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

    [Theory(DisplayName = "Encrypt & Decrypt (Compress)")]
    [InlineData("sample01.txt", "password1")]
    [InlineData("sample02.txt", "password2")]
    [InlineData("1KB.bin", "password1KB")]
    [InlineData("100KB.bin", "password100KB")]
    [InlineData("100MB.bin", "password100MB")]
    [InlineData("186245.bin", "passw0rd")]
    public async Task EncryptCompressAsyncTest(
        string fileName,
        string encryptPassword)
    {
        var encryptFileSystemOptions = new FileSystemOptions
        {
            IsFile = true,
            Path = Path.Combine(AppContext.BaseDirectory, "Resources", fileName),
        };
        var expected = await File.ReadAllBytesAsync(encryptFileSystemOptions.Path);

        await foreach (var task in Encryptor.EncryptAsync(
                           encryptFileSystemOptions,
                           encryptPassword,
                           false,
                           true,
                           true,
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

        await foreach (var task in Encryptor.DecryptAsync(
                           decryptFileSystemOptions,
                           encryptPassword,
                           false,
                           true,
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