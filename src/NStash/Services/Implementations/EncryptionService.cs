using System;
using System.Buffers;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Threading;
using NStash.Commands;
using NStash.Events;

namespace NStash.Services.Implementations;

internal sealed class EncryptionService : IEncryptionService
{
    private const string EncryptedExtension = ".nstash";

    private const int DefaultKeySize = 256;

    private const int DefaultBlockSize = 128;

    private const int DefaultSaltSize = 8;

    private const int DefaultIterations = 1000;

    private const int DefaultBufferSize = 4096;

    private static readonly HashAlgorithmName DefaultHashAlgorithm = HashAlgorithmName.SHA256;

    private static readonly byte[] EncryptedPrefix = new byte[32];

    public EncryptionService()
    {
        var prefix = "NStashEncryptedFile"u8.ToArray();

        Array.Copy(prefix, EncryptedPrefix, prefix.Length);
    }

    public event EventHandler<FileEncryptionEventArgs>? FileEncrypting;

    public event EventHandler<FileEncryptionEventArgs>? FileDecrypting;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ValueTask EncryptAsync(
        FileSystemOptions fileSystemOptions,
        string password,
        bool dryRun,
        CancellationToken cancellationToken = default)
    {
        if (fileSystemOptions.IsFile)
        {
            return this.EncryptFileAsync(fileSystemOptions.Path, password, dryRun, cancellationToken);
        }

        return this.EncryptDirectoryAsync(fileSystemOptions.Path, password, dryRun, cancellationToken);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ValueTask DecryptAsync(
        FileSystemOptions fileSystemOptions,
        string password,
        bool dryRun,
        CancellationToken cancellationToken = default)
    {
        if (fileSystemOptions.IsFile)
        {
            return this.DecryptFileAsync(fileSystemOptions.Path, password, dryRun, cancellationToken);
        }

        return this.DecryptDirectoryAsync(fileSystemOptions.Path, password, dryRun, cancellationToken);
    }

    private async ValueTask EncryptDirectoryAsync(
        string path,
        string password,
        bool dryRun,
        CancellationToken cancellationToken)
    {
        foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
        {
            await this.EncryptFileAsync(file, password, dryRun, cancellationToken).ConfigureAwait(false);
        }
    }

    private async ValueTask DecryptDirectoryAsync(
        string path,
        string password,
        bool dryRun,
        CancellationToken cancellationToken)
    {
        foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
        {
            await this.DecryptFileAsync(file, password, dryRun, cancellationToken).ConfigureAwait(false);
        }
    }

    private async ValueTask EncryptFileAsync(
        string path,
        string password,
        bool dryRun,
        CancellationToken cancellationToken)
    {
        var sourceFileStream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            DefaultBufferSize,
            true);
        var filePath = $"{path}{EncryptedExtension}";

        this.FileEncrypting?.Invoke(this, new FileEncryptionEventArgs(path, filePath));

        await using (sourceFileStream.ConfigureAwait(false))
        {
            if (dryRun)
            {
                return;
            }

            try
            {
                var destinationFileStream = new FileStream(
                    filePath,
                    FileMode.Create,
                    FileAccess.Write,
                    FileShare.Write,
                    DefaultBufferSize,
                    true);

                await using (destinationFileStream.ConfigureAwait(false))
                {
                    var encryptInfo = this.GenerateEncryptInfo(password);
                    using var aes = Aes.Create();

                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.KeySize = DefaultKeySize;
                    aes.BlockSize = DefaultBlockSize;
                    aes.Key = encryptInfo.Item2;
                    aes.IV = encryptInfo.Item3;
                    await destinationFileStream.WriteAsync(EncryptedPrefix, cancellationToken).ConfigureAwait(false);
                    await destinationFileStream.WriteAsync(encryptInfo.Item1, cancellationToken).ConfigureAwait(false);
                    await destinationFileStream.WriteAsync(aes.IV, cancellationToken).ConfigureAwait(false);

                    using var cryptoTransform = aes.CreateEncryptor();
                    var cryptoStream = new CryptoStream(destinationFileStream, cryptoTransform, CryptoStreamMode.Write);

                    await using (cryptoStream.ConfigureAwait(false))
                    {
                        await sourceFileStream.CopyToAsync(
                            cryptoStream,
                            DefaultBufferSize,
                            cancellationToken).ConfigureAwait(false);
                        /*using var memoryOwner = MemoryPool<byte>.Shared.Rent(1024);
                        var buffer = memoryOwner.Memory;
                        var length = await sourceFileStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
    
                        while (length > 0)
                        {
                            cancellationToken.ThrowIfCancellationRequested();
                            await cryptoStream.WriteAsync(buffer[..length], cancellationToken).ConfigureAwait(false);
                            await cryptoStream.FlushFinalBlockAsync(cancellationToken).ConfigureAwait(false);
                            length = await sourceFileStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                        }*/
                    }
                }
            }
            catch (Exception)
            {
                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                }

                throw;
            }
        }
    }

    private async ValueTask DecryptFileAsync(
        string path,
        string password,
        bool dryRun,
        CancellationToken cancellationToken)
    {
        var filePath = path;

        if (path.EndsWith(EncryptedExtension, StringComparison.Ordinal))
        {
            filePath = path[..^EncryptedExtension.Length];
        }

        var sourceFileStream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            DefaultBufferSize,
            true);
        var ivSize = DefaultBlockSize / 8;
        var prefixSize = EncryptedPrefix.Length + DefaultSaltSize + ivSize;
        var salt = new byte[DefaultSaltSize];
        var iv = new byte[ivSize];

        using (var memoryOwner = MemoryPool<byte>.Shared.Rent(prefixSize))
        {
            var buffer = memoryOwner.Memory[..prefixSize];

            _ = await sourceFileStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);

            if (buffer[..EncryptedPrefix.Length].Span.SequenceEqual(EncryptedPrefix.AsSpan()) is false)
            {
                throw new CryptographicException("The target file is not in NStash encrypted format.");
            }

            buffer[EncryptedPrefix.Length..(EncryptedPrefix.Length + DefaultSaltSize)].CopyTo(salt);
            buffer[(EncryptedPrefix.Length + DefaultSaltSize)..].CopyTo(iv);
        }

        this.FileDecrypting?.Invoke(this, new FileEncryptionEventArgs(path, filePath));

        await using (sourceFileStream.ConfigureAwait(false))
        {
            if (dryRun)
            {
                return;
            }

            var destinationFileStream = new FileStream(
                filePath,
                FileMode.Create,
                FileAccess.Write,
                FileShare.Write,
                DefaultBufferSize,
                true);

            await using (destinationFileStream.ConfigureAwait(false))
            {
                using var aes = Aes.Create();

                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.KeySize = DefaultKeySize;
                aes.BlockSize = DefaultBlockSize;
                aes.Key = this.GenerateKey(password, salt);
                aes.IV = iv;

                using var cryptoTransform = aes.CreateDecryptor(aes.Key, aes.IV);
                var cryptoStream = new CryptoStream(destinationFileStream, cryptoTransform, CryptoStreamMode.Write);

                await using (cryptoStream.ConfigureAwait(false))
                {
                    await sourceFileStream.CopyToAsync(
                        cryptoStream,
                        DefaultBufferSize,
                        cancellationToken).ConfigureAwait(false);
                    /*using var memoryOwner = MemoryPool<byte>.Shared.Rent(1024);
                    var buffer = memoryOwner.Memory;
                    var length = await cryptoStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);

                    while (length > 0)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        await destinationFileStream.WriteAsync(buffer[..length], cancellationToken).ConfigureAwait(false);
                        length = await cryptoStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                    }*/
                }
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private (byte[], byte[], byte[]) GenerateEncryptInfo(string password)
    {
        using var derivedBytes = new Rfc2898DeriveBytes(password, DefaultSaltSize, DefaultIterations, DefaultHashAlgorithm);

        return (
            derivedBytes.Salt,
            derivedBytes.GetBytes(DefaultKeySize / 8),
            derivedBytes.GetBytes(DefaultBlockSize / 8));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private byte[] GenerateKey(string password, byte[] salt)
    {
        using var derivedBytes = new Rfc2898DeriveBytes(password, salt, DefaultIterations, DefaultHashAlgorithm);

        return derivedBytes.GetBytes(DefaultKeySize / 8);
    }
}