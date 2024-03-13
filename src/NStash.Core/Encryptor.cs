using System.Buffers;
using System.IO.Compression;
using System.Runtime.CompilerServices;
#if NET7_0_OR_GREATER
using System.Runtime.InteropServices;
#endif
using System.Security.Cryptography;
using System.Text;
using NStash.Core.Events;

namespace NStash.Core;

public static class Encryptor
{
    private const string EncryptedExtension = ".nstash";

    private const int NStashPrefixSize = 32;

    private const int DefaultKeySize = 256;

    private const int DefaultBlockSize = 128;

    private const int DefaultSaltSize = 8;

    private const int DefaultIterations = 310_000;

    private const int DefaultBufferSize = 4_096;

    private const CompressionLevel DefaultCompressionLevel = CompressionLevel.Optimal;

    private static readonly HashAlgorithmName DefaultHashAlgorithm = HashAlgorithmName.SHA256;

    private static readonly byte[] EncryptedPrefix = new byte[NStashPrefixSize];

    private static readonly byte[] CompressedPrefix = new byte[NStashPrefixSize];

    private static readonly Encoding DefaultEncoding = new UTF8Encoding(false);

    static Encryptor()
    {
        var encryptedPrefix = "NStashEncryptedFile"u8.ToArray();
        var compressedPrefix = "NStashCompressedFile"u8.ToArray();

        Array.Copy(encryptedPrefix, EncryptedPrefix, encryptedPrefix.Length);
        Array.Copy(compressedPrefix, CompressedPrefix, compressedPrefix.Length);
    }

    public static async IAsyncEnumerable<ValueTask> EncryptAsync(
        FileSystemOptions fileSystemOptions,
        string password,
        bool dryRun,
        bool compress = false,
        bool afterDelete = false,
        IProgress<FileEncryptionEventArgs>? progress = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        if (fileSystemOptions.IsFile)
        {
            yield return EncryptFileAsync(
                fileSystemOptions.Path,
                password,
                dryRun,
                compress,
                afterDelete,
                progress,
                cancellationToken);
        }
        else
        {
            await foreach (var task in EncryptDirectoryAsync(
                               fileSystemOptions.Path,
                               password,
                               dryRun,
                               compress,
                               afterDelete,
                               progress,
                               cancellationToken).ConfigureAwait(false))
            {
                yield return task;
            }
        }
    }

    public static async IAsyncEnumerable<ValueTask> DecryptAsync(
        FileSystemOptions fileSystemOptions,
        string password,
        bool dryRun,
        bool afterDelete = false,
        IProgress<FileEncryptionEventArgs>? progress = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        if (fileSystemOptions.IsFile)
        {
            yield return DecryptFileAsync(
                fileSystemOptions.Path,
                password,
                dryRun,
                afterDelete,
                progress,
                cancellationToken);
        }
        else
        {
            await foreach (var task in DecryptDirectoryAsync(
                               fileSystemOptions.Path,
                               password,
                               dryRun,
                               afterDelete,
                               progress,
                               cancellationToken).ConfigureAwait(false))
            {
                yield return task;
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static async ValueTask WriteIntBytesAsync(
        Stream stream,
        Memory<byte> buffer,
        int value,
        CancellationToken cancellationToken)
    {
        BitConverter.TryWriteBytes(buffer.Span, value);
        await stream.WriteAsync(buffer[..sizeof(int)], cancellationToken).ConfigureAwait(false);
        buffer.Span.Clear();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static async ValueTask WriteLongBytesAsync(
        Stream stream,
        Memory<byte> buffer,
        long value,
        CancellationToken cancellationToken)
    {
        BitConverter.TryWriteBytes(buffer.Span, value);
        await stream.WriteAsync(buffer[..sizeof(long)], cancellationToken).ConfigureAwait(false);
        buffer.Span.Clear();
    }

    private static async ValueTask<int> ReadIntBytesAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        const int size = sizeof(int);
        var offset = 0;

        while (true)
        {
            offset += await stream.ReadAsync(buffer[offset..size], cancellationToken).ConfigureAwait(false);

            if (offset >= size)
            {
                break;
            }
        }

        var result = BitConverter.ToInt32(buffer[..size].Span);
        
        buffer.Span.Clear();
        return result;
    }

    private static async ValueTask<long> ReadLongBytesAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        const int size = sizeof(long);
        var offset = 0;

        while (true)
        {
            offset += await stream.ReadAsync(buffer[offset..size], cancellationToken).ConfigureAwait(false);

            if (offset >= size)
            {
                break;
            }
        }

        var result = BitConverter.ToInt64(buffer[..size].Span);

        buffer.Span.Clear();
        return result;
    }

    private static async IAsyncEnumerable<ValueTask> EncryptDirectoryAsync(
        string path,
        string password,
        bool dryRun,
        bool compress,
        bool afterDelete,
        IProgress<FileEncryptionEventArgs>? progress,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
        {
            yield return EncryptFileAsync(file, password, dryRun, compress, afterDelete, progress, cancellationToken);
        }

        await ValueTask.CompletedTask.ConfigureAwait(false);
    }

    private static async IAsyncEnumerable<ValueTask> DecryptDirectoryAsync(
        string path,
        string password,
        bool dryRun,
        bool afterDelete,
        IProgress<FileEncryptionEventArgs>? progress,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
        {
            yield return DecryptFileAsync(file, password, dryRun, afterDelete, progress, cancellationToken);
        }

        await ValueTask.CompletedTask.ConfigureAwait(false);
    }

    private static async ValueTask EncryptFileAsync(
        string path,
        string password,
        bool dryRun,
        bool compress,
        bool afterDelete,
        IProgress<FileEncryptionEventArgs>? progress,
        CancellationToken cancellationToken)
    {
        var sourceFileStream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            DefaultBufferSize,
            true);

        await using (sourceFileStream.ConfigureAwait(false))
        {
            var filePath = $"{path}{EncryptedExtension}";

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
                    var (salt, key, iv) = GenerateEncryptInfo(password);
                    using var aes = Aes.Create();

                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.KeySize = DefaultKeySize;
                    aes.BlockSize = DefaultBlockSize;
                    aes.Key = key;
                    aes.IV = iv;

                    if (compress)
                    {
                        await destinationFileStream.WriteAsync(
                            CompressedPrefix,
                            cancellationToken).ConfigureAwait(false);
                    }
                    else
                    {
                        await destinationFileStream.WriteAsync(
                            EncryptedPrefix,
                            cancellationToken).ConfigureAwait(false);
                    }

                    await destinationFileStream.WriteAsync(salt, cancellationToken).ConfigureAwait(false);
                    await destinationFileStream.WriteAsync(aes.IV, cancellationToken).ConfigureAwait(false);

                    var fileInfo = new FileInfo(path);
                    var fileSize = fileInfo.Length;
                    var creationTime = fileInfo.CreationTimeUtc.Ticks;
                    var lastWriteTime = fileInfo.LastWriteTimeUtc.Ticks;
                    var lastAccessTime = fileInfo.LastAccessTimeUtc.Ticks;
                    var attributes = (int)fileInfo.Attributes;
#if NET7_0_OR_GREATER
                    var unixFileMode = (int)fileInfo.UnixFileMode;
#endif
                    var fileName = fileInfo.Name;
                    var fileNameBytes = DefaultEncoding.GetBytes(fileName);
                    var fileNameBytesLength = fileNameBytes.Length;

                    using var cryptoTransform = aes.CreateEncryptor(aes.Key, aes.IV);
                    var cryptoStream = new CryptoStream(destinationFileStream, cryptoTransform, CryptoStreamMode.Write);

                    await using (cryptoStream.ConfigureAwait(false))
                    {
                        using (var memoryOwner = MemoryPool<byte>.Shared.Rent(sizeof(long)))
                        {
                            var fileInfoBuffer = memoryOwner.Memory;

                            await WriteLongBytesAsync(
                                cryptoStream,
                                fileInfoBuffer,
                                fileSize,
                                cancellationToken).ConfigureAwait(false);
                            await WriteLongBytesAsync(
                                cryptoStream,
                                fileInfoBuffer,
                                creationTime,
                                cancellationToken).ConfigureAwait(false);
                            await WriteLongBytesAsync(
                                cryptoStream,
                                fileInfoBuffer,
                                lastWriteTime,
                                cancellationToken).ConfigureAwait(false);
                            await WriteLongBytesAsync(
                                cryptoStream,
                                fileInfoBuffer,
                                lastAccessTime,
                                cancellationToken).ConfigureAwait(false);
                            await WriteIntBytesAsync(
                                cryptoStream,
                                fileInfoBuffer,
                                attributes,
                                cancellationToken).ConfigureAwait(false);
#if NET7_0_OR_GREATER
                            await WriteIntBytesAsync(
                                cryptoStream,
                                fileInfoBuffer,
                                unixFileMode,
                                cancellationToken).ConfigureAwait(false);
#else
                            await WriteIntBytesAsync(
                                cryptoStream,
                                fileInfoBuffer,
                                0,
                                cancellationToken).ConfigureAwait(false);
#endif
                            await WriteIntBytesAsync(
                                cryptoStream,
                                fileInfoBuffer,
                                fileNameBytesLength,
                                cancellationToken).ConfigureAwait(false);
                            await cryptoStream.WriteAsync(
                                fileNameBytes[..fileNameBytesLength],
                                cancellationToken).ConfigureAwait(false);
                        }

                        var totalLength = (double)sourceFileStream.Length;
                        var currentLength = 0D;
                        using var destinationMemoryOwner = MemoryPool<byte>.Shared.Rent(DefaultBufferSize);
                        var buffer = destinationMemoryOwner.Memory;
                        var length = await sourceFileStream.ReadAsync(buffer, cancellationToken)
                            .ConfigureAwait(false);

                        if (compress)
                        {
                            var deflateStream = new DeflateStream(cryptoStream, DefaultCompressionLevel);

                            await using (deflateStream.ConfigureAwait(false))
                            {
                                while (length > 0)
                                {
                                    cancellationToken.ThrowIfCancellationRequested();
                                    await deflateStream.WriteAsync(buffer[..length], cancellationToken)
                                        .ConfigureAwait(false);
                                    currentLength += length;
                                    progress?.Report(new FileEncryptionEventArgs(
                                        sourceFileStream.Name,
                                        destinationFileStream.Name,
                                        Convert.ToInt32((currentLength / totalLength) * 100)));
                                    length = await sourceFileStream.ReadAsync(buffer, cancellationToken)
                                        .ConfigureAwait(false);
                                }
                            }
                        }
                        else
                        {
                            while (length > 0)
                            {
                                cancellationToken.ThrowIfCancellationRequested();
                                await cryptoStream.WriteAsync(buffer[..length], cancellationToken)
                                    .ConfigureAwait(false);
                                currentLength += length;
                                progress?.Report(new FileEncryptionEventArgs(
                                    sourceFileStream.Name,
                                    destinationFileStream.Name,
                                    Convert.ToInt32((currentLength / totalLength) * 100)));
                                length = await sourceFileStream.ReadAsync(buffer, cancellationToken)
                                    .ConfigureAwait(false);
                            }
                        }

                        progress?.Report(new FileEncryptionEventArgs(
                            sourceFileStream.Name,
                            destinationFileStream.Name,
                            100));
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

        if (afterDelete)
        {
            if (File.Exists(path))
            {
                var fileInfo = new FileInfo(path);

                if ((fileInfo.Attributes & FileAttributes.ReadOnly) is FileAttributes.ReadOnly)
                {
                    fileInfo.Attributes = FileAttributes.Normal;
                }

                File.Delete(path);
            }
        }
    }

    private static async ValueTask DecryptFileAsync(
        string path,
        string password,
        bool dryRun,
        bool afterDelete,
        IProgress<FileEncryptionEventArgs>? progress,
        CancellationToken cancellationToken)
    {
        var sourceFileStream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            DefaultBufferSize,
            true);

        await using (sourceFileStream.ConfigureAwait(false))
        {
            var ivSize = DefaultBlockSize / 8;
            var prefixSize = NStashPrefixSize + DefaultSaltSize + ivSize;
            var salt = new byte[DefaultSaltSize];
            var iv = new byte[ivSize];
            var compress = false;

            using (var memoryOwner = MemoryPool<byte>.Shared.Rent(prefixSize))
            {
                var buffer = memoryOwner.Memory[..prefixSize];

                _ = await sourceFileStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);

                var nStashPrefix = buffer[..NStashPrefixSize];

                if (nStashPrefix.Span.SequenceEqual(CompressedPrefix.AsSpan()))
                {
                    compress = true;
                }
                else if (nStashPrefix.Span.SequenceEqual(EncryptedPrefix.AsSpan()) is false)
                {
                    throw new CryptographicException("The target file is not in NStash encrypted format.");
                }

                buffer[NStashPrefixSize..(NStashPrefixSize + DefaultSaltSize)].CopyTo(salt);
                buffer[(NStashPrefixSize + DefaultSaltSize)..].CopyTo(iv);
            }

            if (dryRun)
            {
                return;
            }

            var destinationFilePath = string.Empty;

            try
            {
                long creationTime;
                long lastWriteTime;
                long lastAccessTime;
                FileAttributes attributes;
#if NET7_0_OR_GREATER
                UnixFileMode unixFileMode;
#endif
                using var aes = Aes.Create();

                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.KeySize = DefaultKeySize;
                aes.BlockSize = DefaultBlockSize;
                aes.Key = GenerateKey(password.AsSpan(), salt);
                aes.IV = iv;

                using var cryptoTransform = aes.CreateDecryptor(aes.Key, aes.IV);
                var cryptoStream = new CryptoStream(sourceFileStream, cryptoTransform, CryptoStreamMode.Read);

                await using (cryptoStream.ConfigureAwait(false))
                {
                    long fileSize;
                    int fileNameBytesLength;

                    using (var memoryOwner = MemoryPool<byte>.Shared.Rent(sizeof(long)))
                    {
                        var fileInfoBuffer = memoryOwner.Memory;

                        fileSize = await ReadLongBytesAsync(cryptoStream, fileInfoBuffer, cancellationToken)
                            .ConfigureAwait(false);
                        creationTime = await ReadLongBytesAsync(cryptoStream, fileInfoBuffer, cancellationToken)
                            .ConfigureAwait(false);
                        lastWriteTime = await ReadLongBytesAsync(cryptoStream, fileInfoBuffer, cancellationToken)
                            .ConfigureAwait(false);
                        lastAccessTime = await ReadLongBytesAsync(cryptoStream, fileInfoBuffer, cancellationToken)
                            .ConfigureAwait(false);
                        attributes = (FileAttributes)await ReadIntBytesAsync(cryptoStream, fileInfoBuffer, cancellationToken)
                            .ConfigureAwait(false);
#if NET7_0_OR_GREATER
                        unixFileMode = (UnixFileMode)await ReadIntBytesAsync(cryptoStream, fileInfoBuffer, cancellationToken)
                            .ConfigureAwait(false);
#else
                        _ = await ReadIntBytesAsync(cryptoStream, fileInfoBuffer, cancellationToken)
                            .ConfigureAwait(false);
#endif
                        fileNameBytesLength = await ReadIntBytesAsync(cryptoStream, fileInfoBuffer, cancellationToken)
                            .ConfigureAwait(false);
                    }

                    string fileName;

                    using (var memoryOwner = MemoryPool<byte>.Shared.Rent(fileNameBytesLength))
                    {
                        var fileNameBuffer = memoryOwner.Memory;
                        var offset = 0;

                        while (true)
                        {
                            offset += await cryptoStream.ReadAsync(
                                fileNameBuffer[offset..fileNameBytesLength],
                                cancellationToken).ConfigureAwait(false);

                            if (offset >= fileNameBytesLength)
                            {
                                break;
                            }
                        }

                        fileName = DefaultEncoding.GetString(fileNameBuffer[..fileNameBytesLength].Span);
                    }

                    destinationFilePath = Path.Combine(
                        Directory.GetParent(sourceFileStream.Name)!.FullName,
                        fileName);

                    var destinationFileStream = new FileStream(
                        destinationFilePath,
                        FileMode.Create,
                        FileAccess.Write,
                        FileShare.Write,
                        DefaultBufferSize,
                        true);

                    await using (destinationFileStream.ConfigureAwait(false))
                    {
                        using var memoryOwner = MemoryPool<byte>.Shared.Rent(DefaultBufferSize);
                        var buffer = memoryOwner.Memory;

                        if (compress)
                        {
                            var deflateStream = new DeflateStream(cryptoStream, CompressionMode.Decompress);

                            await using (deflateStream.ConfigureAwait(false))
                            {
                                var currentLength = 0D;
                                var length = await deflateStream.ReadAsync(buffer, cancellationToken)
                                    .ConfigureAwait(false);

                                while (length > 0)
                                {
                                    cancellationToken.ThrowIfCancellationRequested();
                                    await destinationFileStream.WriteAsync(buffer[..length], cancellationToken)
                                        .ConfigureAwait(false);
                                    currentLength += length;
                                    progress?.Report(new FileEncryptionEventArgs(
                                        sourceFileStream.Name,
                                        destinationFileStream.Name,
                                        Convert.ToInt32((currentLength / fileSize) * 100)));
                                    length = await deflateStream.ReadAsync(buffer, cancellationToken)
                                        .ConfigureAwait(false);
                                }
                            }
                        }
                        else
                        {
                            var currentLength = 0D;
                            var length = await cryptoStream.ReadAsync(buffer, cancellationToken)
                                .ConfigureAwait(false);

                            while (length > 0)
                            {
                                cancellationToken.ThrowIfCancellationRequested();
                                await destinationFileStream.WriteAsync(buffer[..length], cancellationToken)
                                    .ConfigureAwait(false);
                                currentLength += length;
                                progress?.Report(new FileEncryptionEventArgs(
                                    sourceFileStream.Name,
                                    destinationFileStream.Name,
                                    Convert.ToInt32((currentLength / fileSize) * 100)));
                                length = await cryptoStream.ReadAsync(buffer, cancellationToken)
                                    .ConfigureAwait(false);
                            }
                        }

                        progress?.Report(new FileEncryptionEventArgs(
                            sourceFileStream.Name,
                            destinationFileStream.Name,
                            100));
                    }
                }

#if NET7_0_OR_GREATER
                var fileInfo = new FileInfo(destinationFilePath)
#else
                _ = new FileInfo(destinationFilePath)
#endif
                {
                    CreationTimeUtc = new DateTime(creationTime, DateTimeKind.Utc),
                    LastWriteTimeUtc = new DateTime(lastWriteTime, DateTimeKind.Utc),
                    LastAccessTimeUtc = new DateTime(lastAccessTime, DateTimeKind.Utc),
                    Attributes = attributes,
                };
#if NET7_0_OR_GREATER

                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) is false)
                {
#pragma warning disable CA1416
                    fileInfo.UnixFileMode = unixFileMode;
#pragma warning restore CA1416
                }
#endif
            }
            catch (Exception)
            {
                if (string.IsNullOrEmpty(destinationFilePath) is false &&
                    File.Exists(destinationFilePath))
                {
                    File.Delete(destinationFilePath);
                }

                throw;
            }
        }

        if (afterDelete)
        {
            if (File.Exists(path))
            {
                var fileInfo = new FileInfo(path);

                if ((fileInfo.Attributes & FileAttributes.ReadOnly) is FileAttributes.ReadOnly)
                {
                    fileInfo.Attributes = FileAttributes.Normal;
                }

                File.Delete(path);
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static (byte[], byte[], byte[]) GenerateEncryptInfo(string password)
    {
        using var derivedBytes = new Rfc2898DeriveBytes(password, DefaultSaltSize, DefaultIterations, DefaultHashAlgorithm);

        return (
            derivedBytes.Salt,
            derivedBytes.GetBytes(DefaultKeySize / 8),
            derivedBytes.GetBytes(DefaultBlockSize / 8));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte[] GenerateKey(ReadOnlySpan<char> password, ReadOnlySpan<byte> salt)
    {
        return Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            DefaultIterations,
            DefaultHashAlgorithm,
            DefaultKeySize / 8);
    }
}