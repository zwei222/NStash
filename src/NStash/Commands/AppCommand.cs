using System.Collections.Concurrent;
using System.CommandLine;
using System.CommandLine.Parsing;
using NStash.Core;
using ValueTaskSupplement;

namespace NStash.Commands;

public sealed class AppCommand : RootCommand
{
    private static readonly int DefaultProcessCount = Environment.ProcessorCount;

    private readonly Argument<FileSystemOptions[]> targetPathArgument;

    private readonly Option<bool> encryptOption;

    private readonly Option<bool> decryptOption;

    private readonly Option<bool> deleteOption;

    private readonly Option<bool> compressOption;

    private readonly Option<int> processCountOption;

    private readonly Option<bool> dryRunOption;

    public AppCommand()
    {
        // Arguments
        this.targetPathArgument = new Argument<FileSystemOptions[]>(
            name: "targets",
            description: "Specifies the path of the file or directory of interest. You can specify multiple targets by separating them with commas.",
            isDefault: false,
            parse: ParseTargetPathArgument);
        this.AddArgument(this.targetPathArgument);

        // Options
        this.encryptOption = new Option<bool>(
            aliases:
            [
                "--encrypt",
                "-e"
            ],
            description: "Encrypt the target file.");
        this.decryptOption = new Option<bool>(
            aliases:
            [
                "--decrypt",
                "-d"
            ],
            description: "Decrypt the target file.");
        this.deleteOption = new Option<bool>(
            aliases:
            [
                "--delete",
                "-D"
            ],
            description: "Delete the original file after encryption/decryption.");
        this.compressOption = new Option<bool>(
            aliases:
            [
                "--compress",
                "-c"
            ],
            description: "Compress the target file before encryption.");
        this.processCountOption = new Option<int>(
            aliases:
            [
                "--process-count",
                "-p"
            ],
            description: "Specifies the number of processes to use for encryption/decryption. The default is the number of logical processors in the system.",
            getDefaultValue: () => Environment.ProcessorCount);
        this.dryRunOption = new Option<bool>(
            name: "--dry-run",
            description: "Practice the encryption/decryption process. No actual processing is performed.");
        this.AddOption(this.encryptOption);
        this.AddOption(this.decryptOption);
        this.AddOption(this.deleteOption);
        this.AddOption(this.compressOption);
        this.AddOption(this.processCountOption);
        this.AddOption(this.dryRunOption);

        // Handlers
        this.SetHandlers();
    }

    private static FileSystemOptions[] ParseTargetPathArgument(ArgumentResult argumentResult)
    {
        if (argumentResult.Tokens.Any() is false)
        {
            argumentResult.ErrorMessage = "No target path specified.";
            return [];
        }

        var values = argumentResult.Tokens[0].Value.Split(',', StringSplitOptions.RemoveEmptyEntries);

        if (values.Length == 0)
        {
            argumentResult.ErrorMessage = "No target path specified.";
            return [];
        }

        var targets = new HashSet<FileSystemOptions>();

        foreach (var value in values)
        {
            if (File.Exists(value))
            {
                targets.Add(new FileSystemOptions
                {
                    Path = value,
                    IsFile = true,
                });
            }
            else if (Directory.Exists(value))
            {
                targets.Add(new FileSystemOptions
                {
                    Path = value,
                    IsFile = false,
                });
            }
        }

        return [.. targets];
    }

    private void SetHandlers()
    {
        this.SetHandler(async (context) =>
        {
            var targetPath = context.ParseResult.GetValueForArgument(this.targetPathArgument);
            var encrypt = context.ParseResult.GetValueForOption(this.encryptOption);
            var decrypt = context.ParseResult.GetValueForOption(this.decryptOption);
            var delete = context.ParseResult.GetValueForOption(this.deleteOption);
            var compress = context.ParseResult.GetValueForOption(this.compressOption);
            var processCount = context.ParseResult.GetValueForOption(this.processCountOption);
            var dryRun = context.ParseResult.GetValueForOption(this.dryRunOption);
            var cancellationToken = context.GetCancellationToken();

            await this.RunAsync(
                targetPath,
                encrypt,
                decrypt,
                delete,
                compress,
                processCount,
                dryRun,
                cancellationToken).ConfigureAwait(false);
        });
    }

    private async ValueTask RunAsync(
        FileSystemOptions[] targetPaths,
        bool encrypt,
        bool decrypt,
        bool delete,
        bool compress,
        int processCount,
        bool dryRun,
        CancellationToken cancellationToken = default)
    {
        try
        {
            if (targetPaths.Length == 0)
            {
                await Console.Error.WriteLineAsync("No target path specified.");
                return;
            }

            if (encrypt == decrypt)
            {
                await Console.Error.WriteLineAsync(
                    "Only one of --encrypt option and --decrypt option must be specified.");
                return;
            }

            Console.Write("Password: ");

            var password = PasswordReader.ReadPassword(cancellationToken);

            if (string.IsNullOrEmpty(password))
            {
                await Console.Error.WriteLineAsync("You did not enter the correct password.");
                return;
            }

            var tasks = new ConcurrentBag<ValueTask>();
            var multiProcessCount = processCount > 0 ? processCount : DefaultProcessCount;
            using var progress = new SpinnerProgress(string.Empty);

            foreach (var targetPath in targetPaths)
            {
                if (encrypt)
                {
                    await foreach (var task in Encryptor.EncryptAsync(
                                       targetPath,
                                       password,
                                       dryRun,
                                       compress,
                                       delete,
                                       progress,
                                       cancellationToken).ConfigureAwait(false))
                    {
                        tasks.Add(task);

                        if (tasks.Count >= multiProcessCount)
                        {
                            await ValueTaskEx.WhenAll(tasks).ConfigureAwait(false);
                            tasks.Clear();
                        }
                    }
                }
                else if (decrypt)
                {
                    await foreach (var task in Encryptor.DecryptAsync(
                                       targetPath,
                                       password,
                                       dryRun,
                                       delete,
                                       progress,
                                       cancellationToken).ConfigureAwait(false))
                    {
                        tasks.Add(task);

                        if (tasks.Count >= multiProcessCount)
                        {
                            await ValueTaskEx.WhenAll(tasks).ConfigureAwait(false);
                            tasks.Clear();
                        }
                    }
                }
            }

            if (tasks.IsEmpty is false)
            {
                await ValueTaskEx.WhenAll(tasks).ConfigureAwait(false);
            }
        }
        catch (Exception exception)
        {
            await Console.Error.WriteLineAsync(exception.ToString());
        }
    }
}