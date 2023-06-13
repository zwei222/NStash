using System;
using System.Collections.Concurrent;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.CommandLine.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NStash.Events;
using NStash.Services;

namespace NStash.Commands.CommandHandlers;

public sealed class DefaultCommandHandler : ICommandHandler
{
    private static readonly int DefaultProcessCount = Environment.ProcessorCount;

    private readonly IConsole console;

    private readonly IEncryptionService encryptionService;

    public DefaultCommandHandler(IConsole console, IEncryptionService encryptionService)
    {
        this.console = console;
        this.encryptionService = encryptionService;
    }

    public FileSystemOptions[] Targets { get; set; } = Array.Empty<FileSystemOptions>();

    public bool Encrypt { get; set; }

    public bool Decrypt { get; set; }

    public bool Delete { get; set; }

    public bool Compress { get; set; }

    public bool DryRun { get; set; }

    public int ProcessCount { get; set; }

    public int Invoke(InvocationContext context)
    {
        throw new NotImplementedException();
    }

    public async Task<int> InvokeAsync(InvocationContext context)
    {
        try
        {
            if (this.Targets.Any() is false)
            {
                this.console.Error.WriteLine("No target path specified.");
                return 1;
            }

            if (this.Encrypt == this.Decrypt)
            {
                this.console.Error.WriteLine("Only one of --encrypt option and --decrypt option must be specified.");
                return 1;
            }

            var cancellationToken = context.GetCancellationToken();

            this.console.Write("Password: ");

            var password = this.ReadPassword(cancellationToken);

            if (string.IsNullOrEmpty(password))
            {
                this.console.Error.WriteLine("You did not enter the correct password.");
                return 1;
            }

            this.encryptionService.AfterDelete = this.Delete;
            this.encryptionService.Compress = this.Compress;

            var tasks = new ConcurrentBag<Task>();
            var processCount = this.ProcessCount > 0 ? this.ProcessCount : DefaultProcessCount;
            using var progress = new SpinnerProgress("");

            foreach (var target in this.Targets)
            {
                if (this.Encrypt)
                {
                    await foreach (var task in this.encryptionService.EncryptAsync(
                                       target,
                                       password,
                                       this.DryRun,
                                       progress,
                                       cancellationToken).ConfigureAwait(false))
                    {
                        tasks.Add(task);

                        if (tasks.Count >= processCount)
                        {
                            await Task.WhenAll(tasks).ConfigureAwait(false);
                            tasks.Clear();
                        }
                    }
                }
                else if (this.Decrypt)
                {
                    await foreach (var task in this.encryptionService.DecryptAsync(
                                       target,
                                       password,
                                       this.DryRun,
                                       progress,
                                       cancellationToken).ConfigureAwait(false))
                    {
                        tasks.Add(task);

                        if (tasks.Count >= processCount)
                        {
                            await Task.WhenAll(tasks).ConfigureAwait(false);
                            tasks.Clear();
                        }
                    }
                }
            }
        }
        catch (Exception exception)
        {
            this.console.Error.WriteLine(exception.ToString());
            return 1;
        }

        return 0;
    }

    private string? ReadPassword(CancellationToken cancellationToken)
    {
        var stringBuilder = new StringBuilder();

        while (cancellationToken.IsCancellationRequested is false)
        {
            if (Console.KeyAvailable is false)
            {
                continue;
            }

            var consoleKeyInfo = Console.ReadKey(true);

            switch (consoleKeyInfo.Key)
            {
                case ConsoleKey.Escape:
                    this.console.WriteLine(string.Empty);
                    return null;
                case ConsoleKey.Enter:
                    this.console.WriteLine(string.Empty);
                    return stringBuilder.ToString();
                case ConsoleKey.Backspace:
                    if (stringBuilder.Length > 0)
                    {
                        stringBuilder.Length -= 1;
                        this.console.Write("\b \b");
                    }
                    else
                    {
                        Console.Beep();
                    }

                    break;
                default:
                    if (char.IsControl(consoleKeyInfo.KeyChar))
                    {
                        Console.Beep();
                    }
                    else
                    {
                        stringBuilder.Append(consoleKeyInfo.KeyChar);
                        this.console.Write("*");
                    }

                    break;
            }
        }

        this.console.WriteLine(string.Empty);

        return null;
    }
}