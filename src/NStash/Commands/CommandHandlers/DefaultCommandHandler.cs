using System;
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

    public bool DryRun { get; set; }

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

            this.encryptionService.FileEncrypting += this.OnFileEncrypting;
            this.encryptionService.FileDecrypting += this.OnFileDecrypting;

            foreach (var target in this.Targets)
            {
                if (this.Encrypt)
                {
                    await this.encryptionService.EncryptAsync(
                        target,
                        password,
                        this.DryRun,
                        cancellationToken).ConfigureAwait(false);
                }
                else if (this.Decrypt)
                {
                    await this.encryptionService.DecryptAsync(
                        target,
                        password,
                        this.DryRun,
                        cancellationToken).ConfigureAwait(false);
                }
            }
        }
        catch (Exception exception)
        {
            this.console.Error.WriteLine(exception.ToString());
            return 1;
        }
        finally
        {
            this.encryptionService.FileEncrypting -= this.OnFileEncrypting;
            this.encryptionService.FileDecrypting -= this.OnFileDecrypting;
        }

        return 0;
    }

    private void OnFileEncrypting(object? sender, FileEncryptionEventArgs e)
    {
        this.console.WriteLine($"{e.SourceFilePath}{Environment.NewLine}-> {e.DestinationFilePath}");
    }

    private void OnFileDecrypting(object? sender, FileEncryptionEventArgs e)
    {
        this.console.WriteLine($"{e.SourceFilePath}{Environment.NewLine}-> {e.DestinationFilePath}");
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