using System;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Parsing;
using System.IO;
using System.Linq;

namespace NStash.Commands;

public sealed class DefaultCommand : RootCommand
{
    public DefaultCommand()
        : base("This program will encrypt/decrypt files.")
    {
        this.SetArguments();
        this.SetOptions();
    }

    private static FileSystemOptions[] ParseTargetPathArgument(ArgumentResult argumentResult)
    {
        if (argumentResult.Tokens.Any() is false)
        {
            argumentResult.ErrorMessage = "No target path specified.";
            return Array.Empty<FileSystemOptions>();
        }

        var values = argumentResult.Tokens[0].Value.Split(',', StringSplitOptions.RemoveEmptyEntries);

        if (values.Any() is false)
        {
            argumentResult.ErrorMessage = "No target path specified.";
            return Array.Empty<FileSystemOptions>();
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

        return targets.ToArray();
    }

    private void SetArguments()
    {
        var targetPathArgument = new Argument<FileSystemOptions[]>(
            name: "targets",
            description: "Specifies the path of the file or directory of interest. You can specify multiple targets by separating them with commas.",
            isDefault: false,
            parse: ParseTargetPathArgument);

        this.AddArgument(targetPathArgument);
    }

    private void SetOptions()
    {
        var encryptOption = new Option<bool>(
            aliases: new[]
            {
                "--encrypt",
                "-e",
            },
            description: "Encrypt the target file.");
        var decryptOption = new Option<bool>(
            aliases: new[]
            {
                "--decrypt",
                "-d",
            },
            description: "Decrypt the target file.");
        var deleteOption = new Option<bool>(
            aliases: new[]
            {
                "--delete",
                "-D",
            },
            description: "Delete the original file after encryption/decryption.");
        var processCountOption = new Option<int>(
            aliases: new[]
            {
                "--process-count",
                "-p",
            },
            description: "Specifies the number of processes to use for encryption/decryption. The default is the number of logical processors in the system.",
            getDefaultValue: () => Environment.ProcessorCount);
        var dryRunOption = new Option<bool>(
            name: "--dry-run",
            description: "Practice the encryption/decryption process. No actual processing is performed.");

        this.AddOption(encryptOption);
        this.AddOption(decryptOption);
        this.AddOption(deleteOption);
        this.AddOption(processCountOption);
        this.AddOption(dryRunOption);
    }
}