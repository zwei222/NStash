using System.CommandLine.Builder;
using System.CommandLine.Hosting;
using System.CommandLine.Parsing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NStash.Commands;
using NStash.Commands.CommandHandlers;
using NStash.Services;
using NStash.Services.Implementations;

var builder = new CommandLineBuilder(new DefaultCommand());

builder.UseDefaults();
builder.UseHost(
    _ => Host.CreateDefaultBuilder(),
    host =>
    {
        host.ConfigureLogging(logging =>
        {
            logging.ClearProviders();
            logging.SetMinimumLevel(LogLevel.Warning);
            logging.AddSimpleConsole();
        });
        host.ConfigureServices(services =>
        {
            services.AddSingleton<IEncryptionService, EncryptionService>();
        });
        host.UseCommandHandler<DefaultCommand, DefaultCommandHandler>();
    });

var parser = builder.Build();

await parser.InvokeAsync(args).ConfigureAwait(false);
