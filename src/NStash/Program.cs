using System.CommandLine;
using NStash.Commands;

var appCommand = new AppCommand();

return await appCommand.InvokeAsync(args);
