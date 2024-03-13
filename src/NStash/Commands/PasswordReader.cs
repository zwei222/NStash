using System.Text;

namespace NStash.Commands;

public static class PasswordReader
{
    public static string? ReadPassword(CancellationToken cancellationToken)
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
                    Console.WriteLine(string.Empty);
                    return null;
                case ConsoleKey.Enter:
                    Console.WriteLine(string.Empty);
                    return stringBuilder.ToString();
                case ConsoleKey.Backspace:
                    if (stringBuilder.Length > 0)
                    {
                        stringBuilder.Length -= 1;
                        Console.Write("\b \b");
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
                        Console.Write("*");
                    }

                    break;
            }
        }

        Console.WriteLine(string.Empty);

        return null;
    }
}