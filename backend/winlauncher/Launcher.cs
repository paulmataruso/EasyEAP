// EasyEAP setup for Windows: the program users double-click. It carries an EasyEAP setup script appended after itself
// (app/enrollment/windows_exe.py writes it, per user, without recompiling), and runs it with Windows PowerShell exactly
// as the .cmd setup file does: the script's own steps, messages and administrator prompt are unchanged.
//
// Layout of the file: [this program][script bytes][script length: 8 bytes, little-endian][MAGIC, ASCII].
// Built by the API image (backend/Dockerfile) for .NET Framework 4, which every Windows 10 and 11 PC has.
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

[assembly: AssemblyTitle("EasyEAP setup")]
[assembly: AssemblyProduct("EasyEAP")]
[assembly: AssemblyDescription("Sets up this PC's network certificates and Wi-Fi/wired 802.1X for EasyEAP")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

static class Launcher
{
    const string Magic = "EASYEAP-SETUP-PAYLOAD-1";
    const string Prefix = "EasyEAP-Setup-";   // its temporary folders (the scripts' own are easyeap-<guid>)

    delegate bool ConsoleEvent(int type);
    [DllImport("kernel32.dll")]
    static extern bool SetConsoleCtrlHandler(ConsoleEvent handler, bool add);
    static ConsoleEvent handler;   // kept here: Windows holds it, the garbage collector mustn't take it
    static string work;

    static int Main()
    {
        try { Console.Title = "EasyEAP setup"; } catch (IOException) { }
        string self = Assembly.GetExecutingAssembly().Location;
        byte[] script = ReadScript(self);
        if (script == null)
        {
            Console.WriteLine("This setup file is incomplete or damaged. Download it again.");
            Pause();
            return 2;
        }
        // Tests only (tests/windows/launcher.sh): write the script out instead of running it.
        string extract = Environment.GetEnvironmentVariable("EASYEAP_LAUNCHER_EXTRACT");
        if (!String.IsNullOrEmpty(extract))
        {
            File.WriteAllBytes(extract, script);
            return 0;
        }

        // The user's own temporary folder (only they and administrators can read it). The administrator part of the
        // setup reads the script again from here, as it reads the .cmd from Downloads. The script holds one-time codes:
        // it goes when PowerShell ends, when the window is closed, and otherwise (a crash, a power cut) at the next run.
        string temp = Path.GetTempPath();
        RemoveStale(temp);
        string dir = Path.Combine(temp, Prefix + Guid.NewGuid().ToString("N"));
        string file = Path.Combine(dir, "setup.ps1");
        try
        {
            Directory.CreateDirectory(dir);
            work = dir;
            handler = OnConsoleEvent;
            SetConsoleCtrlHandler(handler, true);
            File.WriteAllBytes(file, script);
            ProcessStartInfo psi = new ProcessStartInfo(PowerShell(),
                "-NoProfile -ExecutionPolicy Bypass -Command \"Invoke-Expression ([IO.File]::ReadAllText($env:EASYEAP_SETUP))\"");
            psi.UseShellExecute = false;   // the same console window
            psi.EnvironmentVariables["EASYEAP_SETUP"] = file;
            psi.EnvironmentVariables.Remove("EASYEAP_PART");
            psi.EnvironmentVariables.Remove("EASYEAP_RUN");
            using (Process p = Process.Start(psi))
            {
                p.WaitForExit();
                return p.ExitCode;
            }
        }
        catch (Exception e)
        {
            Console.WriteLine("EasyEAP setup couldn't start Windows PowerShell: " + e.Message);
            Pause();
            return 3;
        }
        finally
        {
            Remove(dir);
        }
    }

    // Ctrl+C and Ctrl+Break (0, 1) reach PowerShell too, which shares the window: wait for it, then clean up as usual.
    // Anything else (2: the window was closed) ends this process within seconds, so the script goes now.
    static bool OnConsoleEvent(int type)
    {
        if (type == 0 || type == 1) return true;
        Remove(work);
        return false;
    }

    // Folders an earlier run couldn't remove. Not recent ones: another setup may be running.
    static void RemoveStale(string temp)
    {
        try
        {
            foreach (string d in Directory.GetDirectories(temp, Prefix + "*"))
            {
                if (Directory.GetLastWriteTimeUtc(d) < DateTime.UtcNow.AddHours(-12)) Remove(d);
            }
        }
        catch (Exception) { }
    }

    static void Remove(string dir)
    {
        if (String.IsNullOrEmpty(dir)) return;
        try { Directory.Delete(dir, true); } catch (Exception) { }
    }

    // Windows PowerShell from Windows' own folder, never one found on the PATH. A 32-bit process on 64-bit Windows
    // reaches the 64-bit one through Sysnative (System32 is redirected for it).
    static string PowerShell()
    {
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string system = Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess ? "Sysnative" : "System32";
        return Path.Combine(Path.Combine(Path.Combine(Path.Combine(windows, system), "WindowsPowerShell"), "v1.0"), "powershell.exe");
    }

    static byte[] ReadScript(string path)
    {
        try
        {
            using (FileStream f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                byte[] magic = Encoding.ASCII.GetBytes(Magic);
                long trailer = magic.Length + 8;
                if (f.Length < trailer) return null;
                byte[] tail = new byte[trailer];
                f.Seek(-trailer, SeekOrigin.End);
                if (!ReadAll(f, tail)) return null;
                for (int i = 0; i < magic.Length; i++)
                {
                    if (tail[8 + i] != magic[i]) return null;
                }
                long length = BitConverter.ToInt64(tail, 0);   // little-endian on every Windows architecture
                if (length <= 0 || length > 16 * 1024 * 1024 || length > f.Length - trailer) return null;
                byte[] script = new byte[length];
                f.Seek(-(trailer + length), SeekOrigin.End);
                return ReadAll(f, script) ? script : null;
            }
        }
        catch (Exception)
        {
            return null;
        }
    }

    static bool ReadAll(Stream s, byte[] buffer)
    {
        int done = 0;
        while (done < buffer.Length)
        {
            int n = s.Read(buffer, done, buffer.Length - done);
            if (n <= 0) return false;
            done += n;
        }
        return true;
    }

    static void Pause()
    {
        Console.WriteLine();
        Console.Write("Press Enter to close");
        try { Console.ReadLine(); } catch (IOException) { }
    }
}
