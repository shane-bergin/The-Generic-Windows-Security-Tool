using System;
using System.IO;

namespace TGWST.Core.Feeds;

public static class FeedPaths
{
    public static string Base => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "TGWST",
        "Feeds");

    public static string Yara => Path.Combine(Base, "Yara");
    public static string Iocs => Path.Combine(Base, "Iocs");

    public static void EnsureDirectoriesExist()
    {
        Directory.CreateDirectory(Base);
        Directory.CreateDirectory(Yara);
        Directory.CreateDirectory(Iocs);
    }
}
