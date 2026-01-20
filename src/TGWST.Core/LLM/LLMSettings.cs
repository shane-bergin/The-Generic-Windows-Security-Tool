using System;
using System.IO;
using System.Text.Json;

namespace TGWST.Core.LLM
{
    public enum LLMProvider
    {
        OpenAI,
        XAI,
        Gemini
    }

    public sealed class LLMSettings
    {
        public LLMProvider Provider { get; set; } = LLMProvider.OpenAI;
        public string ApiKey { get; set; } = string.Empty;
        public string? Model { get; set; }
        public string? Endpoint { get; set; } // used for OpenAI/XAI style endpoints

        public static string GetSettingsPath()
        {
            var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            var dir = Path.Combine(programData, "TGWST");
            Directory.CreateDirectory(dir);
            return Path.Combine(dir, "llm-settings.json");
        }

        public static LLMSettings Load()
        {
            var path = GetSettingsPath();
            if (!File.Exists(path)) return new LLMSettings();

            try
            {
                var json = File.ReadAllText(path);
                var settings = JsonSerializer.Deserialize<LLMSettings>(json);
                return settings ?? new LLMSettings();
            }
            catch
            {
                return new LLMSettings();
            }
        }

        public void Save()
        {
            var path = GetSettingsPath();
            var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(path, json);
        }
    }
}
