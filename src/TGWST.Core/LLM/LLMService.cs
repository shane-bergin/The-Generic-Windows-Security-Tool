using System;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace TGWST.Core.LLM
{
    public class LLMService
    {
        private readonly HttpClient _httpClient = new HttpClient();
        private LLMSettings _settings = new LLMSettings();
        private bool _isInitialized = false;

        public LLMService()
        {
        }

        public async Task InitializeAsync()
        {
            if (_isInitialized)
            {
                return;
            }

            _settings = LLMSettings.Load();
            ValidateSettingsOrThrow(_settings);
            _isInitialized = true;
            await Task.CompletedTask;
        }

        public async Task<string> AnalyzeScriptAsync(string scriptContent)
        {
            if (!_isInitialized)
            {
                return "LLM not initialized. Please configure an API provider/key.";
            }

            if (string.IsNullOrWhiteSpace(scriptContent))
            {
                return "Error: Script content is empty or null.";
            }

            var prompt = BuildPrompt(scriptContent);

            return _settings.Provider switch
            {
                LLMProvider.OpenAI => await CallOpenAIStyleAsync(prompt, isXai: false),
                LLMProvider.XAI => await CallOpenAIStyleAsync(prompt, isXai: true),
                LLMProvider.Gemini => await CallGeminiAsync(prompt),
                _ => "Unsupported LLM provider."
            };
        }

        private static string BuildPrompt(string scriptContent)
        {
            if (scriptContent.Length > 4000)
            {
                scriptContent = scriptContent.Substring(0, 4000) + "\n... [truncated]";
            }

            return $"""
You are a cybersecurity expert. Analyze this script for malicious intent.
Identify suspicious actions like obfuscation, persistence, credential access, or data exfiltration.
Conclude with a verdict: [Benign, Suspicious, Malicious].

--- SCRIPT ---
{scriptContent}
--- END ---
""";
        }

        private static void ValidateSettingsOrThrow(LLMSettings settings)
        {
            if (settings == null || string.IsNullOrWhiteSpace(settings.ApiKey))
            {
                throw new InvalidOperationException("LLM is not configured. Set provider and API key in LLM Settings.");
            }
        }

        private string GetOpenAiLikeEndpoint(bool isXai)
        {
            if (!string.IsNullOrWhiteSpace(_settings.Endpoint))
            {
                return _settings.Endpoint.TrimEnd('/');
            }

            return isXai ? "https://api.x.ai" : "https://api.openai.com";
        }

        private string GetOpenAiLikeModel(bool isXai)
        {
            if (!string.IsNullOrWhiteSpace(_settings.Model))
            {
                return _settings.Model!;
            }

            return isXai ? "grok-beta" : "gpt-4o-mini";
        }

        private async Task<string> CallOpenAIStyleAsync(string prompt, bool isXai)
        {
            var baseUrl = GetOpenAiLikeEndpoint(isXai);
            var model = GetOpenAiLikeModel(isXai);
            var url = $"{baseUrl}/v1/chat/completions";

            using var req = new HttpRequestMessage(HttpMethod.Post, url);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _settings.ApiKey);
            var payload = new
            {
                model,
                messages = new[]
                {
                    new { role = "system", content = "You are a cybersecurity analyst. Be concise." },
                    new { role = "user", content = prompt }
                },
                temperature = 0.2,
                max_tokens = 256
            };
            req.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

            var resp = await _httpClient.SendAsync(req).ConfigureAwait(false);
            var body = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
            {
                return $"LLM API error ({resp.StatusCode}): {body}";
            }

            try
            {
                using var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;
                var content = root.GetProperty("choices")[0].GetProperty("message").GetProperty("content").GetString();
                return content ?? "LLM returned empty response.";
            }
            catch
            {
                return body;
            }
        }

        private async Task<string> CallGeminiAsync(string prompt)
        {
            var model = string.IsNullOrWhiteSpace(_settings.Model) ? "gemini-1.5-flash" : _settings.Model!;
            var url = $"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={_settings.ApiKey}";

            using var req = new HttpRequestMessage(HttpMethod.Post, url);
            var payload = new
            {
                contents = new[]
                {
                    new
                    {
                        parts = new[] { new { text = prompt } }
                    }
                }
            };

            req.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

            var resp = await _httpClient.SendAsync(req).ConfigureAwait(false);
            var body = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
            {
                return $"LLM API error ({resp.StatusCode}): {body}";
            }

            try
            {
                using var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;
                var candidates = root.GetProperty("candidates");
                var content = candidates[0].GetProperty("content").GetProperty("parts")[0].GetProperty("text").GetString();
                return content ?? "LLM returned empty response.";
            }
            catch
            {
                return body;
            }
        }
    }
}
