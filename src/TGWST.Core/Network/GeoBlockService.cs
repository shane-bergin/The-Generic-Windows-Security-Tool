using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Principal;

namespace TGWST.Core.Network
{
    public sealed record GeoBlockCountry(string Name, string Code, string Label);

    public sealed record GeoBlockSelection(string Name, string Code, bool Blocked);

    public sealed class GeoBlockService
    {
        public static readonly IReadOnlyList<GeoBlockCountry> Countries =
        [
            // Eastern Europe / Balkans
            new("Russia", "ru", "Russia"),
            new("Ukraine", "ua", "Ukraine"),
            new("Belarus", "by", "Belarus"),
            new("Romania", "ro", "Romania"),
            new("Bulgaria", "bg", "Bulgaria"),
            new("Serbia", "rs", "Serbia"),
            new("Bosnia", "ba", "Bosnia"),
            new("Moldova", "md", "Moldova"),
            new("Albania", "al", "Albania"),
            new("NorthMacedonia", "mk", "North Macedonia"),
            new("Montenegro", "me", "Montenegro"),

            // Middle East
            new("Iran", "ir", "Iran"),
            new("Syria", "sy", "Syria"),
            new("Iraq", "iq", "Iraq"),
            new("Lebanon", "lb", "Lebanon"),
            new("Jordan", "jo", "Jordan"),
            new("SaudiArabia", "sa", "Saudi Arabia"),
            new("Yemen", "ye", "Yemen"),
            new("Israel", "il", "Israel"),
            new("Palestine", "ps", "Palestine"),
            new("Kuwait", "kw", "Kuwait"),
            new("Qatar", "qa", "Qatar"),
            new("UAE", "ae", "UAE"),
            new("Oman", "om", "Oman"),

            // Caucasus / nearby
            new("Turkey", "tr", "Turkey"),
            new("Georgia", "ge", "Georgia"),
            new("Armenia", "am", "Armenia"),
            new("Azerbaijan", "az", "Azerbaijan"),

            // Explicit high-risk
            new("China", "cn", "China"),
            new("NorthKorea", "kp", "North Korea")
        ];

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        public async Task<HashSet<string>> GetBlockedCountriesAsync(CancellationToken ct = default)
        {
            var nameLiterals = string.Join(", ", Countries.Select(c => PsSingleQuote(c.Name)));
            var script = $@"
$names = @({nameLiterals})
$result = foreach ($n in $names) {{
  $display = ""GeoBlock-$n""
  $enabled = @(Get-NetFirewallRule -DisplayName ""$display*"" -ErrorAction SilentlyContinue | Where-Object {{ $_.Enabled -eq 'True' }}).Count -gt 0
  [pscustomobject]@{{ Name = $n; Blocked = [bool]$enabled }}
}}
$result | ConvertTo-Json -Compress
";

            var stdout = await RunPowerShellAsync(script, ct);
            if (string.IsNullOrWhiteSpace(stdout)) return new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var parsed = JsonSerializer.Deserialize<List<GeoBlockState>>(stdout, JsonOptions) ?? [];
            return parsed.Where(p => p.Blocked).Select(p => p.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        }

        public async Task ApplyAsync(IEnumerable<GeoBlockSelection> selections, CancellationToken ct = default)
        {
            EnsureAdmin();

            var byName = selections.ToDictionary(s => s.Name, s => s, StringComparer.OrdinalIgnoreCase);
            var normalized = Countries.Select(c =>
            {
                var blocked = byName.TryGetValue(c.Name, out var selection) && selection.Blocked;
                return new GeoBlockSelection(c.Name, c.Code, blocked);
            }).ToArray();

            var payload = JsonSerializer.Serialize(normalized, JsonOptions);
            var payloadLiteral = PsSingleQuote(payload);

            var script = $@"
$items = {payloadLiteral} | ConvertFrom-Json
$tempDir = Join-Path $env:TEMP 'GeoBlock'
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null

function Remove-GeoRules([string]$baseName) {{
  $prefix = ""GeoBlock-$baseName""
  Get-NetFirewallRule -DisplayName ""$prefix*"" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
}}

foreach ($item in $items) {{
  if (-not $item.Blocked) {{
    Remove-GeoRules $item.Name
    continue
  }}

  Remove-GeoRules $item.Name

  $url = ""https://www.ipdeny.com/ipblocks/data/aggregated/$($item.Code)-aggregated.zone""
  $listPath = Join-Path $tempDir (""$($item.Code).zone"")
  Invoke-WebRequest $url -OutFile $listPath -UseBasicParsing

  $ips = Get-Content $listPath | Where-Object {{ $_ -match '/' }}
  if ($ips.Count -eq 0) {{
    continue
  }}

  $chunkSize = 2000
  $ruleBase = ""GeoBlock-$($item.Name)""
  if ($ips.Count -le $chunkSize) {{
    New-NetFirewallRule -DisplayName $ruleBase -Direction Inbound -Action Block -RemoteAddress $ips -Profile Any -Enabled True | Out-Null
    continue
  }}

  $i = 0
  $ruleIndex = 1
  while ($i -lt $ips.Count) {{
    $end = [Math]::Min($i + $chunkSize - 1, $ips.Count - 1)
    $chunk = $ips[$i..$end]
    New-NetFirewallRule -DisplayName (""$ruleBase ($ruleIndex)"") -Direction Inbound -Action Block -RemoteAddress $chunk -Profile Any -Enabled True | Out-Null
    $i += $chunkSize
    $ruleIndex++
  }}
}}
";

            _ = await RunPowerShellAsync(script, ct);
        }

        private static void EnsureAdmin()
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
                    throw new InvalidOperationException("Administrator rights are required to apply region lock firewall rules. Re-run TGWST as Administrator.");
            }
            catch (InvalidOperationException)
            {
                throw;
            }
            catch
            {
                throw new InvalidOperationException("Administrator rights are required to apply region lock firewall rules. Re-run TGWST as Administrator.");
            }
        }

        private static string PsSingleQuote(string value) => "'" + value.Replace("'", "''") + "'";

        private static async Task<string> RunPowerShellAsync(string script, CancellationToken ct)
        {
            var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));

            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoLogo -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardError = true,
                RedirectStandardOutput = true
            };

            using var p = Process.Start(psi);
            if (p == null) throw new InvalidOperationException("Failed to start PowerShell");

            var stderrTask = p.StandardError.ReadToEndAsync();
            var stdoutTask = p.StandardOutput.ReadToEndAsync();
            await p.WaitForExitAsync(ct);
            var stderr = await stderrTask;
            var stdout = await stdoutTask;

            if (p.ExitCode != 0)
            {
                var error = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;
                throw new InvalidOperationException($"PowerShell failed (exit {p.ExitCode}): {Truncate(error)}");
            }

            return stdout.Trim();
        }

        private static string Truncate(string value, int max = 600)
        {
            var trimmed = value.Trim();
            return trimmed.Length <= max ? trimmed : trimmed[..max] + "...";
        }

        private sealed class GeoBlockState
        {
            public string Name { get; set; } = "";
            public bool Blocked { get; set; }
        }
    }
}
