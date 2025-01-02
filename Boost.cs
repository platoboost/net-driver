using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Platoboost;

public class Boost
{
    private readonly HttpClient _httpClient;
    private readonly string _identifier;
    private readonly Action<string> _onMessageCallback;
    private readonly string _secretKey;
    private readonly int _serviceId;
    private readonly bool _useNonce;
    private readonly string _baseUrl = "https://api.platoboost.com";
    private string _cachedLink = string.Empty;
    private DateTime _cachedTime;

    public Boost(int serviceId, string secretKey, bool useNonce, Action<string> onMessageCallback)
    {
        _serviceId = serviceId;
        _secretKey = secretKey;
        _useNonce = useNonce;
        _onMessageCallback = onMessageCallback ?? throw new ArgumentNullException(nameof(onMessageCallback));
        _httpClient = new HttpClient();
        _identifier = GenerateHWID();
    }

    private string GenerateHWID()
    {
        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var output = ExecuteCommand("wmic csproduct get uuid");
                var uuid = ExtractUUID(output);
                if (!string.IsNullOrEmpty(uuid))
                    return HashSHA256(uuid);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                var machineId = File.ReadAllText("/etc/machine-id").Trim();
                if (!string.IsNullOrEmpty(machineId))
                    return HashSHA256(machineId);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                var output = ExecuteCommand("ioreg -rd1 -c IOPlatformExpertDevice");
                var serialNumber = ExtractMacSerialNumber(output);
                if (!string.IsNullOrEmpty(serialNumber))
                    return HashSHA256(serialNumber);
            }
        }
        catch (Exception ex)
        {
            _onMessageCallback?.Invoke($"Failed to generate HWID: {ex.Message}");
        }

        return HashSHA256(Guid.NewGuid().ToString());
    }

    private string ExecuteCommand(string command)
    {
        var processStartInfo = new ProcessStartInfo
        {
            FileName = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "cmd.exe" : "/bin/bash",
            Arguments = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? $"/C {command}" : $"-c \"{command}\"",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(processStartInfo);
        if (process != null)
        {
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            return output;
        }

        return string.Empty;
    }

    private string ExtractUUID(string output)
    {
        var lines = output.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
        return lines.Length > 1 ? lines[1].Trim() : string.Empty;
    }

    private string ExtractMacSerialNumber(string output)
    {
        foreach (var line in output.Split('\n'))
            if (line.Contains("IOPlatformSerialNumber"))
                return line.Split('=')[1].Trim().Trim('"');

        return string.Empty;
    }

    private string HashSHA256(string input)
    {
        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
        return ConvertToHex(hashBytes);
    }

    private string ConvertToHex(byte[] bytes)
    {
        var stringBuilder = new StringBuilder();
        foreach (var b in bytes) stringBuilder.Append(b.ToString("x2"));

        return stringBuilder.ToString();
    }

    public async Task<string> GetLink()
    {
        if (!string.IsNullOrEmpty(_cachedLink) && (DateTime.UtcNow - _cachedTime).TotalMinutes < 5) return _cachedLink;

        var requestBody = new
        {
            service = _serviceId,
            identifier = _identifier
        };

        var content = new StringContent(JsonSerializer.Serialize(requestBody), Encoding.UTF8, "application/json");

        try
        {
            var response = await _httpClient.PostAsync($"{_baseUrl}/public/start", content);

            if (response.IsSuccessStatusCode)
            {
                var responseBody = await response.Content.ReadAsStringAsync();
                var jsonResponse = JsonSerializer.Deserialize<JsonElement>(responseBody);

                if (jsonResponse.GetProperty("success").GetBoolean())
                {
                    _cachedLink = jsonResponse.GetProperty("data").GetProperty("url").GetString() ?? string.Empty;
                    _cachedTime = DateTime.UtcNow;
                    return _cachedLink;
                }
            }

            _onMessageCallback.Invoke("Failed to fetch link.");
        }
        catch (Exception ex)
        {
            _onMessageCallback.Invoke($"Error fetching link: {ex.Message}");
        }

        return string.Empty;
    }

    public async Task<object?> GetFlag(string name)
    {
        var nonce = GenerateNonce();
        var url = $"{_baseUrl}/public/flag/{_serviceId}?name={name}&identifier={_identifier}";

        if (_useNonce) url += $"&nonce={nonce}";

        try
        {
            var response = await _httpClient.GetAsync(url);

            if (response.IsSuccessStatusCode)
            {
                var responseBody = await response.Content.ReadAsStringAsync();
                var jsonResponse = JsonSerializer.Deserialize<JsonElement>(responseBody);

                if (jsonResponse.GetProperty("success").GetBoolean())
                {
                    var data = jsonResponse.GetProperty("data");
                    var value = data.GetProperty("value");

                    object? flagValue = value.ValueKind switch
                    {
                        JsonValueKind.String => value.GetString(),
                        JsonValueKind.Number => (int)value.GetDouble(),
                        JsonValueKind.True => true,
                        JsonValueKind.False => false,
                        _ => null
                    };

                    if (_useNonce)
                    {
                        var stringValueForHash = flagValue switch
                        {
                            bool boolValue => boolValue.ToString().ToLower(),
                            int numberValue => numberValue.ToString(),
                            _ => flagValue?.ToString() ?? string.Empty
                        };

                        var serverHash = data.GetProperty("hash").GetString();
                        var computedHash = HashSHA256($"{stringValueForHash}-{nonce}-{_secretKey}");
                        if (serverHash == computedHash) return flagValue;

                        _onMessageCallback.Invoke("Integrity check failed for flag.");
                        return null;
                    }

                    return flagValue;
                }
            }

            _onMessageCallback.Invoke("Failed to fetch flag.");
        }
        catch (Exception ex)
        {
            _onMessageCallback.Invoke($"Error fetching flag: {ex.Message}");
        }

        return null;
    }

    public async Task<bool> Verify(string key)
    {
        var nonce = GenerateNonce();
        var url = $"{_baseUrl}/public/whitelist/{_serviceId}?identifier={_identifier}&key={key}";

        if (_useNonce) url += $"&nonce={nonce}";

        try
        {
            var response = await _httpClient.GetAsync(url);

            if (response.IsSuccessStatusCode)
            {
                var responseBody = await response.Content.ReadAsStringAsync();
                var jsonResponse = JsonSerializer.Deserialize<JsonElement>(responseBody);

                if (jsonResponse.GetProperty("success").GetBoolean())
                {
                    var data = jsonResponse.GetProperty("data");
                    var valid = data.GetProperty("valid").GetBoolean();

                    if (valid)
                    {
                        if (_useNonce)
                        {
                            var serverHash = data.GetProperty("hash").GetString();
                            var computedHash = HashSHA256($"{valid.ToString().ToLower()}-{nonce}-{_secretKey}");
                            if (serverHash == computedHash) return true;

                            _onMessageCallback.Invoke("Integrity check failed during key verification.");
                            return false;
                        }

                        return true;
                    }

                    if (key.StartsWith("KEY_", StringComparison.OrdinalIgnoreCase)) return await Redeem(key);

                    _onMessageCallback.Invoke("Key is invalid.");
                }
            }

            _onMessageCallback.Invoke("Failed to verify key.");
        }
        catch (Exception ex)
        {
            _onMessageCallback.Invoke($"Error verifying key: {ex.Message}");
        }

        return false;
    }

    public async Task<bool> Redeem(string key)
    {
        var nonce = GenerateNonce();
        var url = $"{_baseUrl}/public/redeem/{_serviceId}";

        var requestBody = new
        {
            identifier = _identifier,
            key,
            nonce = _useNonce ? nonce : null
        };

        var content = new StringContent(JsonSerializer.Serialize(requestBody), Encoding.UTF8, "application/json");

        try
        {
            var response = await _httpClient.PostAsync(url, content);

            if (response.IsSuccessStatusCode)
            {
                var responseBody = await response.Content.ReadAsStringAsync();
                var jsonResponse = JsonSerializer.Deserialize<JsonElement>(responseBody);

                if (jsonResponse.GetProperty("success").GetBoolean())
                {
                    var data = jsonResponse.GetProperty("data");
                    var valid = data.GetProperty("valid").GetBoolean();

                    if (valid)
                    {
                        if (_useNonce)
                        {
                            var serverHash = data.GetProperty("hash").GetString();
                            var computedHash = HashSHA256($"{valid.ToString().ToLower()}-{nonce}-{_secretKey}");
                            if (serverHash == computedHash) return true;

                            _onMessageCallback.Invoke("Integrity check failed during key redemption.");
                            return false;
                        }

                        return true;
                    }

                    _onMessageCallback.Invoke("Key redemption failed: Key is invalid.");
                }
            }

            _onMessageCallback.Invoke("Failed to redeem key.");
        }
        catch (Exception ex)
        {
            _onMessageCallback.Invoke($"Error redeeming key: {ex.Message}");
        }

        return false;
    }

    private string GenerateNonce()
    {
        return _useNonce ? Guid.NewGuid().ToString() : "empty";
    }
}