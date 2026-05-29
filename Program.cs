using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// QuickSheet TLS Extension — reads JSON-lines from stdin, writes JSON-lines to stdout.
/// Registers the "tls" prefix. Given a host[:port], opens a TLS connection and reports
/// certificate expiry days, issuer, and SAN count.
/// Usage in QuickSheet: `tls: example.com, 1, 3` → fills 3 rows (host, days-to-expiry, issuer).
/// </summary>
class Program
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false
    };

    static void Main()
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        string? line;
        while ((line = Console.ReadLine()) != null)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            try
            {
                using var doc = JsonDocument.Parse(line);
                string? type = doc.RootElement.TryGetProperty("type", out var tp) ? tp.GetString() : null;
                switch (type)
                {
                    case "init": HandleInit(); break;
                    case "activate": HandleActivate(doc.RootElement); break;
                }
            }
            catch (Exception ex)
            {
                SendLog($"parse error: {ex.Message}");
            }
        }
    }

    static void HandleInit()
    {
        SendJson(new
        {
            type = "register",
            prefix = "tls",
            name = "TLS Certificate Checker",
            version = "1.0.0"
        });
        SendLog("TLS extension registered with prefix 'tls'");
    }

    static void HandleActivate(JsonElement root)
    {
        string id = root.TryGetProperty("id", out var idProp) ? idProp.GetString() ?? "" : "";
        int gridCols = root.TryGetProperty("gridCols", out var gc) ? gc.GetInt32() : 1;
        int gridRows = root.TryGetProperty("gridRows", out var gr) ? gr.GetInt32() : 3;

        string[] extParams = [];
        if (root.TryGetProperty("params", out var p) && p.ValueKind == JsonValueKind.Array)
            extParams = p.EnumerateArray().Select(x => x.GetString() ?? "").ToArray();

        if (extParams.Length == 0)
        {
            WriteCells(id, [["tls: <host>"]]);
            return;
        }

        string target = extParams[0].Trim();
        string host = target;
        int port = 443;
        int idx = target.IndexOf(':');
        if (idx > 0)
        {
            host = target[..idx];
            int.TryParse(target[(idx + 1)..], out port);
            if (port <= 0) port = 443;
        }

        try
        {
            var cert = FetchCert(host, port);
            int days = (int)Math.Floor((cert.NotAfter - DateTime.UtcNow).TotalDays);
            string issuer = ShortIssuer(cert.Issuer);
            string subject = ShortSubject(cert.Subject);

            var rows = new List<string[]>
            {
                new[] { $"{host}:{port}" },
                new[] { $"expires in {days}d" },
                new[] { $"issuer: {issuer}" },
                new[] { $"cn: {subject}" }
            };
            // Trim/pad to requested row count
            while (rows.Count < gridRows) rows.Add(new[] { "" });
            if (rows.Count > gridRows) rows = rows.Take(gridRows).ToList();
            WriteCells(id, rows);
        }
        catch (Exception ex)
        {
            WriteCells(id, new[] { new[] { $"err: {ex.Message}" } });
        }
    }

    static X509Certificate2 FetchCert(string host, int port)
    {
        using var tcp = new TcpClient();
        tcp.Connect(host, port);
        using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
        ssl.AuthenticateAsClient(host);
        var raw = ssl.RemoteCertificate ?? throw new Exception("no remote cert");
        return new X509Certificate2(raw);
    }

    static string ShortIssuer(string dn)
    {
        foreach (string part in dn.Split(','))
        {
            string t = part.Trim();
            if (t.StartsWith("O=", StringComparison.OrdinalIgnoreCase)) return t[2..];
        }
        return dn;
    }

    static string ShortSubject(string dn)
    {
        foreach (string part in dn.Split(','))
        {
            string t = part.Trim();
            if (t.StartsWith("CN=", StringComparison.OrdinalIgnoreCase)) return t[3..];
        }
        return dn;
    }

    static void WriteCells(string id, IEnumerable<string[]> rows)
    {
        SendJson(new { type = "write", id, cells = rows });
    }

    static void SendJson(object obj)
    {
        Console.WriteLine(JsonSerializer.Serialize(obj, JsonOpts));
    }

    static void SendLog(string message)
    {
        SendJson(new { type = "log", message });
    }
}
