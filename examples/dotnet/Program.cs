using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Text;
using PrivateRelay;

// Modes: api (default), websocket, bridge. Credentials come only from environment.
var endpoint = Environment.GetEnvironmentVariable("RELAY_ENDPOINT")
    ?? throw new InvalidOperationException("Set RELAY_ENDPOINT=wss://relay.example/tunnel");
var keyId = Environment.GetEnvironmentVariable("RELAY_KEY_ID") ?? "default";
var secret = Environment.GetEnvironmentVariable("RELAY_SECRET")
    ?? throw new InvalidOperationException("Set RELAY_SECRET");
var relay = new RelayTransport(new Uri(endpoint), keyId, secret);
using var shutdown = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; shutdown.Cancel(); };
var mode = args.FirstOrDefault() ?? "api";

if (mode == "bridge")
{
    // For libraries exposing IWebProxy but no custom HTTP/WebSocket handler.
    // Loopback only: the relay key must never be exposed through a public CONNECT proxy.
    var port = int.Parse(Environment.GetEnvironmentVariable("LOCAL_PROXY_PORT") ?? "8787");
    var listener = new TcpListener(IPAddress.Loopback, port);
    var slots = new SemaphoreSlim(16, 16);
    listener.Start(16);
    Console.WriteLine($"Local proxy listening on 127.0.0.1:{port}");
    try
    {
        while (!shutdown.IsCancellationRequested)
        {
            await slots.WaitAsync(shutdown.Token);
            TcpClient client;
            try { client = await listener.AcceptTcpClientAsync(shutdown.Token); }
            catch { slots.Release(); throw; }
            _ = HandleClient(client);
        }
    }
    catch (OperationCanceledException) { }
    finally { listener.Stop(); }

    async Task HandleClient(TcpClient client)
    {
        using (client)
        using (var lifetime = CancellationTokenSource.CreateLinkedTokenSource(shutdown.Token))
        {
            try
            {
                var stream = client.GetStream();
                // Read just the HTTP header, never consume the bot's initial TLS bytes.
                using var handshake = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
                handshake.CancelAfter(TimeSpan.FromSeconds(15));
                var header = new List<byte>();
                var single = new byte[1];
                while (header.Count < 8192)
                {
                    if (await stream.ReadAsync(single, handshake.Token) == 0) return;
                    header.Add(single[0]);
                    if (header.Count >= 4 && header[^4] == 13 && header[^3] == 10
                        && header[^2] == 13 && header[^1] == 10) break;
                }
                var line = Encoding.ASCII.GetString(header.ToArray()).Split("\r\n")[0].Split(' ');
                if (header.Count >= 8192 || line.Length != 3 || line[0] != "CONNECT"
                    || !Uri.TryCreate("https://" + line[1], UriKind.Absolute, out var target)
                    || target.Port != 443 || !string.IsNullOrEmpty(target.UserInfo)
                    || target.AbsolutePath != "/" || !string.IsNullOrEmpty(target.Query)
                    || !string.IsNullOrEmpty(target.Fragment))
                {
                    await stream.WriteAsync("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"u8.ToArray(), handshake.Token);
                    return;
                }
                await using var tunnel = await relay.OpenAsync(target.Host, target.Port, handshake.Token);
                await stream.WriteAsync("HTTP/1.1 200 Connection Established\r\n\r\n"u8.ToArray(), handshake.Token);
                var up = stream.CopyToAsync(tunnel, lifetime.Token);
                var down = tunnel.CopyToAsync(stream, lifetime.Token);
                await Task.WhenAny(up, down);
                lifetime.Cancel();
                try { await Task.WhenAll(up, down); }
                catch (OperationCanceledException) { }
            }
            catch (Exception) { Console.Error.WriteLine("Local proxy connection closed."); }
            finally { slots.Release(); }
        }
    }
}
else if (mode == "websocket")
{
    using var handler = relay.CreateHandler();
    using var invoker = new HttpMessageInvoker(handler, disposeHandler: false);
    using var socket = new ClientWebSocket();
    // This is the inner Discord WebSocket; target TLS validation stays enabled.
    await socket.ConnectAsync(new Uri("wss://gateway.discord.gg/?v=10&encoding=json"), invoker, shutdown.Token);
    var buffer = new byte[16384];
    var message = await socket.ReceiveAsync(buffer, shutdown.Token);
    Console.WriteLine($"Gateway received {message.Count} bytes through relay.");
    await socket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "Example finished", shutdown.Token);
}
else if (mode == "api")
{
    using var http = new HttpClient(relay.CreateHandler());
    // Inject this HttpClient into your bot SDK. Long polling needs an adequate timeout.
    http.Timeout = TimeSpan.FromSeconds(120);
    using var response = await http.GetAsync("https://discord.com/api/v10/gateway", shutdown.Token);
    Console.WriteLine($"API status through relay: {(int)response.StatusCode}");
    Console.WriteLine(await response.Content.ReadAsStringAsync(shutdown.Token));
}
else throw new ArgumentException("Use api, websocket or bridge.");
