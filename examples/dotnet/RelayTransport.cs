using System.Net;
using System.Net.WebSockets;

namespace PrivateRelay;

/// <summary>
/// TCP over WSS; .NET itself still negotiates and validates the target's TLS.
/// Copy this file into a .NET 8+ bot, then inject CreateHandler() into its HTTP stack.
/// </summary>
public sealed class RelayTransport
{
    private readonly Uri _endpoint;
    private readonly string _keyId;
    private readonly string _secret;

    public RelayTransport(Uri endpoint, string keyId, string secret)
    {
        if (endpoint.Scheme != "wss" || !string.IsNullOrEmpty(endpoint.UserInfo)
            || !string.IsNullOrEmpty(endpoint.Query) || !string.IsNullOrEmpty(endpoint.Fragment))
            throw new ArgumentException("Relay endpoint must be wss://host/tunnel without credentials/query.");
        if (string.IsNullOrWhiteSpace(keyId) || secret.Length is < 32 or > 256
            || secret.Any(c => c < 33 || c > 126))
            throw new ArgumentException("Invalid relay credentials.");
        _endpoint = endpoint;
        _keyId = keyId;
        _secret = secret;
    }

    public SocketsHttpHandler CreateHandler() => new()
    {
        UseProxy = false,
        UseCookies = false,
        AllowAutoRedirect = false,
        ConnectTimeout = TimeSpan.FromSeconds(15),
        PooledConnectionLifetime = TimeSpan.FromMinutes(10),
        ConnectCallback = (context, cancellationToken) => OpenAsync(
            context.DnsEndPoint.Host, context.DnsEndPoint.Port, cancellationToken)
    };

    public async ValueTask<Stream> OpenAsync(string host, int port, CancellationToken cancellationToken)
    {
        if (port != 443) throw new ArgumentException("Only target port 443 is supported.");
        var uri = new UriBuilder(_endpoint)
        {
            Query = $"host={Uri.EscapeDataString(host)}&port={port}"
        }.Uri;
        var socket = new ClientWebSocket();
        // Outer transport never uses the bot's proxy/ConnectCallback; avoid recursion.
        var outerHandler = new SocketsHttpHandler { UseProxy = false, UseCookies = false };
        var invoker = new HttpMessageInvoker(outerHandler, disposeHandler: true);
        socket.Options.SetRequestHeader("X-Proxy-Key", _keyId);
        socket.Options.SetRequestHeader("X-Proxy-Secret", _secret);
        socket.Options.KeepAliveInterval = TimeSpan.FromSeconds(30);
        try
        {
            await socket.ConnectAsync(uri, invoker, cancellationToken);
            return new TunnelStream(socket, invoker);
        }
        catch
        {
            socket.Dispose();
            invoker.Dispose();
            // Do not include secret, target bot URL or upstream exception text in logs.
            throw new IOException("Could not establish the relay tunnel.");
        }
    }

    private sealed class TunnelStream(ClientWebSocket socket, HttpMessageInvoker invoker) : Stream
    {
        private readonly SemaphoreSlim _readLock = new(1, 1);
        private readonly SemaphoreSlim _writeLock = new(1, 1);
        private bool _disposed;
        public override bool CanRead => !_disposed;
        public override bool CanWrite => !_disposed;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (buffer.IsEmpty) return 0;
            await _readLock.WaitAsync(cancellationToken);
            try
            {
                while (true)
                {
                    var result = await socket.ReceiveAsync(buffer, cancellationToken);
                    if (result.MessageType == WebSocketMessageType.Close) return 0;
                    if (result.MessageType != WebSocketMessageType.Binary)
                        throw new IOException("Relay sent a non-binary frame.");
                    if (result.Count != 0) return result.Count;
                }
            }
            finally { _readLock.Release(); }
        }

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await _writeLock.WaitAsync(cancellationToken);
            try
            {
                while (!buffer.IsEmpty)
                {
                    var count = Math.Min(buffer.Length, 16384);
                    await socket.SendAsync(buffer[..count], WebSocketMessageType.Binary, true, cancellationToken);
                    buffer = buffer[count..];
                }
            }
            finally { _writeLock.Release(); }
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        public override int Read(byte[] buffer, int offset, int count) =>
            ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
        public override void Write(byte[] buffer, int offset, int count) =>
            WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        protected override void Dispose(bool disposing)
        {
            if (disposing && !_disposed)
            {
                _disposed = true;
                // Abort immediately to unblock pending reads; the server closes its target socket.
                socket.Abort();
                socket.Dispose();
                invoker.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
