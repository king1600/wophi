using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Net.Sockets;
using System.Net.Security;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Wophi {

  public class ServerSslOptions {
    private X509Certificate2 certificate;

    public X509Certificate2 GetCertificate() {
      return certificate;
    }
    public void SetCertificate(string filename) {
      certificate = new X509Certificate2(filename);
    }
  }

  public class WebsockServer : IDisposable {
    private bool isSsl = false;
    private bool running = false;
    private CancellationToken token;
    private readonly TcpListener server;
    private ServerSslOptions sslOptions;
    private List<Stream> clientStreams;

    private static readonly UInt32 BufferSize = 8192;

    private static readonly string WebsockGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    private static readonly string HttpHandshakeSucces =
      "HTTP/1.1 101 Switching Protocols\r\n" +
      "Upgrade: websocket\r\n" +
      "Connection: Upgrade\r\n" +
      "Sec-WebSocket-Accept: {WebsockKey}\r\n\r\n";

    private static readonly string HttpErrorTemplate =
      "HTTP/1.1 400 Bad Request\r\n" +
      "Server: Wophi\r\n" +
      "Content-Type: {ContentType}\r\n" +
      "Content-Length: {ContentLength}\r\n" +
      "\r\n{Content}";

    public WebsockServer(IPAddress address, int port) {
      clientStreams = new List<Stream>();
      server = new TcpListener(address, port);
      server.Server.SetSocketOption(
        SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, 1);
    }

    public void SetSslOptions(ServerSslOptions options) {
      isSsl = true;
      sslOptions = options;
    }

    private async Task<bool> RejectClient(TcpClient client, Stream stream, string errorMessage) {
      byte[] errorData = Encoding.UTF8.GetBytes(HttpErrorTemplate
        .Replace("{Content}", errorMessage)
        .Replace("{ContentType}", "text/plain")
        .Replace("{ContentLength}", errorMessage.Length.ToString()));
      await stream.WriteAsync(errorData, 0, errorData.Length);
      stream.Dispose();
      client.Dispose();
      return false;
    }

    private string GenerateKey(string clientKey) {
      byte[] hash = SHA1.Create().ComputeHash(
        Encoding.UTF8.GetBytes(clientKey + WebsockGUID));
      return System.Convert.ToBase64String(hash);
    }

    private async Task<bool> HandshakeClient(TcpClient client, Stream stream) {
      byte[] httpData = new byte[4096];
      await stream.ReadAsync(httpData, 0, httpData.Length);
      HttpPacket packet = new HttpPacket(httpData);

      if (!packet.Method.ToLower().StartsWith("get"))
        return await RejectClient(client, stream, "Only allows GET Requests");
      if (!packet.Headers.ContainsKey("Sec-WebSocket-Key"))
        return await RejectClient(client, stream, "No WebSocket-Key found");
      if (!packet.Headers.ContainsKey("Upgrade"))
        return await RejectClient(client, stream, "Upgrade header not set");
      else if (!packet.Headers["Upgrade"].ToLower().StartsWith("websocket"))
        return await RejectClient(client, stream, "Upgrade header not websocket");
      if (!packet.Headers.ContainsKey("Connection"))
        return await RejectClient(client, stream, "Connection header not set");
      else if (!packet.Headers["Connection"].ToLower().StartsWith("upgrade"))
        return await RejectClient(client, stream, "Connection header not upgrade");
      
      httpData = Encoding.UTF8.GetBytes(HttpHandshakeSucces.Replace(
        "{WebsockKey}", GenerateKey(packet.Headers["Sec-WebSocket-Key"])));
      await stream.WriteAsync(httpData, 0, httpData.Length);
      return true;
    }

    private async Task HandleFrame(TcpClient client, Stream stream, Frame frame) {

    }

    private async Task HandleClient(TcpClient client, Stream stream) {
      clientStreams.Add(stream);
      if (!(await HandshakeClient(client, stream))) return;

      Frame frame;
      int frameRead;
      byte[] frameData = null;
      using (MemoryStream builder = new MemoryStream()) {

        while (client.Connected) {
          frameData = new byte[BufferSize];
          frameRead = await stream.ReadAsync(frameData, 0, frameData.Length);
          Array.Resize(ref frameData, frameRead);
          if (builder.Length > 0) {
            builder.Write(frameData, 0, frameData.Length);
            frame = Framing.Parse(builder.ToArray());
          } else frame = Framing.Parse(frameData);
          if (frame.Complete) {
            builder.SetLength(0);
            await HandleFrame(client, stream, frame);
          } else {
            builder.Write(frameData, 0, frameData.Length);
          }
        }

      }
    }

    public void Start() {
      StartAsync().GetAwaiter().GetResult();
    }

    public async Task StartAsync(CancellationToken? _token = null) {
      token = CancellationTokenSource.CreateLinkedTokenSource(
        _token ?? new CancellationToken()).Token;
      server.Start();

      try {
        while (!token.IsCancellationRequested) {
          await Task.Run(async () => {
            TcpClient client = await server.AcceptTcpClientAsync();
            client.NoDelay = true;
            if (isSsl) {
              SslStream stream = new SslStream(client.GetStream());
              await stream.AuthenticateAsServerAsync(sslOptions.GetCertificate());
              await HandleClient(client, stream);
            } else {
              await HandleClient(client, client.GetStream());
            }
          }, token);
        }
      } finally {
        server.Stop();
        running = false;
      }
    }

    public void Stop() {

    }

    public void Dispose() {
      Stop();
    }
  }

}