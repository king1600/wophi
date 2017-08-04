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

  public class WebsockServerClient {
    private Stream stream;
    private TcpClient client;
    private Queue<PingCallback> pingQueue;
    private readonly WebsockServer server;

    // triggerable events
    public event CloseCallback OnClose;
    public event MessageCallback OnMessage;
    public delegate void MessageCallback(byte[] data);
    public delegate void CloseCallback(int code, string reason);

    // Stream Read buffer size
    private static readonly UInt32 BufferSize = 8192;

    // default ping function callback
    private delegate void PingCallback(byte[] data);

    // Default ping message
    private static readonly byte[] PingMessage = Encoding.UTF8.GetBytes("ping");

    public WebsockServerClient(WebsockServer server, ref Stream stream, ref TcpClient client) {
      this.server = server;
      this.stream = stream;
      this.client = client;
      pingQueue = new Queue<PingCallback>();
    }

    // send a websocket frame over the network
    private async Task SendFrame(OpCode opcode, byte[] data) {
      Frame frame = new Frame();
      frame.Fin = true;
      frame.Data = data;
      frame.Masked = false;
      frame.Opcode = opcode;
      byte[] output = Framing.Dump(ref frame);
      if (client.Connected)
        await stream.WriteAsync(output, 0, output.Length);
    }

    // perform synchronous ping
    public void Ping(byte[] message = null) {
      PingAsync(message).GetAwaiter().GetResult();
    }

    // perform asynchronous ping
    public async Task PingAsync(byte[] message = null) {
      TaskCompletionSource<byte[]> onReceived = new TaskCompletionSource<byte[]>();
      pingQueue.Enqueue(data => {
        onReceived.SetResult(data);
      });
      await SendFrame(OpCode.Ping, message ?? PingMessage);
      await onReceived.Task;
    }

    // handle a websocket frame. Returns false if frame is continue, true otherwise
    private async Task<bool> HandleFrame(Frame frame) {

      // the frame is fragmented
      if (frame.Opcode == OpCode.Continue) {
        return false;

      // return with pong
      } else if (frame.Opcode == OpCode.Ping) {
        await SendFrame(OpCode.Pong, frame.Data);

      // handle ping request by client
      } else if (frame.Opcode == OpCode.Pong) {
        if (pingQueue.Count > 0)
          pingQueue.Dequeue()(frame.Data);

      // client is requesting close, echo back and close connection
      } else if (frame.Opcode == OpCode.Close) {
        CloseFrame closeFrame = Framing.ParseClose(frame.Data);
        await SendFrame(OpCode.Close, frame.Data);
        OnClose(closeFrame.Code, closeFrame.Reason);

      // handle text and binary data
      } else {
        OnMessage(frame.Data);
      }

      // packet was successfull handling
      return true;
    }

    // start reading frames from the client
    public async Task StartAsync() {

      // prepare data for reading from client
      Frame frame;
      int frameRead;
      byte[] frameData = null;
      using (MemoryStream frameBuilder = new MemoryStream()) {
      using (MemoryStream dataBuilder = new MemoryStream()) {

        // read data from client
        try {
          while (client.Connected) {
            frameData = new byte[BufferSize];
            frameRead = await stream.ReadAsync(frameData, 0, frameData.Length);
            Array.Resize(ref frameData, frameRead);

            // parse byte data into websocket frame
            if (frameBuilder.Length > 0) {
              frameBuilder.Write(frameData, 0, frameData.Length);
              frame = Framing.Parse(frameBuilder.ToArray());
            } else frame = Framing.Parse(frameData);

            // prepend data from last frame if it was fragmented
            if (dataBuilder.Length > 0) {
              using (MemoryStream combined = new MemoryStream()) {
                combined.Write(dataBuilder.ToArray(), 0, (int)dataBuilder.Length);
                combined.Write(frame.Data, 0, frame.Data.Length);
                frame.Data = combined.ToArray();
                dataBuilder.SetLength(0);
              }
            }

            // if a complete frame was parsed, handle it
            if (frame.Complete) {
              frameBuilder.SetLength(0);
              if (!(await HandleFrame(frame)))
                dataBuilder.Write(frame.Data, 0, frame.Data.Length);
            } else {
              frameBuilder.Write(frameData, 0, frameData.Length);
            }
          }

        // remove client from server listing
        } catch (Exception) {
          if (server.GetClients().Contains(this))
            server.GetClients().Remove(this);
        }
      }
      }
    }
  }

  public class WebsockServer : IDisposable {
    private bool isSsl = false;
    private bool running = false;
    private readonly TcpListener server;
    private ServerSslOptions sslOptions;
    private List<WebsockServerClient> clients;
    private CancellationTokenSource tokenSource;

    // Special Websocket Server GUID for prepending client keys
    private static readonly string WebsockGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    // Server http handshake response template
    private static readonly string HttpHandshakeSucces =
      "HTTP/1.1 101 Switching Protocols\r\n" +
      "Upgrade: websocket\r\n" +
      "Connection: Upgrade\r\n" +
      "Sec-WebSocket-Accept: {WebsockKey}\r\n\r\n";

    // Server http error response template
    private static readonly string HttpErrorTemplate =
      "HTTP/1.1 400 Bad Request\r\n" +
      "Server: Wophi\r\n" +
      "Content-Type: {ContentType}\r\n" +
      "Content-Length: {ContentLength}\r\n" +
      "\r\n{Content}";

    // create server object an client container
    public WebsockServer(IPAddress address, int port) {
      server = new TcpListener(address, port);
      clients = new List<WebsockServerClient>();
      server.Server.SetSocketOption(
        SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, 1);
    }

    // set server options (before start)
    public void SetSslOptions(ServerSslOptions options) {
      isSsl = true;
      sslOptions = options;
    }

    // get list of clients connected to server
    public List<WebsockServerClient> GetClients() {
      return clients;
    }

    // Deny client with http error message
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

    // Create Sec-WebSocket-Accept key from Sec-Web
    private string GenerateKey(string clientKey) {
      byte[] hash = SHA1.Create().ComputeHash(
        Encoding.UTF8.GetBytes(clientKey + WebsockGUID));
      return System.Convert.ToBase64String(hash);
    }

    // Perform websocket handshake with client 
    private async Task<bool> HandshakeClient(TcpClient client, Stream stream) {

      // read and parse http request data
      byte[] httpData = new byte[4096];
      await stream.ReadAsync(httpData, 0, httpData.Length);
      HttpPacket packet = new HttpPacket(httpData);

      // client requests checks
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
      
      // generate websocket key, send response to client and complete handshake
      httpData = Encoding.UTF8.GetBytes(HttpHandshakeSucces.Replace(
        "{WebsockKey}", GenerateKey(packet.Headers["Sec-WebSocket-Key"])));
      await stream.WriteAsync(httpData, 0, httpData.Length);
      return true;
    }

    // handle a new client connection
    private async Task HandleClient(TcpClient client, Stream stream) {
      // first, handshake with the client
      if (!(await HandshakeClient(client, stream))) return;

      // then, create client and add to stream
      WebsockServerClient serverClient = new WebsockServerClient(this, ref stream, ref client);
      clients.Add(serverClient);
      await serverClient.StartAsync();
    }

    // start server and block (synchronously)
    public void Start() {
      StartAsync().GetAwaiter().GetResult();
    }

    // start server asynchronously
    public async Task StartAsync(CancellationToken? _token = null) {

      // create task cancellation token and start tcp server
      tokenSource = CancellationTokenSource.CreateLinkedTokenSource(
        _token ?? new CancellationToken());
      CancellationToken token = tokenSource.Token;
      server.Start();
      Console.WriteLine("Started");

      // start server accept event loop
      try {
        while (!token.IsCancellationRequested) {
          await Task.Run(async () => {

            // accept an incoming client
            TcpClient client = await server.AcceptTcpClientAsync();
            client.NoDelay = true;

            // get stream from client even if server is SSL
            if (isSsl) {
              SslStream stream = new SslStream(client.GetStream());
              await stream.AuthenticateAsServerAsync(sslOptions.GetCertificate());
              await HandleClient(client, stream);
            } else {
              await HandleClient(client, client.GetStream());
            }
          }, token);
        }

      // close resources on exit
      } finally {
        server.Stop();
        running = false;
      }
    }

    // stop running server if running
    public void Stop() {
      if (tokenSource != null)
        tokenSource.Cancel();
    }

    // disposable stop
    public void Dispose() {
      Stop();
    }
  }

}