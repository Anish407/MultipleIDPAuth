using Duende.IdentityModel.OidcClient.Browser;
using System;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MultipleIDPAuth.Client
{
    public sealed class SystemBrowser : IBrowser
    {
        public async Task<BrowserResult> InvokeAsync(
            BrowserOptions options,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            var callback = new Uri(options.EndUrl);

            if (callback.Scheme != Uri.UriSchemeHttp ||
                callback.Host != "localhost" ||
                !callback.AbsolutePath.EndsWith("/"))
            {
                throw new InvalidOperationException(
                    "Use an HTTP localhost callback ending with '/'.");
            }

            using (var listener = new HttpListener())
            using (var timeout =
                CancellationTokenSource.CreateLinkedTokenSource(
                    cancellationToken))
            {
                timeout.CancelAfter(TimeSpan.FromMinutes(5));

                listener.Prefixes.Add(callback.GetLeftPart(UriPartial.Path));
                listener.Start();

                using (timeout.Token.Register(() => listener.Close()))
                {
                    try
                    {
                        timeout.Token.ThrowIfCancellationRequested();

                        Process.Start(new ProcessStartInfo(options.StartUrl)
                        {
                            UseShellExecute = true
                        });

                        while (true)
                        {
                            var context = await listener.GetContextAsync();
                            var request = context.Request;

                            // Ignore unrelated requests under the listener prefix.
                            if (request.HttpMethod != "GET" ||
                                request.Url.AbsolutePath != callback.AbsolutePath ||
                                (request.QueryString["code"] == null &&
                                 request.QueryString["error"] == null))
                            {
                                context.Response.StatusCode = 404;
                                context.Response.Close();
                                continue;
                            }

                            var responseUrl = request.Url.AbsoluteUri;
                            var html = Encoding.UTF8.GetBytes(
                                "<!doctype html><html><body>" +
                                "Login response received. Return to the application." +
                                "</body></html>");

                            context.Response.ContentType = "text/html; charset=utf-8";
                            context.Response.Headers["Cache-Control"] = "no-store";
                            context.Response.Headers["Referrer-Policy"] = "no-referrer";
                            context.Response.ContentLength64 = html.Length;

                            try
                            {
                                await context.Response.OutputStream.WriteAsync(
                                    html, 0, html.Length);
                            }
                            finally
                            {
                                context.Response.Close();
                            }

                            return new BrowserResult
                            {
                                ResultType = BrowserResultType.Success,
                                Response = responseUrl
                            };
                        }
                    }
                    catch (Exception) when (timeout.IsCancellationRequested)
                    {
                        return new BrowserResult
                        {
                            ResultType = cancellationToken.IsCancellationRequested
                                ? BrowserResultType.UserCancel
                                : BrowserResultType.Timeout
                        };
                    }
                }
            }
        }
    }
}