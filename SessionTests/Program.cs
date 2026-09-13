using System;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Duende.IdentityModel.Client;
using Duende.IdentityModel.OidcClient;
using Duende.IdentityModel.OidcClient.Results;
using MultipleIDPAuth.Client;

internal static class Program
{
    private static readonly CancellationToken None = CancellationToken.None;
    private static void Check(bool value, string description)
    {
        if (!value) throw new Exception(description);
        Console.WriteLine("PASS: " + description);
    }

    public static int Main(string[] args)
    {
        try
        {
            var root = args[0]; // Explicit workspace-owned test directory, no production cache.
            var store = new DpapiTokenStore("https://example.test", "client", "openid api", root);
            if (args.Length > 1)
            {
                for (int i = 0; i < 20; i++) store.Transaction(() =>
                {
                    var s = store.Read();
                    s.DisplayName = (int.Parse(s.DisplayName) + 1).ToString();
                    store.Write(s);
                    return true;
                }, None);
                return 0;
            }
            var initial = store.Transaction(() => store.Read(), None);
            initial.AccessToken = "test-access-token-secret";
            initial.RefreshToken = "test-refresh-token-secret";
            initial.DisplayName = "0";
            store.Transaction(() => { store.Write(initial); return true; }, None);
            var path = Directory.GetFiles(root, "session.dat", SearchOption.AllDirectories).Single();
            Check(!Encoding.UTF8.GetString(File.ReadAllBytes(path)).Contains(initial.RefreshToken),
                "cache does not contain plaintext refresh token");
            Check(store.Transaction(() => store.Read().RefreshToken, None) == initial.RefreshToken,
                "DPAPI roundtrip");
            var second = new DpapiTokenStore("https://example.test", "client", "api openid", root);
            Check(second.Transaction(() => second.Read().Generation, None) == initial.Generation,
                "scope ordering does not create a separate cache");
            var other = new DpapiTokenStore("https://other.test", "client", "openid api", root);
            Check(other.Transaction(() => other.Read().AccessToken, None) == null,
                "provider configuration isolation");
            var children = Enumerable.Range(0, 3).Select(_ => System.Diagnostics.Process.Start(
                new System.Diagnostics.ProcessStartInfo(System.Reflection.Assembly.GetExecutingAssembly().Location,
                    "\"" + root + "\" increment") { UseShellExecute = false, CreateNoWindow = true })).ToArray();
            foreach (var child in children) { child.WaitForExit(); Check(child.ExitCode == 0, "worker completed"); }
            Check(store.Transaction(() => store.Read().DisplayName, None) == "60",
                "cross-process transactions do not lose updates");
            File.WriteAllText(path, "corrupt-cache");
            Check(store.Transaction(() => store.Read().AccessToken, None) == null,
                "corruption recovers to signed-out state");
            var client = new FakeClient();
            var service = new TokenSessionService(client, store);
            var generation = service.BeginLoginAsync(None).GetAwaiter().GetResult();
            service.SaveLoginAsync(Login(), generation, None).GetAwaiter().GetResult();
            var deadlineBeforeRefresh = service.GetInfoAsync(None).Result.SessionExpiresAt;
            store.Transaction(() => { var s = store.Read(); s.RefreshAt = DateTimeOffset.UtcNow.AddSeconds(-1); store.Write(s); return true; }, None);
            var requests = Enumerable.Range(0, 8).Select(_ => service.GetValidAccessTokenAsync(None)).ToArray();
            Task.WaitAll(requests);
            Check(client.RefreshCount == 1 && requests.All(r => r.Result == "replacement-access"),
                "concurrent requests share one refresh");
            Check(store.Transaction(() => store.Read().RefreshToken, None) == "replacement-refresh",
                "rotated refresh token persisted");
            Check(service.GetInfoAsync(None).Result.SessionExpiresAt == deadlineBeforeRefresh,
                "token refresh does not extend session duration");
            var pendingGeneration = service.BeginLoginAsync(None).GetAwaiter().GetResult();
            service.ClearAsync(None).GetAwaiter().GetResult();
            bool rejected = false;
            try { service.SaveLoginAsync(Login(), pendingGeneration, None).GetAwaiter().GetResult(); }
            catch (InvalidOperationException) { rejected = true; }
            Check(rejected && store.Transaction(() => store.Read().AccessToken, None) == null,
                "logout prevents stale interactive login save");
            Check(!Directory.GetFiles(root, "*.tmp", SearchOption.AllDirectories).Any(),
                "atomic writes leave no temporary files");
            // DataContract JSON timestamps have millisecond precision.
            var clock = DateTimeOffset.FromUnixTimeMilliseconds(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            var timed = new TokenSessionService(client, store, TimeSpan.FromHours(3), () => clock);
            timed.SaveLoginAsync(Login(), timed.BeginLoginAsync(None).Result, None).GetAwaiter().GetResult();
            var firstDeadline = timed.GetInfoAsync(None).Result.SessionExpiresAt;
            clock = clock.AddHours(2);
            var restarted = new TokenSessionService(client, store, TimeSpan.FromHours(3), () => clock);
            restarted.StartApplicationSessionAsync(None).GetAwaiter().GetResult();
            Check(restarted.GetInfoAsync(None).Result.SessionExpiresAt == clock.AddHours(3),
                "restart resets session duration with cached credentials");
            Check(timed.GetInfoAsync(None).Result.SessionExpiresAt == firstDeadline,
                "another process restart does not extend an existing process deadline");
            clock = clock.AddHours(3);
            rejected = false;
            var refreshesBeforeExpiry = client.RefreshCount;
            try { restarted.GetValidAccessTokenAsync(None).GetAwaiter().GetResult(); }
            catch (SignInRequiredException) { rejected = true; }
            Check(rejected && client.RefreshCount == refreshesBeforeExpiry,
                "absolute expiry blocks requests without refreshing");
            var emptyRestart = new TokenSessionService(client, store, TimeSpan.FromHours(3), () => clock);
            emptyRestart.StartApplicationSessionAsync(None).GetAwaiter().GetResult();
            Check(!emptyRestart.GetInfoAsync(None).Result.IsSignedIn,
                "restart after credentials were cleared requires login");
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine(ex); return 1; }
    }

    // Duende result setters are internal. Test-only reflection constructs fake
    // successful protocol responses without contacting an identity provider.
    private static void Set(object result, string property, object value)
    {
        result.GetType().GetProperty(property).SetValue(result, value);
    }

    private static LoginResult Login()
    {
        var result = new LoginResult();
        Set(result, "AccessToken", "initial-access");
        Set(result, "RefreshToken", "initial-refresh");
        Set(result, "AccessTokenExpiration", DateTimeOffset.UtcNow.AddMinutes(5));
        Set(result, "User", new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("sub", "test-user") })));
        return result;
    }

    private sealed class FakeClient : OidcClient
    {
        public int RefreshCount;
        public FakeClient() : base(new OidcClientOptions { Authority = "https://example.test", ClientId = "client", Scope = "openid api" }) { }
        public override Task<RefreshTokenResult> RefreshTokenAsync(string refreshToken,
            Parameters backChannelParameters = null, string scope = null,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            Interlocked.Increment(ref RefreshCount);
            var result = new RefreshTokenResult();
            Set(result, "AccessToken", "replacement-access");
            Set(result, "RefreshToken", "replacement-refresh");
            Set(result, "AccessTokenExpiration", DateTimeOffset.UtcNow.AddMinutes(5));
            return Task.FromResult(result);
        }
    }
}
