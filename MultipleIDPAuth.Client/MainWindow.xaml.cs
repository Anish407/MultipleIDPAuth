using Duende.IdentityModel.Client;
using Duende.IdentityModel.OidcClient;
using System;
using System.Configuration;
using System.Threading;
using System.Windows;

namespace MultipleIDPAuth.Client
{
    internal sealed class RefreshResult
    {
        public string AccessToken { get; set; }

        public DateTimeOffset AccessTokenExpiresAt { get; set; }

        public string RefreshToken { get; set; }
    }
    public partial class MainWindow : Window
    {
        private readonly OidcClient _oidcClient;

        private readonly DpapiTokenStore _tokenStore;

        // Access token stays only in this process.
        private string _accessToken;
        private string _refreshToken;

        private DateTimeOffset _accessTokenExpiresAt;

        public MainWindow()
        {
            InitializeComponent();

            _oidcClient =
                CreateOidcClient();

            /*
             * Create one token store for this application instance.
             *
             * Other WPF processes using the same values below
             * calculate the same:
             *
             * - token-store folder
             * - named mutex
             */
            _tokenStore =
                new DpapiTokenStore(
                    environmentName:
                        GetRequiredSetting(
                            "Environment.Name"),

                    authority:
                        GetRequiredSetting(
                            "Oidc.Authority"),

                    clientId:
                        GetRequiredSetting(
                            "Oidc.ClientId"),

                    scopes:
                        GetRequiredSetting(
                            "Oidc.Scope"),

                    resource:
                        ConfigurationManager
                            .AppSettings["Oidc.Resource"]);
        }

        private OidcClient CreateOidcClient()
        {
            var options =
                new OidcClientOptions
                {
                    Authority =
                        GetRequiredSetting(
                            "Oidc.Authority"),

                    ClientId =
                        GetRequiredSetting(
                            "Oidc.ClientId"),

                    RedirectUri =
                        GetRequiredSetting(
                            "Oidc.RedirectUri"),

                    Scope =
                        GetRequiredSetting(
                            "Oidc.Scope"),

                    Browser =
                        new SystemBrowser(),

                    LoadProfile = false
                };

            var additionalBaseAddresses =
                ConfigurationManager
                    .AppSettings[
                        "Oidc.AdditionalEndpointBaseAddresses"];

            if (!string.IsNullOrWhiteSpace(
                    additionalBaseAddresses))
            {
                foreach (
                    var address
                    in additionalBaseAddresses
                        .Split(';'))
                {
                    if (!string.IsNullOrWhiteSpace(
                            address))
                    {
                        options
                            .Policy
                            .Discovery
                            .AdditionalEndpointBaseAddresses
                            .Add(
                                address.Trim());
                    }
                }
            }

            return new OidcClient(
                options);
        }

        private static string GetRequiredSetting(
            string name)
        {
            var value =
                ConfigurationManager
                    .AppSettings[name];

            if (string.IsNullOrWhiteSpace(
                    value))
            {
                throw new ConfigurationErrorsException(
                    "Missing configuration: " +
                    name);
            }

            return value.Trim();
        }
        private async void LoginButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                LoginButton.IsEnabled = false;
                StatusText.Text = "Opening browser...";
                var resource =
            ConfigurationManager.AppSettings["Oidc.Resource"];
                var request = new LoginRequest
                {
                    FrontChannelExtraParameters = new Parameters()
                };
                request.FrontChannelExtraParameters.Add("prompt", "login");

                if (!string.IsNullOrWhiteSpace(resource))
                {
                    request.FrontChannelExtraParameters.Add(
                        "resource",
                        resource.Trim());
                }

                var result = await _oidcClient.LoginAsync(request);

                if (result.IsError)
                {
                    StatusText.Text =
                        "Login failed: " + result.Error;

                    return;
                }
                string idToken = result.IdentityToken;
                _accessToken = result.AccessToken;
                _refreshToken = result.RefreshToken;
                _accessTokenExpiresAt = result.AccessTokenExpiration;
                string subject = result.User?.FindFirst("sub")?.Value ?? "Unknown subject";

                var displayName =
                    result.User?.FindFirst("name")?.Value ??
                    result.User?.FindFirst("preferred_username")?.Value ??
                    subject;

                if (!string.IsNullOrWhiteSpace(_refreshToken))
                {
                    var storedSession = new StoredTokenSession
                    {
                        RefreshToken = _refreshToken,
                        Subject = subject,
                        DisplayName = displayName
                    };

                    _tokenStore.Save(storedSession);
                }

                StatusText.Text =
                    "Login successful" +
                    Environment.NewLine +
                    "User: " + displayName +
                    Environment.NewLine +
                    "Access token expires: " +
                    _accessTokenExpiresAt.ToLocalTime() +
                    Environment.NewLine +
                    "Refresh token received: " +
                    (!string.IsNullOrEmpty(_refreshToken) ? "Yes" : "No");
            }
            catch (Exception ex)
            {
                StatusText.Text =
                    "Unexpected error:" +
                    Environment.NewLine +
                    ex.Message;
            }
            finally
            {
                LoginButton.IsEnabled = true;
            }
        }

        private async void RefreshButton_Click(
    object sender,
            RoutedEventArgs e)
        {
            RefreshButton.IsEnabled = false;

            StatusText.Text =
                "Waiting for refresh lock...";

            try
            {
                var refreshed =
                    await System.Threading.Tasks.Task.Run(
                        () =>
                        {
                            return _tokenStore.ExecuteExclusive(
                                () =>
                                {
                                    /*
                                     * IMPORTANT:
                                     *
                                     * Load happens AFTER acquiring
                                     * the cross-process mutex.
                                     *
                                     * We therefore get the latest
                                     * refresh token written by any
                                     * other application instance.
                                     */
                                    var session =
                                        _tokenStore.Load();

                                    if (session == null)
                                    {
                                        throw new InvalidOperationException(
                                            "No stored login session exists.");
                                    }

                                    if (string.IsNullOrWhiteSpace(
                                            session.RefreshToken))
                                    {
                                        throw new InvalidOperationException(
                                            "No refresh token is stored.");
                                    }

                                    /*
                                     * DO NOT await while holding a
                                     * System.Threading.Mutex.
                                     *
                                     * We are already running on a
                                     * Task.Run worker thread, so
                                     * synchronously wait here.
                                     */
                                    var result =
                                        _oidcClient
                                            .RefreshTokenAsync(
                                                session.RefreshToken)
                                            .GetAwaiter()
                                            .GetResult();

                                    if (result.IsError)
                                    {
                                        throw new InvalidOperationException(
                                            "Token refresh failed: " +
                                            result.Error);
                                    }

                                    if (string.IsNullOrWhiteSpace(
                                            result.AccessToken))
                                    {
                                        throw new InvalidOperationException(
                                            "Identity provider returned no access token.");
                                    }

                                    /*
                                     * Some providers rotate refresh
                                     * tokens and return a new one.
                                     *
                                     * Others may not return a new
                                     * refresh token every time.
                                     *
                                     * Only replace our persisted
                                     * refresh token when a new one
                                     * was actually returned.
                                     */
                                    if (!string.IsNullOrWhiteSpace(
                                            result.RefreshToken))
                                    {
                                        session.RefreshToken =
                                            result.RefreshToken;
                                    }

                                    /*
                                     * Persist the potentially rotated
                                     * refresh token while we STILL
                                     * hold the same mutex.
                                     */
                                    _tokenStore.Save(session);

                                    return new RefreshResult
                                    {
                                        AccessToken =
                                            result.AccessToken,

                                        AccessTokenExpiresAt =
                                            result.AccessTokenExpiration,

                                        RefreshToken =
                                            session.RefreshToken
                                    };
                                });
                        });

                /*
                 * We are back on the WPF UI thread here.
                 *
                 * Access token stays only in process memory.
                 */
                _accessToken =
                    refreshed.AccessToken;

                _accessTokenExpiresAt =
                    refreshed.AccessTokenExpiresAt;

                StatusText.Text =
                    "Refresh successful" +
                    Environment.NewLine +
                    "Access token expires: " +
                    _accessTokenExpiresAt
                        .ToLocalTime() +
                    Environment.NewLine +
                    "Refresh token persisted: Yes";
            }
            catch (Exception ex)
            {
                StatusText.Text =
                    "Refresh failed:" +
                    Environment.NewLine +
                    ex.Message;
            }
            finally
            {
                RefreshButton.IsEnabled = true;
            }
        }
    }
}