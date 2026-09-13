using Duende.IdentityModel.Client;
using Duende.IdentityModel.OidcClient;
using MultipleIDPAuth.Client.Properties;
using System;
using System.Configuration;
using System.Windows;
using System.Xml.Linq;

namespace MultipleIDPAuth.Client
{
    public partial class MainWindow : Window
    {
        private OidcClient _oidcClient;

        // For now tokens exist only while the application is running.
        private string _accessToken;
        private string _refreshToken;
        private DateTimeOffset _accessTokenExpiresAt;
        private DpapiTokenStore _tokenStore { get; set; }

        public MainWindow()
        {
            InitializeComponent();
            _tokenStore = new DpapiTokenStore();

            _oidcClient = CreateOidcClient();
        }

        private OidcClient CreateOidcClient()
        {
            var options = new OidcClientOptions
            {
                Authority = GetRequiredSetting("Oidc.Authority"),
                ClientId = GetRequiredSetting("Oidc.ClientId"),
                RedirectUri = GetRequiredSetting("Oidc.RedirectUri"),
                Scope = GetRequiredSetting("Oidc.Scope"),
                Browser = new SystemBrowser(),

                // We don't need to call the UserInfo endpoint.
                LoadProfile = false
            };

            var additionalBaseAddresses =
          ConfigurationManager.AppSettings[
              "Oidc.AdditionalEndpointBaseAddresses"];

          

            if (!string.IsNullOrWhiteSpace(additionalBaseAddresses))
            {
                foreach (var address in additionalBaseAddresses.Split(';'))
                {
                    if (!string.IsNullOrWhiteSpace(address))
                    {
                        options.Policy.Discovery
                            .AdditionalEndpointBaseAddresses
                            .Add(address.Trim());
                    }
                }
            }

            return new OidcClient(options);
        }

        private async void RefreshButton_Click(object sender, RoutedEventArgs e)
        {

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

        private static string GetRequiredSetting(string name)
        {
            var value = ConfigurationManager.AppSettings[name];

            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ConfigurationErrorsException(
                    "Missing configuration: " + name);
            }

            return value.Trim();
        }
    }
}