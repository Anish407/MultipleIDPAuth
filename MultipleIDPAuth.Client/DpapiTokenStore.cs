using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace MultipleIDPAuth.Client
{
    /// <summary>
    /// Data that is persisted between application runs.
    ///
    /// The access token is intentionally not stored here.
    /// It will only live in memory while an application instance is running.
    /// </summary>
    internal sealed class StoredTokenSession
    {
        // Version of the persisted file structure.
        //
        // If we change the structure later, we can increase this value
        // and decide how older stored sessions should be handled.
        public int Version { get; set; } = 1;

        // Identifies the shared authentication session.
        //
        // We are only storing this value for now.
        // Later we will use it to detect when another application instance
        // has replaced or ended the shared session.
        public string Generation { get; set; }
            = Guid.NewGuid().ToString("N");

        // Persisted so the application can obtain a new access token
        // after restart without requiring interactive login again.
        public string RefreshToken { get; set; }

        public string Subject { get; set; }

        public string DisplayName { get; set; }
    }

    /// <summary>
    /// Persists the authentication session using Windows DPAPI.
    ///
    /// The session is stored separately for each environment and
    /// OIDC configuration.
    /// </summary>
    internal sealed class DpapiTokenStore
    {
        private const int CurrentVersion = 1;

        // A normal token session should only be a few KB.
        // This prevents us from attempting to process a clearly invalid
        // or unexpectedly large file.
        private const int MaxSessionFileSizeBytes =
            1024 * 1024;

        private readonly string _directory;
        private readonly string _filePath;

        public DpapiTokenStore(
            string environmentName,
            string authority,
            string clientId,
            string scope,
            string resource = null)
        {
            if (string.IsNullOrWhiteSpace(environmentName))
            {
                throw new ArgumentException(
                    "Environment name is required.",
                    nameof(environmentName));
            }

            if (string.IsNullOrWhiteSpace(authority))
            {
                throw new ArgumentException(
                    "Authority is required.",
                    nameof(authority));
            }

            if (string.IsNullOrWhiteSpace(clientId))
            {
                throw new ArgumentException(
                    "Client ID is required.",
                    nameof(clientId));
            }

            if (string.IsNullOrWhiteSpace(scope))
            {
                throw new ArgumentException(
                    "Scope is required.",
                    nameof(scope));
            }

            /*
             * Scope order should not create a different storage folder.
             *
             * These should be treated as equivalent:
             *
             *   openid profile offline_access
             *   offline_access openid profile
             *
             * Sorting them gives us one consistent representation.
             */
            var normalizedScopes =
                string.Join(
                    " ",
                    scope
                        .Split(
                            new[] { ' ' },
                            StringSplitOptions.RemoveEmptyEntries)
                        .Distinct(StringComparer.Ordinal)
                        .OrderBy(
                            value => value,
                            StringComparer.Ordinal));

            /*
             * This string uniquely identifies the OIDC configuration
             * within the selected environment.
             */
            var configurationIdentity =
                authority.TrimEnd('/') +
                "\n" +
                clientId.Trim() +
                "\n" +
                normalizedScopes +
                "\n" +
                (resource ?? string.Empty).Trim();

            string configurationKey;

            /*
             * Hash the configuration instead of using authority/clientId
             * directly as folder names.
             *
             * This gives us a short, filesystem-safe identifier.
             */
            using (var sha256 = SHA256.Create())
            {
                var identityBytes =
                    Encoding.UTF8.GetBytes(
                        configurationIdentity);

                try
                {
                    configurationKey =
                        BitConverter
                            .ToString(
                                sha256.ComputeHash(
                                    identityBytes))
                            .Replace("-", string.Empty);
                }
                finally
                {
                    Array.Clear(
                        identityBytes,
                        0,
                        identityBytes.Length);
                }
            }

            /*
             * Example:
             *
             * %LOCALAPPDATA%
             *   MultipleIDPAuth
             *     dev
             *       Auth
             *         <configuration hash>
             *           session.dat
             */
            _directory =
                Path.Combine(
                    Environment.GetFolderPath(
                        Environment.SpecialFolder.LocalApplicationData),
                    "MultipleIDPAuth",
                    environmentName.Trim(),
                    "Auth",
                    configurationKey);

            _filePath =
                Path.Combine(
                    _directory,
                    "session.dat");
        }

        /// <summary>
        /// Encrypts and persists the current session.
        ///StoredTokenSession
                ///    ↓
                ///JSON
                ///    ↓
                ///UTF-8 bytes
                ///    ↓
                ///DPAPI encrypt
                ///    ↓
                ///session.dat
        /// The new session is written to a temporary file first and only
        /// replaces session.dat after the write succeeds.
        /// </summary>
        public void Save(
            StoredTokenSession session)
        {
            if (session == null)
            {
                throw new ArgumentNullException(
                    nameof(session));
            }

            if (session.Version != CurrentVersion)
            {
                throw new InvalidOperationException(
                    "Unsupported token-store version.");
            }

            if (string.IsNullOrWhiteSpace(
                session.Generation))
            {
                throw new InvalidOperationException(
                    "Session generation is required.");
            }

            Directory.CreateDirectory(
                _directory);

            /*
             * Never overwrite session.dat directly.
             *
             * If writing fails halfway through, the previous valid
             * session.dat remains untouched.
             */
            var temporaryPath =
                Path.Combine(
                    _directory,
                    Guid.NewGuid().ToString("N") +
                    ".tmp");

            byte[] plainBytes = null;
            byte[] encryptedBytes = null;

            try
            {
                var json =
                    JsonSerializer.Serialize(
                        session);

                plainBytes =
                    Encoding.UTF8.GetBytes(
                        json);

                /*
                 * CurrentUser means Windows DPAPI protects the data
                 * for the currently logged-in Windows user.
                 */
                encryptedBytes =
                    ProtectedData.Protect(
                        plainBytes,
                        null,
                        DataProtectionScope.CurrentUser);

                /*
                 * Write the complete new encrypted file first.
                 */
                using (var stream =
                    new FileStream(
                        temporaryPath,
                        FileMode.CreateNew,
                        FileAccess.Write,
                        FileShare.None,
                        4096,
                        FileOptions.WriteThrough))
                {
                    stream.Write(
                        encryptedBytes,
                        0,
                        encryptedBytes.Length);

                    // Flush buffered data before replacing session.dat.
                    stream.Flush(true);
                }

                /*
                 * Only now replace the official session file.
                 */
                if (File.Exists(_filePath))
                {
                    File.Replace(
                        temporaryPath,
                        _filePath,
                        null);
                }
                else
                {
                    File.Move(
                        temporaryPath,
                        _filePath);
                }
            }
            finally
            {
                if (plainBytes != null)
                {
                    Array.Clear(
                        plainBytes,
                        0,
                        plainBytes.Length);
                }

                if (encryptedBytes != null)
                {
                    Array.Clear(
                        encryptedBytes,
                        0,
                        encryptedBytes.Length);
                }

                /*
                 * If anything failed before File.Replace/File.Move,
                 * remove the unfinished temporary file.
                 */
                if (File.Exists(
                    temporaryPath))
                {
                    File.Delete(
                        temporaryPath);
                }
            }
        }

        /// <summary>
        /// Loads and decrypts the persisted authentication session.
        /// Load()
        ///  session.dat
        ///      ↓
        ///  encrypted bytes
        ///      ↓
        ///  DPAPI decrypt
        ///      ↓
        ///  UTF-8 JSON
        ///      ↓
        ///  StoredTokenSession
        /// Returns null when there is no usable stored session.
        /// </summary>
        /// <summary>
        /// Loads and decrypts the persisted authentication session.
        ///
        /// Returns null if no usable stored session exists.
        /// </summary>
        public StoredTokenSession Load()
        {
            if (!File.Exists(_filePath))
            {
                return null;
            }

            var fileInfo =
                new FileInfo(_filePath);

            /*
             * A normal session file should be very small.
             *
             * If the file is empty or unexpectedly huge, treat it as invalid
             * instead of trying to decrypt/process it.
             */
            if (fileInfo.Length <= 0 ||
                fileInfo.Length > MaxSessionFileSizeBytes)
            {
                return null;
            }

            byte[] encryptedBytes = null;
            byte[] plainBytes = null;

            try
            {
                /*
                 * Read the encrypted DPAPI payload from disk.
                 */
                encryptedBytes =
                    File.ReadAllBytes(
                        _filePath);

                /*
                 * Decrypt using the current Windows user's DPAPI context.
                 *
                 * This must match the DataProtectionScope.CurrentUser used
                 * when Save() encrypted the session.
                 */
                plainBytes =
                    ProtectedData.Unprotect(
                        encryptedBytes,
                        null,
                        DataProtectionScope.CurrentUser);

                /*
                 * Convert decrypted bytes back into the JSON that Save()
                 * originally serialized.
                 */
                var json =
                    Encoding.UTF8.GetString(
                        plainBytes);

                var session =
                    JsonSerializer
                        .Deserialize<StoredTokenSession>(
                            json);

                /*
                 * Validate the stored structure before returning it.
                 */
                if (session == null)
                {
                    return null;
                }

                if (session.Version != CurrentVersion)
                {
                    return null;
                }

                if (string.IsNullOrWhiteSpace(
                    session.Generation))
                {
                    return null;
                }

                return session;
            }
            catch (CryptographicException)
            {
                /*
                 * Examples:
                 *
                 * - file is corrupted
                 * - file was encrypted by another Windows user
                 * - DPAPI cannot decrypt it
                 */
                return null;
            }
            catch (JsonException)
            {
                /*
                 * DPAPI decryption worked, but the decrypted data is not
                 * a valid StoredTokenSession JSON document.
                 */
                return null;
            }
            finally
            {
                /*
                 * Remove byte-array copies of credential data as soon as
                 * we are finished with them.
                 */
                if (plainBytes != null)
                {
                    Array.Clear(
                        plainBytes,
                        0,
                        plainBytes.Length);
                }

                if (encryptedBytes != null)
                {
                    Array.Clear(
                        encryptedBytes,
                        0,
                        encryptedBytes.Length);
                }
            }
        }

        /// <summary>
        /// Removes the persisted session completely.
        ///
        /// For now this is intentionally simple.
        /// We will revisit multi-instance logout behavior later.
        /// </summary>
        public void Clear()
        {
            if (File.Exists(_filePath))
            {
                File.Delete(
                    _filePath);
            }
        }
    }
}