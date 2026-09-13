using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace MultipleIDPAuth.Client
{
    internal sealed class StoredTokenSession
    {
        public int Version { get; set; } = 1;

        public string Generation { get; set; } =
            Guid.NewGuid().ToString("N");

        public string RefreshToken { get; set; }

        public string Subject { get; set; }

        public string DisplayName { get; set; }
    }

    internal sealed class DpapiTokenStore
    {
        private const int CurrentVersion = 1;

        private const long MaxSessionFileSize =
            1024 * 1024;

        private readonly string _directory;

        private readonly string _filePath;

        private readonly string _mutexName;

        public DpapiTokenStore(
            string environmentName,
            string authority,
            string clientId,
            string scopes,
            string resource)
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

            if (string.IsNullOrWhiteSpace(scopes))
            {
                throw new ArgumentException(
                    "Scopes are required.",
                    nameof(scopes));
            }

            var normalizedScopes =
                NormalizeScopes(scopes);

            var normalizedResource =
                string.IsNullOrWhiteSpace(resource)
                    ? string.Empty
                    : resource.Trim();

            /*
             * This identifies one logical authentication store.
             *
             * Same environment + same IdP configuration
             * => same storeKey
             *
             * Different environment/configuration
             * => different storeKey
             */
            var storeIdentity =
                environmentName.Trim() + "\n" +
                authority.Trim().TrimEnd('/') + "\n" +
                clientId.Trim() + "\n" +
                normalizedScopes + "\n" +
                normalizedResource;

            string storeKey;

            var identityBytes =
                Encoding.UTF8.GetBytes(storeIdentity);

            try
            {
                using (var sha256 = SHA256.Create())
                {
                    var hash =
                        sha256.ComputeHash(identityBytes);

                    storeKey =
                        BitConverter
                            .ToString(hash)
                            .Replace("-", "");
                }
            }
            finally
            {
                Array.Clear(
                    identityBytes,
                    0,
                    identityBytes.Length);
            }

            _directory =
                Path.Combine(
                    Environment.GetFolderPath(
                        Environment.SpecialFolder
                            .LocalApplicationData),
                    "MultipleIDPAuth",
                    "Auth",
                    storeKey);

            _filePath =
                Path.Combine(
                    _directory,
                    "session.dat");

            /*
             * This is a Windows named mutex.
             *
             * It is NOT attached to session.dat.
             *
             * Every process using the same name
             * participates in the same cross-process lock.
             */
            _mutexName =
                @"Local\MultipleIDPAuth-" +
                storeKey;
        }

        /// <summary>
        /// Executes an entire logical session transaction
        /// exclusively across WPF processes using the same
        /// token store.
        ///
        /// Everything inside operation() runs while this
        /// process owns the named mutex.
        /// </summary>
        public T ExecuteExclusive<T>(
            Func<T> operation)
        {
            if (operation == null)
            {
                throw new ArgumentNullException(
                    nameof(operation));
            }

            using (var mutex =
                   new Mutex(
                       initiallyOwned: false,
                       name: _mutexName))
            {
                var acquired = false;

                try
                {
                    /*
                     * This inner try/catch deals specifically
                     * with acquiring the mutex.
                     */
                    try
                    {
                        /*
                         * If another process currently owns
                         * this named mutex, this thread waits
                         * here.
                         *
                         * It does NOT continue to Load(),
                         * check expiry, refresh, etc.
                         */
                        mutex.WaitOne();

                        acquired = true;
                    }
                    catch (AbandonedMutexException)
                    {
                        /*
                         * Another thread/process died while
                         * owning this mutex.
                         *
                         * Important:
                         *
                         * When AbandonedMutexException is
                         * thrown from WaitOne(), this thread
                         * has actually acquired ownership of
                         * the mutex.
                         *
                         * Therefore acquired = true.
                         *
                         * The previous logical operation may
                         * not have completed, so persisted
                         * state could potentially represent
                         * an interrupted operation.
                         */
                        acquired = true;
                    }

                    /*
                     * operation() is still inside the OUTER
                     * try block.
                     *
                     * At this point we own the mutex.
                     *
                     * Everything executed by operation()
                     * remains protected until the finally
                     * block releases the mutex.
                     */
                    var result =
                        operation();

                    return result;
                }
                finally
                {
                    /*
                     * Runs whether:
                     *
                     * - operation succeeds
                     * - operation throws
                     * - Load throws
                     * - Save throws
                     * - refresh throws
                     *
                     * If we obtained ownership, always
                     * release it.
                     */
                    if (acquired)
                    {
                        mutex.ReleaseMutex();
                    }
                }
            }
        }

        /// <summary>
        /// Convenience overload for operations that return
        /// no value.
        /// </summary>
        public void ExecuteExclusive(
            Action operation)
        {
            if (operation == null)
            {
                throw new ArgumentNullException(
                    nameof(operation));
            }

            ExecuteExclusive(
                () =>
                {
                    operation();

                    return true;
                });
        }

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
                    "Unsupported token session version.");
            }

            if (string.IsNullOrWhiteSpace(
                    session.Generation))
            {
                throw new InvalidOperationException(
                    "Token session generation is required.");
            }

            Directory.CreateDirectory(
                _directory);

            var temporaryFilePath =
                Path.Combine(
                    _directory,
                    Guid.NewGuid()
                        .ToString("N") +
                    ".tmp");

            byte[] plainBytes = null;

            byte[] encryptedBytes = null;

            try
            {
                var json =
                    JsonSerializer.Serialize(
                        session);

                plainBytes =
                    Encoding.UTF8
                        .GetBytes(json);

                encryptedBytes =
                    ProtectedData.Protect(
                        plainBytes,
                        optionalEntropy: null,
                        scope:
                            DataProtectionScope
                                .CurrentUser);

                /*
                 * Write the complete encrypted payload to
                 * a separate temporary file first.
                 */
                using (var stream =
                       new FileStream(
                           temporaryFilePath,
                           FileMode.CreateNew,
                           FileAccess.Write,
                           FileShare.None,
                           bufferSize: 4096,
                           options:
                               FileOptions.WriteThrough))
                {
                    stream.Write(
                        encryptedBytes,
                        0,
                        encryptedBytes.Length);

                    /*
                     * Flush the data through the underlying
                     * file handle before replacing the
                     * existing session.dat.
                     */
                    stream.Flush(true);
                }

                /*
                 * Never rewrite session.dat in place.
                 *
                 * Replace the old complete file with the
                 * new complete file.
                 */
                if (File.Exists(_filePath))
                {
                    File.Replace(
                        temporaryFilePath,
                        _filePath,
                        destinationBackupFileName:
                            null);
                }
                else
                {
                    File.Move(
                        temporaryFilePath,
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
                 * If anything failed before the Move or
                 * Replace completed, clean up the
                 * temporary file.
                 */
                if (File.Exists(
                        temporaryFilePath))
                {
                    try
                    {
                        File.Delete(
                            temporaryFilePath);
                    }
                    catch
                    {
                        /*
                         * Do not replace the original Save
                         * exception with a cleanup error.
                         */
                    }
                }
            }
        }

        public StoredTokenSession Load()
        {
            if (!File.Exists(_filePath))
            {
                return null;
            }

            byte[] encryptedBytes = null;

            byte[] plainBytes = null;

            try
            {
                var fileInfo =
                    new FileInfo(
                        _filePath);

                /*
                 * The token session should be tiny.
                 *
                 * This protects us against unexpectedly
                 * large/corrupt files.
                 */
                if (fileInfo.Length <= 0 ||
                    fileInfo.Length >
                    MaxSessionFileSize)
                {
                    return null;
                }

                encryptedBytes =
                    File.ReadAllBytes(
                        _filePath);

                plainBytes =
                    ProtectedData.Unprotect(
                        encryptedBytes,
                        optionalEntropy: null,
                        scope:
                            DataProtectionScope
                                .CurrentUser);

                var json =
                    Encoding.UTF8
                        .GetString(
                            plainBytes);

                var session =
                    JsonSerializer
                        .Deserialize
                        <StoredTokenSession>(
                            json);

                if (session == null)
                {
                    return null;
                }

                if (session.Version !=
                    CurrentVersion)
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
                 * - data cannot be decrypted by this
                 *   Windows user
                 *
                 * - encrypted data is corrupt
                 */
                return null;
            }
            catch (JsonException)
            {
                return null;
            }
            catch (IOException)
            {
                return null;
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
            }
        }

        public void Clear()
        {
            if (File.Exists(_filePath))
            {
                File.Delete(
                    _filePath);
            }
        }

        private static string NormalizeScopes(
            string scopes)
        {
            return string.Join(
                " ",
                scopes
                    .Split(
                        new[] { ' ' },
                        StringSplitOptions
                            .RemoveEmptyEntries)
                    .Select(
                        scope =>
                            scope.Trim())
                    .Where(
                        scope =>
                            scope.Length > 0)
                    .Distinct(
                        StringComparer.Ordinal)
                    .OrderBy(
                        scope => scope,
                        StringComparer.Ordinal));
        }
    }
}