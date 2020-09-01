using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Singulink.Cryptography
{
    /// <summary>
    /// Provides upgradable password hashing functionality.
    /// </summary>
    public sealed class PasswordHasher
    {
        private const int SaltSize = 16;
        private const char Separator = ' ';

        private readonly Dictionary<string, PasswordHashAlgorithm> _algorithmLookup = new Dictionary<string, PasswordHashAlgorithm>();

        /// <summary>
        /// Gets the main password hashing algorithm.
        /// </summary>
        public PasswordHashAlgorithm Algorithm { get; }

        /// <summary>
        /// Gets the number of iterations that should be performed using the main password algorithm.
        /// </summary>
        public int Iterations { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="PasswordHasher"/> class.
        /// </summary>
        /// <param name="algorithm">The password hashing algorithm.</param>
        /// <param name="iterations">The number of hashing iterations to perform.</param>
        /// <param name="legacyAlgorithms">The collection of legacy algorithms supported by this hasher.</param>
        public PasswordHasher(PasswordHashAlgorithm algorithm, int iterations, params PasswordHashAlgorithm[] legacyAlgorithms)
        {
#pragma warning disable CS0618 // Type or member is obsolete

            if (algorithm == PasswordHashAlgorithm.SHA1)
                throw new ArgumentException("SHA1 is not considered safe and is only supported as a legacy algorithm.");

#pragma warning restore CS0618 // Type or member is obsolete

            if (iterations <= 0)
                throw new ArgumentOutOfRangeException(nameof(iterations));

            if (legacyAlgorithms.Any(a => a == null))
                throw new ArgumentException("Items cannot be null.", nameof(legacyAlgorithms));

            Algorithm = algorithm;
            Iterations = iterations;

            _algorithmLookup.Add(algorithm.AlgorithmId, algorithm);

            foreach (var legacyAlgorithm in legacyAlgorithms) {
                if (_algorithmLookup.ContainsKey(legacyAlgorithm.AlgorithmId))
                    throw new ArgumentException("Algorithm IDs must be unique.");

                _algorithmLookup.Add(legacyAlgorithm.AlgorithmId, legacyAlgorithm);
            }
        }

        /// <summary>
        /// Creates a hash string from the specified password.
        /// </summary>
        /// <param name="password">The password to hash.</param>
        /// <returns>A string containing the algorith ID, number of iterations, salt value and password hash.</returns>
        public string Hash(string password) => Hash(GetPasswordBytes(password), Iterations);

        /// <inheritdoc cref="Hash(string)"/>
        public string Hash(byte[] password) => Hash(password, Iterations);

        /// <summary>
        /// Validates a password against a hash string.
        /// </summary>
        /// <param name="hash">The hash string representing the password.</param>
        /// <param name="password">The password to validate.</param>
        /// <returns>True if the password is correct, otherwise false.</returns>
        public bool Verify(string hash, string password) => Verify(GetPasswordBytes(password), hash);

        /// <inheritdoc cref="Verify(string, string)"/>
        public bool Verify(byte[] password, string hash)
        {
            if (password.Length == 0)
                throw new ArgumentException("Password cannot be empty.", nameof(password));

            string[] hashParts = GetHashParts(hash);

            for (int i = 0; i < hashParts.Length - 1; i++) {
                var info = HashAlgorithmInfo.Parse(hashParts[i], _algorithmLookup);
                password = info.Algorithm.Hash(password, info.Salt, info.Iterations);
            }

            byte[] hashBytes = Convert.FromBase64String(hashParts[^1]);

            return SlowEquals(password, hashBytes);
        }

        /// <summary>
        /// Returns a value indicating whether a hash should be regenerated from the known password to eliminate hash chaining or to produce a hash that uses
        /// the main algorithm and required number of iterations.
        /// </summary>
        public bool RequiresRehash(string hash)
        {
            string[] hashParts = GetHashParts(hash);

            if (hashParts.Length > 2)
                return true;

            var info = HashAlgorithmInfo.Parse(hashParts[0], _algorithmLookup);
            return info.Algorithm != Algorithm || info.Iterations != Iterations;
        }

        /// <summary>
        /// Returns a value indicating whether the hash chain should be upgraded so that it utilizes the main algorithm and required number of iterations.
        /// </summary>
        public bool RequiresHashChainUpgrade(string hash)
        {
            int actualIterations = GetIterations(hash);
            return actualIterations < Iterations;
        }

        /// <summary>
        /// Upgrades the specified hash to the main algorithm and number of iterations without knowing the password via algorithm chaining. The resulting hash
        /// will return true if passed into the <see cref="RequiresRehash(string)"/> method, which should be tested on successful user login if hash chains
        /// were upgraded at some point so that a new hash without chaining can replace the chained hash. This method returns null if the hash does not require
        /// an upgrade. Hashes that already use the main algorithm with a lower number of iterations will chain the difference needed to reach the required
        /// total iteration count.
        /// </summary>
        public string? UpgradeHashChain(string hash)
        {
            int requiredIterations = Iterations - GetIterations(hash);

            if (requiredIterations <= 0)
                return null;

            string[] hashParts = GetHashParts(hash);
            byte[] oldHash = Convert.FromBase64String(hashParts[^1]);

            string newHashString = Hash(oldHash, requiredIterations);

            return hash.Substring(0, hash.LastIndexOf(Separator) + 1) + newHashString;
        }

        private string Hash(byte[] password, int iterations)
        {
            if (password.Length == 0)
                throw new ArgumentException("Password cannot be empty.", nameof(password));

            byte[] salt = new byte[SaltSize];
            using var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(salt);

            byte[] hashBytes = Algorithm.Hash(password, salt, iterations);

            var hashInfo = new HashAlgorithmInfo(Algorithm, iterations, salt);

            var result = new StringBuilder(100);
            result.Append(hashInfo.ToString());
            result.Append(Separator);
            result.Append(Convert.ToBase64String(hashBytes));

            return result.ToString();
        }

        private int GetIterations(string hash)
        {
            string[] hashParts = GetHashParts(hash);
            int totalIterations = 0;

            for (int i = 0; i < hashParts.Length - 1; i++) {
                var info = HashAlgorithmInfo.Parse(hashParts[i], _algorithmLookup);

                if (info.Algorithm == Algorithm)
                    totalIterations += info.Iterations;
            }

            return totalIterations;
        }

        private static string[] GetHashParts(string hash)
        {
            string[] hashParts = hash.Split(Separator);

            if (hashParts.Length < 2)
                throw GetHashStringFormatException("Missing hash parts.");

            return hashParts;
        }

        private static byte[] GetPasswordBytes(string password)
        {
            if (password.Length == 0)
                throw new ArgumentException("Password cannot be empty.", nameof(password));

            return Encoding.UTF8.GetBytes(password);
        }

        /// <summary>
        /// Compares two byte arrays in length-constant time. This comparison
        /// method is used so that password hashes cannot be extracted from
        /// online systems using a timing attack and then attacked offline.
        /// </summary>
        private static bool SlowEquals(byte[] a, byte[] b)
        {
            uint diff = (uint)a.Length ^ (uint)b.Length;
            for (int i = 0; i < a.Length && i < b.Length; i++)
                diff |= (uint)(a[i] ^ b[i]);
            return diff == 0;
        }

        private static Exception GetHashStringFormatException(string message) => new FormatException("Hash string was in an invalid format: " + message);

        private struct HashAlgorithmInfo
        {
            private const char Separator = ':';

            public PasswordHashAlgorithm Algorithm { get; }

            public int Iterations { get; }

            public byte[] Salt { get; }

            public HashAlgorithmInfo(PasswordHashAlgorithm algorithm, int iterations, byte[] salt)
            {
                Algorithm = algorithm;
                Iterations = iterations;
                Salt = salt;
            }

            public static HashAlgorithmInfo Parse(string s, Dictionary<string, PasswordHashAlgorithm> algorithms)
            {
                string[] parts = s.Split(Separator);

                if (parts.Length != 3)
                    throw GetHashStringFormatException("Incorrect number of hash info parts.");

                string algorithmId = parts[0];
                string iterationString = parts[1];
                string saltBase64 = parts[2];

                if (!algorithms.TryGetValue(algorithmId, out PasswordHashAlgorithm algorithm))
                    throw GetHashStringFormatException($"Unknown hash algorithm ID '{algorithmId}'.");

                if (!int.TryParse(iterationString, NumberStyles.None, CultureInfo.InvariantCulture, out int iterations))
                    throw GetHashStringFormatException($"Could not parse iteration count '{iterationString}'");

                byte[] salt;

                try {
                    salt = Convert.FromBase64String(saltBase64);
                }
                catch (FormatException) {
                    throw GetHashStringFormatException($"Could not convert base64 salt '{saltBase64}'");
                }

                return new HashAlgorithmInfo(algorithm, iterations, salt);
            }

            public override string ToString() => string.Join(Separator.ToString(), Algorithm.AlgorithmId, Iterations, Convert.ToBase64String(Salt));
        }
    }
}
