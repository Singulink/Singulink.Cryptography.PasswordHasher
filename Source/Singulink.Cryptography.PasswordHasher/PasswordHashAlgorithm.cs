using System;
using System.Linq;
using System.Security.Cryptography;

namespace Singulink.Cryptography
{
    /// <summary>
    /// Represents an iterative password hash algorithm such as PBKDF2-based algorithms or bcrypt/scrypt.
    /// </summary>
    public abstract class PasswordHashAlgorithm
    {
        /// <summary>
        /// The set of reserved characters that cannot be used in the algorithm ID.
        /// </summary>
        public const string ReservedIdCharacters = " ~!@#$%^";

        /// <summary>
        /// Gets the SHA256 password hash algorith that is iterated using PBKDF2. This is only included for upgrading legacy hashes - using it as the primary
        /// hash algorithm will throw an exception.
        /// </summary>
        [Obsolete("SHA1 is not considered safe - only use this for upgrading legacy hashes.", false)]
        public static PasswordHashAlgorithm SHA1 { get; } = new Pbkdf2PasswordHashAlgorithm("SHA1", HashAlgorithmName.SHA1, 20);

        /// <summary>
        /// Gets the SHA256 password hash algorith that is iterated using PBKDF2.
        /// </summary>
        public static PasswordHashAlgorithm SHA256 { get; } = new Pbkdf2PasswordHashAlgorithm("SHA256", HashAlgorithmName.SHA256, 32);

        /// <summary>
        /// Gets the SHA384 password hash algorith that is iterated using PBKDF2.
        /// </summary>
        public static PasswordHashAlgorithm SHA384 { get; } = new Pbkdf2PasswordHashAlgorithm("SHA384", HashAlgorithmName.SHA384, 48);

        /// <summary>
        /// Gets the SHA512 password hash algorith that is iterated using PBKDF2.
        /// </summary>
        public static PasswordHashAlgorithm SHA512 { get; } = new Pbkdf2PasswordHashAlgorithm("SHA512", HashAlgorithmName.SHA512, 64);

        /// <summary>
        /// Gets the hash algorithm ID that is included in the output hash string to identify the algorithm.
        /// </summary>
        /// <remarks>
        /// <para>The algorithm ID cannot contain spaces or any of the following reserved characters: <c>~!@#$%^</c>.</para>
        /// </remarks>
        public string Id { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="PasswordHashAlgorithm"/> class.
        /// </summary>
        /// <param name="algorithmId">Hash algorithm identifier that is included in the output hash string to identify the algorithm.</param>
        protected PasswordHashAlgorithm(string algorithmId)
        {
            if (algorithmId.Length == 0)
                throw new ArgumentException("Algorithm ID cannot be empty.", nameof(algorithmId));

            if (ReservedIdCharacters.Any(c => algorithmId.Contains(c, StringComparison.Ordinal)))
                throw new ArgumentException("Algorithm ID contains invalid characters.", nameof(algorithmId));

            Id = algorithmId;
        }

        /// <summary>
        /// Creates a hash of the specified password and salt using the specified number of iterations.
        /// </summary>
        /// <param name="password">The password to hash.</param>
        /// <param name="salt">The password salt.</param>
        /// <param name="iterations">The number of iterations the algorithm should use.</param>
        /// <returns>The resulting hash.</returns>
        public abstract byte[] Hash(byte[] password, byte[] salt, int iterations);

        internal class Pbkdf2PasswordHashAlgorithm : PasswordHashAlgorithm
        {
            public HashAlgorithmName AlgorithmName { get; }

            public int HashSize { get; }

            public Pbkdf2PasswordHashAlgorithm(string algorithmId, HashAlgorithmName algorithmName, int hashSize) : base(algorithmId)
            {
                AlgorithmName = algorithmName;
                HashSize = hashSize;
            }

            public override byte[] Hash(byte[] password, byte[] salt, int iterations)
            {
                // CA5379 false-positive: https://github.com/dotnet/roslyn-analyzers/issues/4110
                #pragma warning disable CA5379 // Do Not Use Weak Key Derivation Function Algorithm
                using var rfc2898 = new Rfc2898DeriveBytes(password, salt, iterations, AlgorithmName);
                #pragma warning restore CA5379 // Do Not Use Weak Key Derivation Function Algorithm

                return rfc2898.GetBytes(HashSize);
            }
        }
    }
}
