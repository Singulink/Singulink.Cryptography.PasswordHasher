using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Singulink.Cryptography;

/// <summary>
/// Provides upgradable password hashing functionality. All operations are thread-safe.
/// </summary>
public sealed class PasswordHasher
{
    private const char Separator = ' ';

    private static readonly RNGCryptoServiceProvider CryptoRandom = new();

    private readonly Dictionary<string, PasswordHashAlgorithm> _algorithmLookup = new();
    private readonly Dictionary<int, HashEncryptionParameters> _encryptionLookup = new();

    /// <summary>
    /// Gets the main password hashing algorithm.
    /// </summary>
    public PasswordHashAlgorithm Algorithm { get; }

    /// <summary>
    /// Gets the number of iterations that should be performed using the main password algorithm.
    /// </summary>
    public int Iterations { get; }

    /// <summary>
    /// Gets the main hash encryption parameters.
    /// </summary>
    public HashEncryptionParameters? EncryptionParameters { get; }

    /// <summary>
    /// Gets the size of the salt that should be generated in bytes.
    /// </summary>
    public int SaltSize { get; }

    /// <summary>
    /// Gets a value indicating whether to perform RFC 8265 normalization of the password when generating UTF8 password bytes.
    /// </summary>
    public bool Normalize { get; }

    /// <summary>
    /// Gets all the hash algorithms that the password hasher can read.
    /// </summary>
    public IEnumerable<PasswordHashAlgorithm> AllHashAlgorithms => _algorithmLookup.Values;

    /// <summary>
    /// Gets all the hash encryption parameters that the password hasher can read.
    /// </summary>
    public IEnumerable<HashEncryptionParameters> AllEncryptionParameters => _encryptionLookup.Values;

    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordHasher"/> class.
    /// </summary>
    /// <param name="algorithm">The password hashing algorithm.</param>
    /// <param name="iterations">The number of hashing iterations to perform.</param>
    /// <param name="options">Any additional options that should be applied to the password hashesr.</param>
    public PasswordHasher(PasswordHashAlgorithm algorithm, int iterations, PasswordHasherOptions? options = null)
    {
#pragma warning disable CS0618 // Type or member is obsolete

        if (algorithm == PasswordHashAlgorithm.SHA1)
            throw new ArgumentException("SHA1 is not considered safe and is only supported as a legacy algorithm.", nameof(algorithm));

#pragma warning restore CS0618 // Type or member is obsolete

        if (iterations <= 0)
            throw new ArgumentOutOfRangeException(nameof(iterations));

        Algorithm = algorithm;
        _algorithmLookup.Add(algorithm.Id, algorithm);
        Iterations = iterations;

        if (options == null)
        {
            SaltSize = PasswordHasherOptions.DefaultSaltSize;
            Normalize = PasswordHasherOptions.DefaultNormalize;
        }
        else
        {
            SaltSize = options.SaltSize;
            Normalize = options.Normalize;

            if (options.EncryptionParameters is { } ep)
            {
                EncryptionParameters = ep;
                _encryptionLookup.Add(ep.Id, ep);
            }

            foreach (var a in options.LegacyHashAlgorithms)
            {
                if (!_algorithmLookup.TryAdd(a.Id, a))
                    throw new ArgumentException("Hash algorithms must all have unique IDs.", nameof(options));
            }

            foreach (var p in options.LegacyEncryptionParameters)
            {
                if (!_encryptionLookup.TryAdd(p.Id, p))
                    throw new ArgumentException("Encryption parameters must all have unique IDs.", nameof(options));
            }
        }
    }

    /// <summary>
    /// Hashes the specified password.
    /// </summary>
    /// <param name="password">The password to hash.</param>
    /// <returns>A string containing the normalization setting, master key ID, algorith ID, number of iterations, salt value and password hash.</returns>
    /// <exception cref="ArgumentException">
    /// If normalization is enabled then password contained invalid Unicode characters or disallowed characters (i.e. control characters).
    /// </exception>
    public string Hash(string password)
    {
        return GetPreamble(Normalize) + HashWithoutPreamble(GetPasswordBytes(password, Normalize), Iterations);
    }

    /// <summary>
    /// Validates a password against a hash string.
    /// </summary>
    /// <param name="hash">The hash string representing the password.</param>
    /// <param name="password">The password to validate.</param>
    /// <returns>True if the password is correct, otherwise false.</returns>
    public bool Verify(string hash, string password)
    {
        if (password.Length == 0)
            throw new ArgumentException("Password cannot be empty.", nameof(password));

        (bool normalized, var encryptionParameters, string[] hashParams, byte[] hashBytes) = GetHashParts(hash);

        if (encryptionParameters != null)
            hashBytes = encryptionParameters.Algorithm.Decrypt(encryptionParameters.Key, hashBytes);

        byte[] passwordHashBytes;

        try
        {
            passwordHashBytes = GetPasswordBytes(password, normalized);
        }
        catch (ArgumentException)
        {
            return false;
        }

        for (int i = 0; i < hashParams.Length; i++)
        {
            var info = HashAlgorithmInfo.Parse(hashParams[i], _algorithmLookup);
            passwordHashBytes = info.Algorithm.Hash(passwordHashBytes, info.Salt, info.Iterations);
        }

        return SlowEquals(passwordHashBytes, hashBytes);
    }

    /// <summary>
    /// Returns a value indicating whether a hash should be regenerated from the known password. Returns <see langword="true"/> if the hash contains
    /// chained hashes, the main algorithm / number of iterations does not match, the main encryption parameters do not match, or normalization settings do
    /// not match.
    /// </summary>
    public bool RequiresRehash(string hash, string password)
    {
        (bool normalized, var encryptionParameters, string[] hashParams, _) = GetHashParts(hash);

        if ((!normalized && Normalize && CanNormalize(password)) || (normalized && !Normalize))
            return true;

        if (encryptionParameters != EncryptionParameters || hashParams.Length > 1)
            return true;

        var info = HashAlgorithmInfo.Parse(hashParams[0], _algorithmLookup);
        return info.Algorithm != Algorithm || info.Iterations != Iterations;
    }

    /// <summary>
    /// Safely rehashes an existing password by falling back to previous normalization settings if normalization fails with current settings.
    /// </summary>
    /// <param name="password">The password to hash.</param>
    /// <returns>A string containing the normalization setting, master key ID, algorith ID, number of iterations, salt value and password hash.</returns>
    public string Rehash(string password)
    {
        byte[] passwordBytes;
        bool normalized;

        try
        {
            passwordBytes = GetPasswordBytes(password, Normalize);
            normalized = Normalize;
        }
        catch (ArgumentException) when (Normalize)
        {
            passwordBytes = GetPasswordBytes(password, false);
            normalized = false;
        }

        return GetPreamble(normalized) + HashWithoutPreamble(passwordBytes, Iterations);
    }

    /// <summary>
    /// Returns a value indicating whether the hash needs to be updated. Returns <see langword="true"/> if the hash chain needs to be updated so that it
    /// utilizes the main algorithm and total required number of iterations. Also returns true if the main encryption parameters do not match.
    /// </summary>
    public bool RequiresUpdate(string hash)
    {
        (_, var encryptionParameters, string[] hashParams, _) = GetHashParts(hash);

        if (encryptionParameters != EncryptionParameters)
            return true;

        int actualIterations = GetMainHashIterations(hashParams);
        return actualIterations < Iterations;
    }

    /// <summary>
    /// Gets an updated hash that uses the main encryption parameters and main hash algorithm with the total number of required iterations without knowing
    /// the password, or returns <see langword="null"/> if hash does not require an update.
    /// </summary>
    /// <remarks>
    /// <para>Changing hash algorithms or adding iterations without knowing the password is achieved by hash chaining. If the hash algorithm or number of
    /// iterations has changed then the resulting hash will return <see langword="true"/> when passed into the <see cref="RequiresRehash(string, string)"/> method, which
    /// should be tested on successful user login so that a new hash without chaining can be generated with the <see cref="Rehash(string)"/>
    /// method.</para>
    /// </remarks>
    public string? Update(string hash)
    {
        (bool normalized, var encryptionParameters, string[] hashParams, byte[] hashBytes) = GetHashParts(hash);

        int extraIterations = Iterations - GetMainHashIterations(hashParams);

        if (extraIterations <= 0 && encryptionParameters == EncryptionParameters)
            return null;

        if (encryptionParameters != null)
            hashBytes = encryptionParameters.Algorithm.Decrypt(encryptionParameters.Key, hashBytes);

        // The new hash will contain the new encryption parameters so just chain hashes if we need extra iterations, otherwise just encrypt the hash bytes
        // with the new key. Preamble needs to be regenerated in each case based on previous normalization settings as updating the hash does not change
        // the normalization.

        if (extraIterations > 0)
        {
            string newHashEnding = HashWithoutPreamble(hashBytes, extraIterations);
            return $"{GetPreamble(normalized)}{string.Join(' ', hashParams)} {newHashEnding}";
        }
        else
        {
            if (EncryptionParameters != null)
                hashBytes = EncryptionParameters.Algorithm.Encrypt(EncryptionParameters.Key, hashBytes);

            return $"{GetPreamble(normalized)}{string.Join(' ', hashParams)} {Convert.ToBase64String(hashBytes)}";
        }
    }

    private string HashWithoutPreamble(byte[] data, int iterations)
    {
        Debug.Assert(data.Length > 0, "data cannot be empty");

        byte[] salt = new byte[SaltSize];
        CryptoRandom.GetBytes(salt);

        byte[] hashBytes = Algorithm.Hash(data, salt, iterations);

        if (EncryptionParameters != null)
            hashBytes = EncryptionParameters.Algorithm.Encrypt(EncryptionParameters.Key, hashBytes);

        var hashInfo = new HashAlgorithmInfo(Algorithm, iterations, salt);

        var result = new StringBuilder(100);
        result.Append(hashInfo.ToString());
        result.Append(Separator);
        result.Append(Convert.ToBase64String(hashBytes));

        return result.ToString();
    }

    private string GetPreamble(bool normalized)
    {
        string preamble = string.Empty;

        if (normalized)
            preamble = "!1 ";

        if (EncryptionParameters != null)
            preamble += $"#{EncryptionParameters.Id} ";

        return preamble;
    }

    private int GetMainHashIterations(string[] hashParams)
    {
        int totalIterations = 0;

        for (int i = 0; i < hashParams.Length; i++)
        {
            var info = HashAlgorithmInfo.Parse(hashParams[i], _algorithmLookup);

            if (info.Algorithm == Algorithm)
                totalIterations += info.Iterations;
        }

        return totalIterations;
    }

    private (bool Normalized, HashEncryptionParameters? EncryptionParameters, string[] HashParams, byte[] HashBytes) GetHashParts(string hash)
    {
        string[] hashParts = hash.Split(Separator, StringSplitOptions.RemoveEmptyEntries);

        if (hashParts.Length < 2)
            throw GetHashStringFormatException("Missing hash parts.");

        int skipParts = 0;
        bool normalized = false;

        if (hashParts[0].StartsWith('!'))
        {
            string normalizationVersion = hashParts[0][1..];

            if (normalizationVersion != "1")
                throw GetHashStringFormatException($"Unknown normalization version '{normalizationVersion}'.");

            normalized = true;
            skipParts++;
        }

        HashEncryptionParameters? encryptionParameters = null;

        if (hashParts[skipParts].StartsWith('#'))
        {
            string encryptionIdString = hashParts[skipParts][1..];

            if (!int.TryParse(encryptionIdString, out int eid))
                throw GetHashStringFormatException($"Invalid encryption ID '{encryptionIdString}'.");

            if (!_encryptionLookup.TryGetValue(eid, out var ep))
                throw GetHashStringFormatException($"Unknown encryption ID '{encryptionIdString}'.");

            encryptionParameters = ep;
            skipParts++;
        }

        if (hashParts.Length < 2 + skipParts)
            throw GetHashStringFormatException("Missing hash parts.");

        string[] hashParams = hashParts[skipParts..^1];
        byte[] hashBytes = Convert.FromBase64String(hashParts[^1]);

        if (hashBytes.Length == 0)
            throw GetHashStringFormatException("Hashing result cannot be empty.");

        return (normalized, encryptionParameters, hashParams, hashBytes);
    }

    private static bool CanNormalize(string password)
    {
        try
        {
            PasswordNormalizer.Normalize(password);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static byte[] GetPasswordBytes(string password, bool normalize)
    {
        if (password.Length == 0)
            throw new ArgumentException("Password cannot be empty.", nameof(password));

        if (normalize)
            password = PasswordNormalizer.Normalize(password);

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

            try
            {
                salt = Convert.FromBase64String(saltBase64);
            }
            catch (FormatException)
            {
                throw GetHashStringFormatException($"Could not convert base64 salt '{saltBase64}'");
            }

            return new HashAlgorithmInfo(algorithm, iterations, salt);
        }

        public override string ToString() => string.Join(Separator.ToString(), Algorithm.Id, Iterations, Convert.ToBase64String(Salt));
    }
}