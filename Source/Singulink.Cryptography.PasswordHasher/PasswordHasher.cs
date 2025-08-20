using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace Singulink.Cryptography;

/// <summary>
/// Provides upgradable password hashing functionality. All operations are thread-safe.
/// </summary>
public sealed class PasswordHasher : IPasswordHasher
{
    private const char Separator = ' ';

    private readonly Dictionary<string, PasswordHashAlgorithm> _algorithmLookup = [];
    private readonly Dictionary<int, HashEncryptionParameters> _encryptionLookup = [];

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
    /// <param name="options">Any additional options that should be applied to the password hasher.</param>
    public PasswordHasher(PasswordHasherOptions options)
    {
        if (options.Algorithm is null || options.Iterations <= 0)
            throw new ArgumentException("Algorithm and iterations must be set in the options.", nameof(options));

        Algorithm = options.Algorithm;
        Iterations = options.Iterations;

        SaltSize = options.SaltSize;
        Normalize = options.Normalize;

        _algorithmLookup.Add(Algorithm.Id, Algorithm);

        foreach (var a in options.LegacyHashAlgorithms)
        {
            if (!_algorithmLookup.TryAdd(a.Id, a))
                throw new ArgumentException("Hash algorithms must all have unique IDs.", nameof(options));
        }

        if (options.EncryptionParameters is { } ep)
        {
            EncryptionParameters = ep;
            _encryptionLookup.Add(ep.Id, ep);
        }

        foreach (var p in options.LegacyEncryptionParameters)
        {
            if (!_encryptionLookup.TryAdd(p.Id, p))
                throw new ArgumentException("Encryption parameters must all have unique IDs.", nameof(options));
        }
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordHasher"/> class with the specified options.
    /// </summary>
    public PasswordHasher(IOptions<PasswordHasherOptions> options) : this(options.Value) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordHasher"/> class with the specified algorithm and iteration count and optional builder function that
    /// configure additional options.
    /// </summary>
    /// <param name="algorithm">The main password hashing algorithm.</param>
    /// <param name="iterations">The number of hashing iterations to perform.</param>
    /// <param name="configure">An optional action that configures additional options.</param>
    public PasswordHasher(PasswordHashAlgorithm algorithm, int iterations, Action<PasswordHasherOptions>? configure = null)
        : this(BuildOptions(algorithm, iterations, configure)) { }

    private static PasswordHasherOptions BuildOptions(PasswordHashAlgorithm algorithm, int iterations, Action<PasswordHasherOptions>? configure)
    {
        var options = new PasswordHasherOptions(algorithm, iterations);
        configure?.Invoke(options);
        return options;
    }

    /// <inheritdoc cref="IPasswordHasher.Hash(string)"/>
    public string Hash(string password)
    {
        return GetPreamble(Normalize) + HashWithoutPreamble(GetPasswordBytes(password, Normalize), Iterations);
    }

    /// <inheritdoc cref="IPasswordHasher.Rehash(string)"/>
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

    /// <inheritdoc cref="IPasswordHasher.RequiresRehash(string, string)"/>
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

    /// <inheritdoc cref="IPasswordHasher.RequiresUpdate(string)"/>
    public bool RequiresUpdate(string hash)
    {
        (_, var encryptionParameters, string[] hashParams, _) = GetHashParts(hash);

        if (encryptionParameters != EncryptionParameters)
            return true;

        int actualIterations = GetMainHashIterations(hashParams);
        return actualIterations < Iterations;
    }

    /// <inheritdoc cref="IPasswordHasher.Update(string)"/>
    public string Update(string hash)
    {
        (bool normalized, var encryptionParameters, string[] hashParams, byte[] hashBytes) = GetHashParts(hash);

        int extraIterations = Iterations - GetMainHashIterations(hashParams);

        if (extraIterations <= 0 && encryptionParameters == EncryptionParameters)
            return hash;

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

    /// <inheritdoc cref="IPasswordHasher.Verify(string, string)"/>
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

    private string HashWithoutPreamble(byte[] data, int iterations)
    {
        Debug.Assert(data.Length > 0, "data cannot be empty");

        byte[] salt = new byte[SaltSize];
        RandomNumberGenerator.Fill(salt);

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

    private static FormatException GetHashStringFormatException(string message) => new("Hash string was in an invalid format: " + message);

    private readonly struct HashAlgorithmInfo(PasswordHashAlgorithm algorithm, int iterations, byte[] salt)
    {
        private const char Separator = ':';

        public PasswordHashAlgorithm Algorithm => algorithm;

        public int Iterations => iterations;

        public byte[] Salt => salt;

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