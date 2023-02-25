namespace Singulink.Cryptography;

/// <summary>
/// Represents a set of parameters used to encrypt password hashes.
/// </summary>
public class HashEncryptionParameters
{
    /// <summary>
    /// Gets the ID for these hash encryption parameters.
    /// </summary>
    public int Id { get; }

    /// <summary>
    /// Gets the encryption algorithm used to encrypt the password hash.
    /// </summary>
    public HashEncryptionAlgorithm Algorithm { get; }

    internal byte[] Key { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="HashEncryptionParameters"/> class using the given ID, key and algorithm.
    /// </summary>
    /// <param name="id">A unique ID identifying this set of encryption parameters.</param>
    /// <param name="algorithm">The algorithm used to encrypt the password hash.</param>
    /// <param name="key">The master key used to encrypt the password hash.</param>
    public HashEncryptionParameters(int id, HashEncryptionAlgorithm algorithm, byte[] key)
    {
        if (!algorithm.IsValidKeySize(key.Length))
            throw new ArgumentException("The key provided is not a valid length for the given algorithm.", nameof(key));

        Id = id;
        Key = key.ToArray();
        Algorithm = algorithm;
    }
}