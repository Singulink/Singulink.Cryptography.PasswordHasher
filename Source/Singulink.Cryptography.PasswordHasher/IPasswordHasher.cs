namespace Singulink.Cryptography;

/// <summary>
/// Represents an upgradable password hasher that can hash and verify passwords.
/// </summary>
public interface IPasswordHasher
{
    /// <summary>
    /// Hashes the specified password.
    /// </summary>
    /// <param name="password">The password to hash.</param>
    /// <returns>A string containing the normalization setting, master key ID, algorithm ID, number of iterations, salt value and password hash.</returns>
    /// <exception cref="ArgumentException">
    /// If normalization is enabled then password contained invalid Unicode characters or disallowed characters (i.e. control characters).
    /// </exception>
    string Hash(string password);

    /// <summary>
    /// Safely rehashes an existing password by falling back to previous normalization settings if normalization fails with current settings.
    /// </summary>
    /// <param name="password">The password to hash.</param>
    /// <returns>A string containing the normalization setting, master key ID, algorithm ID, number of iterations, salt value and password hash.</returns>
    string Rehash(string password);

    /// <summary>
    /// Returns a value indicating whether a hash should be regenerated from the known password. Returns <see langword="true"/> if the hash contains
    /// chained hashes, the main algorithm / number of iterations does not match, the main encryption parameters do not match, or normalization settings do
    /// not match.
    /// </summary>
    bool RequiresRehash(string hash, string password);

    /// <summary>
    /// Returns a value indicating whether the hash needs to be updated. Returns <see langword="true"/> if the hash chain needs to be updated so that it
    /// utilizes the main algorithm and total required number of iterations. Also returns true if the main encryption parameters do not match.
    /// </summary>
    bool RequiresUpdate(string hash);

    /// <summary>
    /// Returns an updated hash that uses the main encryption parameters and main hash algorithm with the total number of required iterations without knowing
    /// the password, or returns the input hash if it does not require an update.
    /// </summary>
    /// <remarks>
    /// <para>Changing hash algorithms or adding iterations without knowing the password is achieved by hash chaining. If the hash algorithm or number of
    /// iterations has changed then the resulting hash will return <see langword="true"/> when passed into the <see cref="RequiresRehash(string, string)"/> method, which
    /// should be tested on successful user login so that a new hash without chaining can be generated with the <see cref="Rehash(string)"/>
    /// method.</para>
    /// </remarks>
    string Update(string hash);

    /// <summary>
    /// Validates a password against a hash string.
    /// </summary>
    /// <param name="hash">The hash string representing the password.</param>
    /// <param name="password">The password to validate.</param>
    /// <returns>True if the password is correct, otherwise false.</returns>
    bool Verify(string hash, string password);
}