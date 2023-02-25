namespace Singulink.Cryptography;

/// <summary>
/// Provides additional options that can be set for <see cref="PasswordHasher"/>.
/// </summary>
public sealed class PasswordHasherOptions
{
    #region Defaults

    /// <summary>
    /// The default salt size.
    /// </summary>
    public const int DefaultSaltSize = 16;

    /// <summary>
    /// The default normalization setting.
    /// </summary>
    public const bool DefaultNormalize = true;

    #endregion

    private int _saltSize = DefaultSaltSize;

    /// <summary>
    /// Gets or sets the size of the salt that should be generated in bytes. Default value is 16.
    /// </summary>
    public int SaltSize
    {
        get => _saltSize;
        set {
            if (value is < 8 or > 32)
                throw new ArgumentOutOfRangeException(nameof(value), "Salt size must be between 8 and 32 bytes.");

            _saltSize = value;
        }
    }

    /// <summary>
    /// Gets or sets a value indicating whether to perform RFC 8265 normalization of the password when generating UTF8 password bytes. Default is true.
    /// </summary>
    public bool Normalize { get; set; } = DefaultNormalize;

    /// <summary>
    /// Gets or sets the main hash encryption parameters.
    /// </summary>
    public HashEncryptionParameters? EncryptionParameters { get; set; }

    /// <summary>
    /// Gets a collection of all the legacy hash algorithms that the password hasher can read.
    /// </summary>
    public ICollection<PasswordHashAlgorithm> LegacyHashAlgorithms { get; } = new HashSet<PasswordHashAlgorithm>();

    /// <summary>
    /// Gets a collection of all the legacy hash encryption parameters that the password hasher can read.
    /// </summary>
    public ICollection<HashEncryptionParameters> LegacyEncryptionParameters { get; } = new HashSet<HashEncryptionParameters>();
}