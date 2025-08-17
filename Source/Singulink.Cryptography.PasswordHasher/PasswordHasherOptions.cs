using System.Diagnostics.CodeAnalysis;

namespace Singulink.Cryptography;

#pragma warning disable SA1513 // Closing brace should be followed by blank line

/// <summary>
/// Provides additional options that can be set for <see cref="PasswordHasher"/>.
/// </summary>
public sealed class PasswordHasherOptions
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordHasherOptions"/> class.
    /// </summary>
    public PasswordHasherOptions() { }

    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordHasherOptions"/> class with the specified algorithm and iteration count.
    /// </summary>
    /// <param name="algorithm">The main password hashing algorithm.</param>
    /// <param name="iterations">The number of hashing iterations to perform.</param>
    [SetsRequiredMembers]
    public PasswordHasherOptions(PasswordHashAlgorithm algorithm, int iterations)
    {
        Algorithm = algorithm;
        Iterations = iterations;
    }

    /// <summary>
    /// Gets or sets the main password hashing algorithm.
    /// </summary>
    public required PasswordHashAlgorithm Algorithm {
        get;
        set {
#pragma warning disable CS0618 // Type or member is obsolete

            if (value == PasswordHashAlgorithm.SHA1)
                throw new ArgumentException("SHA1 is not considered safe and is only supported as a legacy algorithm.", nameof(value));

#pragma warning restore CS0618

            field = value;
        }
    }

    /// <summary>
    /// Gets or sets the number of hashing iterations to perform. Must be at least 1.
    /// </summary>
    public required int Iterations
    {
        get;
        set {
            if (value <= 0)
                throw new ArgumentOutOfRangeException(nameof(value), "Iterations must be at least 1.");

            field = value;
        }
    }

    /// <summary>
    /// Gets or sets the size of the salt that should be generated in bytes. Default value is 16.
    /// </summary>
    public int SaltSize
    {
        get;
        set {
            if (value is < 8 or > 32)
                throw new ArgumentOutOfRangeException(nameof(value), "Salt size must be between 8 and 32 bytes.");

            field = value;
        }
    } = 16;

    /// <summary>
    /// Gets or sets a value indicating whether to perform RFC 8265 normalization of the password when generating UTF8 password bytes. Default is true.
    /// </summary>
    public bool Normalize { get; set; } = true;

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