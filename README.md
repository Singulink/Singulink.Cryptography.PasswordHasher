# Singulink.Cryptography.PasswordHasher

[![Join the chat](https://badges.gitter.im/Singulink/community.svg)](https://gitter.im/Singulink/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![View nuget packages](https://img.shields.io/nuget/v/Singulink.Cryptography.PasswordHasher.svg)](https://www.nuget.org/packages/Singulink.Cryptography.PasswordHasher/)
[![Build and Test](https://github.com/Singulink/Singulink.Cryptography.PasswordHasher/workflows/build%20and%20test/badge.svg)](https://github.com/Singulink/Singulink.Cryptography.PasswordHasher/actions?query=workflow%3A%22build+and+test%22)

**PasswordHasher** greatly simplifies implementing security best practices with upgradable hash algorithm passwords. Hashes are upgradable in the sense that you can easily transition them to a different algorithm or increase the total number of iterations as periodically required in order to maintain the desired level of password security.

Support for PBKDF2 (SHA256/SHA384/SHA512) and Argon2 (Argon2i/Argon2d/Argon2id) is included out-of-the-box. PBKDF2 with SHA1 is also supported but only for reading/upgrading legacy hashes. Other algorithms (i.e. bcrypt, scrypt, etc) can be easily plugged in by adding a custom implementation of the `PasswordHashAlgorithm` class, which only requires overriding a single `Hash` method which generates the hash.

An additional layer of security can be added by encrypting hashes with a master key that is stored outside of the database so that hashes are not compromised if an attacker gains access to the database. AES128 encryption is included out-of-the-box, but other algorithms can be easily plugged in by adding a custom implementation of the `HashEncryptionAlgorithm` class which only requires overriding an `Encrypt`, `Decrypt` and `IsValidKeySize` method. Master keys can be updated or rotated with minimal effort and should be generated from a completely random source.

**PasswordHasher** implements RFC 8265 / RFC 7613 PRECIS Framework-compliant password normalization to ensure users don't have any Unicode encoding related issues with entering passwords. All spaces are replaced with standard ASCII spaces, invalid Unicode and control characters are blocked, and passwords are normalized to `Normalization Form C` as per the spec. Normalization can be turned off with a simple boolean property if you don't want normalization or you want to pre-process passwords with your own normalization scheme.

### About Singulink

*Shameless plug*: We are a small team of engineers and designers dedicated to building beautiful, functional and well-engineered software solutions. We offer very competitive rates as well as fixed-price contracts and welcome inquiries to discuss any custom development / project support needs you may have.

This package is part of our **Singulink Libraries** collection. Visit https://github.com/Singulink to see our full list of publicly available libraries and other open-source projects.

## Installation

The package is available on NuGet - simply install the `Singulink.Cryptography.PasswordHasher` package. If Argon2 support is needed then also install the `Singulink.Cryptography.PasswordHasher.Argon2` package.

**Supported Runtimes**: Anywhere .NET Standard 2.1+ is supported, including:
- .NET Core 3.0+
- Mono 6.4+
- Xamarin.iOS 12.16+
- Xamarin.Android 10.0+

## API

You can view the API on [FuGet](https://www.fuget.org/packages/Singulink.Cryptography.PasswordHasher). All the functionality is exposed via the `PasswordHasher` and `PasswordHashAlgorithm` classes in the `Singulink.Cryptography` namespace.

## Changes from Version 1.x to 2.x

Newer versions of **PasswordHasher** are backwards-compatible and thus can always read and verify hashes from previous versions and continue to work as expected. The `RequiresRehash()` method will return `true` if a rehash should be performed because settings have changed (i.e. normalization is now on by default) but old hashes will still continue to verify just fine.

New features added in version 2 include:
- Added Argon2 support via the `Singulink.Cryptography.PasswordHasher.Argon2` package
- Added hash encryption support
- Added password normalization support (enabled by default)

API changes:
- Legacy hash algorithms are no longer passed into the `PasswordHasher` constructor - use `PasswordHasherOptions` to add legacy algorithms and pass that into the constructor instead.
- `RequiresHashChainUpgrade()` has been renamed to `RequiresUpdate`.
- `UpgradeHashChain()` has been renamed to `Update`.
- `RequiresRehash()` requires an additional `password` parameter now.
- Rehashing existing passwords should be done with `Rehash()` instead of `Hash()`.
- Methods that accept passwords in `byte[]` format have been removed in order to properly facilitate normalization functionality.

## Usage

To create a `PasswordHasher` you use the following constructor:

```cs
public PasswordHasher(PasswordHashAlgorithm algorithm, int iterations, PasswordHasherOptions? options);
```

The `algorithm` and `iterations` parameters specify what the main algorithm and total number of iterations should be. The `options` parameter specifies any additional options, i.e. normalization, salt size, or any legacy algorithms and encryption parameters that the hasher must still be capable of reading.

`PasswordHasher` is thread-safe so instances can be safely shared between threads. It contains the following primary methods:

```cs
string Hash(string password);
bool Verify(string hash, string password);
bool RequiresRehash(string hash, string password);
string Rehash(string password);
bool RequiresUpdate(string hash);
string? Update(string hash);
```

The first two methods should be self-explanatory: `Hash` produces a password hash, where-as `Verify` is used to verify a hash/password combo.

The last four methods are where it gets interesting:
- `RequiresRehash`: Returns a value indicating whether a hash should be regenerated from the known password. Returns true if the hash contains chained hashes, the main algorithm / number of iterations does not match, the main encryption parameters do not match, or normalization settings do not match.
- `Rehash`: Safely rehashes an existing password by falling back to previous normalization settings if normalization fails with current settings.
- `RequiresUpdate`: Returns a value indicating whether the hash needs to be updated. Returns true if the hash chain needs to be updated so that it utilizes the main algorithm and total required number of iterations. Also returns true if the main encryption parameters do not match.
- `Update`: Gets an updated hash that uses the main encryption parameters and main hash algorithm with the total number of required iterations without knowing the password, or returns `null` if hash does not require an update.
  Changing hash algorithms or adding iterations without knowing the password is achieved by hash chaining. If the hash algorithm or number of iterations has changed then the resulting hash will return `true` when passed into the `RequiresRehash()` method, which should be tested on successful user login so that a new hash without chaining can be generated with the `Rehash()` method.

## Hash String Format

The format of the hash string is as follows:

```
!normalization_version #encryption_parameters_id hash_algorithm_id:iterations:salt hash
```

The first two parts are optional, so if normalization or encryption is not enabled then those elements are omitted.

**Example 1:**

```
!1 SHA256:1000:FV6nVAAqg1exolA+9fY2Nw== eqko5aiXBc+1BIBMKNi3VIhK9iPPW/dX85FcsVd1ITs=

Normalization: V1 algorithm (PRECIS RFC 8265)
Hash Encryption: None
Hash Algorithm: SHA256 (PBKDF2)
Iterations: 1000
Salt (Base64): FV6nVAAqg1exolA+9fY2Nw==
Hash (Base64): eqko5aiXBc+1BIBMKNi3VIhK9iPPW/dX85FcsVd1ITs= (Base64 encoded)
```

**Example 2:**

```
#123 Argon2idV19-128-4P-512MB:5:1KmmrJ5fTKXOUWqlYCD7zQ== Nw0DxzZnXhe531IhEoE3ziqRJLxQiqh7Ovcs6H8IZVNqiKHilbhYKAJnBYJIyVybtc8U93P1Kr8gvIK18HtkboQYdnpFShbnEVCnjRXiF076kMxf4FtX4+kA+wUHVuzR

Normalization: None
Hash Encryption: Using parameters with ID# 123
Hash Algorithm: Argon2id V19[1.3] (128bit hash, parallelism: 4, memory: 512MB)
Iterations: 5
Salt (Base64): 1KmmrJ5fTKXOUWqlYCD7zQ==
Hash (Base64): Nw0DxzZnXhe531IhEoE3ziqRJLxQiqh7Ovcs6H8IZVNqiKHilbhYKAJnBYJIyVybtc8U93P1Kr8gvIK18HtkboQYdnpFShbnEVCnjRXiF076kMxf4FtX4+kA+wUHVuzR
```

The hash in example 2 is the result of encrypting the hash algorithm output using the encyption parameters with ID `123`.

If the hash chain was updated at some point (i.e. had additional algorithms or iterations applied to it), then those are added to the list. Each chained algorithm has its own salt value and the output bytes from the previous algorithm is fed into the next one. For example, if we started with SHA256 with 1000 iterations and upgraded to SHA512 with 20,000 iterations, the hash string might look something like this:

```
SHA256:1000:9QTkU8cSJ8xXkUdrx8qQVg== SHA512:20000:dlZfZk6CQstiyUAnZH5L7w== 07qYVKg1yx+AiRP+2oLxv3ozRmJ4tvb/IkgnsCO40LXT8Pm+bXXQnHoqKTQMy7e4IbMbTzOVH7cDqqBZ5RyygA==
```

## Code Examples

Usage of the library is best demonstrated with some examples:

### Basic hashing and verification

```cs
using Singulink.Cryprography;

string password = "12345678";

// Create hasher that uses SHA256 with 10,000 PBKDF2 iterations

var hasher = new PasswordHasher(PasswordHashAlgorithm.SHA256, 10000);

// Create a password hash

string hash = hasher.Hash(password);

// Verify the password

bool success = hasher.Verify(hash, password); // true
```

### Turning normalization on or off or changing salt size

`PasswordHasherOptions` can be used to specify additional options:

```cs
var options = new PasswordHasherOptions { 
    Normalize = false,
    SaltSize = 20,
};

var hasher = new PasswordHasher(PasswordHashAlgorithm.SHA256, 10000, options);
```

### Updating hash algorithm or iterations

Hashes can be mass-updated with more iterations or new agorithms by writing a script (i.e. a CSX script) or a small utility program that does something like the following:

```cs
// Upgrade hashes in the database to SHA512 with 20,000 iterations. The SHA256 algorithm must be 
// passed into the legacyAlgorithms parameter so the hasher can read the current SHA256 hashes.

var options = new PasswordHasherOptions { 
    LegacyHashAlgorithms = { PasswordHashAlgorithm.SHA256 },
};

var hasher = new PasswordHasher(PasswordHashAlgorithm.SHA512, 20000, options);

foreach (var user in database.GetUsers())
{
    if (hasher.RequiresUpdate(user.PasswordHash))
        user.PasswordHash = hasher.Update(user.PasswordHash);
}

database.SaveChanges();
```

After running the script above, hashes in the database would now be composed of a SHA256 10,000 iteration hash which is chained to a SHA512 20,000 iteration hash. You will then want to rehash chained hashes to eliminate the chaining upon successful authentication using login code similar to the following:

```cs
// The SHA256 algorithm must still be passed into the legacyAlgorithms parameter as the chained
// hashes contain a SHA256 component until they are rehashed.

var options = new PasswordHasherOptions { 
    LegacyHashAlgorithms = { 
        PasswordHashAlgorithm.SHA256,
    },
};

var hasher = new PasswordHasher(PasswordHashAlgorithm.SHA512, 20000, options);

bool Login(string username, string password)
{
    var user = database.GetUser(username);

    if (user == null || !hasher.Verify(user.PasswordHash, password))
        return false;

    if (hasher.RequiresRehash(user.PasswordHash, password)) 
    {
        // Generate a "pure" SHA512 hash since it is currently chained with the old SHA256 hash       
        user.PasswordHash = hasher.Rehash(password);
        database.SaveChanges();
    }
    
    return true;
}
```

If you don't want to mass-update all the hashes up-front, you can simply skip that step and use the code above to rehash passwords incrementally when users successfully login, or a combination of both approaches (i.e. rehash on login for a period of time before mass-updating any leftover old hashes).

### Adding or updating hash encryption

Adding new hash encryption parameters is done in a similar manner as updating the hash algorithm / iterations:

```cs
// Set main encryption parameters to ID 10, AES128 algorithm and MasterKey1.
// GetMasterKey1() should get the key from somewhere other than the database
// (i.e. secure storage, config file, hard-coded, etc).

var options = new PasswordHasherOptions { 
    EncryptionParameters = new HashEncryptionParameters(10, HashEncryptionAlgorithm.AES128, GetMasterKey1()),
};

var hasher = new PasswordHasher(PasswordHashAlgorithm.SHA512, 20000, options);

// Update all hashes to use the encryption parameters:

foreach (var user in database.GetUsers())
{
    if (hasher.RequiresUpdate(user.PasswordHash))
        user.PasswordHash = hasher.Update(user.PasswordHash);
}

database.SaveChanges();
```

Updating the master key is done by adding another set of encryption parameters with a new ID and putting the old parameters into the `LegacyEncryptionParameters` collection so the hasher can still decrypt the old values:

```cs
var options = new PasswordHasherOptions { 
    EncryptionParameters = new HashEncryptionParameters(11, HashEncryptionAlgorithm.AES128, GetMasterKey2()),
    LegacyEncryptionParameters = {
        new HashEncryptionParameters(10, HashEncryptionAlgorithm.AES128, GetMasterKey1()),
    },
};

var hasher = new PasswordHasher(PasswordHashAlgorithm.SHA512, 20000, options);

// Update all hashes to use the new encryption parameters:

foreach (var user in database.GetUsers())
{
    if (hasher.RequiresUpdate(user.PasswordHash))
        user.PasswordHash = hasher.Update(user.PasswordHash);
}

database.SaveChanges();
```

### Argon2

After adding the `Singulink.Cryptography.PasswordHasher.Argon2` package, you can do the following:

```cs
// Create Argon2id v19/1.3 with parallelism: 4, memory: 512MB and 256-bit output.
var argon2Algorithm = new Argon2HashAlgorithm(Argon2Type.Argon2id, Argon2Version.V19, 4, 512, 256);

// Create a hasher that uses the above algorithm with 5 iterations
var hasher = new PasswordHasher(argon2Algorithm, 5);

string hash = hasher.Hash(password);
```

All the features of `PasswordHasher` work as you would expect with Argon2. It is noteworthy to add that all the Argon2 parameters must stay the same for incremental iteration chaining to be utilized when `Update()` is called. If any of the parameters change, it is considered a new algorithm and the full number of iterations will be chained to the previous hash. Since every set of parameters is considered a different algorithm, make sure you add the `Argon2HashAlgorithm` instance with the old parameters to `PasswordHasherOptions.LegacyHashAlgorithms` so the hasher knows how to read those hashes.

Argon2 support is provided via a dependency to the excellent [Isopoh.Cryptography.Argon2](https://github.com/mheyman/Isopoh.Cryptography.Argon2) package.