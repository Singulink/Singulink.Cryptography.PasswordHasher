# Singulink.Cryptography.PasswordHasher

[![Join the chat](https://badges.gitter.im/Singulink/community.svg)](https://gitter.im/Singulink/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![View nuget packages](https://img.shields.io/nuget/v/Singulink.Cryptography.PasswordHasher.svg)](https://www.nuget.org/packages/Singulink.Cryptography.PasswordHasher/)
[![Build and Test](https://github.com/Singulink/Singulink.Cryptography.PasswordHasher/workflows/build%20and%20test/badge.svg)](https://github.com/Singulink/Singulink.Cryptography.PasswordHasher/actions?query=workflow%3A%22build+and+test%22)

**Singulink.Cryptography.PasswordHasher** greatly simplifies implementing security best practices with upgradable hash algorithm passwords. Hashes are upgradable in the sense that you can easily transition them to a different algorithm or increase the total number of iterations as periodically required in order to maintain the desired level of password security.

Support for SHA256, SHA384 and SHA512 using PBKDF2 for iteration is included out-of-the-box (as well as SHA1, but only for reading/upgrading legacy hashes). Other algorithms (i.e. bcrypt, scrypt, etc) can be easily plugged in by adding a custom implementation of the `PasswordHashAlgorithm` class, which only requires overriding a single `Hash` method which generates the hash.

### About Singulink

*Shameless plug*: We are a small team of engineers and designers dedicated to building beautiful, functional and well-engineered software solutions. We offer very competitive rates as well as fixed-price contracts and welcome inquiries to discuss any custom development / project support needs you may have.

This package is part of our **Singulink Libraries** collection. Visit https://github.com/Singulink to see our full list of publicly available libraries and other open-source projects.

## Installation

The package is available on NuGet - simply install the `Singulink.Cryptography.PasswordHasher` package.

**Supported Runtimes**: Anywhere .NET Standard 2.1+ is supported, including:
- .NET Core 3.0+
- Mono 6.4+
- Xamarin.iOS 12.16+
- Xamarin.Android 10.0+

## API

You can view the API on [FuGet](https://www.fuget.org/packages/Singulink.Cryptography.PasswordHasher). All the functionality is exposed via the `PasswordHasher` and `PasswordHashAlgorithm` classes in the `Singulink.Cryptography` namespace.

## Usage

To create a `PasswordHasher` you use the following constructor:

```c#
public PasswordHasher(PasswordHashAlgorithm algorithm, int iterations, params PasswordHashAlgorithm[] legacyAlgorithms)
```

The `algorithm` and `iterations` parameters specify what the main algorithm and total number of iterations should be. The `legacyAlgorithms` parameter specifies any additional algorithms that the hasher should be capable of hashing, i.e. any older hash algorithms that were upgraded to the main algorithm but which may still be present in the database until upgraded hash chains are rehashed.

The `PasswordHasher` class contains the following primary methods:

```c#
string Hash(string password);
bool Verify(string hash, string password);
bool RequiresRehash(string hash);
bool RequiresHashChainUpgrade(string hash);
string? UpgradeHashChain(string hash);
```

The first two methods should be self-explanatory: `Hash` produces a password hash, where-as `Verify` is used to verify a hash/password combo.

The last three methods are where it gets interesting:
- `RequiresRehash`: Returns true if a hash should be regenerated from the known password to eliminate algorithm chaining or to produce a hash that uses the main algorithm and required number of iterations.
- `RequiresHashChainUpgrade`: Returns true if the hash chain should be upgraded so that it utilizes the main algorithm and required number of iterations.
- `UpgradeHashChain`: Upgrades the specified hash to use the main algorithm and required number of iterations without knowing the password via algorithm chaining. The resulting hash will return true if passed into the `RequiresRehash` method, which should be tested on successful user login if hash chains were upgraded at some point so that a new hash without chaining replaces the chained hash. This method returns `null` if the hash does not require an upgrade. Hashes that already use the main algorithm with a lower number of iterations will chain the difference needed to reach the required total number of iterations.

The format of the hash string is as follows:

```
hash_algorithm:iterations:salt hash
```

If the hash chain was upgraded at some point (i.e. had additional algorithms or iterations applied to it), then those are added to the list. For example, if we started with SHA256 with 1000 iterations and upgraded to SHA512 with 20,000 iterations, the hash string might look something like this:

```
SHA256:1000:9QTkU8cSJ8xXkUdrx8qQVg== SHA512:20000:dlZfZk6CQstiyUAnZH5L7w== 07qYVKg1yx+AiRP+2oLxv3ozRmJ4tvb/IkgnsCO40LXT8Pm+bXXQnHoqKTQMy7e4IbMbTzOVH7cDqqBZ5RyygA==
```

Usage of the library is best demonstrated with an example:

```c#
using Singulink.Cryprography;

string password = "12345678";

// Create hasher that uses SHA256 with 10,000 PBKDF2 iterations

var hasher = new PasswordHasher(PasswordHashAlgorithm.SHA256, 10000);

// Create a password hash

string hash = hasher.Hash(password);

// Verify the password

bool success = hasher.Verify(hash, password); // true
```

Hashes can be upgraded by writing a script (i.e. a CSX script) or a small utility program that does something like the following:

```c#
// Upgrade hashes in the database to SHA512 with 20,000 iterations. The SHA256 algorithm must be 
// passed into the legacyAlgorithms parameter so the hasher can read the current SHA256 hashes.

var hasher = new PasswordHasher(PasswordHashAlgorithm.SHA512, 20000, PasswordHashAlgorithm.SHA256);

foreach (var user in database.GetUsers())
{
    if (hasher.RequiresHashChainUpgrade(user.PasswordHash))
        user.PasswordHash = hasher.UpgradeHashChain(user.PasswordHash);
}

database.SaveChanges();
```

After running the script above, hashes in the database would now be composed of a SHA256 10,000 iteration hash which is chained to a SHA512 20,000 iteration hash. You will then want to rehash chained hashes to eliminate the chaining upon successful authentication using login code similar to the following:

```c#
// The SHA256 algorithm must still be passed into the legacyAlgorithms parameter as the chained
// hashes contain a SHA256 component until they are rehashed.

var hasher = new PasswordHasher(PasswordHashAlgorithm.SHA512, 20000, PasswordHashAlgorithm.SHA256);

bool Login(string username, string password)
{
    var user = database.GetUser(username);

    if (user == null || !hasher.Verify(user.PasswordHash, password))
        return false;

    if (hasher.RequiresRehash(user.PasswordHash)) 
    {
        // Generate a "pure" SHA512 hash since it is currently chained with the old SHA256 hash       
        user.PasswordHash = hasher.Hash(password);
        database.SaveChanges();
    }
    
    return true;
}
```