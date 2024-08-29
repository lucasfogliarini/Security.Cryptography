using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography;
using System.Text;

namespace Security.Cryptography
{
    public class PasswordHasher(int iterationCount = 10000, int numBytesRequested = 256 / 8, KeyDerivationPrf prf = KeyDerivationPrf.HMACSHA1)
    {
        public string HashPassword(string password, string salt)
        {
            byte[] saltBytes = Convert.FromBase64String(salt);
            var pbkdf2Bytes = KeyDerivation.Pbkdf2(
                password: password,
                salt: saltBytes,
                prf: prf,
                iterationCount: iterationCount,
                numBytesRequested: numBytesRequested);

            return Convert.ToBase64String(pbkdf2Bytes);
        }

        public static byte[] GenerateSalt(int size = 32)
        {
            byte[] salt = new byte[size];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }
            return salt;
        }
    }
}
