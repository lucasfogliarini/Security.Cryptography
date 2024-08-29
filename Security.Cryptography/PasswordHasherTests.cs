namespace Security.Cryptography
{
    public class PasswordHasherTests
    {
        const string salt = "6foSo2hH0GlWqfPPJTffqGzXKZxHUMDE7wlbXfvyZMM=";

        [Theory]
        [InlineData("KeyDerivation.Pbkdf2.IsSecure", salt, "RDih/HNnV4qehWsXTioez7IdItmPAHP6DXEzXfoeBns=")]
        [InlineData("Md5.IsNotSecure", salt, "zUn+lXtZTOlfo+BmJnqNcsGotspVCljN6qQDsQR8F3M=")]
        public void HashPassword(string password, string salt, string expectedHashedPassword)
        {
            var hasher = new PasswordHasher();

            string hashedPassword = hasher.HashPassword(password, salt);

            Assert.Equal(expectedHashedPassword, hashedPassword);
        }
    }
}