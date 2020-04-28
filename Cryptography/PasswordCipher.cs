using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace VaslD.Utility.Cryptography
{
    public sealed class PasswordCipher : IDisposable
    {
        public const int KeySize = 256;

        public string Password { get; }
        public string Salt { get; }

        public ICryptoTransform Encryptor { get; }
        public ICryptoTransform Decryptor { get; }

        [Obsolete("Using unsalted password is extremely insecure. Construct this object with a text password and at least 16 salt bytes instead.")]
        public PasswordCipher(string password) : this(password, new byte[16]) { }

        public PasswordCipher(string password, byte[] salt)
        {
            if (salt.Length < 16) throw new ArgumentException(nameof(salt));
            if (!salt.Any(x => x != 0)) Console.Error.WriteLine("[PasswordCipher] Calling cipher constructor with empty salt. This is extremely insecure!");

            Password = password;
            Salt = Convert.ToBase64String(salt);
            var cipher = InitCipher();
            cipher.Padding = PaddingMode.None;
            Encryptor = cipher.CreateEncryptor();
            Decryptor = cipher.CreateDecryptor();
        }

        // Made private to avoid unintentional use. The string parameter salt must be Base64 encoded bytes, not any arbitrary string (like password).
        private PasswordCipher(string password, string salt) : this(password, Convert.FromBase64String(salt)) { }

        private Aes InitCipher()
        {
            var salt = new byte[16];
            var bytes = Convert.FromBase64String(Salt);
            Buffer.BlockCopy(bytes, 0, salt, 0, 16);
            using var keyGen = new Rfc2898DeriveBytes(Password, salt);
            var standaloneCipher = Aes.Create();
            standaloneCipher.KeySize = KeySize;
            standaloneCipher.Key = keyGen.GetBytes(KeySize / 8);
            standaloneCipher.Mode = CipherMode.CBC;
            standaloneCipher.IV = salt;
            standaloneCipher.Padding = PaddingMode.PKCS7;
            return standaloneCipher;
        }

        public string EncryptContinuousText(string plainText)
        {
            var bytes = Encoding.UTF8.GetBytes(plainText);
            using var input = new MemoryStream(bytes);
            using var output = new MemoryStream(bytes.Length);
            var inBuffer = new byte[16];
            var bytesRead = 0;
            while ((bytesRead = input.Read(inBuffer)) > 0)
            {
                var bytesToAdd = 16 - bytesRead;
                if (bytesRead != 16)
                {
                    Buffer.BlockCopy(new byte[bytesToAdd], 0, inBuffer, bytesRead, bytesToAdd);
                    bytesRead = 16;
                }
                var outBuffer = new byte[16];
                var bytesWritten = Encryptor.TransformBlock(inBuffer, 0, bytesRead, outBuffer, 0);
                output.Write(outBuffer, 0, bytesWritten);
            }
            return Convert.ToBase64String(output.ToArray());
        }

        public string DecryptContinuousText(string text)
        {
            var bytes = Convert.FromBase64String(text);
            using var input = new MemoryStream(bytes);
            using var output = new MemoryStream(bytes.Length);
            var inBuffer = new byte[16];
            var bytesRead = 0;
            while ((bytesRead = input.Read(inBuffer)) > 0)
            {
                var outBuffer = new byte[16];
                var bytesWritten = Decryptor.TransformBlock(inBuffer, 0, bytesRead, outBuffer, 0);
                output.Write(outBuffer, 0, bytesWritten);
            }
            return Encoding.UTF8.GetString(output.ToArray()).Trim((char)0);
        }

        public string EncryptTextOnce(string plainText)
        {
            var input = Encoding.UTF8.GetBytes(plainText);
            using var output = new MemoryStream(input.Length);
            using var standaloneCipher = InitCipher();
            using var transformer = standaloneCipher.CreateEncryptor();
            using var crypto = new CryptoStream(output, transformer, CryptoStreamMode.Write);
            crypto.Write(input, 0, input.Length);
            crypto.Close();
            return Convert.ToBase64String(output.ToArray());
        }

        public string DecryptTextOnce(string text)
        {
            var bytes = Convert.FromBase64String(text);
            using var input = new MemoryStream(bytes);
            using var output = new MemoryStream(bytes.Length);
            using var standaloneCipher = InitCipher();
            using var transformer = standaloneCipher.CreateDecryptor();
            using var crypto = new CryptoStream(input, transformer, CryptoStreamMode.Read);
            var buffer = new byte[128 / 8];
            var bytesRead = 0;
            while ((bytesRead = crypto.Read(buffer)) > 0) output.Write(buffer, 0, bytesRead);
            return Encoding.UTF8.GetString(output.ToArray());
        }

        public void Dispose()
        {
            Encryptor.Dispose();
            Decryptor.Dispose();
        }
    }

}
