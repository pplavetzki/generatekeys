using System;
using System.Text;
using System.Security.Cryptography;
using System.IdentityModel;
using System.IdentityModel.Tokens;

using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.IdentityModel.Protocols.WSTrust;
using System.ServiceModel.Security.Tokens;
using System.Web;

namespace GenerateKeys
{
    class Program
    {
        static readonly string mainKey = CipherKey();

        static void Main(string[] args)
        {
            var exit = false;

            do
            {
                Console.WriteLine("1.  Create 256 bit Cipher Key.");
                Console.WriteLine("2.  Create 256 bit hmac key.");
                Console.WriteLine("3.  Create JWToken.");
                Console.WriteLine("4.  Exit.");
                Console.WriteLine();
                Console.Write("Selection: ");

                var selection = Console.ReadLine();

                switch (selection)
                {
                    case "1":
                        Console.WriteLine(CipherKey());
                        Console.WriteLine();
                        break;
                    case "2":
                        Console.WriteLine(HmacKey());
                        Console.WriteLine();
                        break;
                    case "3":
                        string token = JWToken();
                        Console.Write("This is the token: ");
                        Console.WriteLine(token);
                        if (VerifyToken(token))
                        {
                            Console.WriteLine("Is Valid: true");
                            Console.WriteLine(BearerToken());
                        }
                        Console.WriteLine();
                        break;
                    default:
                        exit = true;
                        break;
                }

                if (exit)
                {
                    break;
                }
            }
            while (true);
        }

        static string JWToken()
        {
            var domain = "http://localhost";
            var allowedAudience = "http://localhost:10100";
            var signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";
            var digestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";
            var issuer = "PareidoliaSW";
           
            var securityKey = Convert.FromBase64String(mainKey);
            var inMemKey = new InMemorySymmetricSecurityKey(securityKey);

            var now = DateTime.UtcNow;
            var expiry = now.AddHours(8);
            var tokenHandler = new JwtSecurityTokenHandler();
            var claimsList = new List<Claim>()
            {
                new Claim(ClaimTypes.Webpage, allowedAudience),
                new Claim(ClaimTypes.Uri, domain),
                new Claim(ClaimTypes.Expiration,expiry.Ticks.ToString()),
                new Claim("scope", "WebBridge")
            };
            //var roles = new List<string>() { "admin" };
            //claimsList.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

            //var identity = new GenericIdentity("user");

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claimsList),
                TokenIssuerName = issuer,
                AppliesToAddress = allowedAudience,
                Lifetime = new Lifetime(now, expiry),
                SigningCredentials = new SigningCredentials(inMemKey, signatureAlgorithm, digestAlgorithm),
            };

            var token = tokenHandler.WriteToken(tokenHandler.CreateToken(tokenDescriptor));

            return token;
        }

        static string GetPayload(string payload64)
        {
            while (payload64.Length % 4 > 0)
            {
                payload64 += "=";
            }

            var decoded = Convert.FromBase64String(payload64);

            return Encoding.UTF8.GetString(decoded, 0, decoded.Length);
        }

        static bool VerifyToken(string token)
        {
            var securityKey = Convert.FromBase64String(mainKey);
            var tokenHandler = new JwtSecurityTokenHandler();
            var jw = new JwtSecurityToken(token);

            var tokens = token.Split('.');
            var payload64 = tokens[1];

            Console.Write("payload: ");
            //do this so we can get the securityKey from the database or something  need the iss value
            Console.WriteLine(GetPayload(payload64));
            
            var validationParameters = new TokenValidationParameters()
            {
                ValidIssuer = "PareidoliaSW",
                ValidAudience = "http://localhost:10100",
                IssuerSigningToken = new BinarySecretSecurityToken(securityKey)
            };

            try
            {
                SecurityToken securityToken;
                tokenHandler.ValidateToken(token, validationParameters, out securityToken);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine("Error {0}", e.Message);
                return false;
            }
        }

        static string BearerToken()
        {
            var signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";
            var digestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";

            var securityKey = Convert.FromBase64String(mainKey);
            var inMemKey = new InMemorySymmetricSecurityKey(securityKey);

            ClaimsIdentity identity = new ClaimsIdentity();
            identity.AddClaim(new Claim("scope", "Full"));

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            SecurityToken securityToken = handler.CreateToken(new SecurityTokenDescriptor()
            {
                TokenType = "Bearer",
                Lifetime = new Lifetime(DateTime.UtcNow, DateTime.UtcNow.AddHours(1)),
                SigningCredentials = new SigningCredentials(inMemKey, signatureAlgorithm, digestAlgorithm),
                //This data I would get by matching the jwtSecurityToken.Audience to database or something
                TokenIssuerName = "PaulsSite",
                AppliesToAddress = "http://JoshsSite",
                Subject = identity
            }
            );

            return handler.WriteToken(securityToken);
        }

        static string CipherKey()
        {
            RandomNumberGenerator rng = RandomNumberGenerator.Create();

            byte[] key = new byte[32];
            rng.GetBytes(key);

            return Convert.ToBase64String(key);
        }

        static string HmacKey()
        {
            var hmac = new HMACSHA256();

            return Convert.ToBase64String(hmac.Key);
        }
    }
}
