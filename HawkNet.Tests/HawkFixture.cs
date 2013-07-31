using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Threading.Tasks;
using System.Security.Claims;

namespace HawkNet.Tests
{
    [TestClass]
    public class HawkFixture
    {
        const string ValidAuthorization = "id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"lDdDLlWQhgcxTvYgzzLo3EZExog=\", ext=\"hello\"";

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public Task ShouldFailAuthenticationOnNullAuthorization()
        {
            return Hawk.Authenticate(null, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), GetCredential);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public Task ShouldFailAuthenticationOnEmptyAuthorization()
        {
            return Hawk.Authenticate("", "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), GetCredential);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public Task ShouldFailAuthenticationOnNullHost()
        {
            return Hawk.Authenticate(ValidAuthorization, null, "get", new Uri("http://example.com:8080/resource/4?filter=a"), GetCredential);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public Task ShouldFailAuthenticationOnEmptyHost()
        {
            return Hawk.Authenticate(ValidAuthorization, "", "get", new Uri("http://example.com:8080/resource/4?filter=a"), GetCredential);
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException), "Missing credentials")]
        public Task ShouldFailAuthenticationOnNullCredential()
        {
            return Hawk.Authenticate(ValidAuthorization, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), (s) => null);
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException), "Missing attributes")]
        public Task ShouldFailAuthenticationOnMissingAuthAttribute()
        {
            return Hawk.Authenticate("ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\"",
                "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), GetCredential);
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException), "Missing attributes")]
        public Task ShouldFailAuthenticationOnUnknownAuthAttribute()
        {
            return Hawk.Authenticate("id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", x=\"3\", mac=\"/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=\", ext=\"hello\"",
                "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), GetCredential);
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException), "Invalid credentials")]
        public Task ShouldFailAuthenticationOnMissingCredentialAlgorithm()
        {
            var credential = new HawkCredential
            {
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                User = "steve"
            };

            return Hawk.Authenticate(ValidAuthorization, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), (s) => Task.FromResult(credential));
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException), "Invalid credentials")]
        public Task ShouldFailAuthenticationOnMissingCredentialKey()
        {
            var credential = new HawkCredential
            {
                Algorithm = "hmacsha1",
                User = "steve"
            };

            return Hawk.Authenticate(ValidAuthorization, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), (s) => Task.FromResult(credential));
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException), "Unknown algorithm")]
        public Task ShouldFailAuthenticationOnUnknownCredentialAlgorithm()
        {
            var credential = new HawkCredential
            {
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                Algorithm = "foo",
                User = "steve"
            };

            return Hawk.Authenticate(ValidAuthorization, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), (s) => Task.FromResult(credential));
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException), "Bad mac")]
        public Task ShouldFailAuthenticationOnInvalidMac()
        {
            var authorization = "id=\"123\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"lDdDLlWQhgcxTvYgzzLo3EZExogXXXX=\", ext=\"hello\"";
            return Hawk.Authenticate(authorization, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), GetCredential);
        }

        [TestMethod]
        public async Task ShouldParseValidAuthHeaderWithSha1()
        {
            var credential = new HawkCredential
                {
                    Id = "123",
                    Algorithm = "hmacsha1",
                    Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                    User = "steve"
                };

            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now) / 1000);
            var mac = Hawk.CalculateMac("example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), "hello", ts.ToString(), "k3j4h2", credential, "header");

            var authorization = string.Format("id=\"456\", ts=\"{0}\", nonce=\"k3j4h2\", mac=\"{1}\", ext=\"hello\"",
                ts, mac);

            var principal = await Hawk.Authenticate(authorization, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), (s) => Task.FromResult(credential));

            Assert.IsNotNull(principal);
        }

        [TestMethod]
        public async Task ShouldParseValidAuthHeaderWithSha256()
        {
          
            var credential = new HawkCredential
            {
                Id = "456",
                Algorithm = "hmacsha256",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                User = "steve"
            };

            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now) / 1000);
            var mac = Hawk.CalculateMac("example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), "hello", ts.ToString(), "k3j4h2", credential, "header");

            var authorization = string.Format("id=\"456\", ts=\"{0}\", nonce=\"k3j4h2\", mac=\"{1}\", ext=\"hello\"",
                ts, mac);

            var principal = await Hawk.Authenticate(authorization, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), (s) => Task.FromResult(credential));

            Assert.IsNotNull(principal);
        }

        [TestMethod]
        public async Task ShouldParseValidAuthHeaderWithPayloadHashAndSha256()
        {
            var credential = new HawkCredential
            {
                Id = "123",
                Algorithm = "hmacsha256",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                User = "steve"
            };

            var hmac = System.Security.Cryptography.HMAC.Create(credential.Algorithm);
            hmac.Key = Encoding.ASCII.GetBytes(credential.Key);

            var payload = Encoding.UTF8.GetBytes("Thank you for flying Hawk");
            var hash = Convert.ToBase64String(hmac.ComputeHash(payload));
            
            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now) / 1000);
            var mac = Hawk.CalculateMac("example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), "hello", ts.ToString(), "k3j4h2", credential, "header", hash);

            var authorization = string.Format("id=\"456\", ts=\"{0}\", nonce=\"k3j4h2\", mac=\"{1}\", ext=\"hello\", hash=\"{2}\"",
                ts, mac, hash);

            var principal = await Hawk.Authenticate(authorization, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), (s) => Task.FromResult(credential), 
                requestPayload:() => payload);

            Assert.IsNotNull(principal);
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException))]
        public Task ShouldFailWithTimestampInThePast()
        {
            var credential = new HawkCredential
            {
                Id = "123",
                Algorithm = "hmacsha1",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                User = "steve"
            };

            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now.Subtract(TimeSpan.FromDays(1))) / 1000);
            var mac = Hawk.CalculateMac("example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), "hello", ts.ToString(), "k3j4h2", credential, "header");

            var authorization = string.Format("id=\"456\", ts=\"{0}\", nonce=\"k3j4h2\", mac=\"{1}\", ext=\"hello\"",
                ts, mac);

            return Hawk.Authenticate(authorization, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), (s) => Task.FromResult(credential));
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException))]
        public Task ShouldFailWithTimestampInTheFuture()
        {
            var credential = new HawkCredential
            {
                Id = "123",
                Algorithm = "hmacsha1",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                User = "steve"
            };

            var ts = Math.Floor(Hawk.ConvertToUnixTimestamp(DateTime.Now.Add(TimeSpan.FromDays(1))) / 1000);
            var mac = Hawk.CalculateMac("example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), "hello", ts.ToString(), "k3j4h2", credential, "header");

            var authorization = string.Format("id=\"456\", ts=\"{0}\", nonce=\"k3j4h2\", mac=\"{1}\", ext=\"hello\"",
                ts, mac);

            return Hawk.Authenticate(authorization, "example.com", "get", new Uri("http://example.com:8080/resource/4?filter=a"), (s) => Task.FromResult(credential));
        }

        [TestMethod]
        public void ShouldCalculateMac()
        {
            var credential = new HawkCredential
            {
                Algorithm = "hmacsha1",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
            };

            var mac = Hawk.CalculateMac("example.com", "Get", 
                new Uri("http://example.com:8080/resource/4?filter=a"), "hello", "1353788437", "abcde", credential, "header");

            Assert.AreEqual("wA0+3ewq39fEvDl9+tm8PF8fpbM=", mac);
        }

        [TestMethod]
        public void ShouldCalculateMacWithPayloadHash()
        {
            var credential = new HawkCredential
            {
                Algorithm = "hmacsha1",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
            };

            var hmac = System.Security.Cryptography.HMAC.Create(credential.Algorithm);
            hmac.Key = Encoding.ASCII.GetBytes(credential.Key);

            var hash = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes("Thank you for flying Hawk")));

            var mac = Hawk.CalculateMac("example.com", "Get",
                new Uri("http://example.com:8080/resource/4?filter=a"), "hello", "1353788437", "123456", credential, "header", hash);

            Assert.AreEqual("FLDcWaRlOYy9NF6KvAPq/OexkmI=", mac);
        }

        [TestMethod]
        public void ShouldCalculateMacWithMissingExt()
        {
            var credential = new HawkCredential
            {
                Algorithm = "hmacsha1",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
            };

            var mac = Hawk.CalculateMac("example.com", "Get", new Uri("http://example.com:8080/resource/4?filter=a"),
                null, "1353788437", "123456", credential, "header");

            Assert.AreEqual("xzewml0eeTU60IbA45JAj/9GbuY=", mac);
        }

        [TestMethod]
        public void ShouldGetBewit()
        {
            var credential = new HawkCredential
            {
                Id = "1",
                Algorithm = "hmacsha1",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
            };

            var bewit = Hawk.GetBewit("example.com", new Uri("http://example.com:8080/resource/4?filter=a"), credential,
                200, "hello");

            var parts = Encoding.UTF8.GetString(Convert.FromBase64String(bewit)).Split('\\');

            Assert.AreEqual(4, parts.Length);
            Assert.AreEqual(credential.Id, parts[0]);
            Assert.AreEqual("hello", parts[3]);
        }

        [TestMethod]
        public async Task ShouldAuthenticateBewit()
        {
            var credential = new HawkCredential
            {
                Id = "1",
                Algorithm = "hmacsha1",
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
            };

            var bewit = Hawk.GetBewit("example.com", new Uri("http://example.com:8080/resource/4?filter=a"), credential,
                200, "hello");

            var claims = await Hawk.AuthenticateBewit(bewit, "example.com", new Uri("http://example.com:8080/resource/4?filter=a&bewit=" + bewit),
                s => Task.FromResult(credential));

            Assert.IsNotNull(claims);
        }

        private Task<HawkCredential> GetCredential(string id)
        {
            var credentials = new HawkCredential
            {
                Id = id,
                Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
                Algorithm = (id == "1" ? "hmacsha1" : "hmacsha256"),
                User = "steve"
            };

            return Task.FromResult(credentials);
        }
    }
}
