using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApp9
{
    class Program
    {
        const string CLIENTSECRET = "0E4Ol[UoM6WJ/Ev:B:zJAMQfracj2QT0";
        const string CLIENTID = "feefed46-c7bb-4867-994f-a140c556dd62";
        //const string BASESECRETURI = "https://satyakeyvault.vault.azure.net/secrets/spk/f26ad3962d8c44dc8a65507a0fe6298e"; // available from the Key Vault resource page

        const string BASESECRETURI = "https://satyakeyvault.vault.azure.net"; // available from the Key Vault resource page
        static KeyVaultClient kvc = null;
        static void Main(string[] args)
        {
            DoVault();

            Console.ReadLine();
        }

        public static async Task<string> GetToken(string authority, string resource, string scope)
        {
            var authContext = new Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext(authority);
            ClientCredential clientCred = new ClientCredential(CLIENTID, CLIENTSECRET);
            AuthenticationResult result = await authContext.AcquireTokenAsync(resource, clientCred);

            if (result == null)
                throw new InvalidOperationException("Failed to obtain the JWT token");

            return result.AccessToken;
        }
        private static void DoVault()
        {
            kvc = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(GetToken));

            // write
            writeKeyVault();
            Console.WriteLine("Press enter after seeing the bundle value show up");
            Console.ReadLine();

            SecretBundle secret = Task.Run(() => kvc.GetSecretAsync(BASESECRETURI)).ConfigureAwait(false).GetAwaiter().GetResult();
            Console.WriteLine(secret.Tags["Test1"].ToString());
            Console.WriteLine(secret.Tags["Test2"].ToString());
            Console.WriteLine(secret.Tags["CanBeAnything"].ToString());

            Console.ReadLine();

        }

        private static async void writeKeyVault()// string szPFX, string szCER, string szPassword)
        {
            SecretAttributes attribs = new SecretAttributes
            {
                Enabled = true//,
                              //Expires = DateTime.UtcNow.AddYears(2), // if you want to expire the info
                              //NotBefore = DateTime.UtcNow.AddDays(1) // if you want the info to 
                              // start being available later
            };

            IDictionary<string, string> alltags = new Dictionary<string, string>();
            alltags.Add("Test1", "This is a test1 value");
            alltags.Add("Test2", "This is a test2 value");
            alltags.Add("CanBeAnything", "Including a long encrypted string if you choose");
            string TestName = "TestSecret";
            string TestValue = "searchValue"; // this is what you will use to search for the item later
            string contentType = "SecretInfo"; // whatever you want to categorize it by; you name it

            SecretBundle bundle = await kvc.SetSecretAsync
               (BASESECRETURI, TestName, TestValue, alltags, contentType, attribs);
            Console.WriteLine("Bundle:" + bundle.Tags["Test1"].ToString());
        }
    }
}
