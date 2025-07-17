using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Net;
using System.Net.Http;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Xml;

namespace Net8_Desktop_InsecureApp
{
    public partial class MainWindow : Window
    {
        // CWE-798: Hardcoded credentials (Multiple instances)
        private const string API_KEY = "sk-1234567890abcdef";
        private const string DB_PASSWORD = "admin123";
        private const string JWT_SECRET = "my-super-secret-key-123";
        private const string AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
        private const string AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        private const string CONNECTION_STRING = "Server=localhost;Database=VulnDB;User Id=sa;Password=admin123;TrustServerCertificate=true;";

        private static HttpClient httpClient = new HttpClient();

        public MainWindow()
        {
            InitializeComponent();
            ConfigureInsecureSettings();
        }

        // CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag
        private void ConfigureInsecureSettings()
        {
            // Disable security protocols
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };

            // Set insecure HTTP client
            httpClient.DefaultRequestHeaders.Add("Api-Key", API_KEY);
        }

        // CWE-89: SQL Injection (Multiple variants)
        private async void btnLogin_Click(object sender, RoutedEventArgs e)
        {
            string username = txtUsername.Text;
            string password = txtPassword.Text;

            // Variant 1: Direct concatenation
            string query = $"SELECT * FROM Users WHERE Username = '{username}' AND Password = '{password}'";

            // Variant 2: String.Format
            string query2 = String.Format("SELECT * FROM Users WHERE Email = '{0}'", username);

            // Variant 3: Interpolation
            string query3 = $@"
                SELECT u.*, r.* FROM Users u
                JOIN Roles r ON u.RoleId = r.Id
                WHERE u.Username = '{username}' 
                AND u.Password = '{GetMD5Hash(password)}'";

            using (SqlConnection conn = new SqlConnection(CONNECTION_STRING))
            {
                SqlCommand cmd = new SqlCommand(query, conn);
                try
                {
                    await conn.OpenAsync();
                    var reader = await cmd.ExecuteReaderAsync();
                    if (reader.HasRows)
                    {
                        MessageBox.Show("Login successful!");
                        LogUserActivity(username, "LOGIN_SUCCESS");
                    }
                }
                catch (Exception ex)
                {
                    // CWE-209: Information Exposure Through Error Messages
                    MessageBox.Show($"Database Error: {ex.ToString()}\nStack: {ex.StackTrace}");
                    File.AppendAllText("errors.log", $"{DateTime.Now}: {ex.ToString()}\n");
                }
            }
        }

        // CWE-78: OS Command Injection
        private async void btnExecute_Click(object sender, RoutedEventArgs e)
        {
            string userInput = txtCommand.Text;

            // Variant 1: Direct process start
            Process.Start("cmd.exe", $"/c {userInput}");

            // Variant 2: PowerShell execution
            Process.Start("powershell.exe", $"-Command {userInput}");

            // Variant 3: Using ProcessStartInfo
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c " + userInput,
                UseShellExecute = true,
                RedirectStandardOutput = false
            };
            Process.Start(psi);

            // Log command execution (information disclosure)
            await File.AppendAllTextAsync("commands.log", $"{DateTime.Now}: Executed: {userInput}\n");
        }

        // CWE-611: XXE Injection
        private void btnParseXML_Click(object sender, RoutedEventArgs e)
        {
            string xmlContent = txtXmlInput.Text;

            // Vulnerable XmlDocument
            XmlDocument doc = new XmlDocument();
            XmlReaderSettings settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Parse,
                XmlResolver = new XmlUrlResolver(),
                MaxCharactersFromEntities = long.MaxValue,
                MaxCharactersInDocument = long.MaxValue
            };

            using (XmlReader reader = XmlReader.Create(new StringReader(xmlContent), settings))
            {
                doc.Load(reader);
            }

            MessageBox.Show("XML parsed: " + doc.OuterXml);
        }

        // CWE-502: Deserialization of Untrusted Data
        private void btnDeserialize_Click(object sender, RoutedEventArgs e)
        {
            string serializedData = txtSerializedData.Text;

            try
            {
                // BinaryFormatter (deprecated but still compilable)
#pragma warning disable SYSLIB0011
                byte[] bytes = Convert.FromBase64String(serializedData);
                BinaryFormatter formatter = new BinaryFormatter();
                using (MemoryStream stream = new MemoryStream(bytes))
                {
                    var obj = formatter.Deserialize(stream);
                    MessageBox.Show("Deserialized: " + obj.ToString());
                }
#pragma warning restore SYSLIB0011
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message);
            }
        }

        // CWE-22: Path Traversal
        private async void btnReadFile_Click(object sender, RoutedEventArgs e)
        {
            string fileName = txtFileName.Text;

            // Direct concatenation - vulnerable to path traversal
            string filePath = Path.Combine(@"C:\Data\", fileName);

            if (File.Exists(filePath))
            {
                string content = await File.ReadAllTextAsync(filePath);
                txtFileContent.Text = content;

                // Also copy to temp without validation
                File.Copy(filePath, Path.Combine(Path.GetTempPath(), fileName), true);
            }
        }

        // CWE-918: SSRF
        private async void btnFetchUrl_Click(object sender, RoutedEventArgs e)
        {
            string url = txtUrl.Text;

            try
            {
                // No URL validation
                var response = await httpClient.GetStringAsync(url);
                txtResult.Text = response;

                // Log the accessed URL (information disclosure)
                await File.AppendAllTextAsync("urls.log", $"{DateTime.Now}: Accessed {url}\n");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.ToString());
            }
        }

        // CWE-94: Code Injection
        private void btnEvaluate_Click(object sender, RoutedEventArgs e)
        {
            string expression = txtExpression.Text;

            // Using CodeDom compiler
            var provider = new Microsoft.CSharp.CSharpCodeProvider();
            var parameters = new System.CodeDom.Compiler.CompilerParameters
            {
                GenerateExecutable = false,
                GenerateInMemory = true
            };
            parameters.ReferencedAssemblies.Add("System.dll");

            string code = $@"
                using System;
                public class Evaluator
                {{
                    public static object Evaluate()
                    {{
                        return {expression};
                    }}
                }}";

            var results = provider.CompileAssemblyFromSource(parameters, code);
            if (!results.Errors.HasErrors)
            {
                var assembly = results.CompiledAssembly;
                var evaluatorType = assembly.GetType("Evaluator");
                var evaluateMethod = evaluatorType.GetMethod("Evaluate");
                var evalResult = evaluateMethod.Invoke(null, null);
                MessageBox.Show("Result: " + evalResult);
            }
        }

        // CWE-79: XSS in WebBrowser
        private void btnDisplayHtml_Click(object sender, RoutedEventArgs e)
        {
            string userHtml = txtHtmlInput.Text;

            // No HTML encoding
            string html = "<html><body><h1>User Input:</h1>" + userHtml + "</body></html>";
            webBrowser.NavigateToString(html);
        }

        // CWE-259: Hard-coded Password
        private void btnValidateAdmin_Click(object sender, RoutedEventArgs e)
        {
            if (ValidateAdminAccess())
            {
                MessageBox.Show("Admin access granted!");
            }
            else
            {
                MessageBox.Show("Invalid password!");
            }
        }

        // CWE-259: Hard-coded Password
        private bool ValidateAdminAccess()
        {
            return txtAdminPassword.Password == "SuperSecret123!";
        }

        // CWE-295: Certificate Validation Bypass
        private void btnHttpsRequest_Click(object sender, RoutedEventArgs e)
        {
            ServicePointManager.ServerCertificateValidationCallback =
                (sender, certificate, chain, errors) => true;

            using (WebClient client = new WebClient())
            {
                string result = client.DownloadString("https://example.com");
                MessageBox.Show("Downloaded: " + result.Substring(0, Math.Min(100, result.Length)));
            }
        }

        // CWE-327: Weak Cryptography
        private string GetMD5Hash(string input)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] inputBytes = Encoding.ASCII.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);
                return Convert.ToBase64String(hashBytes);
            }
        }

        // CWE-321: Hard-coded Cryptographic Key
        private string EncryptDataAES(string plainText)
        {
            byte[] key = Encoding.UTF8.GetBytes("ThisIsMySecretKey12345678901234!");
            byte[] iv = Encoding.UTF8.GetBytes("1234567890123456");

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.ECB; // Insecure mode

                ICryptoTransform encryptor = aes.CreateEncryptor();
                byte[] encrypted = encryptor.TransformFinalBlock(
                    Encoding.UTF8.GetBytes(plainText), 0, plainText.Length);
                return Convert.ToBase64String(encrypted);
            }
        }

        // CWE-73: External Control of File Name
        private void btnSaveFile_Click(object sender, RoutedEventArgs e)
        {
            string fileName = txtSaveFileName.Text;
            string content = txtSaveContent.Text;

            // No path validation
            File.WriteAllText(fileName, content);
            MessageBox.Show("File saved!");
        }

        // CWE-117: Log Injection
        private void LogUserActivity(string username, string action)
        {
            string logEntry = $"{DateTime.Now}|{username}|{action}";
            File.AppendAllText("activity.log", logEntry + Environment.NewLine);
        }

        // CWE-331: Insufficient Entropy
        private string GenerateInsecureToken()
        {
            Random rand = new Random();
            return rand.Next(1000000, 9999999).ToString();
        }

        // CWE-759: No Salt in Password Hash
        private string HashPasswordInsecure(string password)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                return Convert.ToBase64String(bytes);
            }
        }

        // CWE-613: Insufficient Session Expiration
        private static Dictionary<string, DateTime> sessions = new Dictionary<string, DateTime>();

        private string CreateSession(string username)
        {
            string sessionId = Guid.NewGuid().ToString();
            sessions[sessionId] = DateTime.Now.AddYears(10); // 10 year session!
            return sessionId;
        }
    }
}