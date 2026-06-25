using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.GlobalSign.Atlas.APIProxy;
using Keyfactor.Extensions.CAPlugin.GlobalSign.Atlas.Client;
using Keyfactor.Logging;
using Keyfactor.PKI.Enums.EJBCA;
using Keyfactor.PKI.PEM;

using Microsoft.Extensions.Logging;

using Newtonsoft.Json;

using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.X509;

using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;

using static Org.BouncyCastle.Math.EC.ECCurve;

namespace Keyfactor.Extensions.CAPlugin.GlobalSign.Atlas
{
	public class AtlasCAPlugin : IAnyCAPlugin
	{
		private AtlasConfig _config;
		private readonly ILogger _logger;
		private ICertificateDataReader _certDataReader;
		private ICertificateResolver _certResolver;

		public AtlasCAPlugin(ICertificateResolver certificateResolver = null)
		{
			_logger = LogHandler.GetClassLogger<AtlasCAPlugin>();
			_certResolver = certificateResolver;
		}

		public void Initialize(IAnyCAPluginConfigProvider configProvider, ICertificateDataReader certificateDataReader)
		{
			_certDataReader = certificateDataReader;
			string rawConfig = JsonConvert.SerializeObject(configProvider.CAConnectionData);
			_config = JsonConvert.DeserializeObject<AtlasConfig>(rawConfig);
		}

		public async Task<EnrollmentResult> Enroll(string csr, string subject, Dictionary<string, string[]> san, EnrollmentProductInfo productInfo, RequestFormat requestFormat, EnrollmentType enrollmentType)
		{
			_logger.MethodEntry(LogLevel.Trace);
			AtlasClient client = AtlasClient.InitializeClient(_config, _certResolver);
			Enroll enrollData = new Enroll();
			
			enrollData.CSR = csr;

			var validation = client.GetValidationPolicy();
			long days = 0;
			if (productInfo.ProductParameters.ContainsKey("Lifetime"))
			{
				days = int.Parse(productInfo.ProductParameters["Lifetime"]);
				_logger.LogTrace($"Verifying provided validity period of {days} days");
			}
			else
			{
				days = validation.Validity.SecondsMax / 60 / 60 / 24;
				_logger.LogTrace($"No validity period provided. Using default maximum of {days} days");
			}
			long validitySeconds = days * 24 * 60 * 60;
			if (validitySeconds > validation.Validity.SecondsMax || validitySeconds < validation.Validity.SecondsMin)
			{
				int minDays = Convert.ToInt32(Math.Ceiling(validation.Validity.SecondsMin / 60.0 / 60.0 / 24.0));
				int maxDays = Convert.ToInt32(Math.Floor(validation.Validity.SecondsMax / 60.0 / 60.0 / 24.0));
				string errMsg = $"Invalid validity period. Valid period is between {minDays} and {maxDays} days.";
				_logger.LogError(errMsg);
				throw new Exception(errMsg);
			}
			enrollData.Validity.NotBefore = DateTime.UtcNow;
			enrollData.Validity.NotAfter = enrollData.Validity.NotBefore.AddDays(days);

			X509Name subjectParsed = new X509Name(subject);
			string subjectField, validationPresence;
			subjectField = subjectParsed.GetValueList(X509Name.CN).Cast<string>().LastOrDefault();
			validationPresence = validation.SubjectDN.CommonName.Presence;
			if (validationPresence.Equals("required", StringComparison.OrdinalIgnoreCase) || validationPresence.Equals("optional", StringComparison.OrdinalIgnoreCase))
			{
				if (validationPresence.Equals("required", StringComparison.OrdinalIgnoreCase) && subjectField == null)
				{
					_logger.LogError($"Common Name is required");
					throw new Exception("Common Name is required");
				}
				enrollData.SubjectDN.CommonName = subjectField;
			}
			else if (subjectField != null)
			{
				_logger.LogWarning($"Validation Policy does not allow Common Name, skipping");
			}
			subjectField = subjectParsed.GetValueList(X509Name.C).Cast<string>().LastOrDefault();
			validationPresence = validation.SubjectDN.Country.Presence;
			if (validationPresence.Equals("required", StringComparison.OrdinalIgnoreCase) || validationPresence.Equals("optional", StringComparison.OrdinalIgnoreCase))
			{
				if (validationPresence.Equals("required", StringComparison.OrdinalIgnoreCase) && subjectField == null)
				{
					_logger.LogError($"Country is required");
					throw new Exception("Country is required");
				}
				enrollData.SubjectDN.Country = subjectField;
			}
			else if (subjectField != null)
			{
				_logger.LogWarning($"Validation Policy does not allow Country, skipping");
			}
			subjectField = subjectParsed.GetValueList(X509Name.E).Cast<string>().LastOrDefault();
			validationPresence = validation.SubjectDN.Email.Presence;
			if (validationPresence.Equals("required", StringComparison.OrdinalIgnoreCase) || validationPresence.Equals("optional", StringComparison.OrdinalIgnoreCase))
			{
				if (validationPresence.Equals("required", StringComparison.OrdinalIgnoreCase) && subjectField == null)
				{
					_logger.LogError($"Email is required");
					throw new Exception("Email is required");
				}
				enrollData.SubjectDN.Email = subjectField;
			}
			else if (subjectField != null)
			{
				_logger.LogWarning($"Validation Policy does not allow Email, skipping");
			}
			subjectField = subjectParsed.GetValueList(X509Name.L).Cast<string>().LastOrDefault();
			validationPresence = validation.SubjectDN.Locality.Presence;
			if (validationPresence.Equals("required", StringComparison.OrdinalIgnoreCase) || validationPresence.Equals("optional", StringComparison.OrdinalIgnoreCase))
			{
				if (validationPresence.Equals("required", StringComparison.OrdinalIgnoreCase) && subjectField == null)
				{
					_logger.LogError($"Locality is required");
					throw new Exception("Locality is required");
				}
				enrollData.SubjectDN.Locality = subjectField;
			}
			else if (subjectField != null)
			{
				_logger.LogWarning($"Validation Policy does not allow Locality, skipping");
			}
			subjectField = subjectParsed.GetValueList(X509Name.O).Cast<string>().LastOrDefault();
			validationPresence = validation.SubjectDN.Organization.Presence;
			if (validationPresence.Equals("required", StringComparison.OrdinalIgnoreCase) || validationPresence.Equals("optional", StringComparison.OrdinalIgnoreCase))
			{
				if (validationPresence.Equals("required", StringComparison.OrdinalIgnoreCase) && subjectField == null)
				{
					_logger.LogError($"Organization is required");
					throw new Exception("Organization is required");
				}
				enrollData.SubjectDN.Organization = subjectField;
			}
			else if (subjectField != null)
			{
				_logger.LogWarning($"Validation Policy does not allow Organization, skipping");
			}
			subjectField = subjectParsed.GetValueList(X509Name.ST).Cast<string>().LastOrDefault();
			validationPresence = validation.SubjectDN.State.Presence;
			if (validationPresence.Equals("required", StringComparison.OrdinalIgnoreCase) || validationPresence.Equals("optional", StringComparison.OrdinalIgnoreCase))
			{
				if (validationPresence.Equals("required", StringComparison.OrdinalIgnoreCase) && subjectField == null)
				{
					_logger.LogError($"State is required");
					throw new Exception("State is required");
				}
				enrollData.SubjectDN.State = subjectField;
			}
			else if (subjectField != null)
			{
				_logger.LogWarning($"Validation Policy does not allow State, skipping");
			}

			var sanDict = new Dictionary<string, string[]>(san, StringComparer.OrdinalIgnoreCase);
			if (!validation.San.DNSNames.Static)
			{
				if (sanDict.ContainsKey("dns"))
					foreach (var dnsSan in sanDict["dns"])
						enrollData.SANs.DNSList.Add(dnsSan);
			}
			else if (sanDict.ContainsKey("dns"))
			{
				_logger.LogWarning($"Validation Policy does not allow DNS SANs, skipping");
			}

			if (!validation.San.IPAddresses.Static)
			{
				if (sanDict.ContainsKey("ipaddress"))
					foreach (var ipSan in sanDict["ipaddress"])
						enrollData.SANs.IPList.Add(ipSan);
			}
			else if (sanDict.ContainsKey("ipaddress"))
			{
				_logger.LogWarning($"Validation Policy does not allow IP address SANs, skipping");
			}

			if (!validation.San.Emails.Static)
			{
				if (sanDict.ContainsKey("email"))
					foreach (var emailSan in sanDict["email"])
						enrollData.SANs.EmailList.Add(emailSan);
			}
			else if (sanDict.ContainsKey("email"))
			{
				_logger.LogWarning($"Validation Policy does not allow email SANs, skipping");
			}

			string keyUsage = ((productInfo.ProductParameters.ContainsKey("KeyUsage")) ? productInfo.ProductParameters["KeyUsage"] : "").ToLower();
			if (!validation.EKUs.EKUs.Static)
			{
				if (string.IsNullOrEmpty(keyUsage))
				{
					keyUsage = "clientserver";
				}
				if (keyUsage.Contains("server"))
				{
					enrollData.EKUList.Add("1.3.6.1.5.5.7.3.1");
				}
				if (keyUsage.Contains("client"))
				{
					enrollData.EKUList.Add("1.3.6.1.5.5.7.3.2");
				}
			}
			else if (!string.IsNullOrEmpty(keyUsage))
			{
				_logger.LogWarning($"Validation Policy does not allow EKUs, skipping");
			}

			if (validation.Signature.HashAlgorithm.Presence.Equals("required", StringComparison.OrdinalIgnoreCase) || validation.Signature.HashAlgorithm.Presence.Equals("optional", StringComparison.OrdinalIgnoreCase))
			{
				enrollData.Sig.HashAlgorithm = "SHA-256";
			}

			var response = client.RequestNewCertificate(enrollData, 5, 5);
			
			if (response.Status != EndEntityStatus.GENERATED && response.Status != EndEntityStatus.INPROCESS)
			{
				throw new Exception($"Certificate was not retrieved. Status: {response.StatusMessage}");
			}

			EnrollmentResult result = new EnrollmentResult();
			result.CARequestID = response.SerialNumber;
			if (response.Status == EndEntityStatus.GENERATED)
			{
				result.Status = (int)EndEntityStatus.GENERATED;
				result.StatusMessage = string.Format(response.StatusMessage, subject);
				result.Certificate = Convert.ToBase64String(PemUtilities.PEMToDER(response.Cert));
			}
			else
			{
				result.Status = (int)EndEntityStatus.EXTERNALVALIDATION;
				result.StatusMessage = $"Certificate request is pending or requires approval. Certificate will be picked up during synchronization once available."; ;
			}
			return result;
		}

		public Dictionary<string, PropertyConfigInfo> GetCAConnectorAnnotations()
		{
			return new Dictionary<string, PropertyConfigInfo>()
			{
				["ApiKey"] = new PropertyConfigInfo()
				{
					Comments = "The API key for the Atlas credentials the gateway will use.",
					Hidden = false,
					DefaultValue = "",
					Type = "String"
				},
				["ApiSecret"] = new PropertyConfigInfo()
				{
					Comments = "The corresponding API secret value that matches with the ApiKey.",
					Hidden = true,
					DefaultValue = "",
					Type = "String"
				},
				["ClientCertificate"] = new PropertyConfigInfo()
				{
					Comments = "The client auth certificate to use with the Atlas API",
					Hidden = false,
					DefaultValue = "",
					Type = "ClientCertificate"
				},
				["SyncStartDate"] = new PropertyConfigInfo()
				{
					Comments = "The earliest date to go back when doing a full sync.",
					Hidden = false,
					DefaultValue = "2024-01-01",
					Type = "String"
				}
			};
		}

		public List<string> GetProductIds()
		{
			// Atlas does not use product IDs. Gateway framework requires a value, so just use 'certificate'
			return new List<string>() { "certificate" };
		}

		public async Task<AnyCAPluginCertificate> GetSingleRecord(string caRequestID)
		{
			AtlasClient client = AtlasClient.InitializeClient(_config, _certResolver);
			var certResponse = client.GetCertificate(caRequestID);

			return new AnyCAPluginCertificate
			{
				CARequestID = caRequestID,
				Certificate = certResponse.Certificate,
				Status = certResponse.Status.Equals("issued", StringComparison.OrdinalIgnoreCase) ? (int)EndEntityStatus.GENERATED :
							certResponse.Status.Equals("revoked", StringComparison.OrdinalIgnoreCase) ? (int)EndEntityStatus.REVOKED : (int)EndEntityStatus.EXTERNALVALIDATION,
			};
		}

		public Dictionary<string, PropertyConfigInfo> GetTemplateParameterAnnotations()
		{
			return new Dictionary<string, PropertyConfigInfo>()
			{
				["Lifetime"] = new PropertyConfigInfo()
				{
					Comments = "The term length (in days) to use for enrollment.",
					Hidden = false,
					DefaultValue = 30,
					Type = "Number"
				},
				["KeyUsage"] = new PropertyConfigInfo()
				{
					Comments = "The key usage to use for enrolled certs. Valid values are 'client', 'server', and 'clientserver'.",
					Hidden = false,
					DefaultValue = "server",
					Type = "String"
				}
			};
		}

		public async Task Ping()
		{
			try
			{
				AtlasClient client = AtlasClient.InitializeClient(_config, _certResolver);
				_ = client.GetValidationPolicy();
			}
			catch (Exception ex)
			{
				_logger.LogError($"Error attempting to contact GlobalSign Atlas: {ex.Message}");
				throw new Exception($"Error attempting to contact GlobalSign Atlas: {ex.Message}", ex);
			}
		}

		public async Task<int> Revoke(string caRequestID, string hexSerialNumber, uint revocationReason)
		{
			AtlasClient client = AtlasClient.InitializeClient(_config, _certResolver);
			client.RevokeCertificate(caRequestID);

			var certResponse = client.GetCertificate(caRequestID);
			return certResponse.Status.Equals("issued", StringComparison.OrdinalIgnoreCase) ? (int)EndEntityStatus.GENERATED :
							certResponse.Status.Equals("revoked", StringComparison.OrdinalIgnoreCase) ? (int)EndEntityStatus.REVOKED : (int)EndEntityStatus.EXTERNALVALIDATION;
		}

		public async Task Synchronize(BlockingCollection<AnyCAPluginCertificate> blockingBuffer, DateTime? lastSync, bool fullSync, CancellationToken cancelToken)
		{
			AtlasClient client = AtlasClient.InitializeClient(_config, _certResolver);
			var certs = client.GetAllCertificates(lastSync, fullSync);

			foreach (var cert in certs)
			{
				var anyCACert = new AnyCAPluginCertificate
				{
					CARequestID = cert.Status.SerialNumber,
					Certificate = cert.Cert.Certificate,
					Status = cert.Cert.Status.Equals("issued", StringComparison.OrdinalIgnoreCase) ? (int)EndEntityStatus.GENERATED :
								cert.Cert.Status.Equals("revoked", StringComparison.OrdinalIgnoreCase) ? (int)EndEntityStatus.REVOKED : (int)EndEntityStatus.EXTERNALVALIDATION,
				};
				blockingBuffer.Add(anyCACert);
			}
		}

		public async Task ValidateCAConnectionInfo(Dictionary<string, object> connectionInfo)
		{
			_logger.LogTrace($"Validating CA Connection info");
			List<string> errors = new List<string>();
			string rawConfig = JsonConvert.SerializeObject(connectionInfo);
			AtlasConfig testConfig = JsonConvert.DeserializeObject<AtlasConfig>(rawConfig);

			_logger.LogTrace($"Checking for API Key/Secret");
			if (string.IsNullOrWhiteSpace(testConfig.ApiKey))
			{
				errors.Add($"The API Key is required");
			}
			if (string.IsNullOrWhiteSpace(testConfig.ApiSecret))
			{
				errors.Add($"The API Secret is required");
			}

			_logger.LogTrace($"Checking Sync Start Date");
			if (string.IsNullOrWhiteSpace(testConfig.SyncStartDate))
			{
				errors.Add($"Sync Start Date is required");
			}
			else
			{
				if (!DateTime.TryParse(testConfig.SyncStartDate, out _))
				{
					errors.Add("The Sync Start Date could not be parsed");
				}
			}

			_logger.LogTrace($"Checking Client Certificate data");
			try
			{
				X509Certificate2 authCert = null;
				if (!string.IsNullOrEmpty(testConfig.Certificate.ImportedCertificate))
				{
					authCert = new X509Certificate2(Convert.FromBase64String(testConfig.Certificate.ImportedCertificate), testConfig.Certificate.ImportedCertificatePassword);
				}
				else
				{
					authCert = _certResolver.ResolveCertificate(testConfig.Certificate);
				}
				if (authCert == null)
				{
					errors.Add($"Unable to load authentication certificate");
				}

				_logger.LogTrace($"Auth Certificate found. Cert Details: \nSerial Number: {authCert.GetSerialNumberString()}\nHas PK: {authCert.HasPrivateKey.ToString()}\nSubject: {authCert.Subject}");
			}
			catch (Exception ex)
			{
				errors.Add($"Unable to load authentication certificate: {ex.Message}");
			}

			if (errors.Any())
			{
				throw new Exception(string.Join("\n", errors));
			}
			_logger.LogTrace($"CA Connection validation complete");
		}

		public async Task ValidateProductInfo(EnrollmentProductInfo productInfo, Dictionary<string, object> connectionInfo)
		{
			// Do nothing
		}
	}
}
