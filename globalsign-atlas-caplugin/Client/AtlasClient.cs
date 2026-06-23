using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Common.Exceptions;
using Keyfactor.Extensions.CAPlugin.GlobalSign.Atlas.APIProxy;
using Keyfactor.Logging;
using Keyfactor.PKI.Enums.EJBCA;

using Microsoft.Extensions.Logging;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Org.BouncyCastle.Crmf;

using Org.BouncyCastle.Pqc.Crypto.Lms;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

using CertificateResponse = Keyfactor.Extensions.CAPlugin.GlobalSign.Atlas.APIProxy.CertificateResponse;

namespace Keyfactor.Extensions.CAPlugin.GlobalSign.Atlas.Client
{
	public class AtlasClient
	{
		private static ILogger Logger => LogHandler.GetClassLogger<AtlasClient>();
		private string _apiKey;
		private string _apiSecret;
		private X509Certificate2 _authCert;
		private string _baseUrl;
		
		private string _token;
		private DateTime _tokenTime;

		private DateTime _syncStart;

		private class AtlasResponse
		{
			public bool Success { get; set; }
			public string Response { get; set; }

			public AtlasResponse()
			{
				Success = true;
				Response = "";
			}
		}

		public AtlasClient(string apiKey, string apiSecret, X509Certificate2 authCert, DateTime syncStart)
			:this(apiKey, apiSecret, authCert, syncStart, "https://emea.api.hvca.globalsign.com:8443/v2/")
		{ }

		public AtlasClient(string apiKey, string apiSecret, X509Certificate2 authCert, DateTime syncStart, string baseUrl)
		{
			_apiKey = apiKey;
			_apiSecret = apiSecret;
			_authCert = authCert;
			_syncStart = syncStart;
			_baseUrl = baseUrl;
			if (!_baseUrl.EndsWith("/"))
				_baseUrl += "/";
		}

		public static AtlasClient InitializeClient(AtlasConfig config, ICertificateResolver certResolver)
		{
			Logger.MethodEntry(LogLevel.Debug);
			Logger.LogTrace($"Retrieving auth certificate");
			X509Certificate2 authCert = null;
			if (!string.IsNullOrEmpty(config.Certificate.ImportedCertificate))
			{
				authCert = new X509Certificate2(Convert.FromBase64String(config.Certificate.ImportedCertificate), config.Certificate.ImportedCertificatePassword);
			}
			else
			{
				authCert = certResolver.ResolveCertificate(config.Certificate);
			}
			if (authCert == null)
			{
				Logger.MethodExit(LogLevel.Debug);
				throw new Exception("Unable to resolve auth certificate.");
			}

			Logger.LogTrace($"Auth Certificate found. Cert Details: \nSerial Number: {authCert.GetSerialNumberString()}\nHas PK: {authCert.HasPrivateKey.ToString()}\nSubject: {authCert.Subject}");

			return new AtlasClient(config.ApiKey, config.ApiSecret, authCert, DateTime.Parse(config.SyncStartDate));
		}

		private void RefreshApiToken()
		{
			Logger.MethodEntry(LogLevel.Debug);
			try
			{
				string targetUri = _baseUrl + "login/";
				HttpWebRequest request = (HttpWebRequest)WebRequest.Create(targetUri);
				request.Method = "POST";
				request.ContentType = "application/json;charset=utf-8";
				request.Headers["X-SSL-Client-Serial"] = _authCert.SerialNumber;
				request.ClientCertificates.Add(_authCert);
				var loginReq = new LoginRequest()
				{
					Key = _apiKey,
					Secret = _apiSecret
				};
				string postBody = JsonConvert.SerializeObject(loginReq, Formatting.None, new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore });
				byte[] postBytes = Encoding.UTF8.GetBytes(postBody);

				request.ContentLength = postBytes.Length;
				Stream requestStream = request.GetRequestStream();
				requestStream.Write(postBytes, 0, postBytes.Length);
				requestStream.Close();

				LoginResponse apiResponse = new LoginResponse();
				_tokenTime = DateTime.UtcNow;

				Logger.LogTrace($"Atlas Request: POST {targetUri}");
				using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
				{
					apiResponse = JsonConvert.DeserializeObject<LoginResponse>(new StreamReader(response.GetResponseStream()).ReadToEnd());
				}
				_token = apiResponse.Token;
			}
			catch (Exception ex)
			{
				Logger.LogError($"Atlas response error: {ex.Message}");
				throw new Exception($"Unable to establish connection to Atlas web service: {ex.Message}", ex);
			}
		}

		public EnrollResponse RequestNewCertificate(Enroll request, int pickupDelay, int pickupRetries)
		{
			EnrollResponse enrollResponse = new EnrollResponse();
			string certUrl = null;
			try
			{
				string targetUri = _baseUrl + "certificates/";
				string method = "POST";

				Logger.LogTrace($"Requesting new certificate");
				HttpWebRequest apiRequest = (HttpWebRequest)WebRequest.Create(targetUri);
				apiRequest.Method = method;
				apiRequest.ContentType = "application/json;charset=utf-8";
				if (string.IsNullOrEmpty(_token) || _tokenTime.AddMinutes(10) < DateTime.UtcNow)
				{
					RefreshApiToken();
				}
				apiRequest.ClientCertificates.Add(_authCert);
				apiRequest.Headers.Add("Authorization", "Bearer " + _token);
				string postJson = JsonConvert.SerializeObject(request);
				byte[] postBytes = Encoding.UTF8.GetBytes(postJson);
				apiRequest.ContentLength = postBytes.Length;
				Stream requestStream = apiRequest.GetRequestStream();
				requestStream.Write(postBytes, 0, postBytes.Length);
				requestStream.Close();

				Logger.LogTrace($"Atlas Request: POST {targetUri}\n{postJson}");
				using (HttpWebResponse apiResponse = (HttpWebResponse)apiRequest.GetResponse())
				{
					Logger.LogTrace($"Atlas API returned response {apiResponse.StatusCode}");
					if (apiResponse.StatusCode == HttpStatusCode.Created)
					{
						certUrl = apiResponse.Headers["Location"];
						enrollResponse.SerialNumber = certUrl.Substring(certUrl.LastIndexOf('/') + 1);
					}
					else
					{
						throw new Exception($"Unable to enroll for certificate, status code: {apiResponse.StatusCode}");
					}
				}

				targetUri = _baseUrl + "certificates/" + enrollResponse.SerialNumber;
				method = "GET";

				Logger.LogTrace($"Enrollment successful, retrieving new certificate");
				bool success = true;
				int attempt = 0;
				do
				{
					try
					{
						System.Threading.Thread.Sleep(pickupDelay * 1000);
						apiRequest = (HttpWebRequest)WebRequest.Create(targetUri);
						apiRequest.Method = method;
						apiRequest.ContentType = "application/json;charset=utf-8";
						if (string.IsNullOrEmpty(_token) || _tokenTime.AddMinutes(10) < DateTime.UtcNow)
						{
							RefreshApiToken();
						}
						apiRequest.ClientCertificates.Add(_authCert);
						apiRequest.Headers.Add("Authorization", "Bearer " + _token);

						Logger.LogTrace($"Atlas Request: GET {targetUri}");
						using (HttpWebResponse apiResponse = (HttpWebResponse)apiRequest.GetResponse())
						{
							Logger.LogTrace($"Atlas API returned response {apiResponse.StatusCode}");
							if (apiResponse.StatusCode == HttpStatusCode.OK)
							{
								Logger.LogTrace($"Certificate retrieved");
								CertificateResponse certResponse = JsonConvert.DeserializeObject<CertificateResponse>(new StreamReader(apiResponse.GetResponseStream()).ReadToEnd());
								enrollResponse.Status = EndEntityStatus.GENERATED;
								enrollResponse.Cert = certResponse.Certificate;
								enrollResponse.StatusMessage = "Successfully enrolled for certificate {0}";
							}
							else if (apiResponse.StatusCode == HttpStatusCode.Accepted)
							{
								Logger.LogTrace($"Certificate request in process");
								CertificateResponse certResponse = JsonConvert.DeserializeObject<CertificateResponse>(new StreamReader(apiResponse.GetResponseStream()).ReadToEnd());

								enrollResponse.Status = EndEntityStatus.INPROCESS;
								enrollResponse.StatusMessage = certResponse.Description;
								success = false;
								attempt++;
							}
							else
							{
								success = false;
								attempt++;
							}
						}
					}
					catch (WebException wex)
					{
						success = false;
						if (wex.Response != null)
						{
							using (var errorResponse = (HttpWebResponse)wex.Response)
							{
								if (errorResponse.StatusCode == (HttpStatusCode)429 /*Too Many Requests*/)
								{
									Logger.LogInformation("Request was rate-limited. Trying again in 5 seconds");
									System.Threading.Thread.Sleep(5000);
								}
								else
								{
									attempt++;
								}
							}
						}
						else
						{
							attempt++;
						}
					}
					if (!success)
					{
						if (attempt <= pickupRetries)
						{
							Logger.LogWarning($"Unable to pickup certificate. Retrying... (Retry attempt {attempt} of {pickupRetries})");
						}
						else
						{
							Logger.LogError($"Failed to pickup enrolled certificate. Current disposition status: {enrollResponse.Status.ToString()}");
						}
					}
				} while (success == false && attempt <= pickupRetries);
				return enrollResponse;
			}
			catch (WebException wex)
			{
				if (wex.Response != null)
				{
					using (var errorResponse = (HttpWebResponse)wex.Response)
					{
						if (errorResponse.StatusCode == (HttpStatusCode)429 /*Too Many Requests*/)
						{
							Logger.LogInformation("Request was rate-limited. Trying again in 5 seconds");
							System.Threading.Thread.Sleep(5000);
							return RequestNewCertificate(request, pickupDelay, pickupRetries);
						}
						else
						{
							using (var stream = wex.Response.GetResponseStream())
							using (var reader = new StreamReader(stream))
							{
								string errorString = reader.ReadToEnd();
								Logger.LogError($"Atlas CA has returned an error from enrolling: '{((HttpWebResponse)wex.Response).StatusCode}: {errorString}");
								throw new Exception(errorString, wex);
							}
						}
					}
				}
				else
				{
					Logger.LogError($"Error enrolling for cert: {wex.Message}");
					throw new Exception($"Error enrolling for cert", wex);
				}
			}
			catch (Exception ex)
			{
				Logger.LogError($"Error enrolling for cert: {ex.Message}");
				throw new Exception($"Error enrolling for cert", ex);
			}
		}

		public CertificateResponse GetCertificate(string caRequestID)
		{
			try
			{
				string targetUri = _baseUrl + "certificates/" + caRequestID;
				string method = "GET";

				Logger.LogTrace($"Retrieving certificate");
				HttpWebRequest apiRequest = (HttpWebRequest)WebRequest.Create(targetUri);
				apiRequest.Method = method;
				apiRequest.ContentType = "application/json;charset=utf-8";
				if (string.IsNullOrEmpty(_token) || _tokenTime.AddMinutes(10) < DateTime.UtcNow)
				{
					RefreshApiToken();
				}
				apiRequest.ClientCertificates.Add(_authCert);
				apiRequest.Headers.Add("Authorization", "Bearer " + _token);

				Logger.LogTrace($"Atlas Request: GET {targetUri}");
				using (HttpWebResponse apiResponse = (HttpWebResponse)apiRequest.GetResponse())
				{
					Logger.LogTrace($"Atlas API returned response {apiResponse.StatusCode}");
					if (apiResponse.StatusCode == HttpStatusCode.OK)
					{
						CertificateResponse certResponse = JsonConvert.DeserializeObject<CertificateResponse>(new StreamReader(apiResponse.GetResponseStream()).ReadToEnd());
						return certResponse;
					}
					else if (apiResponse.StatusCode == HttpStatusCode.Accepted)
					{
						CertificateResponse certResponse = JsonConvert.DeserializeObject<CertificateResponse>(new StreamReader(apiResponse.GetResponseStream()).ReadToEnd());

						return certResponse;
					}
					else
					{
						throw new Exception($"Unable to retrieve certificate, status code: {apiResponse.StatusCode}");
					}
				}
			}
			catch (WebException wex)
			{
				if (wex.Response != null)
				{
					using (var errorResponse = (HttpWebResponse)wex.Response)
					{
						if (errorResponse.StatusCode == (HttpStatusCode)429 /*Too Many Requests*/)
						{
							Logger.LogInformation($"Request was rate-limited. Trying again in 5 seconds");
							System.Threading.Thread.Sleep(5000);
							return GetCertificate(caRequestID);
						}
						else
						{
							using (var stream = wex.Response.GetResponseStream())
							using (var reader = new StreamReader(stream))
							{
								string errorString = reader.ReadToEnd();
								Logger.LogError($"Atlas CA has returned an error from retrieving certificate: '{((HttpWebResponse)wex.Response).StatusCode}: {errorString}");
								throw new Exception(errorString, wex);
							}
						}
					}
				}
				else
				{
					Logger.LogError($"Error retrieving cert: {wex.Message}");
					throw new Exception($"Error retrieving cert", wex);
				}
			}
			catch (Exception ex)
			{
				Logger.LogError($"Error retrieving cert: {ex.Message}");
				throw new Exception($"Error retrieving cert", ex);
			}
		}

		public void RevokeCertificate(string caRequestID)
		{
			try
			{
				string targetUri = _baseUrl + "certificates/" + caRequestID;
				string method = "DELETE";

				Logger.LogTrace($"Attempting to revoke certificate");
				HttpWebRequest apiRequest = (HttpWebRequest)WebRequest.Create(targetUri);
				apiRequest.Method = method;
				apiRequest.ContentType = "application/json;charset=utf-8";
				if (string.IsNullOrEmpty(_token) || _tokenTime.AddMinutes(10) < DateTime.UtcNow)
				{
					RefreshApiToken();
				}
				apiRequest.ClientCertificates.Add(_authCert);
				apiRequest.Headers.Add("Authorization", "Bearer " + _token);

				Logger.LogTrace($"Atlas Request: DELETE {targetUri}");
				using (HttpWebResponse apiResponse = (HttpWebResponse)apiRequest.GetResponse())
				{
					Logger.LogTrace($"Atlas API returned response {apiResponse.StatusCode}");
					if (apiResponse.StatusCode == HttpStatusCode.NoContent)
					{
						Logger.LogTrace($"Certificate successfully revoked");
					}
					else
					{
						throw new Exception($"Unable to revoke certificate, status code: {apiResponse.StatusCode}");
					}
				}
			}
			catch (WebException wex)
			{
				if (wex.Response != null)
				{
					using (var errorResponse = (HttpWebResponse)wex.Response)
					{
						if (errorResponse.StatusCode == (HttpStatusCode)429 /*Too Many Requests*/)
						{
							Logger.LogInformation("Request was rate-limited. Trying again in 5 seconds.");
							System.Threading.Thread.Sleep(5000);
							RevokeCertificate(caRequestID);
						}
						else
						{
							using (var stream = wex.Response.GetResponseStream())
							using (var reader = new StreamReader(stream))
							{
								string errorString = reader.ReadToEnd();
								Logger.LogError($"Atlas CA has returned an error from revoking certificate: '{((HttpWebResponse)wex.Response).StatusCode}: {errorString}");
								throw new Exception(errorString, wex);
							}
						}
					}
				}
				else
				{
					Logger.LogError($"Error revoking cert: {wex.Message}");
					throw new Exception($"Error revoking cert", wex);
				}
			}
			catch (Exception ex)
			{
				Logger.LogError($"Error revoking cert: {ex.Message}");
				throw new Exception($"Error revoking cert", ex);
			}
		}

		public ValidationPolicyResponse GetValidationPolicy()
		{
			try
			{
				string targetUri = _baseUrl + "validationpolicy/";
				string method = "GET";

				Logger.LogTrace($"Retrieving validation policy");
				HttpWebRequest apiRequest = (HttpWebRequest)WebRequest.Create(targetUri);
				apiRequest.Method = method;
				apiRequest.ContentType = "application/json;charset=utf-8";
				if (string.IsNullOrEmpty(_token) || _tokenTime.AddMinutes(10) < DateTime.UtcNow)
				{
					RefreshApiToken();
				}
				apiRequest.ClientCertificates.Add(_authCert);
				apiRequest.Headers.Add("Authorization", "Bearer " + _token);
				Logger.LogTrace($"Atlas Request: GET {targetUri}");
				using (HttpWebResponse apiResponse = (HttpWebResponse)apiRequest.GetResponse())
				{
					var fullResponse = new StreamReader(apiResponse.GetResponseStream()).ReadToEnd();
					Logger.LogTrace($"Atlas API returned response {apiResponse.StatusCode}");
					if (apiResponse.StatusCode == HttpStatusCode.OK)
					{
						ValidationPolicyResponse validationResponse = JsonConvert.DeserializeObject<ValidationPolicyResponse>(fullResponse);
						return validationResponse;
					}
					else
					{
						throw new Exception("Error retrieving validation policy");
					}
				}
			}
			catch (WebException wex)
			{
				if (wex.Response != null)
				{
					using (var errorResponse = (HttpWebResponse)wex.Response)
					{
						if (errorResponse.StatusCode == (HttpStatusCode)429 /*Too Many Requests*/)
						{
							Logger.LogInformation("Request was rate-limited. Trying again in 5 seconds.");
							System.Threading.Thread.Sleep(5000);
							return GetValidationPolicy();
						}
						else
						{
							using (var stream = wex.Response.GetResponseStream())
							using (var reader = new StreamReader(stream))
							{
								string errorString = reader.ReadToEnd();
								Logger.LogError($"Atlas CA has returned an error from retrieving validation policy: '{((HttpWebResponse)wex.Response).StatusCode}: {errorString}");
								throw new Exception(errorString, wex);
							}
						}
					}
				}
				else
				{
					Logger.LogError($"Error retrieving validation policy: {wex.Message}");
					throw new Exception($"Error retrieving validation policy", wex);
				}
			}
			catch (Exception ex)
			{
				Logger.LogError($"Error retrieving validation policy: {ex.Message}");
				throw new Exception($"Error retrieving validation policy", ex);
			}
		}

		public List<CertificateDetailsResponse> GetAllCertificates(DateTime? lastIncrementalSync, bool doFullSync)
		{
			if (!lastIncrementalSync.HasValue)
			{
				lastIncrementalSync = _syncStart;
			}
			DateTime startTime = doFullSync ? _syncStart : (lastIncrementalSync.Value);
			DateTime endTime = DateTime.UtcNow;
			long startTimeTicks = ((DateTimeOffset)startTime).ToUnixTimeSeconds();
			long endTimeTicks = ((DateTimeOffset)endTime).ToUnixTimeSeconds();

			List<CertificateDetailsResponse> certs = new List<CertificateDetailsResponse>();

			for (long i = startTimeTicks; i <= endTimeTicks; i += 1728000) // Sync 20 days at a time
			{
				int pagenum = 1;
				bool morePages = false;
				long toTicks = i + 1728000;
				if (toTicks > endTimeTicks)
				{
					toTicks = endTimeTicks;
				}
				do
				{
					morePages = false;
					string targetUri = _baseUrl + "stats/issued?page=" + pagenum + "&from=" + i + "&to=" + toTicks;
					string method = "GET";

					Logger.LogTrace($"Retrieving certificate list");
					HttpWebRequest apiRequest = (HttpWebRequest)WebRequest.Create(targetUri);
					apiRequest.Method = method;
					apiRequest.ContentType = "application/json;charset=utf-8";
					if (string.IsNullOrEmpty(_token) || _tokenTime.AddMinutes(10) < DateTime.UtcNow)
					{
						RefreshApiToken();
					}
					apiRequest.ClientCertificates.Add(_authCert);
					apiRequest.Headers.Add("Authorization", "Bearer " + _token);
					List<CertificateStatusResponse> certResponse;
					try
					{
						Logger.LogTrace($"Atlas Request: GET {targetUri}");
						using (HttpWebResponse apiResponse = (HttpWebResponse)apiRequest.GetResponse())
						{
							Logger.LogTrace($"Atlas API returned response {apiResponse.StatusCode}");
							if (apiResponse.StatusCode == HttpStatusCode.OK)
							{
								certResponse = JsonConvert.DeserializeObject<List<CertificateStatusResponse>>(new StreamReader(apiResponse.GetResponseStream()).ReadToEnd());

								var header = apiResponse.Headers["Links"];
								if (header.Contains("next"))
								{
									morePages = true;
									pagenum++;
								}
							}
							else
							{
								throw new Exception($"Unable to retrieve certificate list, status code: {apiResponse.StatusCode}");
							}
						}
					}
					catch (WebException wex)
					{
						if (wex.Response != null)
						{
							using (var errorResponse = (HttpWebResponse)wex.Response)
							{
								if (errorResponse.StatusCode == (HttpStatusCode)429 /*Too Many Requests*/)
								{
									Logger.LogInformation("Request was rate-limited. Trying again in 5 seconds.");
									System.Threading.Thread.Sleep(5000);
									continue;
								}
							}
							using (var stream = wex.Response.GetResponseStream())
							using (var reader = new StreamReader(stream))
							{
								string errorString = reader.ReadToEnd();
								Logger.LogError($"Atlas CA has returned an error from retrieving certificate: '{((HttpWebResponse)wex.Response).StatusCode}: {errorString}");
								throw new Exception(errorString, wex);
							}
						}
						else
						{
							Logger.LogError($"Error retrieving cert: {wex.Message}");
							throw new Exception($"Error retrieving cert", wex);
						}
					}
					catch (Exception ex)
					{
						Logger.LogError($"Error retrieving cert: {ex.Message}");
						throw new Exception($"Error retrieving cert", ex);
					}
					foreach (var certStatus in certResponse)
					{
						CertificateDetailsResponse details = new CertificateDetailsResponse();
						details.Status = certStatus;
						details.Cert = GetCertificate(certStatus.SerialNumber);
						certs.Add(details);
					}
				} while (morePages);
			}
			return certs;
		}
	}
}
