using Keyfactor.AnyGateway.Extensions;

using Newtonsoft.Json;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Keyfactor.Extensions.CAPlugin.GlobalSign.Atlas
{
	public class AtlasConfig
	{
		public class Constants
		{
			public static string API_KEY = "ApiKey";
			public static string API_SECRET = "ApiSecret";
			public static string CLIENT_CERTIFICATE = "ClientCertificate";
			public static string SYNC_START_DATE = "SyncStartDate";
			public static string ENABLED = "Enabled";

			public static string LIFETIME = "Lifetime";
			public static string KEY_USAGE = "KeyUsage";
		}

		public AtlasConfig() { }

		[JsonProperty("ApiKey")]
		public string ApiKey { get; set; }

		[JsonProperty("ApiSecret")]
		public string ApiSecret { get; set; }

		[JsonProperty("ClientCertificate")]
		public ClientCertificate Certificate { get; set; }

		[JsonProperty("SyncStartDate")]
		public string SyncStartDate { get; set; }

		[JsonProperty("Enabled")]
		public bool Enabled { get; set; } = true;
	}
}
