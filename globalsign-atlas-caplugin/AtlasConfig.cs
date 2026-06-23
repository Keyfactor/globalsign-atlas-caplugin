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
		public AtlasConfig() { }

		[JsonProperty("ApiKey")]
		public string ApiKey { get; set; }

		[JsonProperty("ApiSecret")]
		public string ApiSecret { get; set; }

		[JsonProperty("ClientCertificate")]
		public ClientCertificate Certificate { get; set; }

		[JsonProperty("SyncStartDate")]
		public string SyncStartDate { get; set; }
	}
}
