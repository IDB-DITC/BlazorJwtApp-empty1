using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;
using System.Diagnostics;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;

namespace BlazorJwtApp_empty1
{
	public class JwtAuthStateProvider : AuthenticationStateProvider
	{
		private readonly ILocalStorageService localStorage;
		private readonly HttpClient httpClient;

		public JwtAuthStateProvider(ILocalStorageService localStorage, HttpClient httpClient)
		{
			this.localStorage = localStorage;
			this.httpClient = httpClient;

		}


		public override async Task<AuthenticationState> GetAuthenticationStateAsync()
		{

			string? token = await localStorage.GetItemAsStringAsync("token");

			var identity = new ClaimsIdentity();

			httpClient.DefaultRequestHeaders.Authorization = null;



			if (!string.IsNullOrEmpty(token))
			{
				identity = new ClaimsIdentity(GetClaimsFromJwt(token), "jwt");



				httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.Replace("\"", ""));
			}
			var user = new ClaimsPrincipal(identity);

			var state = new AuthenticationState(user);

			NotifyAuthenticationStateChanged(Task.FromResult(state));
			return state;
		}




		public IEnumerable<Claim>? GetClaimsFromJwt(string jwt)
		{
			try
			{
				var payload = jwt.Split('.')[1];
				var jwtBytes = ParsePayload(payload);

				var claimPairs = JsonSerializer.Deserialize<Dictionary<string, object>>(jwtBytes);

				return claimPairs?.Select(s => new Claim(s.Key, s.Value?.ToString() ?? ""));
			}
			catch (Exception ex)
			{
				Debug.WriteLine(ex);

			}
			return null;
		}

		private byte[] ParsePayload(string payload)
		{
			switch (payload.Length % 4)
			{
				case 2:
					payload += "==";
					break;
				case 3:
					payload += "=";
					break;
			}

			return Convert.FromBase64String(payload);
		}

	}
}
