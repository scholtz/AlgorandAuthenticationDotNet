# Algorand Standard for authentication implementation in .net

https://scholtz.github.io/AMS/AMS-0003/AMS-0003.html

https://github.com/algorandfoundation/ARCs/issues/42

## Usage

StartUp.cs
```c#
public void ConfigureServices(
	IServiceCollection services)
{

...

  services
   .AddAuthentication(AlgorandAuthenticationHandler.ID)
   .AddAlgorand(o =>
   {
    o.CheckExpiration = true;
    o.AlgodServer = Configuration["algod:server"];
    o.AlgodServerToken = Configuration["algod:token"];
    o.Realm = Configuration["algod:realm"];
    o.NetworkGenesisHash = Configuration["algod:networkGenesisHash"];
   });

...

}

public void Configure(
	IApplicationBuilder app
	)
{

...

  app.UseAuthentication();
  app.UseAuthorization();

...

}
```

appsettings.json
```json
{
  "algod": {
    "server": "https://testnet.algoexplorerapi.io",
    "token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "networkGenesisHash": "SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=",
    "realm": "www.globdrem.com",
    "CheckExpiration": "true"
  },
}
```

Controller/Example.cs
```
        [Authorize]
        [HttpPost("Create")]
        public async Task<ActionResult<bool>> Create()
        {
        ...
        }
```
