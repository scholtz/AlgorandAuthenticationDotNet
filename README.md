# Algorand Standard for authentication implementation in .net

ARC-0014 implementation in .net

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
    o.AlgodServerHeader = Configuration["algod:header"];
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
    "server": "https://node.testnet.algoexplorerapi.io",
    "token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "networkGenesisHash": "SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=",
    "header": "X-Algo-API-Token",
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

## Activity diagram

Plantuml:

@startuml

User -> Website: User wish to login to the website 


Website -> AnyAlgorandNode : Request /v2/transactions/params
AnyAlgorandNode  -> Website : Returns transaction params

Website -> Wallet : Website produces through algosdk messege to be signed, note as realm, params as session timeout
Wallet -> Website: Signed tx, website stores tx in temporary memory, localstorage or cookie the same as jwt

Website --> User: Displays eg auth address

Website -> Backend: Request authorized method, use SigTx Authorization header, fe /getUser

Backend -> AnyAlgorandNode : Request /v2/transactions/params
AnyAlgorandNode  -> Backend : Returns current block round number

Backend -> Website: 401 if signature, genesis or round is wrong
Backend -> Website: 200 if authorized and returns content

Website --> User: Displays /getUser content, fe roles or username

@enduml

![image](https://user-images.githubusercontent.com/1223439/195995737-7524c1fb-d5ae-432e-b6ff-9aac730e476b.png)

## Example use

### Algorand KMD Node

Algorand KMD Node is proxy to algorand participation node which allow to create participation keys. It uses ARC-0014 authentication to ensure no spam traffic to cpu sensitive methods.

https://github.com/scholtz/AlgorandKMDServer/blob/f9d04b717f0f58cf9151bd8fa9a65b7e805db87c/Program.cs#L48

### Hasura Algorand Auth Web Hook

GraphQL algorand authentication for live websocket authenticated feeds.

https://github.com/scholtz/HasuraAlgorandAuthWebHook
