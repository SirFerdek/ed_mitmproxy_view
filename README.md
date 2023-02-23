# ED mitmproxy view plugin

Tested only for active, non-legacy Horizons after Odyssey update.

## Installation / preparation

1. Install mitmproxy
   * Download latest version (v9 at least) and follow installation instructions at [mitmproxy](https://mitmproxy.org/)
   * Read [getting started](https://docs.mitmproxy.org/stable/overview-getting-started/) - navigate to <http://mitm.it> and install the mitmproxy Certificate Authority system-wide

2. Install mitmproxy Certificate Authority for the game
   * Navigate to `%UserProfile%\.mitmproxy`, open `mitmproxy-ca.pem` in your favourite editor and copy public part of the certificate (everything including `-----BEGIN CERTIFICATE-----` to the end)
   * Paste what you just copied to `EliteDangerous\Products\FORC-FDEV-DO-38-IN-40\ControlSchemes\miiddtcca.dat`, do not delete original file contents. This must be done after every game update.

3. Install and learn to use [min-ed-launcher](https://github.com/rfvgyhn/min-ed-launcher)
4. Launch game in such a way that you can control environment variables for game process
   * The game uses libcurl internally, `http_proxy` and `https_proxy` environment variables are sanctioned when performing REST API requests.
   * The goal is to minimize amount of noise in mitmproxy console and be able to use it real-time on second screen to cross-reference actions to API requests. Set "somehow" environment variables `http_proxy` and `https_proxy` to 'http://127.0.0.1:8080/' only for the game process.
   * See [EDProxy.ps1](EDProxy.ps1) script for example using [legendary](https://github.com/derrod/legendary) in place of Epic Games Launcher.
   * Similarly for Steam, you can simply configure Steam to launch your custom script instead of original game exe, which will first set env variables and then forward all passed arguments to [min-ed-launcher](https://github.com/rfvgyhn/min-ed-launcher) (modification of what you can find in min-ed-launcher's Readme).

## Usage

1. Navigate to this directory
2. `mitmweb.exe -s ed_mitmproxy_view.py`
3. Have fun
