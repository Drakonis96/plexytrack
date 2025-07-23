# PlexyTrack

<p align="center">
  <img src="static/plexytrack_logo.png" alt="PlexyTrack Logo" width="200" />
</p>

This project synchronizes your Plex library with Trakt. Besides watched history it can optionally add items to your Trakt collection, sync ratings and watchlists, and now mirrors Trakt lists you like as Plex collections. Collections created in Plex will in turn appear as Trakt lists. A small Flask web interface lets you choose which features to enable and configure the sync interval. Items that are manually marked as watched in Plex are detected as well. The interface also includes a tool for creating backups of your history, watchlist and ratings.
The recommended sync interval is **at least 60 minutes**. Shorter intervals generally do not provide any benefit, and you can even synchronize once every 24 hours to reduce the load on your server and the API.

## Features

- Bidirectional sync of watched history between Plex and Trakt or Simkl
- Optional synchronization of ratings, collections, liked lists and watchlists
- Live Sync mode to trigger updates immediately from Plex webhooks
- Simple backup and restore of all your Trakt data from the web interface
- Intuitive UI for configuration and user selection

## CONTENTS

- [Disclaimer](#disclaimer)
- [Requirements](#requirements)
- [Collections and watchlists](#collections-and-watchlists)
- [Backup and restore](#backup-and-restore)
- [Live sync](#live-sync)
- [Getting a Plex token](#getting-a-plex-token)
- [Getting Trakt API credentials](#getting-trakt-api-credentials)
- [Running with Docker Compose](#running-with-docker-compose)
- [Screenshots](#screenshots)


## Disclaimer

This application is currently in testing and is provided **as is**. I take no responsibility for any data loss that may occur when using it. Before you begin, you should use the backup tool to export your history, watchlist and ratings so they can be restored easily from the UI.

## Requirements

The application expects the following API credentials:

### Plex Authentication

- `PLEX_BASEURL` – URL of your Plex server, e.g. `http://localhost:32400`.
- `PLEX_TOKEN` – your Plex authentication token.

### Optional enviroment variables
You can automatically set upt these directly on the web interface by logging in to your Plex account. So you do not need to provide them on .env or compose files.

- `PLEX_EMAIL` – your Plex account email address.
- `PLEX_PASSWORD` – your Plex account password.
- `PLEX_2FA_CODE` – optional 2FA code (required if 2FA is enabled on your Plex account).
- `PLEX_SERVER_NAME` – optional specific server name (if you have multiple servers).

### Sync Services

- `TRAKT_CLIENT_ID` – client ID for your Trakt application (optional if only using Simkl).
- `TRAKT_CLIENT_SECRET` – client secret from your Trakt application (optional if only using Simkl).
- `SIMKL_CLIENT_ID` – client ID for your Simkl application (optional if only using Trakt).
- `SIMKL_CLIENT_SECRET` – client secret for your Simkl application (optional if only using Trakt).
- `TRAKT_REDIRECT_URI` – optional custom OAuth redirect URI for Trakt. If not
  set, the application uses the address from which the UI is accessed (for
  example, `http://localhost:5030/oauth/trakt`).
- `SIMKL_REDIRECT_URI` – optional custom OAuth redirect URI for Simkl. When
  unset, the address of the current UI is used automatically.
- `TZ` – timezone for log timestamps, defaults to `Europe/Madrid`.

You must set the Plex base URL, plex token (as fallback) and at least one pair of Trakt or Simkl
credentials. Leave the variables for the service you are not using unset.

You do **not** need to provide a Trakt access token or refresh token. The web
interface will guide you through authorizing the app and will store the tokens
for you.

Authorization codes will appear in the **OAuth** tab and can then be entered from the **Config.** tab, which shows whether each service is already configured.
If you want to remove saved tokens, the Config page also provides **Clear Config** buttons for both Trakt and Simkl.

All sync options and the chosen Plex user are saved to `settings.json` and
`selected_user.json` so your configuration persists across restarts.
When running PlexyTrack in Docker, mount a host directory and set
`PLEXYTRACK_DATA_DIR` to that path (for example `/data`) so the tokens and
settings survive container re-creation.


When specifying a custom redirect URI for either service, ensure the same
value is configured in your Trakt or Simkl application and passed via the
`TRAKT_REDIRECT_URI` or `SIMKL_REDIRECT_URI` environment variables.
PlexyTrack now honours the `X-Forwarded-Proto` and `X-Forwarded-Host` headers,
so when running behind a reverse proxy the correct redirect URI is detected
automatically. Set a redirect URI explicitly only when you need to override the
auto-detected value.

The application uses `plexapi` version 4.15 or newer (but below 5).

If you don't already have the Trakt or Simkl credentials, please see the next sections on how to obtain them.

## Quick Start

1. Install **Docker Desktop** (Windows/macOS) or `docker` and `docker-compose` (Linux).
2. [Download]([https://github.com/](https://github.com/Drakonis96/plexytrack)) or clone this repository and open a terminal inside the folder.
3. Create a file named `.env` and paste your Plex, Trakt or Simkl details as shown below:

   ```
   # Example .env
   PLEX_BASEURL=your_plex_base_url
   PLEX_TOKEN=your_plex_token
   
   TRAKT_CLIENT_ID=YOUR_TRAKT_CLIENT_ID
   TRAKT_CLIENT_SECRET=YOUR_TRAKT_CLIENT_SECRET
   
   SIMKL_CLIENT_ID=YOUR_SIMKL_CLIENT_ID
   SIMKL_CLIENT_SECRET=YOUR_SIMKL_CLIENT_SECRET
   
   # ...other variables...
   TZ=Europe/Madrid
   ```

4. Start the application with:

   ```
   docker-compose up -d
   ```

5. Open `http://localhost:5030` in your browser and follow the on‑screen steps to authorize Trakt or Simkl and select the Plex user you want to sync.

Once configured, PlexyTrack will keep your libraries in sync on the schedule you choose.

### Collections and watchlists

If you mark a list as liked on Trakt, PlexyTrack will create a Plex collection with the same name and add the matching movies or shows found in your library. Likewise, any collection created in Plex will be mirrored as a list on Trakt. Watchlists are also kept in sync both ways, so adding or removing an item in one platform is reflected in the other.
When the Simkl provider is selected, your Plex library is copied to the **My TV Shows** and **My Movies** sections on Simkl and Plex collections are mirrored as Simkl lists.

### Backup and restore

From the web interface you can download a backup file containing your Trakt history, watchlist and ratings. This JSON file can be uploaded again to restore your data at any time. Creating a backup is recommended before starting synchronization for the first time.

### Live sync

When **Live Sync** is enabled on the main page, PlexyTrack will start a
webhook endpoint at `/webhook`. Configure a Plex Webhook to call this URL and
the application will trigger an immediate sync whenever an event is received.

## Getting a Plex token

1. Open the Plex Web application and sign in.
2. Pick any movie or show and click the three dots in the lower right corner to
   open **Get Info**.
3. In the information panel choose **View XML**. A new tab will display the XML
   data for that item.
4. Copy the value of `X-Plex-Token` from the URL bar – that's your token.
5. If you need more details, Plex offers instructions at <https://support.plex.tv/articles/204059436-finding-an-authentication-token-x-plex-token/>.

## Getting Trakt API credentials

1. Log in to your Trakt account and open <https://trakt.tv/oauth/applications>.
2. Create a new application. Any name will work and you can use `urn:ietf:wg:oauth:2.0:oob` as the redirect URL. If you want the authorization code to be filled automatically, set the redirect URL to something like `http://localhost:5030/oauth/trakt` and configure the same value if you provide a `TRAKT_REDIRECT_URI` environment variable.
3. After saving the app you will see a **Client ID** and **Client Secret**. Keep them handy.
4. Start PlexyTrack and open `http://localhost:5030` in your browser. From the **Config.** tab you can authorize PlexyTrack on Trakt. After authorizing, Trakt will redirect you to the **OAuth** tab where the code will appear automatically.

## Getting Simkl API credentials

1. Sign in to your Simkl account and visit <https://simkl.com/apps>.
2. Click **Create new app**, provide any name and set the redirect URL to match `http://localhost:5030/oauth/simkl` or your `SIMKL_REDIRECT_URI`.
3. After saving the app you will see a **Client ID** and **Client Secret**. Keep them handy.
4. Open PlexyTrack and from the **Config.** tab choose **Configure** under Simkl to authorize the app.


## Running with Docker Compose

1. Clone this repository.
2. Create a `.env` file in the project root and define the variables listed above. Example:

```
PLEX_BASEURL=your_plex_base_url
PLEX_TOKEN=your_plex_token

#PLEX_EMAIL=your_plex_email@example.com #Better to provide it through the webUI
#PLEX_PASSWORD=your_plex_password #Better to provide it through the webUI
#PLEX_2FA_CODE=123456  # Only if 2FA is enabled and better to provide it through the webUI
#PLEX_SERVER_NAME=MyServer  # Only if you have multiple servers, but still, better to provide it through the webUI

TRAKT_CLIENT_ID=YOUR_TRAKT_CLIENT_ID
TRAKT_CLIENT_SECRET=YOUR_TRAKT_CLIENT_SECRET

SIMKL_CLIENT_ID=YOUR_SIMKL_CLIENT_ID
SIMKL_CLIENT_SECRET=YOUR_SIMKL_CLIENT_SECRET

# Optional custom redirect URIs
# TRAKT_REDIRECT_URI=http://localhost:5030/oauth/trakt
# SIMKL_REDIRECT_URI=http://localhost:5030/oauth/simkl

TZ=Europe/Madrid
# Directory to store tokens and settings
PLEXYTRACK_DATA_DIR=/data
```

Make sure a `data/` folder exists next to the compose file so the container can
persist its configuration.

3. Start the application using Docker Compose. The default `docker-compose.yml`
   pulls the image from Docker Hub:

```
docker-compose up -d
```

If you prefer to build the image locally use the `docker-compose-local.yml`
file:

```
docker-compose -f docker-compose-local.yml up --build
```

4. Visit `http://localhost:5030` in your browser. You can adjust the sync interval on the page. The **Start Sync** button schedules the job, while **Stop Sync** now immediately cancels any running sync and removes future scheduled jobs.

   A sync interval of **at least 60 minutes is recommended**. Shorter intervals are generally unnecessary, and you can even schedule the job every 24 hours to reduce the load on your server and the Trakt or Simkl API.

That's it! The container will continue to sync your Plex account with Trakt and/or Simkl according to the interval you set.

## User Selection

When using PlexyTrack with multiple Plex users (owner and managed users), you can choose which user's viewing history to synchronize.

After selecting a user, you'll see a confirmation message indicating that the user was selected successfully. Each user's history is synchronized independently and always with a **full sync** to ensure complete data integrity across Plex, Trakt and Simkl.

## Personalized Sync Direction

Owner users can choose how each sync type flows between Plex and the selected provider. For Watched History, Liked Lists, Watchlists, Collections and Ratings you may select:

- **Bidirectional** – changes are mirrored both ways.
- **Plex → Trakt/Simkl** – only send data from Plex to the service.
- **Trakt/Simkl → Plex** – only import data from the service into Plex.

Managed users always use the Plex → service direction.

## Screenshots

Below are a few images of the PlexyTrack web interface.

<p align="center">
  <img src="screenshots/Screenshot%201.png" alt="Screenshot 1" width="400" />
  <img src="screenshots/Screenshot%202.png" alt="Screenshot 2" width="400" />
  <br />
  <img src="screenshots/Screenshot%203.png" alt="Screenshot 3" width="400" />
  <img src="screenshots/Screenshot%204.png" alt="Screenshot 4" width="400" />
</p>


