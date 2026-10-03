# mailtest

An auto-responder for [mailcow](https://mailcow.email/). Send a mail with
the subject **Mailtest** to the configured address and receive a branded HTML
report showing everything your receiving server could see about the sender:
connecting IP, rDNS/FCrDNS, HELO, TLS, SPF/DKIM/DMARC results, DNS records of
the sender domain, the full Received path, Rspamd score, and all raw headers.

If the service is used more than `ALERT_THRESHOLD` times per day an alert is
sent once per day to `ALERT_TO`.

---

<!-- screenshot placeholder -->
> **Screenshot** – replace this placeholder with a real screenshot once the
> service is running.

---

## Mailcow setup

1. Log into your mailcow admin panel.
2. Create a new mailbox, e.g. `mail-test@yourdomain.example`.
3. Generate an **app password** for that mailbox (Mailboxes → Edit → App
   passwords). Do **not** use the account password.
4. Note the IMAP/SMTP hostname (usually the same as your mailcow FQDN).

---

## Configuration

All settings are passed as environment variables.

| Variable | Default | Description |
|---|---|---|
| `IMAP_HOST` | *(required)* | IMAP server hostname |
| `IMAP_PORT` | `993` | IMAP port |
| `SMTP_HOST` | `$IMAP_HOST` | SMTP server hostname |
| `SMTP_PORT` | `587` | SMTP port (587 = STARTTLS, 465 = SSL) |
| `MAIL_USER` | *(required)* | Login username (usually the full e-mail address) |
| `MAIL_PASSWORD` | *(required)* | App password |
| `MAIL_ADDRESS` | `$MAIL_USER` | From-address used in replies |
| `MY_HOSTNAME` | *(empty)* | FQDN of your MX as written in `by …` of Received headers – used to pick the right hop and trusted `Authentication-Results` header |
| `TRIGGER_SUBJECT` | `Mailtest` | Subject that triggers a reply |
| `FOLDERS` | `INBOX,Junk` | Comma-separated list of folders to poll |
| `PROCESSED_FOLDER` | `Processed` | Folder messages are moved to after processing |
| `POLL_SECONDS` | `30` | IMAP poll interval |
| `ALERT_TO` | `info@lucalutz.net` | Address for daily over-use alerts |
| `ALERT_THRESHOLD` | `5` | Uses per day that trigger an alert |
| `PER_SENDER_LIMIT_PER_HOUR` | `5` | Max replies to the same sender per hour |
| `COMPANY_NAME` | `Luca Lutz Networks` | Company name in the reply mail |
| `CONTACT_ADDRESS` | `info@lucalutz.net` | Contact address in the reply mail |
| `WEBSITE_URL` | `https://lucalutz.net` | URL linked in the footer |
| `LOGO_URL` | `https://lucalutz.net/logo-llwn.png` | Logo image URL – **use PNG**, Gmail and Outlook do not render SVG |
| `TZ` | `Europe/Berlin` | Timezone for timestamps in the report |
| `DB_PATH` | `/data/state.db` | Path to the SQLite state database |
| `DNS_SERVER` | *(system default)* | Custom resolver IPs, comma-separated |
| `MAX_ATTACH_BYTES` | `5242880` | Maximum size of the original mail attached to the reply |

---

## Deployment – Docker Compose

```sh
# 1. Copy the example env file and fill in your values
cp .env.example .env
$EDITOR .env

# 2. Start
docker compose up -d

# 3. Follow logs
docker compose logs -f
```

The default `docker-compose.yml` pulls the pre-built image from GHCR:

```yaml
image: ghcr.io/<owner>/mailtest:latest
```

To build locally instead, comment out the `image:` line and uncomment
`build: .`.

### Logo

Upload your logo to a public URL and set `LOGO_URL` to that address. Gmail
and Outlook do not display SVG images, so always use a PNG URL.

---

## Deployment – NixOS

### Flake input

```nix
# flake.nix
{
  inputs = {
    nixpkgs.url      = "github:NixOS/nixpkgs/nixos-unstable";
    mailtest.url     = "github:<owner>/mailtest";
    sops-nix.url     = "github:Mic92/sops-nix";   # optional, for secrets
  };

  outputs = { nixpkgs, mailtest, sops-nix, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        mailtest.nixosModules.default
        sops-nix.nixosModules.sops        # optional
        ./configuration.nix
      ];
    };
  };
}
```

### Module usage

```nix
# configuration.nix
{
  services.mailtest = {
    enable          = true;
    imapHost        = "mail.example.com";
    user            = "mail-test@example.com";
    myHostname      = "mail.example.com";
    alertTo         = "admin@example.com";
    companyName     = "My Company";
    contactAddress  = "admin@example.com";
    websiteUrl      = "https://example.com";
    logoUrl         = "https://example.com/logo.png";

    # Path to a file that contains MAIL_PASSWORD=...
    # The file is read by systemd and never enters the Nix store.
    environmentFile = "/run/secrets/mailtest";
  };
}
```

### Secrets with sops-nix

```nix
sops.secrets."mailtest" = {
  format      = "dotenv";
  sopsFile    = ./secrets/mailtest.env.enc;
  # file content: MAIL_PASSWORD=your-app-password
  owner       = "root";
  group       = "root";
  mode        = "0400";
};

services.mailtest.environmentFile = config.sops.secrets."mailtest".path;
```

### Secrets with agenix

```nix
age.secrets.mailtest = {
  file  = ./secrets/mailtest.age;   # content: MAIL_PASSWORD=...
  owner = "root";
  mode  = "0400";
};

services.mailtest.environmentFile = config.age.secrets.mailtest.path;
```

---

## Development

```sh
# Enter the dev shell (provides python, dnspython, pytest, ruff)
nix develop

# Run tests
pytest tests/ -q

# Lint / format
ruff check src/ tests/
ruff format src/ tests/

# Build the Nix package (includes tests)
nix build

# Check the full flake (package + NixOS module evaluation)
nix flake check
```
