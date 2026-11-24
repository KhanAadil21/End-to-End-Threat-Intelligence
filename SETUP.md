# How I set up Stage 3

These are the steps I followed to build the Stage 3 lab, in the order I'd do them again. It covers the Azure side, T-Pot, the Wazuh manager, getting alerts into Sentinel, the analytics rules and the playbook.

I hit a fair few problems along the way, so I've written the guide around what actually worked rather than the first plan. Where something tripped me up, there's a note about it.

Anything in `<angle brackets>` is a placeholder. Swap in your own values, and keep the real ones out of Git.

## Contents

1. [What you need first](#1-what-you-need-first)
2. [Azure basics](#2-azure-basics)
3. [The two VMs](#3-the-two-vms)
4. [T-Pot as a Sensor](#4-t-pot-as-a-sensor)
5. [Wazuh manager and rules](#5-wazuh-manager-and-rules)
6. [Wazuh agent on T-Pot](#6-wazuh-agent-on-t-pot)
7. [Azure Monitor (where the alerts land)](#7-azure-monitor-where-the-alerts-land)
8. [Connecting Wazuh to Sentinel](#8-connecting-wazuh-to-sentinel)
9. [Turning on Sentinel](#9-turning-on-sentinel)
10. [The playbook](#10-the-playbook)
11. [Checking it all works](#11-checking-it-all-works)
12. [When things break](#12-when-things-break)
13. [Tearing it down](#13-tearing-it-down)

## 1. What you need first

- An Azure subscription. I used a Free Trial ($200 credit for 30 days) and ran the lab for about three weeks.
- An SSH key. I made a separate one just for this project: `ssh-keygen -t ed25519 -f ~/.ssh/azure-soc`. Write the passphrase down somewhere safe. I forgot mine once and had to make a new key.
- A free AbuseIPDB account and API key, for the playbook.
- Optional: a Telegram bot from @BotFather (you'll need its token and your own chat ID), and a Slack workspace with an incoming webhook, if you want alerts on your phone.

## 2. Azure basics

**Register the resource providers.** A new subscription can't create some resource types until their provider is registered. Under Subscriptions → Resource providers, register `Microsoft.Compute`, `Microsoft.Network`, `Microsoft.OperationalInsights`, `Microsoft.Insights`, `Microsoft.SecurityInsights` and `Microsoft.OperationsManagement`. Until I did this, the Quotas page showed nothing at all.

**Check the quota and pick a region.** The Free Trial gives you 4 vCPUs per region, which is exactly enough for two 2-vCPU VMs. In Quotas → Compute, check both Total Regional vCPUs and Standard BASv2 Family. I started in Canada Central, but the B-series sizes weren't available to my subscription there, so the VMs ended up in **Austria East**.

**Set a budget.** Cost Management → Budgets. I set $150 with email alerts at 25%, 50% and 90%. The 25% one did fire, which was a nice way of knowing where I stood.

**Make one resource group** called `rg-honeypot-soc1` and put everything in it. When the lab is done, deleting that one group removes all of it.

**Build the network** in the same region as the VMs: a VNet called `vnet-soc1` with two subnets, `snet-siem` (10.10.1.0/24) for Wazuh and `snet-honeypot` (10.10.2.0/24) for T-Pot.

**Add the firewalls.** Each subnet gets its own NSG. I attached them to the subnets rather than the VMs' network cards, so there's only one place to change rules. Source port is `*` on every rule (clients pick a random one), and I mixed that up with the destination port the first time.

`nsg-siem`, on `snet-siem`:

| Priority | Name | From | Ports | Protocol | Action |
|---|---|---|---|---|---|
| 100 | Allow-SSH-MyIP | My IP address | 22 | TCP | Allow |
| 110 | Allow-Wazuh-Agents-VNet | Service tag VirtualNetwork | 1514-1515 | TCP | Allow |
| 4000 | Deny-VNet-Other | Service tag VirtualNetwork | * | Any | Deny |

`nsg-honeypot`, on `snet-honeypot`:

| Priority | Name | From | Ports | Protocol | Action |
|---|---|---|---|---|---|
| 100 | Allow-Mgmt-MyIP | My IP address | 22, 64295, 64297 | TCP | Allow |
| 110 | Deny-VNet-Other | Service tag VirtualNetwork | * | Any | Deny |
| 200 | Allow-Honeypot-Internet | Any | 1-64000 | Any | Allow |

Hold off on the priority 200 rule until step 6. There's no point letting attackers in before anything is recording them.

## 3. The two VMs

| | Wazuh VM | T-Pot VM |
|---|---|---|
| Image | Ubuntu Server 24.04 LTS | Ubuntu Server 26.04 LTS (the plain one, not Ubuntu Pro) |
| Size | B2als_v2 (2 vCPU, 4 GB) | B2as_v2 (2 vCPU, 8 GB) |
| Security type | Standard | Standard |
| Login | SSH key | SSH key |
| Public inbound ports | None | None |
| Disk | 64 GB Standard SSD | 128 GB Standard SSD |
| Subnet | snet-siem | snet-honeypot |
| NIC security group | None | None |
| Auto-shutdown | Off | Off |
| Boot diagnostics | On | On |

A few notes on these choices:

- **Security type Standard**, because Trusted launch was blocking the B-series sizes for me.
- **Public inbound ports None**, because the subnet NSGs already handle access. Opening ports here would add a second firewall to keep in sync.
- **T-Pot needs Ubuntu 26.04.** I built it on 24.04 first and the installer refused to run.
- Tick **Delete with VM** for the disk, network card and public IP, so nothing gets left behind and keeps billing.

## 4. T-Pot as a Sensor

On the T-Pot VM, logged in as your normal user (the installer won't run as root):

```bash
sudo apt update && sudo apt upgrade -y
cd ~
env bash -c "$(curl -sL https://github.com/telekom-security/tpotce/raw/master/install.sh)"
```

Pick **Sensor** (`s`). The Hive option runs its own Elasticsearch, and on an 8 GB VM that left me with about 400 MB free. I didn't need ELK anyway, since Sentinel does that job now.

Here's the part that cost me an evening. A Sensor expects to send its logs to a T-Pot Hive, and its startup container (`tpotinit`) refuses to start without one. None of the honeypots start until `tpotinit` is happy. I don't have a Hive, so I gave it placeholder values:

```bash
sed -i 's/^TPOT_TYPE=.*/TPOT_TYPE=SENSOR/' ~/tpotce/.env
sed -i 's/^TPOT_HIVE_USER=.*/TPOT_HIVE_USER=bm9oaXZlOm5vaGl2ZQ==/' ~/tpotce/.env   # "nohive:nohive" in base64
sed -i 's/^TPOT_HIVE_IP=.*/TPOT_HIVE_IP=127.0.0.1/' ~/tpotce/.env
sudo reboot
```

After the reboot, your SSH moves to port 64295 (T-Pot gives port 22 to the fake Cowrie SSH):

```bash
ssh -i ~/.ssh/azure-soc -p 64295 <user>@<TPOT_PUBLIC_IP>
sudo docker ps --format "table {{.Names}}\t{{.Status}}"
```

You should see 30-odd containers, all Up. The honeypot logs live in `~/tpotce/data/<honeypot>/log/`.

If `docker ps` comes back empty, run `cd ~/tpotce && sudo docker compose up tpotinit`. It prints the real error straight to your screen, which the system logs don't.

## 5. Wazuh manager and rules

On the Wazuh VM, add Wazuh's repository and install just the manager (no indexer or dashboard, since Sentinel replaces them):

```bash
sudo apt install -y gnupg apt-transport-https
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update && sudo apt install -y wazuh-manager
sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-manager
```

Then copy in the rules from `wazuh/`. I add a `9` to the front of each file name. Wazuh loads its own rules and yours as one alphabetical list, and a rule can only build on a parent that's already loaded. With the original names, three of my Windows rules pointed at parents that loaded later, so Wazuh quietly ignored them.

```bash
for f in wazuh/0*_rules.xml; do sudo cp "$f" "/var/ossec/etc/rules/9$(basename "$f")"; done
sudo sh -c 'chown wazuh:wazuh /var/ossec/etc/rules/90*_rules.xml && chmod 660 /var/ossec/etc/rules/90*_rules.xml'
sudo /var/ossec/bin/wazuh-analysisd -t      # silence means everything loaded
sudo systemctl restart wazuh-manager
```

The `sh -c` is there because the rules folder is root-only. Your own shell can't see inside it, so a plain `sudo chmod ... *` fails with "No such file".

You don't need the custom Cowrie decoder from Stage 2 on Wazuh 4.14.9. I checked with `sudo /var/ossec/bin/wazuh-logtest` and a real line from `cowrie.json`, and the built-in JSON decoder handled it fine.

## 6. Wazuh agent on T-Pot

On T-Pot, add the same Wazuh repository (the first three commands in step 5), then install the agent pointed at the manager's **private** IP, so logs stay inside the VNet:

```bash
sudo WAZUH_MANAGER="<WAZUH_PRIVATE_IP>" WAZUH_AGENT_NAME="tpot-sensor" apt install -y wazuh-agent
```

The agent doesn't go looking for log files by itself. Append the blocks from `wazuh/tpot-agent-localfiles.xml` to `/var/ossec/etc/ossec.conf` (change `/home/<user>/` to your username), then start it:

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent
sudo grep "Analyzing file" /var/ossec/logs/ossec.log | tail     # one line per honeypot log
```

On the manager, `sudo /var/ossec/bin/agent_control -l` should show the agent as Active. Don't worry if its IP shows as "any"; that's the default, and the agent key is what identifies it.

Now go back and add the `Allow-Honeypot-Internet` rule. Attacks usually start within minutes.

## 7. Azure Monitor (where the alerts land)

**Use a region where Sentinel actually runs.** I built all of this in Austria East first, and then couldn't turn Sentinel on. Microsoft's Sentinel region list doesn't include it. I rebuilt it in **Canada Central**, and the VMs stayed where they were. The workspace, DCE and DCR all have to be in the same region as each other.

1. **Workspace.** Create a Log Analytics workspace, `law-honeypot-soc-ca` (pay-as-you-go is the right tier). Then set Usage and estimated costs → Daily cap to **1 GB**, as a safety net.
2. **Data collection endpoint.** Create `dce-honeypot-soc-ca` and copy its **Logs Ingestion** URL. This is the address the script sends to.
3. **App registration.** In Entra ID, register `wazuh-sentinel-ingest` (single tenant, no redirect URI). Copy the tenant ID and client ID. Under Certificates & secrets, make a client secret and copy the **Value** straight away. Azure only shows it once, and it's easy to grab the Secret ID by mistake.
4. **Table and DCR.** In the workspace, go to Tables → Create → New custom log (DCR-based). Call the table `WazuhAlerts` (Azure adds `_CL`), keep the Analytics plan, create a new DCR called `dcr-wazuh-alerts-ca`, and pick your DCE. Upload `integrations/sample-record.json` so Azure can work out the columns, and leave the transformation as `source`.
5. **Permission.** On the **DCR** (not the table or the workspace), go to Access control (IAM) and give the app **Monitoring Metrics Publisher**. That's all it can do: send data to this one DCR. It can take up to 30 minutes to kick in.
6. **DCR ID.** DCR → Overview → JSON View, and copy the `immutableId`.

## 8. Connecting Wazuh to Sentinel

Copy the script onto the manager and give it a launcher. Wazuh doesn't run integration `.py` files directly; it runs a small launcher script that starts them. Without one, integratord complains that the file "has write permissions", which threw me because the permissions were fine. Copying the built-in Slack launcher works:

```bash
sudo cp integrations/custom-sentinel.py /var/ossec/integrations/custom-sentinel.py
sudo cp -p /var/ossec/integrations/slack /var/ossec/integrations/custom-sentinel
sudo chown root:wazuh /var/ossec/integrations/custom-sentinel*
sudo chmod 750 /var/ossec/integrations/custom-sentinel*
```

Make `/var/ossec/integrations/sentinel.json` from `integrations/sentinel.json.example`, fill in the six values from step 7, and lock it down, since it holds the client secret:

```bash
sudo chown root:wazuh /var/ossec/integrations/sentinel.json
sudo chmod 640 /var/ossec/integrations/sentinel.json
```

Test it by hand before switching on automatic sending:

```bash
sudo tail -n 1 /var/ossec/logs/alerts/alerts.json | sudo tee /tmp/test-alert.json >/dev/null
sudo chmod 644 /tmp/test-alert.json
PY=/var/ossec/framework/python/bin/python3
sudo -u wazuh $PY /var/ossec/integrations/custom-sentinel.py --dry-run /tmp/test-alert.json
sudo -u wazuh $PY /var/ossec/integrations/custom-sentinel.py /tmp/test-alert.json; echo "exit code: $?"
```

The dry run prints the record it would send. The second command actually sends it. Exit code 0 means Azure took it. Give the first row 5 to 15 minutes to show up, then check in the workspace's Logs:

```kusto
WazuhAlerts_CL
| take 10
```

Once that works, append `integrations/ossec-integration-block.xml` to `/var/ossec/etc/ossec.conf` and restart:

```bash
sudo systemctl restart wazuh-manager
sudo grep -i integratord /var/ossec/logs/ossec.log | tail -n 3
```

You want to see `Enabling integration for: 'custom-sentinel'`. From then on, every alert at level 7 or above goes to Sentinel by itself.

## 9. Turning on Sentinel

1. Search Microsoft Sentinel → Create, pick `law-honeypot-soc-ca`, and Add. The 31-day trial (10 GB a day free) starts here, so I left this until data was already flowing. Day to day, Sentinel is now run from the Defender portal at security.microsoft.com.
2. **Analytics rules.** Configuration → Analytics → Import, choose `sentinel/Azure_Sentinel_analytics_rules.json`, and give it the workspace name.
3. **Workbook.** Workbooks → Add workbook → Edit → the `</>` Advanced Editor, paste in `sentinel/honeypot-soc-overview.workbook.json`, Apply, then Save.

## 10. The playbook

**Create the Logic App.** Make a Consumption Logic App called `pb-abuseipdb-enrich`, open Logic app code view, and paste in `playbook/pb-abuseipdb-enrich.json`. Then replace the placeholders: `<SUBSCRIPTION_ID>`, `<ABUSEIPDB_API_KEY>`, `<TELEGRAM_BOT_TOKEN>`, `<TELEGRAM_CHAT_ID>` and `<SLACK_WEBHOOK_URL>`.

If you'd rather build it in the designer, the steps are: Sentinel incident trigger → Entities - Get IPs → For each IP: HTTP to AbuseIPDB → Parse JSON → Add comment to incident (V3) → HTTP to Telegram → HTTP to Slack.

**Give it an identity.** Turn on the system-assigned managed identity, and use it for the Sentinel connection. That way there's no password to store.

**Permissions.** Two different identities need roles:

| Who | Role | Where | Why |
|---|---|---|---|
| The playbook's managed identity | Microsoft Sentinel Responder | The workspace | So it can comment on incidents |
| Azure Security Insights (Sentinel itself) | Microsoft Sentinel Automation Contributor | The resource group | So Sentinel can start the playbook |

**Hide the secrets.** On every HTTP step, turn on Secure inputs and Secure outputs in Settings. Otherwise your API key, bot token and webhook sit in plain text in the run history.

**Automation rule.** Sentinel → Automation → Create → Automation rule. Trigger "When incident is created", condition Analytic rule name contains both honeypot rules, action Run playbook `pb-abuseipdb-enrich`, order 1.

The Defender portal kept showing "Missing permissions" next to my playbook. It's looking for a Microsoft service account that doesn't exist in a new tenant. As long as the roles above are in place, it works. I'd test it with a real incident before changing anything.

## 11. Checking it all works

- `sudo docker ps` on T-Pot shows every honeypot Up.
- `agent_control -l` on the manager shows the agent Active.
- `wazuh-analysisd -t` prints nothing.
- In Logs, `WazuhAlerts_CL | summarize count() by RuleId` shows your custom rule IDs arriving.
- Incidents appear in Sentinel from both analytics rules.
- The playbook's Run history shows green runs.
- Each new incident gets the AbuseIPDB comment, and the alert reaches Telegram and Slack.

The quickest end-to-end test I found: SSH to port 22 on T-Pot (that's Cowrie), log in as root with any password except `root`, run `wget http://example.com/test` and exit. That creates a High incident within about 10 to 15 minutes.

## 12. When things break

These all happened to me at some point.

| What you see | What's going on | What fixed it |
|---|---|---|
| T-Pot installer won't start | Wrong Ubuntu version | Use the one it asks for (26.04) |
| `docker ps` is empty and `tpotinit` keeps restarting | Sensor with no Hive settings | The `.env` values in step 4; `docker compose up tpotinit` shows the real error |
| `if_sid ... not found` warnings | Rule file load order | Put a `9` in front of the custom rule file names |
| `CERTIFICATE_VERIFY_FAILED` in integrations.log | Wazuh's Python can't find Ubuntu's certificates | The script in this repo already points at `/etc/ssl/certs/ca-certificates.crt` |
| integratord says the file "has write permissions" | No launcher | Create the `custom-sentinel` launcher and use that name in ossec.conf |
| HTTP 401 | Wrong tenant ID, client ID or secret (often the Secret ID instead of the Value) | Recheck `sentinel.json` |
| HTTP 403 | Role missing on the DCR, or not active yet | Assign it on the DCR and wait up to 30 minutes |
| HTTP 404 | Wrong DCR ID or stream name | Recheck `sentinel.json` |
| Sentinel's Add button is greyed out | Workspace in a region Sentinel doesn't support | Rebuild step 7 somewhere supported |
| Portal says 401 "token from the wrong issuer" | You've ended up in a different tenant | Settings → Directories + subscriptions → switch back |
| Telegram says the bot "can't send messages to the bot" | You used the bot's own ID as the chat ID | Use your own ID instead |

## 13. Tearing it down

When you're done:

1. Delete the resource group `rg-honeypot-soc1`. That takes everything inside it.
2. Delete the app registration `wazuh-sentinel-ingest` in Entra ID. Its secret would otherwise stay valid for months.
3. Delete the AbuseIPDB key, revoke the Telegram bot token with BotFather, and remove the Slack webhook.
4. Check Cost Management the next day to make sure the daily cost has dropped to zero.
