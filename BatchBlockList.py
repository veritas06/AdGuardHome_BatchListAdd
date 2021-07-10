from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
import ssl
import requests
import json

## CHANGE HERE ##
# ip address of AdGuard Home
# "http(s)://<adguardHomeIp:<port>"
host = "https://<<hostname_or_IP>>:<<port>>" 
# user name
userName = "userName"
# password
password = "password"

# block list 
# taken from Wally3K's Firebog https://firebog.net/
urls = [
"https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt",
"https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt",
"https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt",
"https://mirror1.malwaredomains.com/files/justdomains",
"https://v.firebog.net/hosts/Prigent-Crypto.txt",
"https://mirror.cedia.org.ec/malwaredomains/immortal_domains.txt",
"https://www.malwaredomainlist.com/hostslist/hosts.txt",
"https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt",
"https://phishing.army/download/phishing_army_blocklist_extended.txt",
"https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt",
"https://v.firebog.net/hosts/Shalla-mal.txt",
"https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",
"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts",
"https://urlhaus.abuse.ch/downloads/hostfile/",
"https://v.firebog.net/hosts/Easyprivacy.txt",
"https://v.firebog.net/hosts/Prigent-Ads.txt",
"https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt",
"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts",
"https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
"https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt",
"https://zerodot1.gitlab.io/CoinBlockerLists/hosts_browser",
"https://adaway.org/hosts.txt",
"https://v.firebog.net/hosts/AdguardDNS.txt",
"https://v.firebog.net/hosts/Admiral.txt",
"https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
"https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
"https://v.firebog.net/hosts/Easylist.txt",
"https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts",
"https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts",
"https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts_without_controversies.txt",
"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts",
"https://v.firebog.net/hosts/static/w3kbl.txt",
"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
"http://sysctl.org/cameleon/hosts",
"https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
"https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
"https://reddestdream.github.io/Projects/MinimalHosts/etc/MinimalHostsBlocker/minimalhosts",
"https://adaway.org/hosts.txt",
"https://v.firebog.net/hosts/AdguardDNS.txt",
"https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
"https://v.firebog.net/hosts/Easylist.txt",
"https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts;showintro=0",
"https://raw.githubusercontent.com/StevenBlack/hosts/master/data/UncheckyAds/hosts",
"https://v.firebog.net/hosts/Easyprivacy.txt",
"https://v.firebog.net/hosts/Prigent-Ads.txt",
"https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt",
"https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.2o7Net/hosts",
"https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt",
"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt",
"https://v.firebog.net/hosts/Airelle-trc.txt",
"https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt",
"https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt",
"https://v.firebog.net/hosts/Prigent-Malware.txt",
"https://v.firebog.net/hosts/Prigent-Phishing.txt",
"https://phishing.army/download/phishing_army_blocklist_extended.txt",
"https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt",
"https://v.firebog.net/hosts/Shalla-mal.txt",
"https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Risk/hosts",
"https://raw.githubusercontent.com/HorusTeknoloji/TR-PhishingList/master/url-lists.txt",
"https://v.firebog.net/hosts/Airelle-hrsk.txt",
"https://github.com/chadmayfield/pihole-blocklists/raw/master/lists/pi_blocklist_porn_all.list",
"https://raw.githubusercontent.com/chadmayfield/pihole-blocklists/master/lists/pi_blocklist_porn_top1m.list",
"https://zerodot1.gitlab.io/CoinBlockerLists/hosts",
"https://raw.githubusercontent.com/anudeepND/blacklist/master/facebook.txt",
"http://winhelp2002.mvps.org/hosts.txt",
"https://dbl.oisd.nl/",
"https://v.firebog.net/hosts/HPHosts-ads.txt",
"https://v.firebog.net/hosts/HPHosts-emd.txt",
"https://www.joewein.net/dl/bl/dom-bl.txt",
"https://gist.githubusercontent.com/anudeepND/adac7982307fec6ee23605e281a57f1a/raw/5b8582b906a9497624c3f3187a49ebc23a9cf2fb/Test.txt",
"https://github.com/StevenBlack/hosts/blob/master/extensions/gambling/hosts",
"https://hostsfile.mine.nu/hosts0.txt",
"https://hostsfile.org/Downloads/hosts.txt",
"https://openphish.com/feed.txt",
"https://pgl.yoyo.org/as/serverlist.php?showintro=0&startdate%5Byear%5D=2000",
"https://raw.githubusercontent.com/anudeepND/blacklist/master/CoinMiner.txt",
"https://raw.githubusercontent.com/Dawsey21/Lists/master/main-blacklist.txt",
"https://raw.githubusercontent.com/piwik/referrer-spam-blacklist/master/spammers.txt",
"https://raw.githubusercontent.com/reek/anti-adblock-killer/master/anti-adblock-killer-filters.txt",
"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts",
"https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Spam/hosts",
"https://raw.githubusercontent.com/StevenBlack/hosts/master/data/KADhosts/hosts",
"https://raw.githubusercontent.com/vokins/yhosts/master/hosts",
"https://v.firebog.net/hosts/BillStearns.txt",
"https://v.firebog.net/hosts/static/SamsungSmart.txt",
"https://v.firebog.net/hosts/static/w3kbl.txt",
"https://www.joewein.net/dl/bl/dom-bl-base.txt",
"https://adblock.mahakala.is/",
"https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&startdate%5Bday%5D=&startdate%5Bmonth%5D=&startdate%5Byear%5D=&useip=0.0.0.0",
"https://someonewhocares.org/hosts/zero/hosts",
"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/AmazonFireTV.txt",
"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SessionReplay.txt",
"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt",
"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/regex.list",
"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling/hosts",
"https://www.github.developerdan.com/hosts/lists/facebook-extended.txt",
"https://raw.githubusercontent.com/superover/TikTok-Blocklist/master/tiktok.txt",
"https://raw.githubusercontent.com/matholio/pihole.newscorp/master/newscorp.txt",
"https://raw.githubusercontent.com/StevenBlack/hosts/master/extensions/fakenews/hosts",
"https://raw.githubusercontent.com/jmdugan/blocklists/master/corporations/facebook/facebook.com",
"https://raw.githubusercontent.com/DandelionSprout/adfilt/master/GameConsoleAdblockList.txt",
"https://raw.githubusercontent.com/DandelionSprout/adfilt/master/AdGuard%20Home%20Compilation%20List/AdGuardHomeCompilationList.txt",
"https://v.firebog.net/hosts/Cameleon.txt",
"https://v.firebog.net/hosts/HostsFileOrg.txt",
"https://v.firebog.net/hosts/JoeWein.txt",
"https://v.firebog.net/hosts/Mahakala.txt",
"https://v.firebog.net/hosts/JoeyLane.txt",
"https://v.firebog.net/hosts/PeterLowe.txt",
"https://v.firebog.net/hosts/PiwikSpam.txt",
"https://v.firebog.net/hosts/ReddestDream.txt",
"https://v.firebog.net/hosts/SBDead.txt",
"https://v.firebog.net/hosts/SBKAD.txt",
"https://v.firebog.net/hosts/SBSpam.txt",
"https://v.firebog.net/hosts/SomeoneWC.txt",
"https://v.firebog.net/hosts/Spam404.txt",
"https://v.firebog.net/hosts/Vokins.txt",
"https://v.firebog.net/hosts/Winhelp2002.txt",
"https://v.firebog.net/hosts/AdAway.txt",
"https://v.firebog.net/hosts/Disconnect-ads.txt",
"https://v.firebog.net/hosts/SBUnchecky.txt",
"https://v.firebog.net/hosts/Disconnect-trc.txt",
"https://v.firebog.net/hosts/Disconnect-mal.txt",
"https://v.firebog.net/hosts/SB2o7Net.txt",
"https://v.firebog.net/hosts/APT1Rep.txt",
"https://v.firebog.net/hosts/MalImmortal.txt",
"https://v.firebog.net/hosts/DNS-BH-mal.txt",
"https://v.firebog.net/hosts/Openphish.txt",
"https://v.firebog.net/hosts/SBRisk.txt",
"https://v.firebog.net/hosts/Admiral.txt",
"https://v.firebog.net/hosts/Kowabit.txt",
"https://v.firebog.net/hosts/neohostsbasic.txt",
"https://v.firebog.net/hosts/Prigent-Crypto.txt",
"https://raw.githubusercontent.com/dnsblocklistnet/blocklists/master/conspiracy.list",
"https://raw.githubusercontent.com/dnsblocklistnet/blocklists/master/multilevelmarketing.list",
"https://raw.githubusercontent.com/antifa-n/pihole/master/blocklist.txt",
"https://raw.githubusercontent.com/antifa-n/pihole/master/blocklist-pop.txt",
"https://raw.githubusercontent.com/antifa-n/pihole/master/blocklist-alttech.txt",
"https://bitbucket.org/Laicure/public/downloads/hosts",
"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/mobile.txt",
"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/general_elemhide.txt",
"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/css_extended.txt",
"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers.txt",
"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers_firstparty.txt",
"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/cname_trackers.txt",
"https://raw.githubusercontent.com/d43m0nhLInt3r/socialblocklists/master/Snapchat/snapchatblocklist.txt",
"https://raw.githubusercontent.com/d43m0nhLInt3r/socialblocklists/master/MobileAppAds/appadsblocklist.txt",
"https://raw.githubusercontent.com/d43m0nhLInt3r/socialblocklists/master/SmartTV/smarttvblocklist.txt",
"https://raw.githubusercontent.com/d43m0nhLInt3r/socialblocklists/master/Facebook/facebookblocklist.txt",
"https://raw.githubusercontent.com/veritas06/pihole_lists/main/AdguardTeam-CNAME.lst",
"https://www.github.developerdan.com/hosts/lists/amp-hosts-extended.txt",
"https://raw.githubusercontent.com/d43m0nhLInt3r/socialblocklists/master/Tracking/trackingblocklist.txt",
"https://raw.githubusercontent.com/craiu/mobiletrackers/master/list.txt",
"https://raw.githubusercontent.com/craiu/mobiletrackers/master/windowslist.txt",
"https://raw.githubusercontent.com/Cauchon/NSABlocklist-pi-hole-edition/master/HOSTS%20(including%20excessive%20GOV%20URLs)",
"https://raw.githubusercontent.com/rimu/no-qanon/master/etc_hosts.txt",
"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/combined_disguised_trackers_justdomains.txt",
"https://raw.githubusercontent.com/veritas06/pihole_lists/main/RightWingWeb.lst",
"https://raw.githubusercontent.com/veritas06/pihole_lists/main/AdguardTeam-GoogleContributorTrackingDomains.lst",
"https://raw.githubusercontent.com/veritas06/pihole_lists/main/clubhouse.lst",
"https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt",
"https://www.github.developerdan.com/hosts/lists/hate-and-junk-extended.txt",
"https://www.github.developerdan.com/hosts/lists/tracking-aggressive-extended.txt"
]

############ End Edits #################

# Open TLSv1 Adapter
class MyAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_version=ssl.PROTOCOL_TLSv1_2)

headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0'}     

s = requests.Session()
s.mount(host, MyAdapter())
x = s.post(host + "/control/login", json.dumps({"name": userName, "password" : password}), headers=headers )
print(x.text)

for u in urls:
        filterObj = json.dumps({'url':u, "name":u,"whitelist":False})
        print(filterObj)
        x = s.post(host + "/control/filtering/add_url", data = filterObj, headers=headers)
        print(x.text)

# help from 
# https://stackoverflow.com/questions/30946370/using-requests-to-login-to-a-website-that-has-javascript-login-form
# https://stackoverflow.com/questions/33818206/python-login-into-a-website-with-javascript-form
