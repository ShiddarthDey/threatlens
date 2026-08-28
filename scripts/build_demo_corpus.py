"""Build demo corpus from two real CIRCL MISP OSINT events (TLP:WHITE),
fetched 2026-06-12 via Claude's web fetch (sandbox lacks direct access).
Data is verbatim from the feed; nothing synthetic."""
import json, sys
sys.path.insert(0, "/tmp/tl")
from threatlens.schema import Report

turla_hosts = ["trytowin.ignorelist.com","treesofter.mooo.com","sportinfo.yourtrap.com",
"profound.zzux.com","badget.ignorelist.com","norwaynews.mooo.com","dellservice.publicvm.com",
"priceline.publicvm.com","forumgeek.zzux.com","mouses.strangled.net"]
turla_ips = ["209.239.79.69","82.146.174.240","82.146.166.61","193.220.55.6","83.229.62.212",
"169.255.100.152","113.208.81.33","82.146.174.40","82.146.175.52","113.208.81.48",
"83.229.75.141","77.246.76.19","209.239.79.121","209.239.79.125","217.194.150.31",
"82.146.166.58","217.194.149.111","169.255.100.122","169.255.101.65","113.208.81.55",
"217.8.36.239","83.229.62.210","82.146.175.48","82.146.175.69","41.203.79.74",
"77.73.187.223","217.194.150.22"]

t_lines = ["OSINT - Turla - Harnessing SSL Certificates Using Infrastructure Chaining",
"Event date: 2016-02-13","",
"Context:",
"Reference: http://blog.passivetotal.org/harnessing-ssl-certificates-using-infrastructure-chaining/",
"threat-actor: Turla","",
"Indicators:"]
t_lines += [f"hostname: {h}" for h in turla_hosts]
t_lines += [f"ip-dst: {i}" for i in turla_ips]
t_lines += ["x509-fingerprint-sha1: f415844680ed9118ea74e0c7712b35044f0cc20d"]

turla = Report(source="misp-circl", source_id="56bf4797-aaf4-4e08-ab5f-6cf102de0b81",
    title="OSINT - Turla - Harnessing SSL Certificates Using Infrastructure Chaining",
    url="https://www.circl.lu/doc/misp/feed-osint/56bf4797-aaf4-4e08-ab5f-6cf102de0b81.json",
    published="2016-02-13", text="\n".join(t_lines))

ds_ips = ["218.106.246.195","218.106.246.220","218.106.246.254","111.67.199.213",
"125.46.42.221","124.162.53.224","124.162.53.203","113.11.202.233","218.106.247.81",
"218.106.246.177","173.252.201.210","120.126.134.196","120.31.68.42","210.51.13.167",
"126.25.172.171","123.254.111.169","114.108.150.38","175.41.23.181","126.25.201.73",
"126.5.125.197","203.124.12.24","218.106.246.222","203.124.12.59","218.106.246.189",
"210.209.116.105","210.209.117.235","113.10.168.22","126.125.35.247","112.218.71.202",
"23.238.229.128","27.255.72.68","27.255.72.69","27.255.72.78","211.42.249.37",
"108.171.240.154","112.175.69.60","112.175.69.89","113.10.139.218","118.193.163.143",
"210.209.117.148","118.99.37.87","111.67.199.222","116.255.131.152","210.105.192.3",
"211.22.125.58","59.188.13.133","59.188.13.137"]
ds_hosts = ["bfym2.amazonwikis.com","books.sfcorporation.com","imnothk.8800.org",
"jiaoshow.9966.org","kb1gs.sfcorporation.com","kersperskey.8800.org","mailxss.9966.org",
"microses.9966.org","microupdate.8800.org","microwmies.oicp.net","mocrosoftds.xicp.net",
"modeless.3322.org","yhkj.sfcorporation.com","323332.3322.org","adobekr.com",
"js.95nb.co.cc","js.adobekr.com","login.live.adobekr.com","login.live.wih365.com",
"mesdata.8866.org","msejake.7766.org","msevpn.3322.org","sdj2b.3322.org",
"auto.glkjcorp.com","gde.moviestops.com","health.dns1.us","mail.adobekr.com",
"mail.glkjcorp.com","nttvps.gnway.net","qsgs.sfcorporation.com","smtp.adobekr.com",
"update.adobekr.com","wsxg.moviestops.com","wxpb.sfcorporation.com","en.amazonwikis.com",
"mail.projectscorp.net","news.sfcorporation.com","pic.elecarrow.com","rbjg.moviestops.com",
"rbny.sfcorporation.com","ssl.gmnspace.com","ssl.projectscorp.net","yahoo.gmnspace.com",
"yahoomail.adobeus.com","b3fk.sfcorporation.com","bdt.wordoscorp.com","blog.sfcorporation.com",
"bygs.sfcorporation.com","cbgs.sfcorporation.com","cdic.sfcorporation.com",
"d2ch.sfcorporation.com","dgfk.sfcorporation.com","guhk.moviestops.com","hglg.wordoscorp.com",
"hjxt.sfcorporation.com","home.sfcorporation.com","hsy.moviestops.com","image.amazonwikis.com",
"jggs.sfcorporation.com","jrfw.amazonwikis.com","jrgs.sfcorporation.com",
"movie.sfcorporation.com","music.sfcorporation.com","news.elecarrow.com","pic.glkjcorp.com",
"pics.adobeus.com","pics.amazonwikis.com","ruag.amazonwikis.com","sgad.sfcorporation.com",
"smgs.amazonwikis.com","sport.sfcorporation.com","ssl.sfcorporation.com","tdfg.moviestops.com",
"tqsj.sfcorporation.com","tzcl.sfcorporation.com","uworks.sfcorporation.com",
"video.sfcorporation.com","vod.sfcorporation.com","wbjs.sfcorporation.com",
"web.sfcorporation.com","wed.amazonwikis.com","xjgs.sfcorporation.com",
"xkgs.sfcorporation.com","ygfk.sfcorporation.com","ekzy.gmnspace.com","hsjs.wordoscorp.com",
"jnhs.tomshardpc.com","rjby.tomshardpc.com","rjjh.wordoscorp.com","ssl.exemail.net",
"tzz.exemail.net","up.adobekr.com","v.exemail.net","wih365.com","yqby.wordoscorp.com",
"zpgx.tomshardpc.com","10kjd.amazonwikis.com","1stone.zapto.org","adobeus.com",
"amazonwikis.com","aqyj.tomshardpc.com","bdgs.amazonwikis.com","blog.adobeus.com",
"blog.amazonwikis.com","blog.wih365.com","bybf.amazonwikis.com","cxks.amazonwikis.com",
"dghk.sfcorporation.com","down.adobeus.com","elecarrow.com","exemail.net",
"flash.adobeus.com","fngs.adobeus.com","fsw.adobeus.com","ghlc.adobeus.com","glkjcorp.com",
"gmnspace.com","hkabinc.com","hkmj.amazonwikis.com","iccbhhjdgb.adobeus.com",
"image.hkabinc.com","js.amazonwikis.com","js.exemail.net","kj.uuvod.net",
"krgt.tomshardpc.com","lhbf.adobeus.com","login.adobekr.com","login.wih365.com",
"microbing.oicp.net","mobile.yqby.wordoscorp.com","moviestops.com","net.amazonwikis.com",
"news.amazonwikis.com","pic.hkabinc.com","projectscorp.net","rbxr.tomshardpc.com",
"rmax.amazonwikis.com","sane.adobeus.com","sfcorporation.com","showjiao.imzone.in",
"showshow.7766.org","ssl.elecarrow.com","sslmails.com","sybf.adobeus.com","tcgs.adobeus.com",
"tech.amazonwikis.com","test.uuvod.net","tomshardpc.com","update.adobeus.com",
"vod.amazonwikis.com","vpntemp.3322.org","wordoscorp.com","www.adobeus.com",
"www.projectscorp.net","www.wih365.com","xrgt.tomshardpc.com","xrgt.wordoscorp.com",
"yjbf.amazonwikis.com","yjxy.sfcorporation.com","zdzl.sfcorporation.com","ziper.imbbs.in"]

d_lines = ["OSINT Dust Storm Campaign Targeting Japanese Critical Infrastructure",
"Event date: 2016-02-23","",
"Context:",
"Reference: https://www.cylance.com/new-security-research-from-cylance-spear-team-uncovers-multi-year-multi-attack-campaign-targeting-japanese-critical-infrastructure",
"Reference: https://www.cylance.com/hubfs/2015_cylance_website/assets/operation-dust-storm/Op_Dust_Storm_Report.pdf",
"Reference: https://github.com/Yara-Rules/rules/blob/master/malware/Operation_Dust_storm.yar",
"campaign-name: Dust Storm","",
"Indicators:"]
d_lines += [f"ip-dst: {i}" for i in ds_ips]
d_lines += [f"hostname: {h}" for h in ds_hosts]

dust = Report(source="misp-circl", source_id="56cdcbde-4fb4-4523-b01d-ff01950d210f",
    title="OSINT Dust Storm Campaign Targeting Japanese Critical Infrastructure",
    url="https://www.circl.lu/doc/misp/feed-osint/56cdcbde-4fb4-4523-b01d-ff01950d210f.json",
    published="2016-02-23", text="\n".join(d_lines))

with open("/tmp/tl/results/corpus_misp.jsonl","w",encoding="utf-8") as f:
    for r in (turla, dust):
        f.write(json.dumps(r.to_dict(), ensure_ascii=False)+"\n")
print("corpus written:", turla.report_id, dust.report_id)
