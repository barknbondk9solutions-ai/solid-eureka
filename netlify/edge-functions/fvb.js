export default async (request, context) => {
  try {
    const userAgent = (request.headers.get("user-agent") || "").toLowerCase();
    const clientIP = context.clientAddress;

    // ==========================
    // 1️⃣ SEO BOT WHITELIST
    // ==========================
    const seoBots = [
      "googlebot","googlebot-image","googlebot-video","googlebot-news",
      "bingbot","slurp","duckduckbot","baiduspider","yandex",
      "facebookexternalhit","twitterbot","linkedinbot",
      "semrushbot","ahrefsbot"
    ];

    if (seoBots.some(bot => userAgent.includes(bot))) {
      const seoResponse = await context.next();
      return addSecurityHeaders(seoResponse);
    }

    // ==========================
    // 2️⃣ GEO / VPN / DATACENTER CHECK
    // ==========================
    let showAccessRestricted = false; 
    let addVpnHeader = false;

    const country = context.geo?.country?.code || "";
    const state = context.geo?.subdivision?.code || "";

    if (country && (country !== "US" || state !== "FL")) {
      showAccessRestricted = true;
    }

if (clientIP) {
  const apiKey = Deno.env.get("IPAPI_API_KEY");
  if (apiKey) {
    try {
      const resp = await fetch(`https://api.ipapi.is/?q=${clientIP}&key=${apiKey}&fields=security,connection,asn,org,type,location`);
      if (resp.ok) {
        const data = await resp.json();

        // ✅ Extract country and state
        const country = data?.location?.country_code || data?.country_code || "";
        const state =
          data?.location?.region_code ||
          data?.location?.region ||
          data?.region_code ||
          data?.region_name ||
          "";

        const vpnFlag =
          Boolean(data?.security?.is_vpn) ||
          Boolean(data?.security?.is_proxy) ||
          Boolean(data?.security?.is_tor) ||
          Boolean(data?.security?.is_hosting) ||
          Boolean(
            data?.connection?.type &&
            [
              "hosting",
              "datacenter",
              "vpn",
              "vpnserver",
              "proxy",
              "residential",
              "business"
            ].some(t => data.connection.type.toLowerCase().includes(t))
          ) ||
          Boolean(data?.connection?.asn && /vpn|proxy|hosting|vps|datacenter/i.test(data.connection.asn)) ||
          Boolean(data?.org && /vpn|proxy|hosting|vps|datacenter/i.test(data.org.toLowerCase()));

        // ✅ Florida-only VPN detection
        if (country === "US" && state === "FL") {
          if (vpnFlag) {
            console.log("⚠️ VPN detected in Florida via API:", clientIP);
            addVpnHeader = true; 
          } else {
            console.log("✅ Florida visitor is clean:", clientIP);
          }
        }

        const suspiciousOrg = (
          (data?.asn?.name || data?.asn?.org || data?.org || data?.connection?.org || data?.connection?.autonomous_system_organization || "")
        ).toString().toLowerCase();

        const hostingKeywords = [
          "amazon","aws","amazonaws","google","microsoft","azure","digitalocean","linode","vultr",
          "hetzner","ovh","ovhcloud","packet","scaleway","oracle","leaseweb","softlayer","cloudflare",
          "aliyun","alibaba","bkcloud","contabo","rackspace","clouvider","colocrossing","servermania",
          "choopa","vpsnet","hivelocity","voxility","hexonet","hostwinds","turnkeyinternet","eukhost",
          "netcup","fastly","akamai","stackpath","keycdn","limelight","edgecast","cloudsigma","upcloud",
          "krypt","datacamp","layerhost","bandwagonhost","phoenixnap","psychz","ovh.ie","soyoustart","kimsufi",
          "dedipath","interserver","ionos","oneprovider","hostgator","bluehost","dreamhost","namecheap",
          "resellerclub","a2hosting","hostinger","wpengine","inmotion","liquidweb","greengeeks",
          "nordvpn","expressvpn","surfshark","cyberghost","privateinternetaccess","pia","protonvpn","windscribe",
          "vpnunlimited","hide.me","torguard","purevpn","ipvanish","vyprvpn","strongvpn","hotspotshield","hola",
          "urbanvpn","atlasvpn","mullvad","perfectprivacy","azirevpn","privado","slickvpn","ivpn","airvpn",
          "fastestvpn","hideipvpn","safervpn","vpnsecure","vpn.ac","zenmate","shieldvpn","goosevpn","rocketvpn",
          "ultravpn","unlocator","kasperskyvpn","avastvpn","bitdefendervpn","browsec","opera-vpn","guardianvpn",
          "totalvpn","okayfreedom","trust.zone","hideallip","seed4.me","vpnarea","supervpn","betternet","psiphon",
          "touchvpn","tunnelbear","xvpn","ultrasurf","thundervpn","melonvpn","snapvpn","securevpn",
          "proxy","tor","openvpn","pptp","l2tp","socks5","shadowsocks","anonine","smartproxy","residentialproxy",
          "brightdata","oxylabs","iproyal","packetstream","netnut","stormproxies","proxyhub","scraperapi",
          "proxyseller","myiphide","proxyrack","ipburger","smartdnsproxy","hidester","kproxy","proxysite",
          "megaproxy","zend2","freeproxy","sslproxy","openproxy","cloudproxy"
        ];

        const typeSuspicious = ["hosting","datacenter","business","vpn","proxy","residential"].some(t => {
          const typ = (data?.type || data?.connection?.type || "").toLowerCase();
          return typ.includes(t);
        });

        // Backup IP check
        try {
          const backupResp = await fetch(`https://ipinfo.io/${clientIP}/json`);
          if (backupResp.ok) {
            const backupData = await backupResp.json();
            const backupOrg = (backupData.org || "").toLowerCase();
            if (/vpn|proxy|vps|hosting|datacenter|network|cloud|colo/i.test(backupOrg)) {
              console.log("⚠️ Backup VPN/proxy detection:", backupOrg);
              return new Response(
                "Access not allowed from VPN/proxy/hosting provider (backup check).",
                { status: 403 }
              );
            }
          }
        } catch (backupErr) {
          console.error("Backup IP check failed:", backupErr);
        }

        if (hostingKeywords.some(k => suspiciousOrg.includes(k)) || typeSuspicious) {
          return new Response(
            "Access not allowed from high-risk VPN/proxy/hosting provider.",
            { status: 403 }
          );
        }
      }
    } catch (err) {
      console.error("VPN/proxy check failed:", err);
    }
  }
}

    // ==========================
    // 3️⃣ Show Access Restricted HTML
    // ==========================
    if (showAccessRestricted) {
      const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Access Restricted | BarkNBondK9Solutions, LLC</title>
<style>
body{font-family:Arial,sans-serif;text-align:center;background:#f9f9f9;color:#333;padding:50px 20px;user-select:none;-webkit-user-select:none;-ms-user-select:none;-webkit-touch-callout:none;-webkit-tap-highlight-color:transparent;overscroll-behavior:none;}
.container{max-width:700px;margin:0 auto;background:#fff;border-radius:12px;padding:40px 30px;box-shadow:0 4px 15px rgba(0,0,0,0.1);}
.logo{max-width:180px;margin-bottom:30px;pointer-events:none;}
h1{font-size:2em;margin-bottom:20px;color:#222;}
p{font-size:1.1em;line-height:1.6;margin-bottom:20px;}
.highlight{color:#e74c3c;font-weight:bold;}
footer{margin-top:40px;font-size:0.9em;color:#666;}
</style>
</head>
<body>
<div class="container">
<img src="https://assets.zyrosite.com/YrDqlxeZ4JTQb14e/logo-clear-m5KMx0qLg1sRj6X7.png" class="logo" alt="Logo" draggable="false">
<h1>Access Restricted</h1>
<p>Thank you for visiting <span class="highlight">BarkNBondK9Solutions, LLC</span>. We are a Florida-based dog training company providing professional services in <span class="highlight">Miami-Dade County</span>.</p>
<p>If you are outside Florida or using a VPN/proxy, access to some parts of the site may be restricted.</p>
<footer>&copy; <span id="currentYear"></span> BarkNBondK9Solutions, LLC | Serving dog owners throughout Miami-Dade County</footer>
</div>
<script>
document.getElementById('currentYear').textContent = new Date().getFullYear();
document.addEventListener('copy',e=>e.preventDefault());
document.addEventListener('cut',e=>e.preventDefault());
document.addEventListener('paste',e=>e.preventDefault());
document.addEventListener('selectstart',e=>e.preventDefault());
document.addEventListener('contextmenu',e=>e.preventDefault());
document.addEventListener('keydown',e=>{if(e.ctrlKey&&['s','p','c','x','a','u'].includes(e.key.toLowerCase())){e.preventDefault();alert("Action disabled.");}if(e.key==='PrintScreen'){navigator.clipboard.writeText('');alert("Screenshots disabled.");}});
document.querySelectorAll('img').forEach(img=>img.setAttribute('draggable','false'));
document.addEventListener('touchstart',e=>e.preventDefault(),{passive:false});
document.addEventListener('gesturestart',e=>e.preventDefault());
(function(){const devtools={open:false};const threshold=160;setInterval(()=>{const w=window.outerWidth-window.innerWidth,h=window.outerHeight-window.innerHeight;if(w>threshold||h>threshold){if(!devtools.open){devtools.open=true;alert("DevTools detected! Page actions are disabled.");document.body.innerHTML="<h1 style='color:red'>Access Denied</h1>";}}else devtools.open=false;},500);window.onkeydown=e=>{if(e.key==="F12"||(e.ctrlKey&&e.shiftKey&&['I','J','C'].includes(e.key))){e.preventDefault();alert("DevTools shortcuts disabled.");}};window.addEventListener('resize',()=>{if(window.outerWidth-window.innerWidth>threshold||window.outerHeight-window.innerHeight>threshold){document.body.innerHTML="<h1 style='color:red'>Access Denied</h1>";}}})();document.addEventListener('touchend',e=>{if(e.touches.length>1)e.preventDefault();},{passive:false});
</script>
</body>
</html>`;
      const response = new Response(html, { status: 200, headers: { "Content-Type": "text/html" } });
      if (addVpnHeader) response.headers.set("X-VPN-Warning","true");
      return addSecurityHeaders(response);
    }

    // ==========================
    // 4️⃣ Default: allow humans
    // ==========================
    const response = await context.next();
    if (addVpnHeader) response.headers.set("X-VPN-Warning","true");
    return addSecurityHeaders(response);

  } catch (err) {
    console.error("Edge Function error:", err);
    const response = await context.next();
    return addSecurityHeaders(response);
  }
};

// ==========================
// Helper: Add security headers
// ==========================
function addSecurityHeaders(response){
  response.headers.set("Strict-Transport-Security","max-age=63072000; includeSubDomains; preload");
  response.headers.set("X-Frame-Options","SAMEORIGIN");
  response.headers.set("X-Content-Type-Options","nosniff");
  response.headers.set("Referrer-Policy","strict-origin-when-cross-origin");
  response.headers.set("Permissions-Policy","geolocation=(), microphone=(), camera=()");
  response.headers.set("Content-Security-Policy",
    "default-src * data: blob: filesystem: about: ws: wss:; "+
    "script-src * 'unsafe-inline' 'unsafe-eval' data: blob:; "+
    "style-src * 'unsafe-inline' data: blob:; "+
    "img-src * data: blob:; "+
    "connect-src * data: blob:; "+
    "frame-src * data: blob:; "+
    "media-src * data: blob:; "+
    "font-src * data: blob:;"
  );
  return response;
}
